"""
tests/test_import_endpoints.py — End-to-end tests for POST /import/cert and POST /import/ssh.

Uses FastAPI TestClient with an in-memory SQLite DB (no Docker required).
Fixtures are the real certificate/key files from agent/tests/import/.

Run:
    cd backend
    py -3.12 -m pytest tests/ -v
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# ---------------------------------------------------------------------------
# Path setup: allow importing backend modules directly
# ---------------------------------------------------------------------------
BACKEND_DIR = Path(__file__).parent.parent          # backend/
REPO_ROOT   = BACKEND_DIR.parent                    # Q-Ready/
SHARED_DIR  = REPO_ROOT / "shared"

# qready_scoring must be importable; support both installed and editable installs
if str(SHARED_DIR) not in sys.path:
    sys.path.insert(0, str(SHARED_DIR))
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

# Fixture directories
CERTS_DIR   = REPO_ROOT / "agent" / "tests" / "import" / "certs"
SSH_DIR     = REPO_ROOT / "agent" / "tests" / "ssh"
CONFIGS_DIR = REPO_ROOT / "agent" / "tests" / "import" / "configs"
OPENSSL_FIXTURES_DIR = REPO_ROOT / "agent" / "tests" / "fixtures"

# ---------------------------------------------------------------------------
# Override the database dependency with an in-memory SQLite DB
# ---------------------------------------------------------------------------
import orm  # noqa: E402, F401 — side-effect: registers ORM models with Base.metadata
from database import Base, get_db  # noqa: E402 (after sys.path setup)
from main import app                # noqa: E402

# Disable the app lifespan so create_tables() does not run against the real
# on-disk engine (sqlite:///../data/qready.db) during tests.
from contextlib import asynccontextmanager  # noqa: E402

@asynccontextmanager
async def _noop_lifespan(application):
    yield

app.router.lifespan_context = _noop_lifespan

TEST_ENGINE = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,  # all connections share the same in-memory DB
)
TestingSessionLocal = sessionmaker(TEST_ENGINE, autoflush=False, autocommit=False)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db

# Create all tables in the in-memory DB before any test runs (SQLAlchemy 2.x API)
Base.metadata.create_all(TEST_ENGINE)

client = TestClient(app)


# ===========================================================================
# Helpers
# ===========================================================================

def post_cert(filename: str, password: str | None = None) -> dict:
    path = CERTS_DIR / filename
    files = {"file": (filename, path.read_bytes())}
    data  = {"password": password} if password else {}
    return client.post("/import/cert", files=files, data=data)


def post_ssh(filename: str) -> dict:
    path = SSH_DIR / filename
    files = {"file": (filename, path.read_bytes())}
    return client.post("/import/ssh", files=files)


def post_config(filename: str, fixture_dir=None):
    if fixture_dir is None:
        fixture_dir = CONFIGS_DIR
    path = fixture_dir / filename
    files = {"file": (filename, path.read_bytes())}
    return client.post("/import/config", files=files)


# ===========================================================================
# /import/cert — PEM
# ===========================================================================

class TestImportCertPEM:
    def test_status_201(self):
        r = post_cert("test_cert.pem")
        assert r.status_code == 201

    def test_returns_list(self):
        r = post_cert("test_cert.pem")
        assert isinstance(r.json(), list)
        assert len(r.json()) >= 1

    def test_finding_has_required_fields(self):
        finding = post_cert("test_cert.pem").json()[0]
        for field in ("id", "algorithm", "severity", "risk_score", "recommendation"):
            assert field in finding, f"Missing field: {field}"

    def test_severity_is_valid_enum(self):
        finding = post_cert("test_cert.pem").json()[0]
        assert finding["severity"] in ("critical", "high", "medium", "low", "info")

    def test_risk_score_in_range(self):
        for finding in post_cert("test_cert.pem").json():
            score = finding["risk_score"]
            assert 0 <= score <= 100, f"risk_score out of range: {score}"

    def test_recommendation_references_pqc(self):
        """Every vulnerable finding must mention the PQC migration target."""
        for finding in post_cert("test_cert.pem").json():
            if finding["severity"] in ("critical", "high"):
                rec = finding["recommendation"]
                assert "ML-" in rec, f"Missing PQC recommendation: {rec}"


# ===========================================================================
# /import/cert — DER (.cer)
# ===========================================================================

class TestImportCertDER:
    def test_status_201(self):
        r = post_cert("test_cert.cer")
        assert r.status_code == 201

    def test_returns_one_finding(self):
        findings = post_cert("test_cert.cer").json()
        assert len(findings) == 1

    def test_algorithm_field_non_empty(self):
        finding = post_cert("test_cert.cer").json()[0]
        assert finding["algorithm"]


# ===========================================================================
# /import/cert — PEM EC P-256 (.crt)
# ===========================================================================

class TestImportCertEC:
    def test_status_201(self):
        r = post_cert("test_cert.crt")
        assert r.status_code == 201

    def test_ec_p256_severity_high(self):
        finding = post_cert("test_cert.crt").json()[0]
        assert finding["severity"] == "high"

    def test_ec_p256_base_score_85(self):
        """EC P-256 base score must be 85 before temporal factor."""
        finding = post_cert("test_cert.crt").json()[0]
        # risk_score = 85 * temporal_factor → always ≤ 85
        assert finding["risk_score"] <= 85

    def test_recommendation_url_present(self):
        finding = post_cert("test_cert.crt").json()[0]
        assert finding.get("recommendation_url"), "recommendation_url should be set for EC"


# ===========================================================================
# /import/cert — PKCS#12 without password (.p12)
# ===========================================================================

class TestImportCertP12NoPassword:
    def test_status_201(self):
        r = post_cert("test_cert.p12")
        assert r.status_code == 201

    def test_returns_findings(self):
        assert len(post_cert("test_cert.p12").json()) >= 1


# ===========================================================================
# /import/cert — PKCS#12 with password (.pfx, password="test")
# ===========================================================================

class TestImportCertPFXWithPassword:
    def test_status_201(self):
        r = post_cert("test_cert.pfx", password="test")
        assert r.status_code == 201

    def test_returns_findings(self):
        assert len(post_cert("test_cert.pfx", password="test").json()) >= 1

    def test_wrong_password_returns_400(self):
        r = post_cert("test_cert.pfx", password="wrong_password")
        assert r.status_code == 400


# ===========================================================================
# /import/cert — edge cases
# ===========================================================================

class TestImportCertEdgeCases:
    def test_empty_file_returns_400(self):
        files = {"file": ("empty.pem", b"")}
        r = client.post("/import/cert", files=files)
        assert r.status_code == 400

    def test_garbage_data_returns_400(self):
        files = {"file": ("garbage.pem", b"\x00\x01\x02\x03")}
        r = client.post("/import/cert", files=files)
        assert r.status_code == 400


# ===========================================================================
# /import/ssh — OpenSSH public key
# ===========================================================================

class TestImportSSH:
    def test_status_201(self):
        r = post_ssh("ssh_key_test")
        assert r.status_code == 201

    def test_returns_list(self):
        assert isinstance(post_ssh("ssh_key_test").json(), list)
        assert len(post_ssh("ssh_key_test").json()) >= 1

    def test_finding_has_required_fields(self):
        finding = post_ssh("ssh_key_test").json()[0]
        for field in ("id", "algorithm", "severity", "risk_score", "recommendation"):
            assert field in finding, f"Missing field: {field}"

    def test_severity_valid_enum(self):
        finding = post_ssh("ssh_key_test").json()[0]
        assert finding["severity"] in ("critical", "high", "medium", "low", "info")

    def test_risk_score_in_range(self):
        score = post_ssh("ssh_key_test").json()[0]["risk_score"]
        assert 0 <= score <= 100, f"risk_score out of range: {score}"

    def test_source_is_import_ssh(self):
        finding = post_ssh("ssh_key_test").json()[0]
        assert finding["source"] == "import_ssh"


# ===========================================================================
# /import/ssh — edge cases
# ===========================================================================

class TestImportSSHEdgeCases:
    def test_empty_file_returns_400(self):
        files = {"file": ("empty.pub", b"")}
        r = client.post("/import/ssh", files=files)
        assert r.status_code == 400

    def test_garbage_data_returns_400_or_empty(self):
        files = {"file": ("garbage.pub", b"\x00\x01\x02")}
        r = client.post("/import/ssh", files=files)
        assert r.status_code in (400, 422)


# ===========================================================================
# Scoring coherence — unit-level checks via qready_scoring directly
# ===========================================================================

class TestScoringCoherence:
    """Verify that qready_scoring values are consistent across agent and backend."""

    def test_rsa_2048_severity_and_score(self):
        from qready_scoring.algo_severity import get_algo_severity
        entry = get_algo_severity("RSA-2048")
        assert entry["severity"] == "high"
        assert entry["score"] == 85
        assert "reason" in entry

    def test_ecdsa_p256_via_curve_alias(self):
        from qready_scoring.algo_severity import get_algo_severity
        # Scanners emit "EC-secp256r1"; must resolve to ECDSA-P256
        entry = get_algo_severity("EC-secp256r1")
        assert entry["severity"] == "high"
        assert entry["score"] == 85

    def test_fallback_for_unknown_algo(self):
        from qready_scoring.algo_severity import get_algo_severity
        entry = get_algo_severity("UNKNOWN-XYZ")
        assert entry["severity"] == "medium"
        assert entry["score"] == 50

    def test_temporal_factor_none_returns_0_8(self):
        from qready_scoring.temporal_factor import temporal_factor
        assert temporal_factor(None) == 0.8

    def test_temporal_factor_expired_returns_0_1(self):
        from datetime import datetime, timezone, timedelta
        from qready_scoring.temporal_factor import temporal_factor
        past = datetime.now(timezone.utc) - timedelta(days=1)
        assert temporal_factor(past) == 0.1

    def test_temporal_factor_far_future_returns_1_0(self):
        from datetime import datetime, timezone, timedelta
        from qready_scoring.temporal_factor import temporal_factor
        future = datetime.now(timezone.utc) + timedelta(days=2000)
        assert temporal_factor(future) == 1.0

    def test_agent_wrapper_imports_same_object(self):
        """agent/scoring/algo_severity must re-export the exact same dict as qready_scoring."""
        from qready_scoring.algo_severity import ALGO_SEVERITY as shared
        from scoring.algo_severity import ALGO_SEVERITY as agent  # noqa: F401
        assert shared is agent, "agent wrapper must re-export the shared dict, not a copy"


# ===========================================================================
# /import/config — sshd_config
# ===========================================================================

class TestImportConfigSshd:
    def test_status_201(self):
        r = post_config("sshd_config")
        assert r.status_code == 201

    def test_returns_findings(self):
        findings = post_config("sshd_config").json()
        assert isinstance(findings, list)
        assert len(findings) >= 1

    def test_source_is_import_config(self):
        findings = post_config("sshd_config").json()
        assert all(f["source"] == "import_config" for f in findings)

    def test_store_or_path_has_uploaded_prefix(self):
        findings = post_config("sshd_config").json()
        assert all(f["store_or_path"].startswith("uploaded:") for f in findings)

    def test_severity_is_valid_enum(self):
        findings = post_config("sshd_config").json()
        valid = {"critical", "high", "medium", "low", "info"}
        for f in findings:
            assert f["severity"] in valid

    def test_weak_kexalgo_detected(self):
        algos = [f["algorithm"] for f in post_config("sshd_config").json()]
        assert "diffie-hellman-group1-sha1" in algos

    def test_weak_cipher_detected(self):
        algos = [f["algorithm"] for f in post_config("sshd_config").json()]
        assert "3des-cbc" in algos

    def test_clean_config_returns_empty_list(self):
        r = post_config("sshd_config_clean")
        assert r.status_code == 201
        assert r.json() == []

    def test_ecdsa_nistp256_detected(self):
        """ecdsa-sha2-nistp256 in HostKeyAlgorithms must produce a finding."""
        content = b"HostKeyAlgorithms ecdsa-sha2-nistp256,ssh-ed25519\n"
        files = {"file": ("sshd_config", content)}
        r = client.post("/import/config", files=files)
        assert r.status_code == 201
        algos = [f["algorithm"] for f in r.json()]
        assert "ecdsa-sha2-nistp256" in algos


# ===========================================================================
# /import/config — openssl.cnf
# ===========================================================================

class TestImportConfigOpenssl:
    def test_status_201_critical(self):
        r = post_config("test_openssl_critical.cnf", fixture_dir=OPENSSL_FIXTURES_DIR)
        assert r.status_code == 201

    def test_critical_finding_detected(self):
        findings = post_config("test_openssl_critical.cnf", fixture_dir=OPENSSL_FIXTURES_DIR).json()
        assert len(findings) >= 1
        assert any(f["severity"] == "critical" for f in findings)

    def test_seclevel_zero_algorithm(self):
        algos = [f["algorithm"] for f in
                 post_config("test_openssl_critical.cnf", fixture_dir=OPENSSL_FIXTURES_DIR).json()]
        assert "OpenSSL-SECLEVEL-0" in algos

    def test_source_is_import_config(self):
        findings = post_config("test_openssl_critical.cnf", fixture_dir=OPENSSL_FIXTURES_DIR).json()
        assert all(f["source"] == "import_config" for f in findings)

    def test_store_or_path_has_uploaded_prefix(self):
        findings = post_config("test_openssl_critical.cnf", fixture_dir=OPENSSL_FIXTURES_DIR).json()
        assert all(f["store_or_path"].startswith("uploaded:") for f in findings)

    def test_strong_config_returns_empty_list(self):
        r = post_config("test_openssl_strong.cnf", fixture_dir=OPENSSL_FIXTURES_DIR)
        assert r.status_code == 201
        assert r.json() == []

    def test_risk_score_not_none(self):
        """OpenSSL findings must have a numeric risk_score, not None."""
        findings = post_config("test_openssl_critical.cnf", fixture_dir=OPENSSL_FIXTURES_DIR).json()
        assert len(findings) >= 1
        for f in findings:
            assert f["risk_score"] is not None, f"risk_score is None for {f['algorithm']}"
            assert 0 <= f["risk_score"] <= 100

    def test_cipher_string_negated_md5_no_finding(self):
        """HIGH:!aNULL:!MD5 — MD5 is excluded, must NOT produce a finding."""
        content = b"[system_default_sect]\nCipherString = HIGH:!aNULL:!MD5\n"
        files = {"file": ("openssl.cnf", content)}
        r = client.post("/import/config", files=files)
        assert r.status_code == 201
        assert len(r.json()) == 0

    def test_cipher_string_active_md5_triggers_finding(self):
        """MD5 (not negated) must produce a finding."""
        content = b"[system_default_sect]\nCipherString = HIGH:MD5\n"
        files = {"file": ("openssl.cnf", content)}
        r = client.post("/import/config", files=files)
        assert r.status_code == 201
        algos = [f["algorithm"] for f in r.json()]
        assert any("MD5" in a for a in algos)


# ===========================================================================
# /import/config — content-based detection (non-standard filenames)
# ===========================================================================

class TestImportConfigContentDetection:
    """Config type is inferred from content keywords when filename does not match."""

    def test_sshd_content_generic_filename_returns_201(self):
        content = b"Port 22\nPermitRootLogin no\nKexAlgorithms diffie-hellman-group1-sha1\n"
        files = {"file": ("config.txt", content)}
        r = client.post("/import/config", files=files)
        assert r.status_code == 201

    def test_sshd_content_generic_filename_detects_weak_kex(self):
        content = b"Port 22\nPermitRootLogin no\nKexAlgorithms diffie-hellman-group1-sha1\n"
        files = {"file": ("config.txt", content)}
        algos = [f["algorithm"] for f in client.post("/import/config", files=files).json()]
        assert "diffie-hellman-group1-sha1" in algos

    def test_openssl_content_generic_filename_returns_201(self):
        content = b"[system_default_sect]\nMinProtocol = TLSv1\nCipherString = DEFAULT\n"
        files = {"file": ("tls_config.conf", content)}
        r = client.post("/import/config", files=files)
        assert r.status_code == 201

    def test_openssl_content_generic_filename_detects_weak_protocol(self):
        content = b"[system_default_sect]\nMinProtocol = TLSv1\nCipherString = DEFAULT\n"
        files = {"file": ("tls_config.conf", content)}
        algos = [f["algorithm"] for f in client.post("/import/config", files=files).json()]
        assert "TLS-TLSv1.0" in algos

    def test_no_keywords_still_returns_400(self):
        files = {"file": ("unknown_file.txt", b"some content without any config directives")}
        r = client.post("/import/config", files=files)
        assert r.status_code == 400
        assert isinstance(r.json()["detail"], str)

    def test_tied_score_returns_400(self):
        """Equal SSH and OpenSSL scores (tie) must be rejected as ambiguous."""
        # Port -> sshd_score=1; MinProtocol -> openssl_score=1 -> tie -> None -> 400
        content = b"Port 22\nMinProtocol = TLSv1\n"
        files = {"file": ("ambiguous.txt", content)}
        r = client.post("/import/config", files=files)
        assert r.status_code == 400


# ===========================================================================
# /import/config — edge cases
# ===========================================================================

class TestImportConfigEdgeCases:
    def test_unknown_filename_returns_400(self):
        files = {"file": ("unknown_file.txt", b"some content")}
        r = client.post("/import/config", files=files)
        assert r.status_code == 400

    def test_empty_sshd_config_returns_empty_list(self):
        files = {"file": ("sshd_config", b"")}
        r = client.post("/import/config", files=files)
        assert r.status_code == 201
        assert r.json() == []

    def test_binary_sshd_config_returns_400(self):
        """A binary file submitted as sshd_config must be rejected with 400."""
        files = {"file": ("sshd_config", b"\x00\x01\x02\x03binary\x00data")}
        r = client.post("/import/config", files=files)
        assert r.status_code == 400

    def test_binary_openssl_cnf_returns_400(self):
        """A binary file submitted as openssl.cnf must be rejected with 400."""
        files = {"file": ("openssl.cnf", b"\x00\x01\x02\x03binary\x00data")}
        r = client.post("/import/config", files=files)
        assert r.status_code == 400


# ===========================================================================
# /import/ssh — private key rejection (regression)
# ===========================================================================

class TestImportSSHPrivateKeyRejection:
    """
    Regression: uploading any SSH private key must return HTTP 400.
    Tests the full HTTP stack (endpoint → parser), not just the parser in isolation.
    """

    _OPENSSH_PRIVATE = (
        b"-----BEGIN OPENSSH PRIVATE KEY-----\n"
        b"ZmFrZQ==\n"
        b"-----END OPENSSH PRIVATE KEY-----\n"
    )
    _RSA_PRIVATE = (
        b"-----BEGIN RSA PRIVATE KEY-----\n"
        b"ZmFrZQ==\n"
        b"-----END RSA PRIVATE KEY-----\n"
    )

    def test_openssh_private_key_returns_400(self):
        files = {"file": ("id_rsa", self._OPENSSH_PRIVATE)}
        r = client.post("/import/ssh", files=files)
        assert r.status_code == 400
        assert "private" in r.json()["detail"].lower()

    def test_rsa_private_key_returns_400(self):
        files = {"file": ("id_rsa", self._RSA_PRIVATE)}
        r = client.post("/import/ssh", files=files)
        assert r.status_code == 400
        assert "private" in r.json()["detail"].lower()

    def test_error_message_is_actionable(self):
        """The 400 detail must guide the user toward uploading a public key."""
        files = {"file": ("id_rsa", self._OPENSSH_PRIVATE)}
        detail = client.post("/import/ssh", files=files).json()["detail"]
        assert "public key" in detail.lower()
