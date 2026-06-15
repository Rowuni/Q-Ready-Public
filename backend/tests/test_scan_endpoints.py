"""
tests/test_scan_endpoints.py — Integration tests for POST /scans/ and GET /scans/.

The agent subprocess is mocked so tests run offline and deterministically.

Run:
    cd backend
    py -3.12 -m pytest tests/test_scan_endpoints.py -v
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from contextlib import asynccontextmanager
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# ---------------------------------------------------------------------------
# Path setup: allow importing backend modules directly
# ---------------------------------------------------------------------------
BACKEND_DIR = Path(__file__).parent.parent
REPO_ROOT = BACKEND_DIR.parent
SHARED_DIR = REPO_ROOT / "shared"

if str(SHARED_DIR) not in sys.path:
    sys.path.insert(0, str(SHARED_DIR))
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

import orm  # noqa: E402, F401
from database import Base, get_db  # noqa: E402
from main import app  # noqa: E402

# Disable lifespan so create_tables() doesn't touch the real DB during tests
@asynccontextmanager
async def _noop_lifespan(application):
    yield

app.router.lifespan_context = _noop_lifespan

TEST_ENGINE = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(bind=TEST_ENGINE, autocommit=False, autoflush=False)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def fresh_db():
    """Re-create all tables and inject the scan-test DB session for each test."""
    Base.metadata.create_all(TEST_ENGINE)
    # Save and restore the previous override so other test files are not affected.
    _prev = app.dependency_overrides.get(get_db)
    app.dependency_overrides[get_db] = override_get_db
    yield
    Base.metadata.drop_all(TEST_ENGINE)
    if _prev is None:
        app.dependency_overrides.pop(get_db, None)
    else:
        app.dependency_overrides[get_db] = _prev


# Minimal valid JSON payload the agent emits via `--output json`
_AGENT_FINDING = {
    "source": "ssh_keys",
    "algorithm": "RSA",
    "severity": "high",
    "name": "id_rsa",
    "key_size": 2048,
    "risk_score": 72.0,
    "recommendation": "Migrate to Ed25519",
    "recommendation_url": "https://example.com",
    "detail": "RSA 2048 is not post-quantum safe",
}

_AGENT_OUTPUT = {
    "timestamp": "2026-06-02T12:00:00+00:00",
    "machine_name": "test-host",
    "os_version": "Windows 10",
    "mode": "testset",
    "qr_score": 45.0,
    "findings": [_AGENT_FINDING],
}


def _mock_proc(returncode: int = 0, stdout: str = "", stderr: str = "") -> MagicMock:
    proc = MagicMock()
    proc.returncode = returncode
    proc.stdout = stdout
    proc.stderr = stderr
    return proc


@pytest.fixture
def client():
    return TestClient(app)


# ---------------------------------------------------------------------------
# POST /scans/ — happy path
# ---------------------------------------------------------------------------

class TestPostScanHappyPath:
    def test_returns_201(self, client):
        proc = _mock_proc(stdout=json.dumps(_AGENT_OUTPUT))
        with patch("routers.scan.subprocess.run", return_value=proc):
            r = client.post("/scans/")
        assert r.status_code == 201

    def test_response_has_id(self, client):
        proc = _mock_proc(stdout=json.dumps(_AGENT_OUTPUT))
        with patch("routers.scan.subprocess.run", return_value=proc):
            r = client.post("/scans/")
        assert r.json()["id"] == 1

    def test_hostname_from_agent(self, client):
        proc = _mock_proc(stdout=json.dumps(_AGENT_OUTPUT))
        with patch("routers.scan.subprocess.run", return_value=proc):
            r = client.post("/scans/")
        assert r.json()["hostname"] == "test-host"

    def test_qr_score_from_agent(self, client):
        proc = _mock_proc(stdout=json.dumps(_AGENT_OUTPUT))
        with patch("routers.scan.subprocess.run", return_value=proc):
            r = client.post("/scans/")
        assert r.json()["qr_score"] == pytest.approx(45.0)

    def test_finished_at_is_set(self, client):
        proc = _mock_proc(stdout=json.dumps(_AGENT_OUTPUT))
        with patch("routers.scan.subprocess.run", return_value=proc):
            r = client.post("/scans/")
        assert r.json()["finished_at"] is not None

    def test_mode_is_auto(self, client):
        proc = _mock_proc(stdout=json.dumps(_AGENT_OUTPUT))
        with patch("routers.scan.subprocess.run", return_value=proc):
            r = client.post("/scans/")
        assert r.json()["mode"] == "auto"

    def test_findings_persisted(self, client):
        """POST /scans/ must persist the finding returned by the agent."""
        proc = _mock_proc(stdout=json.dumps(_AGENT_OUTPUT))
        with patch("routers.scan.subprocess.run", return_value=proc):
            client.post("/scans/")
        from orm import FindingORM
        db = TestingSessionLocal()
        count = db.query(FindingORM).count()
        db.close()
        assert count == 1

    def test_no_findings_still_returns_201(self, client):
        payload = {**_AGENT_OUTPUT, "findings": [], "qr_score": 100.0}
        proc = _mock_proc(stdout=json.dumps(payload))
        with patch("routers.scan.subprocess.run", return_value=proc):
            r = client.post("/scans/")
        assert r.status_code == 201
        assert r.json()["qr_score"] == pytest.approx(100.0)

    def test_no_qr_score_in_agent_output(self, client):
        payload = {**_AGENT_OUTPUT, "qr_score": None}
        proc = _mock_proc(stdout=json.dumps(payload))
        with patch("routers.scan.subprocess.run", return_value=proc):
            r = client.post("/scans/")
        assert r.status_code == 201
        assert r.json()["qr_score"] is None
        assert r.json()["finished_at"] is None

    def test_source_alias_normalised(self, client):
        """'ssh_keys' alias from agent must be stored as 'ssh_key'."""
        proc = _mock_proc(stdout=json.dumps(_AGENT_OUTPUT))
        db = TestingSessionLocal()
        with patch("routers.scan.subprocess.run", return_value=proc):
            client.post("/scans/")
        from orm import FindingORM
        finding = db.query(FindingORM).first()
        db.close()
        assert finding is not None
        assert finding.source == "ssh_key"


# ---------------------------------------------------------------------------
# POST /scans/ — error paths
# ---------------------------------------------------------------------------

class TestPostScanErrors:
    def test_agent_timeout_returns_504(self, client):
        with patch("routers.scan.subprocess.run", side_effect=subprocess.TimeoutExpired(cmd=[], timeout=60)):
            r = client.post("/scans/")
        assert r.status_code == 504

    def test_agent_os_error_returns_500(self, client):
        with patch("routers.scan.subprocess.run", side_effect=OSError("not found")):
            r = client.post("/scans/")
        assert r.status_code == 500

    def test_agent_nonzero_exit_returns_500(self, client):
        proc = _mock_proc(returncode=1, stderr="something went wrong")
        with patch("routers.scan.subprocess.run", return_value=proc):
            r = client.post("/scans/")
        assert r.status_code == 500

    def test_agent_no_output_returns_500(self, client):
        proc = _mock_proc(returncode=0, stdout="   ")
        with patch("routers.scan.subprocess.run", return_value=proc):
            r = client.post("/scans/")
        assert r.status_code == 500

    def test_agent_invalid_json_returns_500(self, client):
        proc = _mock_proc(returncode=0, stdout="not json {{{")
        with patch("routers.scan.subprocess.run", return_value=proc):
            r = client.post("/scans/")
        assert r.status_code == 500


# ---------------------------------------------------------------------------
# GET /scans/ — list
# ---------------------------------------------------------------------------

class TestGetScans:
    def _create_scan(self, client):
        proc = _mock_proc(stdout=json.dumps(_AGENT_OUTPUT))
        with patch("routers.scan.subprocess.run", return_value=proc):
            return client.post("/scans/").json()

    def test_empty_list_when_no_scans(self, client):
        r = client.get("/scans/")
        assert r.status_code == 200
        assert r.json() == []

    def test_returns_one_scan_after_post(self, client):
        self._create_scan(client)
        r = client.get("/scans/")
        assert r.status_code == 200
        assert len(r.json()) == 1

    def test_summary_fields_present(self, client):
        self._create_scan(client)
        summary = client.get("/scans/").json()[0]
        assert "id" in summary
        assert "timestamp" in summary
        assert "machine_name" in summary
        assert "qr_score" in summary
        assert "nb_findings_by_severity" in summary

    def test_machine_name_matches_agent(self, client):
        self._create_scan(client)
        summary = client.get("/scans/").json()[0]
        assert summary["machine_name"] == "test-host"

    def test_qr_score_matches_agent(self, client):
        self._create_scan(client)
        summary = client.get("/scans/").json()[0]
        assert summary["qr_score"] == pytest.approx(45.0)

    def test_findings_severity_count(self, client):
        self._create_scan(client)
        summary = client.get("/scans/").json()[0]
        counts = summary["nb_findings_by_severity"]
        assert counts["high"] == 1
        assert counts["critical"] == 0

    def test_pagination_page1(self, client):
        for _ in range(3):
            self._create_scan(client)
        r = client.get("/scans/?page=1&limit=2")
        assert r.status_code == 200
        assert len(r.json()) == 2

    def test_pagination_page2(self, client):
        for _ in range(3):
            self._create_scan(client)
        r = client.get("/scans/?page=2&limit=2")
        assert r.status_code == 200
        assert len(r.json()) == 1

    def test_pagination_invalid_page_returns_422(self, client):
        r = client.get("/scans/?page=0")
        assert r.status_code == 422

    def test_multiple_scans_ordered_most_recent_first(self, client):
        for _ in range(2):
            self._create_scan(client)
        scans = client.get("/scans/").json()
        assert scans[0]["id"] > scans[1]["id"]
