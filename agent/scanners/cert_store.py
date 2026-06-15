"""
cert_store.py — Scanner for the Windows Certificate Store.
Implementation: task S1.
"""
from __future__ import annotations

import logging
import sys
import warnings
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography import x509
from cryptography.utils import CryptographyDeprecationWarning
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.x509.oid import NameOID

from scoring.criticality_factor import Category
from scoring.recommendations import get_recommendation

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model                                                        (step 1)
# ---------------------------------------------------------------------------

@dataclass
class CertFinding:
    source: str                       # always "cert_store"
    algorithm: str                    # e.g. "RSA-2048", "EC-secp256r1"
    severity: str                     # "critical"|"high"|"medium"|"low"|"info"
    name: str | None                  # subject CN
    key_size: int | None              # key size in bits
    expiration_date: datetime | None  # not_valid_after_utc
    store_or_path: str                # e.g. "CurrentUser\MY"
    detail: str | None
    recommendation: str | None
    recommendation_url: str | None
    risk_score: float | None = None   # reserved for SC4


# ---------------------------------------------------------------------------
# Public-key parser                                                  (step 3)
# ---------------------------------------------------------------------------

def _parse_public_key(pub_key: object) -> tuple[str, int | None]:
    """
    Extract (algorithm_label, key_size_bits) from a cryptography public-key object.
    See agent/scanners/__init__.py for the naming convention.
    """
    if isinstance(pub_key, rsa.RSAPublicKey):
        return f"RSA-{pub_key.key_size}", pub_key.key_size
    if isinstance(pub_key, ec.EllipticCurvePublicKey):
        return f"EC-{pub_key.curve.name}", pub_key.key_size
    if isinstance(pub_key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(pub_key, ed448.Ed448PublicKey):
        return "Ed448", 448
    if isinstance(pub_key, dsa.DSAPublicKey):
        return f"DSA-{pub_key.key_size}", pub_key.key_size
    return f"Unknown-{type(pub_key).__name__}", None


# ---------------------------------------------------------------------------
# Microsoft system-cert filter                                       (step 4)
# ---------------------------------------------------------------------------

_MS_ISSUER_PATTERNS = [
    "microsoft root certificate authority",
    "microsoft root authority",
    "microsoft authenticode",
    "microsoft time-stamp",
]


def _is_ms_system_cert(cert: x509.Certificate) -> bool:
    """
    Return True if this certificate was issued by a Microsoft root CA.
    These certs are managed by Windows Update and are not actionable.
    """
    try:
        attrs = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        if not attrs:
            return False
        cn_lower = attrs[0].value.lower()
        return any(pat in cn_lower for pat in _MS_ISSUER_PATTERNS)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Detail builder                                                     (step 5)
# ---------------------------------------------------------------------------

def _build_detail(
    algo: str,
    key_size: int | None,
    store: str,
    name: str | None,
    is_expired: bool,
) -> str:
    """Build a human-readable detail string for a certificate finding."""
    parts = [f"Algorithm: {algo}"]
    if key_size is not None:
        parts.append(f"key size: {key_size} bits")
    parts.append(f"store: {store}")
    if name:
        parts.append(f"subject: {name}")
    if is_expired:
        parts.append("(expired)")
    return "; ".join(parts)


# ---------------------------------------------------------------------------
# Entry point                                                        (step 6)
# ---------------------------------------------------------------------------

# wincertstore 0.2 wraps CertOpenSystemStore which opens CurrentUser stores only.
# LocalMachine stores require CertOpenStore with CERT_SYSTEM_STORE_LOCAL_MACHINE,
# which is not exposed by this library.  Scope prefix is kept in the label so
# findings remain unambiguous if LocalMachine support is added later.
_STORES = ["MY", "ROOT", "CA", "TRUSTEDPUBLISHER"]


def _parse_cert(der_bytes: bytes, store_label: str) -> CertFinding | None:
    """
    Parse a DER-encoded certificate and return a CertFinding, or None if the
    certificate should be skipped (Microsoft system cert or parse failure).
    """
    try:
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
            cert = x509.load_der_x509_certificate(der_bytes)
    except Exception as e:
        logger.warning("_parse_cert: cannot parse cert in %s: %s", store_label, e)
        return None

    if _is_ms_system_cert(cert):
        logger.debug("_parse_cert: skipping Microsoft system cert in %s", store_label)
        return None

    # Subject CN (falls back to full subject string if CN is absent)
    try:
        cns = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        name: str | None = cns[0].value if cns else str(cert.subject)
    except Exception:
        name = None

    # Expiration date (UTC-aware, requires cryptography >= 42.0)
    try:
        expiration: datetime | None = cert.not_valid_after_utc
    except Exception:
        expiration = None

    is_expired = expiration is not None and expiration < datetime.now(timezone.utc)

    # Algorithm + key size
    try:
        algo, key_size = _parse_public_key(cert.public_key())
    except Exception as e:
        logger.warning(
            "_parse_cert: cannot read public key in %s: %s", store_label, e
        )
        algo, key_size = "Unknown", None

    severity = "info"  # populated by _enrich_risk_scores (SC4)
    detail = _build_detail(algo, key_size, store_label, name, is_expired)
    recommendation, rec_url = get_recommendation(
        algo, Category.CERTIFICATE, key_size=key_size, is_expired=is_expired
    )

    return CertFinding(
        source="cert_store",
        algorithm=algo,
        severity=severity,
        name=name,
        key_size=key_size,
        expiration_date=expiration,
        store_or_path=store_label,
        detail=detail,
        recommendation=recommendation,
        recommendation_url=rec_url,
    )


def scan_cert_store() -> list[CertFinding]:
    """Enumerate certificates in the Windows Certificate Store and return a list of findings."""
    if sys.platform != "win32":
        logger.info("scan_cert_store: non-Windows platform, skipping")
        return []

    import wincertstore  # Windows-only; imported after platform guard

    findings: list[CertFinding] = []

    for store_name in _STORES:
        label = f"CurrentUser\\{store_name}"
        try:
            with wincertstore.CertSystemStore(store_name) as store:
                for cert_ctx in store.itercerts(usage=None):
                    finding = _parse_cert(cert_ctx.get_encoded(), label)
                    if finding is not None:
                        findings.append(finding)
        except OSError as e:
            logger.warning("scan_cert_store: cannot open store %s: %s", label, e)

    logger.info(
        "scan_cert_store: found %d findings across %d stores",
        len(findings),
        len(_STORES),
    )
    return findings
