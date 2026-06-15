"""
cert_parser.py — Parse certificate files uploaded via the API.

Supports:
  - PEM (single certificate or chain)
  - DER / CER / CRT (binary)
  - PKCS#12 / PFX (with optional password)

Security: private keys extracted from .p12 files are never stored or logged.
"""
from __future__ import annotations

import logging
import re
from datetime import datetime, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from qready_scoring.algo_severity import get_algo_severity as _get_algo_severity
from qready_scoring.temporal_factor import temporal_factor as _temporal_factor
from qready_scoring.recommendation import build_recommendation as _build_recommendation

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_public_key(pub_key: object) -> tuple[str, int | None]:
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


def _extract_finding_dict(cert: x509.Certificate, filename: str) -> dict:
    """Return a dict ready to be passed as kwargs to repository.create_finding()."""
    algo, key_size = _parse_public_key(cert.public_key())

    try:
        expiration_date: datetime | None = cert.not_valid_after_utc
    except AttributeError:
        # cryptography < 42.x fallback
        exp = cert.not_valid_after
        expiration_date = exp.replace(tzinfo=timezone.utc) if exp else None

    try:
        cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        name: str | None = cn_attrs[0].value if cn_attrs else None
    except Exception:
        name = None

    severity_entry = _get_algo_severity(algo, key_size)
    base_score: float = severity_entry["score"]
    tf = _temporal_factor(expiration_date)
    risk_score = round(base_score * tf, 1)

    recommendation, recommendation_url = _build_recommendation(algo)

    detail_parts = [f"Algorithm: {algo}"]
    if key_size:
        detail_parts.append(f"key size: {key_size} bits")
    detail_parts.append(f"file: {filename}")
    if name:
        detail_parts.append(f"subject: {name}")
    detail = "; ".join(detail_parts)

    return {
        "source": "import_cert",
        "algorithm": algo,
        "severity": severity_entry["severity"],
        "name": name,
        "key_size": key_size,
        "expiration_date": expiration_date,
        "store_or_path": filename,
        "risk_score": risk_score,
        "recommendation": recommendation,
        "recommendation_url": recommendation_url,
        "detail": detail,
    }


# ---------------------------------------------------------------------------
# Format-specific parsers
# ---------------------------------------------------------------------------

_PEM_CERT_RE = re.compile(
    b"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)


def _parse_pem(content: bytes, filename: str) -> list[dict]:
    findings = []
    for match in _PEM_CERT_RE.finditer(content):
        try:
            cert = x509.load_pem_x509_certificate(match.group())
            findings.append(_extract_finding_dict(cert, filename))
        except Exception as exc:
            logger.warning("cert_parser: could not parse PEM block in %r: %s", filename, exc)
    return findings


def _parse_der(content: bytes, filename: str) -> list[dict]:
    try:
        cert = x509.load_der_x509_certificate(content)
        return [_extract_finding_dict(cert, filename)]
    except Exception as exc:
        raise ValueError(f"Cannot parse {filename!r} as DER certificate: {exc}") from exc


def _parse_p12(content: bytes, password: bytes | None, filename: str) -> list[dict]:
    try:
        _private_key, cert, chain = pkcs12.load_key_and_certificates(content, password)
        # _private_key is intentionally discarded — never stored or logged
    except Exception as exc:
        raise ValueError(f"Cannot load PKCS#12 file {filename!r}: {exc}") from exc

    findings = []
    if cert is not None:
        findings.append(_extract_finding_dict(cert, filename))
    for c in chain or []:
        findings.append(_extract_finding_dict(c, filename))
    return findings


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def parse_certificate_file(
    content: bytes,
    filename: str,
    password: Optional[bytes] = None,
) -> list[dict]:
    """
    Auto-detect the certificate format and return a list of finding dicts.

    Detection order:
      1. Starts with b"-----BEGIN" → PEM
      2. password provided          → PKCS#12
      3. otherwise                  → attempt PKCS#12 first (common for .p12/.pfx),
                                      then fall back to DER
    """
    if not content:
        raise ValueError("Empty file content")

    if content.lstrip()[:11] == b"-----BEGIN ":
        return _parse_pem(content, filename)

    if password is not None:
        # Try PKCS#12 first; fall back to DER in case a password field was
        # accidentally filled for a non-PKCS#12 file (e.g. a .cer/.crt).
        try:
            return _parse_p12(content, password, filename)
        except ValueError as p12_exc:
            try:
                return _parse_der(content, filename)
            except ValueError:
                raise p12_exc  # re-raise the PKCS#12 error (more informative)

    # Unknown binary: try PKCS#12 (no password), then DER
    try:
        return _parse_p12(content, None, filename)
    except ValueError:
        pass

    return _parse_der(content, filename)
