"""
ssh_parser.py — Parse SSH key files uploaded via the API.

Supports:
  public keys in OpenSSH or putty format.
"""
from __future__ import annotations

import logging
import base64
import re
import struct
try:
    import paramiko
except ImportError:
    paramiko = None
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.hazmat.primitives.serialization import load_ssh_public_key

from qready_scoring.algo_severity import get_algo_severity
from qready_scoring.recommendation import build_recommendation as _build_recommendation

logger = logging.getLogger(__name__)


def _extract_key_info(key) -> tuple[str, int | None]:
    """Extract (algorithm_label, key_size_bits) from a cryptography public-key object."""
    if isinstance(key, rsa.RSAPublicKey):
        return f"RSA-{key.key_size}", key.key_size
    if isinstance(key, ec.EllipticCurvePublicKey):
        name = key.curve.name
        if name == "secp256r1":
            return "ECDSA-P256", 256
        if name == "secp384r1":
            return "ECDSA-P384", 384
        if name == "secp521r1":
            return "ECDSA-P521", 521
        return f"EC-{name}", key.curve.key_size
    if isinstance(key, ed25519.Ed25519PublicKey):
        return "Ed25519", 256
    if isinstance(key, ed448.Ed448PublicKey):
        return "Ed448", 448
    if isinstance(key, dsa.DSAPublicKey):
        return f"DSA-{key.key_size}", key.key_size
    return "Unknown", None

def _fallback_paramiko(content: bytes) -> tuple[str, int | None]:
    """Uses paramiko as a fallback for keys that cryptography rejects (like DSA > 1024)."""
    if paramiko is None:
        return "Unknown", None

    try:
        # PKey.from_string expects a string block, often starting with the algo type
        # Or you can do it carefully by isolating the base64 part
        lines = content.decode("utf-8", errors="ignore").splitlines()
        for line in lines:
            if line.startswith("ssh-dss "):
                # Extract the base64 part
                parts = line.split(maxsplit=2)
                if len(parts) >= 2:
                    k = paramiko.DSSKey(data=base64.b64decode(parts[1]))
                    return f"DSA-{k.get_bits()}", k.get_bits()
            # We can also fallback for RSA just in case
            elif line.startswith("ssh-rsa "):
                parts = line.split(maxsplit=2)
                if len(parts) >= 2:
                    k = paramiko.RSAKey(data=base64.b64decode(parts[1]))
                    return f"RSA-{k.get_bits()}", k.get_bits()
    except Exception as e:
        logger.debug("Paramiko fallback failed: %s", e)

    return "Unknown", None

# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def _convert_rfc4716_to_openssh(content: bytes) -> bytes:
    """
    Converts a multi-line RFC 4716 / SSH2 public key (like those from PuTTYgen)
    into a single-line OpenSSH format that cryptography can parse.
    """
    lines = content.decode("utf-8", errors="ignore").splitlines()
    in_key = False
    b64_lines = []

    for line in lines:
        line = line.strip()
        if line.startswith("---- BEGIN SSH2 PUBLIC KEY"):
            in_key = True
            continue
        if line.startswith("---- END SSH2 PUBLIC KEY"):
            break
        if in_key:
            # Skip header lines (like Comment: "...") or continuations
            if ":" in line or line.endswith("\\"):
                continue
            b64_lines.append(line)

    if not b64_lines:
        return content

    b64_data = "".join(b64_lines)
    try:
        raw_blob = base64.b64decode(b64_data)
        type_len = struct.unpack(">I", raw_blob[:4])[0]
        key_type = raw_blob[4:4+type_len].decode("ascii")
        return f"{key_type} {b64_data}".encode("utf-8")
    except Exception as e:
        logger.debug("Failed to convert RFC4716 to OpenSSH: %s", e)
        return content


def _looks_like_authorized_keys(content: bytes) -> bool:
    """True if content has more than one non-comment key line."""
    key_lines = [
        ln for ln in content.decode("utf-8", errors="ignore").splitlines()
        if ln.strip() and not ln.strip().startswith("#")
    ]
    return len(key_lines) > 1


def _is_authorized_keys_file(filename: str) -> bool:
    base = filename.rsplit(".", 1)[0]  # strip .txt, .bak, etc.
    return base.endswith("authorized_keys") or base.endswith("authorized_keys2")


def _strip_authorized_keys_options(line: str) -> str:
    """Strip leading options from an authorized_keys entry."""
    # Fast path: no options present
    for prefix in ("ssh-", "ecdsa-", "sk-"):
        if line.startswith(prefix):
            return line
    # Slow path: find the key type after options
    # Covers: ssh-rsa, ecdsa-sha2-nistp256, sk-ssh-ed25519@openssh.com, etc.
    match = re.search(r'((?:ssh|ecdsa|sk)-[A-Za-z0-9\-\.@]+)\s+', line)
    return line[match.start():] if match else line


def _parse_authorized_keys(content: bytes, filename: str) -> list[dict]:
    findings = []
    for line_num, raw_line in enumerate(
        content.decode("utf-8", errors="ignore").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        line = _strip_authorized_keys_options(line)
        try:
            pub_key = load_ssh_public_key(line.encode("utf-8"))
            algo, size = _extract_key_info(pub_key)
            severity_info = get_algo_severity(algo, size)
            recommendation, rec_url = _build_recommendation(algo)
            findings.append({
                "algorithm":          algo,
                "key_size":           size,
                "severity":           severity_info["severity"],
                "risk_score":         severity_info["score"],
                "recommendation":     recommendation,
                "recommendation_url": rec_url,
                "source":             "import_ssh",
                "store_or_path":      f"{filename}:{line_num}",
            })
        except Exception as e:
            logger.warning("authorized_keys: skipping line %d — %s", line_num, e)
    return findings


def parse_ssh_public_key(content: bytes, filename: str) -> list[dict]:
    if not content:
        raise ValueError("SSH public key file is empty")

    # Reject private keys early — pattern covers all standard PEM private key headers.
    # re.IGNORECASE is intentionally omitted: PEM headers are standardised uppercase.
    if re.search(rb"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----", content):
        raise ValueError("Private keys are not accepted. Please provide a public key instead.")

    logger.debug("parse_ssh_public_key: filename=%r len=%d", filename, len(content))
    if b"---- BEGIN SSH2 PUBLIC KEY" in content:
        content = _convert_rfc4716_to_openssh(content)

    is_ak_file = _is_authorized_keys_file(filename)
    looks_ak = _looks_like_authorized_keys(content)
    logger.debug("authorized_keys detection: is_file=%s looks_like=%s", is_ak_file, looks_ak)
    if is_ak_file or looks_ak:
        return _parse_authorized_keys(content, filename)

    try:
        pub_key = load_ssh_public_key(content)
        algo, size = _extract_key_info(pub_key)
    except Exception as e:
        logger.debug("cryptography parsing failed: %s. Trying paramiko fallback.", e)
        algo, size = _fallback_paramiko(content)

        if algo == "Unknown":
            logger.error("Failed to parse SSH public key from %r: %s", filename, e)
            return []

    severity_info = get_algo_severity(algo, size)
    recommendation, rec_url = _build_recommendation(algo)
    score = severity_info["score"]
    return [{
        "algorithm":          algo,
        "key_size":           size,
        "severity":           severity_info["severity"],
        "risk_score":         score,
        "recommendation":     recommendation,
        "recommendation_url": rec_url,
        "source":             "import_ssh",
        "store_or_path":      filename,
    }]
