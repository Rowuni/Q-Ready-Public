"""
ssh_keys.py — Scanner for SSH key files on the local machine.
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import paramiko
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.hazmat.primitives.serialization import load_ssh_public_key

from scoring.criticality_factor import Category
from scoring.recommendations import get_recommendation

logger = logging.getLogger(__name__)

# Canonical filenames for OpenSSH private keys (without extension)
PRIVATE_KEY_STEMS = {"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "id_xmss"}

# Extensions associated with private keys (excluding files without extension)
PRIVATE_KEY_EXTENSIONS = {".pem", ".ppk", ".key"}

# Files to explicitly ignore in ~/.ssh even if they do not have an extension
SSH_CONFIG_FILES = {
    "known_hosts", "authorized_keys", "config",
    "known_hosts.old", "environment", "rc",
}

PUBLIC_KEY_PREFIXES = {
    "ssh-rsa ",
    "ssh-ed25519 ",
    "ecdsa-sha2-nistp256 ",
    "ecdsa-sha2-nistp384 ",
    "ecdsa-sha2-nistp521 ",
    "sk-ssh-ed25519@openssh.com ",           # FIDO2 hardware keys
    "sk-ecdsa-sha2-nistp256@openssh.com "
}

# Headers identifying a private key at the beginning of a file
PRIVATE_KEY_HEADERS = {
    "-----BEGIN OPENSSH PRIVATE KEY-----",   # Modern OpenSSH format
    "-----BEGIN RSA PRIVATE KEY-----",        # Legacy PEM RSA format
    "-----BEGIN EC PRIVATE KEY-----",         # Legacy PEM ECDSA format
    "-----BEGIN DSA PRIVATE KEY-----",        # Legacy PEM DSA format
    "-----BEGIN ENCRYPTED PRIVATE KEY-----",  # Encrypted PKCS#8
    "-----BEGIN PRIVATE KEY-----",            # Unencrypted PKCS#8
    "PuTTY-User-Key-File-2:",                 # PuTTY PPK v2 format
    "PuTTY-User-Key-File-3:",                 # PuTTY PPK v3 format
}

# Headers identifying a public key at the beginning of a file
PUBLIC_KEY_HEADERS = {
    "---- BEGIN SSH2 PUBLIC KEY ----",        # SSH2 format (RFC 4716)
}

# Maximum number of bytes read for content-based detection (64 bytes are enough
# for all headers above)
_HEADER_READ_BYTES = 64


@dataclass
class SshKeyFinding:
    path: Path
    algorithm: str
    key_size: int | None = None
    type: str | None = None  # "public" or "private"
    file_size: int | None = None
    last_modified: datetime | None = None
    is_paired: bool | None = None
    recommendation: str | None = None
    recommendation_url: str | None = None


# ---------------------------------------------------------------------------
# Helpers — key type detection
# ---------------------------------------------------------------------------

def _read_header(path: Path) -> str:
    """
    Reads the first bytes of a file and decodes them as text.
    Returns an empty string on error (permissions, binary file, etc.).
    Used only as a last resort, after fast filters.
    """
    try:
        with path.open("rb") as f:
            return f.read(_HEADER_READ_BYTES).decode("utf-8", errors="ignore")
    except OSError:
        return ""


def _detect_key_type_by_content(path: Path) -> str | None:
    """
    Returns "private", "public", or None based on file content.
    Reads only the first bytes to stay performant.
    """
    header = _read_header(path)
    if not header:
        return None
    if any(header.startswith(h) for h in PRIVATE_KEY_HEADERS):
        return "private"
    if any(header.startswith(p) for p in PUBLIC_KEY_HEADERS) or any(header.startswith(p) for p in PUBLIC_KEY_PREFIXES):
        return "public"
    return None


def _is_public_key_file(path: Path) -> bool:
    """
    Detects public keys by extension (.pub) first,
    then falls back to content for atypical names.
    """
    # 1. Unambiguous extension — no disk read
    if path.suffix.lower() == ".pub":
        return True

    # 2. Fast exclusions: known SSH config files
    if path.stem.lower() in SSH_CONFIG_FILES:
        return False

    # 3. Fallback: content-based detection
    return _detect_key_type_by_content(path) == "public"


def _is_private_key_file(path: Path) -> bool:
    """
    Detects private keys by name/extension first,
    then falls back to content - disk reads always come last.
    """
    stem = path.stem.lower()
    suffix = path.suffix.lower()

    # 1. Fast exclusions: known SSH config files
    if stem in SSH_CONFIG_FILES:
        return False

    # 2. Unambiguous extensions — no disk read
    if suffix in PRIVATE_KEY_EXTENSIONS:
        return True

    # 3. Canonical names without extension — no disk read
    if suffix == "" and stem in PRIVATE_KEY_STEMS:
        return True

    # 4. Fallback: content-based detection (reads first bytes)
    return _detect_key_type_by_content(path) == "private"


def _get_paired_public_key_path(path: Path) -> Path | None:
    """Returns the path to the associated public key if it exists, else None."""
    stem = path.stem
    candidates = [
        path.parent / f"{stem}.pub",
        path.parent / stem
    ]
    for p in candidates:
        if p.exists() and p != path and _is_public_key_file(p):
            return p
    return None

def _paired_key_exists(path: Path, key_type: str) -> bool:
    """Checks whether the paired key (public ↔ private) exists."""
    stem = path.stem
    if key_type == "public":
        # Public key -> look for the private key (without extension, or with .ppk, .pem, .key)
        candidates = [
            path.parent / stem,
            path.parent / f"{stem}.ppk",
            path.parent / f"{stem}.pem",
            path.parent / f"{stem}.key"
        ]
        return any(
            p != path and p.is_file() and _is_private_key_file(p)
            for p in candidates
        )
    else:
        # Private key -> look for the public key (.pub, or without extension)
        return _get_paired_public_key_path(path) is not None


# ---------------------------------------------------------------------------
# Helpers — metadata extraction
# ---------------------------------------------------------------------------

def _infer_key_metadata(path: Path) -> tuple[str, int | None]:
    """
    Best-effort inference of the algorithm from the filename.
    Used as a fallback when Paramiko is missing or fails.
    """
    stem = path.stem.lower()
    suffix = path.suffix.lower()

    if stem == "id_rsa":
        return "Unknown-RSA", None
    if stem == "id_ed25519":
        return "Ed25519", 256
    if stem == "id_ecdsa":
        return "Unknown-EC", None
    if stem == "id_dsa":
        return "Unknown-DSA", None
    if stem == "id_xmss":
        return "Unknown-XMSS", None
    if suffix == ".pem":
        return "Unknown-PEM", None
    if suffix == ".ppk":
        return "Unknown-PPK", None
    if suffix in {".key", ""}:
        return "Unknown-Key", None
    return f"Unknown-{path.suffix.lstrip('.').upper() or 'File'}", None


def _parse_pubkey_file(path: Path) -> tuple[str, int | None]:
    """
    Reads a public key file (.pub) and extracts the algorithm.
    Uses cryptography for precise binary decoding when possible,
    and falls back to strict token parsing for recognized formats.
    """
    try:
        # Proper binary parsing via cryptography (handles OpenSSH keys perfectly)
        key = load_ssh_public_key(path.read_bytes())
        if isinstance(key, rsa.RSAPublicKey):
            return f"RSA-{key.key_size}", key.key_size
        elif isinstance(key, ec.EllipticCurvePublicKey):
            return f"EC-{key.curve.name}", key.curve.key_size
        elif isinstance(key, ed25519.Ed25519PublicKey):
            return "Ed25519", 256
        elif isinstance(key, ed448.Ed448PublicKey):
            return "Ed448", 448
        elif isinstance(key, dsa.DSAPublicKey):
            return f"DSA-{key.key_size}", key.key_size
    except Exception:
        pass

    try:
        # Strict parsing fallback: read only the first line to match the key type token.
        # No substring search — only explicit prefix matching.
        with path.open(encoding="utf-8", errors="ignore") as f:
            header = f.readline().lstrip()

        if header.startswith("ssh-rsa "):
            return "Unknown-RSA", None
        if header.startswith("ssh-ed25519 ") or header.startswith("sk-ssh-ed25519@openssh.com "):
            return "Ed25519", 256
        if header.startswith("ssh-dss "):
            return "Unknown-DSA", None
        if header.startswith("ecdsa-sha2-") or header.startswith("sk-ecdsa-sha2-"):
            return "Unknown-EC", None
    except Exception:
        pass

    return _infer_key_metadata(path)


def _parse_private_key_file(path: Path) -> tuple[str, int | None]:
    """
    Extracts algorithm and key size for a private key file.
    Order of attempts (least invasive first):
      1. Paired public key — no private material read.
      2. Paramiko — reads material only for unencrypted keys
         (PasswordRequiredException means the key is encrypted: no read occurs).
      3. Filename inference — last resort.
    """
    # 1. Paired public key — preferred, no private material involved
    paired_pub = _get_paired_public_key_path(path)
    if paired_pub:
        pub_algo, pub_bits = _parse_pubkey_file(paired_pub)
        if not pub_algo.startswith("Unknown-"):
            return pub_algo, pub_bits

    # 2. Paramiko — only reads material for unencrypted keys
    loaders = [
        (paramiko.Ed25519Key, "Ed25519"),
        (paramiko.ECDSAKey,   "EC"),
        (paramiko.RSAKey,     "RSA"),
    ]

    for loader, label in loaders:
        try:
            key = loader(filename=str(path))
            bits = key.get_bits() if hasattr(key, "get_bits") else None
            if label == "Ed25519":
                algorithm = "Ed25519"
            else:
                algorithm = f"{label}-{bits}" if bits else f"Unknown-{label}"
            return algorithm, bits
        except paramiko.ssh_exception.PasswordRequiredException:
            # Encrypted key — cannot read without passphrase; stop trying
            break
        except Exception:
            continue

    return _infer_key_metadata(path)


# ---------------------------------------------------------------------------
# Search paths
# ---------------------------------------------------------------------------

def _build_search_paths() -> list[Path]:
    """
    Builds the list of directories to scan.
    Focuses on known, recurring paths.
    """
    home = Path.home()
    candidates = [
        home / ".ssh",                  # Standard OpenSSH location
        Path("C:/ProgramData/ssh"),     # SSH server system (Windows Server / OpenSSH)
        Path("C:/Users/Public/.ssh"),   # Public profile
    ]

    appdata_str = os.environ.get("APPDATA")
    if appdata_str:
        appdata = Path(appdata_str)
        candidates.extend([
            appdata / "ssh",                # AppData\Roaming\ssh
            appdata / ".ssh",
            appdata / "PuTTY",              # PuTTY sessions (no keys, but useful)
            appdata / "Termius" / "ssh",
        ])

    local_appdata_str = os.environ.get("LOCALAPPDATA")
    if local_appdata_str:
        local_appdata = Path(local_appdata_str)
        candidates.extend([
            local_appdata / "ssh",          # AppData\Local\ssh
            local_appdata / "Programs" / "Git" / "etc" / "ssh",
        ])

    # Deduplicate and keep only existing paths (or let scan_ssh_keys filter)
    seen: set[Path] = set()
    result: list[Path] = []
    for p in candidates:
        resolved = p.resolve() if p.exists() else p
        if resolved not in seen:
            seen.add(resolved)
            result.append(p)

    return result


# ---------------------------------------------------------------------------
# Main scanner
# ---------------------------------------------------------------------------

def scan_ssh_keys(target_dir: Path | None = None) -> list[SshKeyFinding]:
    """
    Scans known SSH directories and returns the list of found keys.
    If target_dir is provided, scans only that directory.
    """
    ssh_keys: list[SshKeyFinding] = []
    search_paths = [target_dir] if target_dir else _build_search_paths()

    for base_path in search_paths:
        if not base_path.exists():
            logger.debug("Search path not found, skipping: %s", base_path)
            continue

        if not base_path.is_dir():
            logger.debug("Search path is not a directory, skipping: %s", base_path)
            continue

        logger.debug("Scanning: %s", base_path)

        for file in base_path.rglob("*"):
            if not file.is_file():
                continue

            if _is_public_key_file(file):
                algorithm, key_size = _parse_pubkey_file(file)
                key_type = "public"
            elif _is_private_key_file(file):
                algorithm, key_size = _parse_private_key_file(file)
                key_type = "private"
            else:
                continue

            try:
                stat = file.stat()
                file_size = stat.st_size
                last_modified = datetime.fromtimestamp(stat.st_mtime)
            except OSError:
                file_size = None
                last_modified = None

            rec_text, rec_url = get_recommendation(
                algorithm, Category.SSH_KEY, key_size=key_size
            )
            ssh_keys.append(
                SshKeyFinding(
                    path=file,
                    algorithm=algorithm,
                    key_size=key_size,
                    type=key_type,
                    file_size=file_size,
                    last_modified=last_modified,
                    is_paired=_paired_key_exists(file, key_type),
                    recommendation=rec_text,
                    recommendation_url=rec_url,
                )
            )

    logger.info(
        "Found %d SSH key file(s) across %d search path(s).",
        len(ssh_keys),
        len(search_paths),
    )
    return ssh_keys