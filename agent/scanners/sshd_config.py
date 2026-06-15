"""
sshd_config.py — Scanner for the sshd_config directives.
"""
from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

_NIST_PQC_URL = "https://csrc.nist.gov/projects/post-quantum-cryptography"
_OPENSSH_DOCS_URL = "https://www.openssh.com/security.html"

# Temporal factor for config findings: no expiration date → same as _temporal_factor(None) = 0.8
_CONFIG_TEMPORAL_FACTOR = 0.8

# ---------------------------------------------------------------------------
# Weak algorithm tables — per issue #9
# Tuple values: (severity, base_score)
# ---------------------------------------------------------------------------

_WEAK_KEXALGO: dict[str, tuple[str, int]] = {
    "diffie-hellman-group1-sha1":  ("critical", 100),
    "diffie-hellman-group14-sha1": ("high",     80),
}

_WEAK_CIPHERS: dict[str, tuple[str, int]] = {
    "3des-cbc":     ("critical", 100),
    "blowfish-cbc": ("high",     85),
    "cast128-cbc":  ("high",     85),
    "arcfour":      ("critical", 100),
    "arcfour128":   ("high",     90),
    "arcfour256":   ("high",     85),
}

_WEAK_MACS: dict[str, tuple[str, int]] = {
    "hmac-md5":     ("critical", 100),
    "hmac-sha1":    ("high",     80),
    "hmac-md5-96":  ("critical", 100),
    "hmac-sha1-96": ("high",     80),
}

_WEAK_HOSTKEYALGOS: dict[str, tuple[str, int]] = {
    "ssh-rsa":              ("high", 80),
    "ecdsa-sha2-nistp256":  ("high", 80),
    "ecdsa-sha2-nistp384":  ("high", 80),
    "ecdsa-sha2-nistp521":  ("high", 75),
}

_WEAK_BY_DIRECTIVE: dict[str, dict[str, tuple[str, int]]] = {
    "kexalgorithms":     _WEAK_KEXALGO,
    "ciphers":           _WEAK_CIPHERS,
    "macs":              _WEAK_MACS,
    "hostkeyalgorithms": _WEAK_HOSTKEYALGOS,
}

_DIRECTIVE_DISPLAY: dict[str, str] = {
    "kexalgorithms":     "KexAlgorithms",
    "ciphers":           "Ciphers",
    "macs":              "MACs",
    "hostkeyalgorithms": "HostKeyAlgorithms",
}

_RECOMMENDATIONS: dict[str, tuple[str, str | None]] = {
    "kexalgorithms": (
        "Migrate to sntrup761x25519-sha512@openssh.com (hybrid PQC) or curve25519-sha256",
        _NIST_PQC_URL,
    ),
    "ciphers": (
        "Use AES-256-GCM (aes256-gcm@openssh.com) or chacha20-poly1305@openssh.com",
        _OPENSSH_DOCS_URL,
    ),
    "macs": (
        "Use ETM MACs: hmac-sha2-256-etm@openssh.com or hmac-sha2-512-etm@openssh.com",
        _OPENSSH_DOCS_URL,
    ),
    "hostkeyalgorithms": (
        "Migrate to Ed25519 host keys (ssh-ed25519)",
        _NIST_PQC_URL,
    ),
}

_MATCH_BLOCK_RE = re.compile(r"^Match\s+", re.IGNORECASE)
_INLINE_COMMENT_RE = re.compile(r"\s*#.*$")

# Only the server config is covered; ssh_config (client) is out of scope for the POC.
_SSH_SERVER_CONFIG_STEM = "sshd_config"


@dataclass
class SshdConfigFinding:
    """
    One finding per weak crypto directive found in a sshd_config file.

    Aligns with the common finding contract (source, algorithm, severity,
    store_or_path…) so it integrates with _enrich_risk_scores() and the
    backend ORM without conversion.

    risk_score is pre-computed here (not by _enrich_risk_scores) because
    sshd_config algorithm names are not in ALGO_SEVERITY; the temporal
    factor defaults to 0.8 (no expiration date).
    """
    source: str
    algorithm: str
    severity: str
    name: str | None
    key_size: None
    expiration_date: None
    store_or_path: str
    detail: str | None
    recommendation: str | None
    recommendation_url: str | None
    risk_score: float | None = None


_COMMON_PATHS = [
    Path(os.environ.get("ProgramData", "C:/ProgramData")) / "ssh",
    Path(os.environ.get("WINDIR", "C:/Windows")) / "System32/OpenSSH",
    Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "OpenSSH",
]


def _parse_sshd_config_directives(text: str) -> tuple[dict[str, str], bool]:
    """Parse sshd_config text into (directives, has_match_block)."""
    directives: dict[str, str] = {}
    has_match_block = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        # Stop parsing global directives at the first Match block.
        if _MATCH_BLOCK_RE.match(line):
            has_match_block = True
            break
        # Strip inline comment from the value (e.g. "Ciphers aes256-ctr  # strong").
        line = _INLINE_COMMENT_RE.sub("", line).strip()
        if not line:
            continue
        parts = re.split(r"[\s=]+", line, 1)
        if len(parts) == 2:
            directive = parts[0].lower()
            value = parts[1].strip()
            # Concatenate repeated directives (e.g. multiple MACs lines).
            if directive in directives:
                directives[directive] += f",{value}"
            else:
                directives[directive] = value
    return directives, has_match_block


def parse_sshd_config_text(
    text: str, virtual_path: str = "sshd_config"
) -> list[SshdConfigFinding]:
    """Parse sshd_config text and emit one finding per weak crypto directive."""
    directives, has_match = _parse_sshd_config_directives(text)
    findings: list[SshdConfigFinding] = []

    if has_match:
        findings.append(SshdConfigFinding(
            source="sshd_config",
            algorithm="Match-block",
            severity="info",
            name="Match",
            key_size=None,
            expiration_date=None,
            store_or_path=virtual_path,
            detail="sshd_config contains Match blocks — scoped configuration not analysed",
            recommendation="Manual audit recommended for directives inside Match blocks",
            recommendation_url=None,
            risk_score=0.0,
        ))

    for directive_key, weak_map in _WEAK_BY_DIRECTIVE.items():
        if directive_key not in directives:
            continue
        raw_value = directives[directive_key]
        directive_display = _DIRECTIVE_DISPLAY.get(directive_key, directive_key)
        rec, rec_url = _RECOMMENDATIONS.get(directive_key, ("Manual review recommended", None))

        for token in raw_value.split(","):
            algo = token.strip().lower()
            if algo not in weak_map:
                continue
            severity, score = weak_map[algo]
            findings.append(SshdConfigFinding(
                source="sshd_config",
                algorithm=algo,
                severity=severity,
                name=directive_display,
                key_size=None,
                expiration_date=None,
                store_or_path=virtual_path,
                detail=f"{directive_display} = {raw_value}",
                recommendation=rec,
                recommendation_url=rec_url,
                risk_score=round(score * _CONFIG_TEMPORAL_FACTOR, 1),
            ))

    return findings


def scan_sshd_config(paths_to_scan: list[Path] | None = None) -> list[SshdConfigFinding]:
    """
    Scan sshd_config files and emit one finding per weak crypto directive.

    Each finding uses the common finding contract (source, algorithm, severity,
    store_or_path…) compatible with _enrich_risk_scores() and the backend ORM.

    POC limitation: directives inside Match blocks are not parsed. When a Match
    block is detected, an info-level finding is emitted recommending manual audit.
    """
    findings: list[SshdConfigFinding] = []

    if paths_to_scan is None:
        paths_to_scan = _COMMON_PATHS

    for base_path in paths_to_scan:
        if not base_path.exists():
            logger.debug("sshd_config search path not found: %s", base_path)
            continue

        files_to_scan: list[Path] = []

        if base_path.is_file():
            if base_path.stem.lower() == _SSH_SERVER_CONFIG_STEM and base_path.suffix != ".py":
                files_to_scan.append(base_path)
        elif base_path.is_dir():
            files_to_scan.extend(base_path.rglob("*"))
        else:
            logger.debug("Skipping non-file, non-directory path: %s", base_path)
            continue

        for file in files_to_scan:
            if not (
                file.is_file()
                and file.stem.lower() == _SSH_SERVER_CONFIG_STEM
                and file.suffix != ".py"
            ):
                continue

            logger.debug("Parsing sshd_config: %s", file)
            try:
                text = file.read_text(encoding="utf-8")
            except OSError as exc:
                logger.warning("Failed to parse sshd_config at %s: %s", file, exc)
                continue
            findings.extend(parse_sshd_config_text(text, str(file)))

    logger.info("scan_sshd_config: found %d finding(s)", len(findings))
    return findings