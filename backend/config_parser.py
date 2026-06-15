"""
config_parser.py — Parse sshd_config and openssl.cnf files uploaded via the API.

Mirrors the detection logic from agent/scanners/sshd_config.py and
agent/scanners/openssl_cnf.py, but works on bytes and returns list[dict]
compatible with repository.create_findings_bulk().
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

_NIST_PQC_URL = "https://csrc.nist.gov/projects/post-quantum-cryptography"
_OPENSSH_DOCS_URL = "https://www.openssh.com/security.html"
_RFC8996_URL = "https://www.rfc-editor.org/rfc/rfc8996"
_OPENSSL_DOCS_URL = "https://www.openssl.org/docs/man3.0/man5/config.html"

# Temporal factor for config findings: no expiration date → same as temporal_factor(None) = 0.8
_CONFIG_TEMPORAL_FACTOR = 0.8

# ---------------------------------------------------------------------------
# sshd_config — weak algorithm tables (mirrors agent/scanners/sshd_config.py)
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

_SSHD_RECOMMENDATIONS: dict[str, tuple[str, str | None]] = {
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

# ---------------------------------------------------------------------------
# Content-based auto-detection (keyword heuristics)
# ---------------------------------------------------------------------------

# sshd_config directives: must appear at the start of a line (after optional spaces)
# followed by at least one whitespace or = and a non-space char.
_SSHD_DIRECTIVE_RE = re.compile(
    r"^\s*(?:Port|PermitRootLogin|KexAlgorithms|HostKeyAlgorithms|AuthorizedKeysFile|"
    r"PubkeyAuthentication|PasswordAuthentication|ListenAddress|UsePAM|X11Forwarding|"
    r"Subsystem|AllowUsers|DenyUsers|AllowGroups|MaxAuthTries|LoginGraceTime|"
    r"PermitEmptyPasswords|GSSAPIAuthentication|PrintMotd|AcceptEnv|"
    r"ChallengeResponseAuthentication|LogLevel|SyslogFacility|Banner|"
    r"ClientAliveInterval|ClientAliveCountMax|TCPKeepAlive)(?:\s+|=)\s*\S",
    re.IGNORECASE | re.MULTILINE,
)

# openssl.cnf section headers — very distinctive, worth double weight
_OPENSSL_SECTION_RE = re.compile(
    r"^\s*\[\s*(?:openssl_init|system_default_sect|default_sect|req|CA_default|"
    r"ca|ssl_sect|req_ext|v3_ca|v3_req|provider_sect|legacy_sect)\s*\]",
    re.IGNORECASE | re.MULTILINE,
)

# openssl.cnf key = value pairs exclusive to openssl config
_OPENSSL_KEY_RE = re.compile(
    r"^\s*(?:MinProtocol|CipherString|openssl_conf|RANDFILE|distinguished_name|"
    r"Curves|providers|x509_extensions|default_ca|default_bits|default_md|"
    r"string_mask|prompt|req_extensions)\s*=",
    re.IGNORECASE | re.MULTILINE,
)


def detect_config_type_from_content(content: bytes) -> str | None:
    """Detect config type by scoring keyword matches against the file content.

    Returns 'sshd', 'openssl', or None if the content is ambiguous or empty.
    """
    try:
        text = content.decode("utf-8", errors="replace")
    except Exception:
        return None

    sshd_score = len(_SSHD_DIRECTIVE_RE.findall(text))
    openssl_score = (
        len(_OPENSSL_SECTION_RE.findall(text)) * 2
        + len(_OPENSSL_KEY_RE.findall(text))
    )

    if sshd_score == 0 and openssl_score == 0:
        return None
    if sshd_score > openssl_score:
        return "sshd"
    if openssl_score > sshd_score:
        return "openssl"
    return None  # tie → ambiguous


# ---------------------------------------------------------------------------
# openssl.cnf — detection helpers (mirrors agent/scanners/openssl_cnf.py)
# ---------------------------------------------------------------------------

_SECLEVEL_RE = re.compile(r"@seclevel\s*=\s*(\d)", re.IGNORECASE)
_WEAK_CURVE_TOKENS = ("secp160", "secp192", "prime192", "secp224", "prime224")

# Base scores per severity for openssl findings (no algorithm-specific score table)
_SEVERITY_DEFAULT_SCORE: dict[str, int] = {
    "critical": 100,
    "high":      80,
    "medium":    60,
    "low":       30,
    "info":       0,
}


# ---------------------------------------------------------------------------
# Auto-detection
# ---------------------------------------------------------------------------

def detect_config_type(filename: str) -> str | None:
    """Detect config type from filename: 'sshd' or 'openssl', or None if unknown."""
    name = Path(filename).name.lower()
    if "sshd_config" in name:
        return "sshd"
    if "openssl" in name and Path(filename).suffix.lower() in (".cnf", ".conf"):
        return "openssl"
    return None


# ---------------------------------------------------------------------------
# sshd_config parser
# ---------------------------------------------------------------------------

def _parse_sshd_directives(text: str) -> tuple[dict[str, str], bool]:
    directives: dict[str, str] = {}
    has_match_block = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if _MATCH_BLOCK_RE.match(line):
            has_match_block = True
            break
        line = _INLINE_COMMENT_RE.sub("", line).strip()
        if not line:
            continue
        parts = re.split(r"[\s=]+", line, 1)
        if len(parts) == 2:
            directive = parts[0].lower()
            value = parts[1].strip()
            if directive in directives:
                directives[directive] += f",{value}"
            else:
                directives[directive] = value
    return directives, has_match_block


def parse_sshd_config(content: bytes, filename: str) -> list[dict]:
    """Parse sshd_config bytes and return findings as list[dict]."""
    if b"\x00" in content[:4096]:
        raise ValueError(f"{filename!r} does not appear to be a text config file")
    text = content.decode("utf-8", errors="replace")
    store_or_path = f"uploaded:{filename}"
    directives, has_match = _parse_sshd_directives(text)
    findings: list[dict] = []

    if has_match:
        findings.append({
            "source": "import_config",
            "algorithm": "Match-block",
            "severity": "info",
            "name": "Match",
            "key_size": None,
            "expiration_date": None,
            "store_or_path": store_or_path,
            "detail": "sshd_config contains Match blocks — scoped configuration not analysed",
            "recommendation": "Manual audit recommended for directives inside Match blocks",
            "recommendation_url": None,
            "risk_score": 0.0,
        })

    for directive_key, weak_map in _WEAK_BY_DIRECTIVE.items():
        if directive_key not in directives:
            continue
        raw_value = directives[directive_key]
        directive_display = _DIRECTIVE_DISPLAY.get(directive_key, directive_key)
        rec, rec_url = _SSHD_RECOMMENDATIONS.get(directive_key, ("Manual review recommended", None))

        for token in raw_value.split(","):
            algo = token.strip().lower()
            if algo not in weak_map:
                continue
            severity, score = weak_map[algo]
            findings.append({
                "source": "import_config",
                "algorithm": algo,
                "severity": severity,
                "name": directive_display,
                "key_size": None,
                "expiration_date": None,
                "store_or_path": store_or_path,
                "detail": f"{directive_display} = {raw_value}",
                "recommendation": rec,
                "recommendation_url": rec_url,
                "risk_score": round(score * _CONFIG_TEMPORAL_FACTOR, 1),
            })

    logger.debug("parse_sshd_config: %d finding(s) in %r", len(findings), filename)
    return findings


# ---------------------------------------------------------------------------
# openssl.cnf parser
# ---------------------------------------------------------------------------

def _parse_openssl_sections(text: str) -> dict[str, dict[str, str]]:
    sections: dict[str, dict[str, str]] = {}
    current: str | None = None
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].strip().lower()
            sections.setdefault(current, {})
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip().lower()
        value = value.strip()
        if current is None:
            current = "default"
            sections.setdefault(current, {})
        sections[current][key] = value
    return sections


def _openssl_finding(
    *,
    store_or_path: str,
    section: str,
    key: str,
    value: str,
    algorithm: str,
    severity: str,
    recommendation: str,
    recommendation_url: str | None = None,
) -> dict:
    base_score = _SEVERITY_DEFAULT_SCORE.get(severity, 50)
    return {
        "source": "import_config",
        "algorithm": algorithm,
        "severity": severity,
        "name": value,
        "key_size": None,
        "expiration_date": None,
        "store_or_path": store_or_path,
        "detail": f"[{section}] {key} = {value}",
        "recommendation": recommendation,
        "recommendation_url": recommendation_url,
        "risk_score": round(base_score * _CONFIG_TEMPORAL_FACTOR, 1),
    }


def _check_min_protocol(store_or_path: str, section: str, value: str) -> dict | None:
    normalized = value.strip().lower().replace(" ", "")
    if normalized in {"tlsv1", "tlsv1.0"}:
        severity, algorithm = "high", "TLS-TLSv1.0"
    elif normalized == "tlsv1.1":
        severity, algorithm = "medium", "TLS-TLSv1.1"
    else:
        return None
    return _openssl_finding(
        store_or_path=store_or_path, section=section, key="MinProtocol", value=value,
        algorithm=algorithm, severity=severity,
        recommendation="Set MinProtocol to TLSv1.2 or TLSv1.3",
        recommendation_url=_RFC8996_URL,
    )


def _check_cipher_string(store_or_path: str, section: str, value: str) -> dict | None:
    normalized = value.strip().lower()
    match = _SECLEVEL_RE.search(normalized)
    if match:
        level = int(match.group(1))
        if level <= 0:
            severity = "critical"
        elif level == 1:
            severity = "high"
        else:
            return None
        return _openssl_finding(
            store_or_path=store_or_path, section=section, key="CipherString", value=value,
            algorithm=f"OpenSSL-SECLEVEL-{level}", severity=severity,
            recommendation="Raise SECLEVEL to 2 or higher",
            recommendation_url=_OPENSSL_DOCS_URL,
        )

    # Split into tokens and ignore negated/removal entries (!…/-…) to avoid false positives
    # on patterns like HIGH:!aNULL:!MD5 where the algorithm is explicitly excluded.
    active_tokens = [
        t for t in re.split(r"[:\s,]+", normalized)
        if t and not t.startswith(("!", "-"))
    ]

    weak_tokens = ("low", "export", "null", "md5", "rc4", "des")
    matched_token = next(
        (tok for tok in weak_tokens if any(tok in t for t in active_tokens)),
        None,
    )
    if matched_token:
        return _openssl_finding(
            store_or_path=store_or_path, section=section, key="CipherString", value=value,
            algorithm=f"OpenSSL-{matched_token.upper()}", severity="high",
            recommendation="Remove weak ciphers or set SECLEVEL to 2 or higher",
            recommendation_url=_OPENSSL_DOCS_URL,
        )

    if any("aes128" in t or "aes-128" in t for t in active_tokens):
        return _openssl_finding(
            store_or_path=store_or_path, section=section, key="CipherString", value=value,
            algorithm="AES-128", severity="low",
            recommendation=(
                "Prefer AES-256 ciphers (e.g. AES256-GCM-SHA384) to maintain "
                "128-bit effective security against Grover's quantum algorithm"
            ),
            recommendation_url=_OPENSSL_DOCS_URL,
        )

    return None


def _check_curves(store_or_path: str, section: str, value: str) -> dict | None:
    candidates = [part.strip() for part in re.split(r"[,:\s]+", value) if part.strip()]
    weak = [c for c in candidates if any(tok in c.lower() for tok in _WEAK_CURVE_TOKENS)]
    if not weak:
        return None
    severity = "high" if any("160" in c or "192" in c for c in weak) else "medium"
    return _openssl_finding(
        store_or_path=store_or_path, section=section, key="Curves", value=", ".join(weak),
        algorithm=f"EC-{weak[0]}", severity=severity,
        recommendation="Remove curves below 256-bit security",
        recommendation_url=_OPENSSL_DOCS_URL,
    )


def _check_legacy_provider(
    sections: dict[str, dict[str, str]], store_or_path: str
) -> dict | None:
    default_section = sections.get("default")
    init_section = None
    if default_section:
        init_section = default_section.get("openssl_conf")
    if not init_section and "openssl_init" in sections:
        init_section = "openssl_init"
    if not init_section:
        return None
    init_config = sections.get(init_section)
    if not init_config:
        return None
    provider_section_name = init_config.get("providers")
    if not provider_section_name:
        return None
    provider_section = sections.get(provider_section_name)
    if not provider_section:
        return None
    legacy_ref = provider_section.get("legacy")
    if not legacy_ref:
        return None
    legacy_section = sections.get(legacy_ref)
    if not legacy_section:
        return None
    activate = legacy_section.get("activate", "").strip().lower()
    if activate not in {"1", "yes", "true", "on"}:
        return None
    return _openssl_finding(
        store_or_path=store_or_path,
        section=provider_section_name,
        key="LegacyProvider",
        value="legacy",
        algorithm="OpenSSL-LegacyProvider",
        severity="high",
        recommendation="Disable the legacy provider unless strictly required",
        recommendation_url=_OPENSSL_DOCS_URL,
    )


def parse_openssl_cnf(content: bytes, filename: str) -> list[dict]:
    """Parse openssl.cnf bytes and return findings as list[dict]."""
    if b"\x00" in content[:4096]:
        raise ValueError(f"{filename!r} does not appear to be a text config file")
    text = content.decode("utf-8", errors="replace")
    store_or_path = f"uploaded:{filename}"
    sections = _parse_openssl_sections(text)
    findings: list[dict] = []

    for section in ("system_default_sect", "default_sect"):
        data = sections.get(section)
        if not data:
            continue

        min_protocol = data.get("minprotocol")
        if min_protocol:
            f = _check_min_protocol(store_or_path, section, min_protocol)
            if f is not None:
                findings.append(f)

        cipher_string = data.get("cipherstring")
        if cipher_string:
            f = _check_cipher_string(store_or_path, section, cipher_string)
            if f is not None:
                findings.append(f)

        curves = data.get("curves")
        if curves:
            f = _check_curves(store_or_path, section, curves)
            if f is not None:
                findings.append(f)

    legacy_finding = _check_legacy_provider(sections, store_or_path)
    if legacy_finding is not None:
        findings.append(legacy_finding)

    logger.debug("parse_openssl_cnf: %d finding(s) in %r", len(findings), filename)
    return findings
