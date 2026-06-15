"""
openssl_cnf.py — Scanner for openssl.cnf configuration.
Implementation: task S4.
"""
from __future__ import annotations

import logging
import os
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path


logger = logging.getLogger(__name__)

_RFC8996_URL = "https://www.rfc-editor.org/rfc/rfc8996"
_OPENSSL_DOCS_URL = "https://www.openssl.org/docs/man3.0/man5/config.html"


_DEFAULT_WINDOWS_CONF = Path(r"C:\Program Files\Common Files\SSL\openssl.cnf")
_DEFAULT_LINUX_CONFS = [
    Path("/etc/ssl/openssl.cnf"),
    Path("/usr/lib/ssl/openssl.cnf"),
]
_SECLEVEL_RE = re.compile(r"@seclevel\s*=\s*(\d)", re.IGNORECASE)
_WEAK_CURVE_TOKENS = (
    "secp160",
    "secp192",
    "prime192",
    "secp224",
    "prime224",
)


@dataclass
class OpensslCnfFinding:
    source: str
    algorithm: str
    severity: str
    name: str | None
    key_size: int | None
    expiration_date: datetime | None
    store_or_path: str
    detail: str | None
    recommendation: str | None
    recommendation_url: str | None
    risk_score: float | None = None


def _resolve_conf_path(path: Path | None) -> Path | None:
    if path is not None:
        return path if path.is_file() else None

    env_path = os.getenv("OPENSSL_CONF")
    if env_path:
        candidate = Path(env_path)
        if candidate.is_file():
            return candidate

    if sys.platform == "win32":
        return _DEFAULT_WINDOWS_CONF if _DEFAULT_WINDOWS_CONF.is_file() else None

    for candidate in _DEFAULT_LINUX_CONFS:
        if candidate.is_file():
            return candidate
    return None


def _parse_config(text: str) -> dict[str, dict[str, str]]:
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


def _make_finding(
    *,
    path: Path,
    section: str,
    key: str,
    value: str,
    algorithm: str,
    severity: str,
    recommendation: str,
    recommendation_url: str | None = None,
) -> OpensslCnfFinding:
    detail = f"[{section}] {key} = {value}"
    return OpensslCnfFinding(
        source="openssl_cnf",
        algorithm=algorithm,
        severity=severity,
        name=value,
        key_size=None,
        expiration_date=None,
        store_or_path=str(path),
        detail=detail,
        recommendation=recommendation,
        recommendation_url=recommendation_url,
    )


def _check_min_protocol(path: Path, section: str, value: str) -> OpensslCnfFinding | None:
    normalized = value.strip().lower().replace(" ", "")
    if normalized in {"tlsv1", "tlsv1.0"}:
        severity = "high"
        algorithm = "TLS-TLSv1.0"
    elif normalized == "tlsv1.1":
        severity = "medium"
        algorithm = "TLS-TLSv1.1"
    else:
        return None

    return _make_finding(
        path=path,
        section=section,
        key="MinProtocol",
        value=value,
        algorithm=algorithm,
        severity=severity,
        recommendation="Set MinProtocol to TLSv1.2 or TLSv1.3",
        recommendation_url=_RFC8996_URL,
    )


def _check_cipher_string(path: Path, section: str, value: str) -> OpensslCnfFinding | None:
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
        return _make_finding(
            path=path,
            section=section,
            key="CipherString",
            value=value,
            algorithm=f"OpenSSL-SECLEVEL-{level}",
            severity=severity,
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
        return _make_finding(
            path=path,
            section=section,
            key="CipherString",
            value=value,
            algorithm=f"OpenSSL-{matched_token.upper()}",
            severity="high",
            recommendation="Remove weak ciphers or set SECLEVEL to 2 or higher",
            recommendation_url=_OPENSSL_DOCS_URL,
        )

    # AES-128: Grover's algorithm halves its key length to 64-bit effective security.
    if any("aes128" in t or "aes-128" in t for t in active_tokens):
        return _make_finding(
            path=path,
            section=section,
            key="CipherString",
            value=value,
            algorithm="AES-128",
            severity="low",
            recommendation=(
                "Prefer AES-256 ciphers (e.g. AES256-GCM-SHA384) to maintain "
                "128-bit effective security against Grover's quantum algorithm"
            ),
            recommendation_url=_OPENSSL_DOCS_URL,
        )

    return None


def _check_curves(path: Path, section: str, value: str) -> OpensslCnfFinding | None:
    candidates = [
        part.strip() for part in re.split(r"[,:\s]+", value) if part.strip()
    ]
    weak = [c for c in candidates if any(tok in c.lower() for tok in _WEAK_CURVE_TOKENS)]
    if not weak:
        return None

    severity = "high" if any("160" in c or "192" in c for c in weak) else "medium"
    return _make_finding(
        path=path,
        section=section,
        key="Curves",
        value=", ".join(weak),
        algorithm=f"EC-{weak[0]}",
        severity=severity,
        recommendation="Remove curves below 256-bit security",
        recommendation_url=_OPENSSL_DOCS_URL,
    )


def _check_legacy_provider(
    sections: dict[str, dict[str, str]],
    path: Path,
) -> OpensslCnfFinding | None:
    init_section = None
    default_section = sections.get("default")
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

    return _make_finding(
        path=path,
        section=provider_section_name,
        key="LegacyProvider",
        value="legacy",
        algorithm="OpenSSL-LegacyProvider",
        severity="high",
        recommendation="Disable the legacy provider unless strictly required",
        recommendation_url=_OPENSSL_DOCS_URL,
    )


def parse_openssl_cnf_text(
    text: str, virtual_path: str = "openssl.cnf"
) -> list[OpensslCnfFinding]:
    """Parse openssl.cnf text and flag insecure TLS/OpenSSL configuration settings."""
    path = Path(virtual_path)
    sections = _parse_config(text)
    findings: list[OpensslCnfFinding] = []

    for section in ("system_default_sect", "default_sect"):
        data = sections.get(section)
        if not data:
            continue

        min_protocol = data.get("minprotocol")
        if min_protocol:
            finding = _check_min_protocol(path, section, min_protocol)
            if finding is not None:
                findings.append(finding)

        cipher_string = data.get("cipherstring")
        if cipher_string:
            finding = _check_cipher_string(path, section, cipher_string)
            if finding is not None:
                findings.append(finding)

        curves = data.get("curves")
        if curves:
            finding = _check_curves(path, section, curves)
            if finding is not None:
                findings.append(finding)

    legacy_finding = _check_legacy_provider(sections, path)
    if legacy_finding is not None:
        findings.append(legacy_finding)

    return findings


def scan_openssl_cnf(path: Path | None = None) -> list[OpensslCnfFinding]:
    """
    Parse openssl.cnf and flag insecure TLS/OpenSSL configuration settings.
    Checks: weak MinProtocol (TLSv1.0/1.1), low CipherString SECLEVEL,
    weak elliptic curves, and activation of the legacy provider.
    Full implementation: task S4.
    """
    conf_path = _resolve_conf_path(path)
    if conf_path is None:
        logger.info("scan_openssl_cnf: openssl.cnf not found, skipping")
        return []

    try:
        content = conf_path.read_text(encoding="utf-8", errors="ignore")
    except OSError as exc:
        logger.warning("scan_openssl_cnf: cannot read %s: %s", conf_path, exc)
        return []

    findings = parse_openssl_cnf_text(content, str(conf_path))
    logger.info(
        "scan_openssl_cnf: found %d finding(s) in %s",
        len(findings),
        conf_path,
    )
    return findings
