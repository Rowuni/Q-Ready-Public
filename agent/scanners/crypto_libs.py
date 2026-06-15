"""
crypto_libs.py — Scanner for installed cryptographic libraries.
Implementation: task S5.
"""
from __future__ import annotations

import re
import platform
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

# winreg is Windows-only; guard the import so the module can be loaded
# on non-Windows environments (e.g. CI runners on Linux).
try:
    import winreg
    _WINREG_AVAILABLE = True
except ImportError:
    _WINREG_AVAILABLE = False

# Temporal factor for library findings: no expiration date → same as _temporal_factor(None) = 0.8
_TEMPORAL_FACTOR = 0.8

_OPENSSL_URL = "https://www.openssl.org/"
_SCHANNEL_URL = (
    "https://learn.microsoft.com/en-us/windows-server/security/tls/tls-registry-settings"
)


@dataclass
class CryptoLibFinding:
    """
    One finding per detected cryptographic library.

    Aligns with the common finding contract (source, algorithm, severity,
    store_or_path…) so it integrates with _enrich_risk_scores() and the
    backend ORM without conversion.

    risk_score is pre-computed here because library/protocol names are not
    in ALGO_SEVERITY; the temporal factor defaults to 0.8 (no expiration date).
    """
    source: str
    algorithm: str
    severity: str
    name: str | None
    key_size: int | None
    expiration_date: str | None
    store_or_path: str
    detail: str | None
    recommendation: str | None
    recommendation_url: str | None
    risk_score: float | None = None


def _run_command(command: list[str]) -> str:
    """Execute a shell command and return stdout, or an error string on failure."""
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip() or result.stderr.strip()
    except Exception as e:
        return f"ERROR: {e}"


# --- OpenSSL ---

def _find_openssl_executable() -> str | None:
    """Search for openssl.exe in PATH then in common Windows install locations."""
    openssl_path = shutil.which("openssl")
    if openssl_path:
        return openssl_path

    common_paths = [
        r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
        r"C:\Program Files\OpenSSL-Win32\bin\openssl.exe",
        r"C:\Program Files\Git\usr\bin\openssl.exe",
    ]
    for path in common_paths:
        if Path(path).exists():
            return path

    return None


def detect_openssl() -> CryptoLibFinding:
    """Detect the installed OpenSSL version and assess its post-quantum readiness."""
    openssl_path = _find_openssl_executable()
    if not openssl_path:
        return CryptoLibFinding(
            source="crypto_lib",
            algorithm="OpenSSL",
            severity="medium",
            name="not_found",
            key_size=None,
            expiration_date=None,
            store_or_path="not_found",
            detail="openssl.exe not found in PATH or common locations",
            recommendation="Install OpenSSL 3.x to enable PQC support via oqs-provider",
            recommendation_url=_OPENSSL_URL,
            risk_score=round(50 * _TEMPORAL_FACTOR, 1),
        )

    output = _run_command([openssl_path, "version"])
    match = re.search(r"OpenSSL\s+(\d+\.\d+\.\d+)", output)

    if not match:
        return CryptoLibFinding(
            source="crypto_lib",
            algorithm="OpenSSL",
            severity="medium",
            name="unknown",
            key_size=None,
            expiration_date=None,
            store_or_path=openssl_path,
            detail=f"Unexpected version output: {output}",
            recommendation="Verify OpenSSL installation and upgrade to 3.x",
            recommendation_url=_OPENSSL_URL,
            risk_score=round(50 * _TEMPORAL_FACTOR, 1),
        )

    version = match.group(1)
    pq_ready = version.startswith("3.")

    return CryptoLibFinding(
        source="crypto_lib",
        algorithm="OpenSSL",
        severity="info" if pq_ready else "high",
        name=version,
        key_size=None,
        expiration_date=None,
        store_or_path=openssl_path,
        detail=f"Found OpenSSL {version} at {openssl_path}",
        recommendation=(
            None if pq_ready
            else "Upgrade to OpenSSL 3.x to enable PQC support via oqs-provider"
        ),
        recommendation_url=None if pq_ready else _OPENSSL_URL,
        risk_score=round((20 if pq_ready else 80) * _TEMPORAL_FACTOR, 1),
    )


# --- SChannel ---

def _read_registry_dword(path: str, name: str) -> int | None:
    """
    Read a DWORD value from the Windows registry.
    Returns None if the key or value is absent.
    """
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
            value, _ = winreg.QueryValueEx(key, name)
            return value
    except FileNotFoundError:
        return None


def _protocol_disabled(protocol_name: str) -> bool:
    """Check whether a SChannel protocol is explicitly disabled in the registry."""
    base_path = (
        r"SYSTEM\CurrentControlSet\Control\SecurityProviders"
        r"\SCHANNEL\Protocols"
    )
    server_path = fr"{base_path}\{protocol_name}\Server"

    enabled = _read_registry_dword(server_path, "Enabled")
    disabled_by_default = _read_registry_dword(server_path, "DisabledByDefault")

    # Microsoft convention:
    #   Enabled = 0 AND DisabledByDefault = 1  →  protocol disabled
    return enabled == 0 and disabled_by_default == 1


def detect_schannel() -> CryptoLibFinding:
    """
    Detect the SChannel TLS/SSL configuration by reading the Windows Registry.

    The non-Windows early-return is kept intentionally: this POC targets Windows,
    but the guard ensures the function remains safe if the scanner is ever extended
    to a cross-platform application.
    """
    if platform.system() != "Windows":
        return CryptoLibFinding(
            source="crypto_lib",
            algorithm="SChannel",
            severity="info",
            name="not_windows",
            key_size=None,
            expiration_date=None,
            store_or_path="n/a",
            detail="SChannel is a Windows-only component; not applicable on this platform",
            recommendation=None,
            recommendation_url=None,
            risk_score=None,
        )

    weak_protocols = ["SSL 2.0", "SSL 3.0", "TLS 1.0", "TLS 1.1"]
    disabled = [p for p in weak_protocols if _protocol_disabled(p)]
    pq_ready = len(disabled) == len(weak_protocols)

    detail = (
        f"Disabled protocols: {', '.join(disabled)}"
        if disabled
        else "No weak protocols are disabled — all legacy protocols are still enabled"
    )

    return CryptoLibFinding(
        source="crypto_lib",
        algorithm="SChannel",
        severity="info" if pq_ready else "high",
        name="system",
        key_size=None,
        expiration_date=None,
        store_or_path="Windows Registry",
        detail=detail,
        recommendation=(
            None if pq_ready
            else "Disable legacy protocols (SSL 2.0, SSL 3.0, TLS 1.0, TLS 1.1) in Windows Registry"
        ),
        recommendation_url=None if pq_ready else _SCHANNEL_URL,
        risk_score=round((20 if pq_ready else 80) * _TEMPORAL_FACTOR, 1),
    )


# --- Scan entry point ---

def scan_crypto_libs() -> list[CryptoLibFinding]:
    """Detect installed cryptographic libraries and return one finding per library."""
    return [
        detect_openssl(),
        detect_schannel(),
    ]
