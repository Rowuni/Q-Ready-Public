"""
recommendations.py — Central recommendation generator (SC5).

Maps (algorithm, category, key_size, is_expired) to actionable text and
a URL pointing to the relevant FIPS final standard or documentation.
This module is the single source of truth for all recommendation text.
"""
from __future__ import annotations

from scoring.criticality_factor import Category

# ---------------------------------------------------------------------------
# Reference URLs — FIPS finals and authoritative documentation
# ---------------------------------------------------------------------------

_FIPS_203_URL = "https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf"  # ML-KEM
_FIPS_204_URL = "https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf"  # ML-DSA
_OPENSSH_90_URL = "https://www.openssh.com/releasenotes.html#9.0"
_OPENSSL_DOCS_URL = "https://www.openssl.org/docs/man3.0/man5/config.html"
_RFC8996_URL = "https://www.rfc-editor.org/rfc/rfc8996"  # Deprecating TLS 1.0/1.1


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_recommendation(
    algorithm: str,
    category: Category,
    key_size: int | None = None,
    is_expired: bool = False,
) -> tuple[str, str | None]:
    """
    Return (recommendation_text, url) for the given algorithm and context.

    Parameters
    ----------
    algorithm:  Algorithm label as produced by the scanners
                (e.g. "RSA-2048", "EC-secp256r1", "Ed25519", "TLS-TLSv1.0").
    category:   Asset category (CERTIFICATE, SSH_KEY, CONFIG, LIBRARY).
    key_size:   Key size in bits when available — improves RSA recommendations.
    is_expired: True if the asset has already expired.  An expired asset will
                not be in service when a CRQC arrives, so no migration is needed.
    """
    if is_expired:
        return (
            "This asset has expired and will not be in service when a "
            "cryptographically relevant quantum computer (CRQC) arrives. "
            "No migration action is required.",
            None,
        )

    a = algorithm.upper()

    # RSA ----------------------------------------------------------------
    if a.startswith("RSA") or a.startswith("UNKNOWN-RSA"):
        return _rsa_recommendation(category, key_size)

    # Ed25519/Ed448 SSH keys: no classical weakness, only quantum risk
    if a in ("ED25519", "ED448") and category == Category.SSH_KEY:
        return (
            f"{algorithm} has no classical weaknesses but remains vulnerable to Shor's "
            "algorithm. Plan migration to ML-DSA-65 (NIST FIPS 204) once OpenSSH adds support.",
            _FIPS_204_URL,
        )

    # Elliptic curves and Edwards curves ---------------------------------
    if (
        a.startswith("EC-")
        or a.startswith("ECDSA")
        or a in ("ED25519", "ED448")
        or a.startswith("UNKNOWN-EC")
    ):
        if category == Category.CONFIG:
            # Weak EC curve in openssl.cnf Curves directive
            return (
                "Remove elliptic curves below 256-bit security from the Curves "
                "directive. Prefer prime256v1, secp384r1, or secp521r1.",
                _OPENSSL_DOCS_URL,
            )
        return _ec_recommendation(category)

    # DSA ----------------------------------------------------------------
    if a.startswith("DSA") or a.startswith("UNKNOWN-DSA"):
        return _dsa_recommendation(category)

    # TLS min protocol (openssl_cnf) ------------------------------------
    if a.startswith("TLS-"):
        return (
            "Set MinProtocol to TLSv1.2 or TLSv1.3 in openssl.cnf to disable "
            "deprecated TLS versions (RFC 8996).",
            _RFC8996_URL,
        )

    # OpenSSL CipherString SECLEVEL -------------------------------------
    if "SECLEVEL" in a:
        return (
            "Raise CipherString SECLEVEL to 2 or higher in openssl.cnf "
            "(e.g. CipherString = DEFAULT@SECLEVEL=2).",
            _OPENSSL_DOCS_URL,
        )

    # OpenSSL weak cipher tokens ----------------------------------------
    if any(tok in a for tok in ("LOW", "EXPORT", "NULL", "-MD5", "-RC4", "-DES")):
        return (
            "Remove weak cipher tokens (LOW, EXPORT, NULL, MD5, RC4, DES) from "
            "CipherString, or raise SECLEVEL to 2 or higher.",
            _OPENSSL_DOCS_URL,
        )

    # AES-128 (Grover's algorithm halves effective security) ------------
    if a == "AES-128":
        return (
            "Prefer AES-256 ciphers (e.g. AES256-GCM-SHA384) to maintain "
            "128-bit effective security against Grover's quantum algorithm.",
            _OPENSSL_DOCS_URL,
        )

    # OpenSSL legacy provider -------------------------------------------
    if "LEGACYPROVIDER" in a or ("LEGACY" in a and "PROVIDER" in a):
        return (
            "Disable the OpenSSL legacy provider unless strictly required. "
            "It enables deprecated algorithms (DES, RC2, MD2…) that weaken the system.",
            _OPENSSL_DOCS_URL,
        )

    # DH / weak KEX (SSH context) ---------------------------------------
    if a.startswith("DH-") or "DIFFIE-HELLMAN" in a or "DIFFIE_HELLMAN" in a:
        return (
            "Replace with sntrup761x25519-sha512@openssh.com (hybrid PQC, OpenSSH 9.0+) "
            "or curve25519-sha256.",
            _OPENSSH_90_URL,
        )

    return "Algorithm not recognized. Manual review recommended.", None


# ---------------------------------------------------------------------------
# Per-family helpers
# ---------------------------------------------------------------------------

def _rsa_recommendation(
    category: Category, key_size: int | None
) -> tuple[str, str | None]:
    if category == Category.SSH_KEY:
        if key_size is not None and key_size < 2048:
            return (
                f"RSA-{key_size} is classically weak. "
                "Generate a new Ed25519 key immediately: ssh-keygen -t ed25519. "
                "Plan migration to ML-DSA once OpenSSH supports NIST FIPS 204.",
                _FIPS_204_URL,
            )
        if key_size == 2048:
            return (
                "RSA-2048 SSH keys will be broken by Shor's algorithm on a CRQC. "
                "Replace with Ed25519 (ssh-keygen -t ed25519) now, "
                "and plan migration to ML-DSA once OpenSSH supports NIST FIPS 204.",
                _FIPS_204_URL,
            )
        return (
            "RSA SSH keys remain vulnerable to Shor's algorithm. "
            "Replace with Ed25519 (ssh-keygen -t ed25519) and "
            "plan migration to ML-DSA once OpenSSH supports NIST FIPS 204.",
            _FIPS_204_URL,
        )

    # CERTIFICATE and all other categories
    if key_size is not None and key_size < 2048:
        return (
            f"RSA-{key_size} is classically weak AND vulnerable to Shor's algorithm. "
            "Replace immediately with ML-DSA-65 (NIST FIPS 204) for signatures, "
            "or at minimum RSA-2048 for short-term classical compatibility.",
            _FIPS_204_URL,
        )
    if key_size == 2048:
        return (
            "RSA-2048 will be broken by Shor's algorithm on a cryptographically "
            "relevant quantum computer. Migrate to ML-DSA-65 (NIST FIPS 204) for "
            "signatures or ML-KEM-768 (NIST FIPS 203) for key exchange.",
            _FIPS_204_URL,
        )
    if key_size is not None and 2048 < key_size < 7680:
        return (
            f"RSA-{key_size} meets current classical standards but remains vulnerable "
            "to Shor's algorithm. Plan migration to ML-DSA-65 (NIST FIPS 204) for "
            "signatures or ML-KEM-768 (NIST FIPS 203) for key exchange.",
            _FIPS_204_URL,
        )
    if key_size is not None and key_size >= 7680:
        return (
            f"RSA-{key_size} requires significant quantum resources to break but remains "
            "vulnerable to Shor's algorithm. Migrate to ML-DSA-65 (NIST FIPS 204) "
            "when feasible.",
            _FIPS_204_URL,
        )
    # No key_size available
    return (
        "This RSA certificate is vulnerable to Shor's quantum algorithm. "
        "Migrate to ML-DSA-65 (NIST FIPS 204) for signatures "
        "or ML-KEM-768 (NIST FIPS 203) for key exchange.",
        _FIPS_204_URL,
    )


def _ec_recommendation(category: Category) -> tuple[str, str | None]:
    if category == Category.SSH_KEY:
        return (
            "Replace this EC/ECDSA key with ssh-ed25519 (ssh-keygen -t ed25519). "
            "Ed25519 is more secure, compact, and widely supported. "
            "Plan migration to ML-DSA once OpenSSH supports NIST FIPS 204.",
            _FIPS_204_URL,
        )
    return (
        "Elliptic curve and Edwards curve algorithms are vulnerable to Shor's algorithm. "
        "Migrate to ML-DSA-65 (NIST FIPS 204) for signatures "
        "or ML-KEM-768 (NIST FIPS 203) for key exchange.",
        _FIPS_204_URL,
    )


def _dsa_recommendation(category: Category) -> tuple[str, str | None]:
    if category == Category.SSH_KEY:
        return (
            "DSA is classically deprecated and vulnerable to Shor's algorithm. "
            "Replace immediately with ssh-ed25519 (ssh-keygen -t ed25519).",
            _FIPS_204_URL,
        )
    return (
        "DSA is classically deprecated (NIST no longer recommends it) "
        "and vulnerable to Shor's algorithm. "
        "Replace immediately with ML-DSA-65 (NIST FIPS 204).",
        _FIPS_204_URL,
    )
