"""
algo_severity.py — Reference table mapping each algorithm to its quantum risk level.
Implementation: task SC1.

Score scale: 0–100 (aligned with FindingRead.risk_score and ScanRead.qr_score).
  100 = already breakable today (no quantum computer needed)
    0 = post-quantum safe or negligible risk
"""
from __future__ import annotations

from typing import Optional


# ---------------------------------------------------------------------------
# OpenSSL curve name → NIST name normalisation
# Scanners follow the <FAMILY>-<DETAIL> convention from scanners/__init__.py
# and use OpenSSL curve names (secp256r1). ALGO_SEVERITY uses NIST names.
# ---------------------------------------------------------------------------
_CURVE_ALIASES: dict[str, str] = {
    "EC-secp256r1":  "ECDSA-P256",
    "EC-secp384r1":  "ECDSA-P384",
    "EC-secp521r1":  "ECDSA-P521",
    "EC-prime256v1": "ECDSA-P256",  # OpenSSL alias for P-256
    "EC-secp256k1":  "ECDSA-P256",  # Bitcoin curve, treat as P-256 for scoring
    # 224-bit curve aliases — all map to the canonical secp224r1 entry
    "EC-prime224v1": "EC-secp224r1",
    "EC-secp224k1":  "EC-secp224r1",
}


# ---------------------------------------------------------------------------
# Main severity table
# ---------------------------------------------------------------------------
ALGO_SEVERITY: dict[str, dict] = {
    # --- RSA ---
    # Shor's algorithm factors RSA in polynomial time on a CRQC.
    "RSA-1024": {"severity": "critical", "score": 100, "reason": "Breakable today without quantum computer"},
    "RSA-2048": {"severity": "high",     "score": 85,  "reason": "Breakable by CRQC ~2030"},
    "RSA-3072": {"severity": "high",     "score": 75,  "reason": "Breakable by CRQC"},
    "RSA-4096": {"severity": "medium",   "score": 60,  "reason": "Breakable by CRQC, longer timeline"},

    # --- ECDSA / ECDH ---
    # Shor solves the elliptic curve discrete logarithm problem.
    "ECDSA-P256": {"severity": "high",   "score": 85, "reason": "Discrete logarithm → vulnerable to Shor"},
    "ECDSA-P384": {"severity": "high",   "score": 85, "reason": "Discrete logarithm → vulnerable to Shor"},
    "ECDSA-P521": {"severity": "high",   "score": 80, "reason": "Discrete logarithm → vulnerable to Shor"},
    "Ed25519":    {"severity": "medium", "score": 50, "reason": "Montgomery curve → vulnerable to Shor, horizon ~2030+"},
    "Ed448":      {"severity": "medium", "score": 50, "reason": "Montgomery curve → vulnerable to Shor, horizon ~2030+"},

    # --- DSA (absent from the issue, added because scanners produce it) ---
    "DSA-1024": {"severity": "critical", "score": 100, "reason": "Breakable today without quantum computer"},
    "DSA-2048": {"severity": "high",     "score": 80,  "reason": "Discrete logarithm → vulnerable to Shor"},

    # --- DH ---
    "DH-1024": {"severity": "critical", "score": 100, "reason": "Breakable today"},
    "DH-2048": {"severity": "high",     "score": 80,  "reason": "Discrete logarithm → vulnerable to Shor"},

    # --- Symmetric ---
    # Grover halves the effective key length: AES-128 → 64-bit effective security.
    "AES-128": {"severity": "low",  "score": 20, "reason": "Grover reduces to 64-bit effective security"},
    "AES-256": {"severity": "info", "score": 0,  "reason": "Grover reduces to 128-bit effective security, acceptable"},

    # --- Post-quantum (NIST standards — no risk) ---
    "ML-KEM-512": {"severity": "info", "score": 0, "reason": "FIPS 203 compliant"},
    "ML-KEM-768": {"severity": "info", "score": 0, "reason": "FIPS 203 compliant"},
    "ML-KEM-1024":{"severity": "info", "score": 0, "reason": "FIPS 203 compliant"},
    "ML-DSA-44":  {"severity": "info", "score": 0, "reason": "FIPS 204 compliant"},
    "ML-DSA-65":  {"severity": "info", "score": 0, "reason": "FIPS 204 compliant"},
    "ML-DSA-87":  {"severity": "info", "score": 0, "reason": "FIPS 204 compliant"},
    "SLH-DSA":    {"severity": "info", "score": 0, "reason": "FIPS 205 compliant"},

    # --- TLS protocol versions (openssl_cnf scanner) ---
    # Deprecated versions negotiate quantum-vulnerable cipher suites.
    "TLS-TLSv1.0": {"severity": "high",   "score": 80, "reason": "TLS 1.0 allows quantum-vulnerable cipher suites"},
    "TLS-TLSv1.1": {"severity": "medium", "score": 55, "reason": "TLS 1.1 deprecated, allows weak cipher suites"},

    # --- OpenSSL SECLEVEL (openssl_cnf scanner) ---
    # Low SECLEVEL allows short keys (RSA-512, DH-512, etc.) that are already
    # classically breakable and have no quantum migration path.
    "OpenSSL-SECLEVEL-0": {"severity": "critical", "score": 100, "reason": "SECLEVEL=0 disables all key-size and algorithm constraints"},
    "OpenSSL-SECLEVEL-1": {"severity": "high",     "score": 85,  "reason": "SECLEVEL=1 allows RSA<2048 and DH<1024"},

    # --- OpenSSL cipher suite tokens (openssl_cnf scanner) ---
    "OpenSSL-NULL":   {"severity": "critical", "score": 100, "reason": "NULL cipher provides no encryption"},
    "OpenSSL-EXPORT": {"severity": "critical", "score": 100, "reason": "EXPORT ciphers are 40-bit, breakable today"},
    "OpenSSL-RC4":    {"severity": "high",     "score": 90,  "reason": "RC4 is cryptographically broken"},
    "OpenSSL-DES":    {"severity": "high",     "score": 90,  "reason": "DES uses a 56-bit key, breakable today"},
    "OpenSSL-LOW":    {"severity": "high",     "score": 80,  "reason": "LOW cipher group includes classically breakable ciphers"},
    "OpenSSL-MD5":    {"severity": "high",     "score": 75,  "reason": "MD5 is collision-broken, unsuitable for signatures"},

    # --- OpenSSL legacy provider (openssl_cnf scanner) ---
    "OpenSSL-LegacyProvider": {"severity": "high", "score": 75,
                               "reason": "Legacy provider enables DES, RC2, IDEA — all quantum-vulnerable"},

    # --- Weak elliptic curves (openssl_cnf scanner, < 256-bit security) ---
    # secp160/secp192 are high-risk (classically weak and quantum-vulnerable).
    "EC-secp160r1": {"severity": "high", "score": 90, "reason": "160-bit curve, below minimum security level"},
    "EC-secp160r2": {"severity": "high", "score": 90, "reason": "160-bit curve, below minimum security level"},
    "EC-secp192r1": {"severity": "high", "score": 80, "reason": "192-bit curve, below NIST recommended minimum of 256-bit"},
    "EC-prime192v1":{"severity": "high", "score": 80, "reason": "192-bit curve, below NIST recommended minimum of 256-bit"},
    # secp224 is medium (not classically broken but deprecated by NIST).
    "EC-secp224r1": {"severity": "medium", "score": 55, "reason": "224-bit curve, deprecated by NIST"},
}

_FALLBACK: dict = {"severity": "medium", "score": 50, "reason": "Algorithm not in reference table"}


def get_algo_severity(algorithm: str, key_size: Optional[int] = None) -> dict:
    """
    Return the quantum risk entry for a given algorithm.

    Lookup order:
      1. Normalise OpenSSL curve names to NIST names via _CURVE_ALIASES.
      2. Try  "<normalised>-<key_size>"  (e.g. RSA + 2048 → "RSA-2048").
      3. Try  "<normalised>"             (e.g. "Ed25519" has no size suffix).
      4. Fall back to a medium/50 entry.

    Returns a dict with keys: severity (str), score (int 0–100), reason (str).
    """
    normalized = _CURVE_ALIASES.get(algorithm, algorithm)

    if key_size:
        candidate = f"{normalized}-{key_size}"
        if candidate in ALGO_SEVERITY:
            return ALGO_SEVERITY[candidate].copy()

    if normalized in ALGO_SEVERITY:
        return ALGO_SEVERITY[normalized].copy()

    return _FALLBACK.copy()
