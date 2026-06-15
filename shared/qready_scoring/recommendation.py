"""
recommendation.py — Post-quantum migration recommendation helper.

Shared between backend parsers (cert_parser, ssh_parser) and any future
importer that needs to produce human-readable migration guidance.
"""
from __future__ import annotations

NIST_PQC_URL = (
    "https://csrc.nist.gov/projects/post-quantum-cryptography"
    "/post-quantum-cryptography-standardization"
)


def build_recommendation(algo: str) -> tuple[str, str | None]:
    """
    Return a (recommendation_text, url) tuple for the given algorithm family.

    The url is always NIST_PQC_URL or None for unrecognised algorithms.
    """
    a = algo.upper()
    if a.startswith("RSA"):
        return (
            "Migrate to ML-KEM-768 (key exchange) or ML-DSA-65 (signature) per NIST FIPS 203/204",
            NIST_PQC_URL,
        )
    if a.startswith("EC-") or a.startswith("ECDSA") or a in ("ED25519", "ED448"):
        return (
            "Migrate to ML-DSA-65 (NIST FIPS 204) for signatures; "
            "ML-KEM-768 (FIPS 203) for key exchange",
            NIST_PQC_URL,
        )
    if a.startswith("DSA"):
        return (
            "DSA is deprecated. Migrate to ML-DSA-65 (NIST FIPS 204)",
            NIST_PQC_URL,
        )
    return "Algorithm not recognized. Manual review required.", None
