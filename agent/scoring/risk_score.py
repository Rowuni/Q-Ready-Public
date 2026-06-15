"""
risk_score.py — SC4: aggregate SC1, SC2 and SC3 into a single risk score.
Implementation: task SC4.

Formula (weighted average):
    SC1_norm = SC1_raw / 100
    raw      = (SC1_norm × 0.5) + (SC2 × 0.25) + (SC3 × 0.25)
    score    = round(raw × 100, 1)            → 0.0–100.0

The algorithm carries the most weight (50 %) because it is the intrinsic,
hardware-independent vulnerability; SC2 and SC3 modulate urgency and
business impact equally (25 % each).

Severity thresholds (derived from the aggregated score):
    ≥ 80  →  critical
    ≥ 60  →  high
    ≥ 35  →  medium
    > 0   →  low
    = 0   →  info
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from scoring.algo_severity import get_algo_severity
from scoring.criticality_factor import Category, criticality_factor
from scoring.temporal_factor import is_expired, temporal_factor


def compute_risk_score(
    algorithm: str,
    key_size: Optional[int],
    expiration_date: Optional[datetime],
    store_or_path: str,
    has_private_key: bool,
    category: Category,
) -> tuple[float, str]:
    """
    Aggregate SC1 × SC2 × SC3 into a single risk score and its severity label.

    Guard (D1): if SC1 = 0, the algorithm is post-quantum safe.  SC2/SC3 are
    not factored in, and the function returns (0.0, "info") immediately.
    This prevents a long-lived AES-256 key from being mis-classified as LOW
    or MEDIUM purely because of its SC2/SC3 context.

    Guard (D2): if the asset has already expired, it will not be in active
    use when the CRQC horizon arrives.  No migration action is needed, so
    the function returns (0.0, "info") immediately.

    Returns
    -------
    tuple[float, str]
        score    : 0.0–100.0 (rounded to one decimal place)
        severity : one of "critical", "high", "medium", "low", "info"
    """
    entry = get_algo_severity(algorithm, key_size)
    sc1_raw: int = entry["score"]

    if sc1_raw == 0:
        return 0.0, "info"

    # D2 guard: expired assets will not exist at the CRQC horizon.
    if is_expired(expiration_date):
        return 0.0, "info"

    sc2: float = temporal_factor(expiration_date)
    sc3: float = criticality_factor(store_or_path, has_private_key, category)

    sc1_norm = sc1_raw / 100.0
    raw = (sc1_norm * 0.5) + (sc2 * 0.25) + (sc3 * 0.25)
    score = round(raw * 100, 1)

    if score >= 80:
        severity = "critical"
    elif score >= 60:
        severity = "high"
    elif score >= 35:
        severity = "medium"
    elif score > 0:
        severity = "low"
    else:
        severity = "info"

    return score, severity
