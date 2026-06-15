"""
qr_score.py — SC6: aggregate all findings into a single Quantum Readiness score.

Formula (average of two sub-scores computed on active findings only):

    simple_score   = conformant / total_active × 100
    weighted_score = (1 - total_risk / max_risk) × 100
    qr_score       = round((simple_score + weighted_score) / 2, 1)

Definitions:
    active      : findings whose asset will still exist at the CRQC horizon,
                  i.e. findings that are NOT already expired.
    conformant  : active findings with severity == "info" (SC1 = 0 → PQC-safe).
    total_risk  : sum of risk_score over all active findings (None treated as 0).
    max_risk    : 100.0 × len(active)  (theoretical maximum)

Expired assets are excluded from both numerator and denominator: they will not
be in service when a cryptographically relevant quantum computer (CRQC) arrives,
so they neither improve nor degrade the machine's PQC posture.

Edge cases:
    no findings at all          → 100.0  (nothing to migrate)
    all findings are expired    → 100.0  (no active risk)
"""
from __future__ import annotations

from scoring.temporal_factor import is_expired


def compute_qr_score(findings: list[dict]) -> float:
    """
    Compute the global Quantum Readiness score for a full-machine scan.

    Parameters
    ----------
    findings : list[dict]
        All findings from all scanners, post-_enrich_risk_scores.

    Returns
    -------
    float
        Score in [0.0, 100.0], rounded to one decimal place.
        100.0 = fully PQC-compliant (or no active assets detected).
        0.0   = all active assets are at maximum risk.
    """
    if not findings:
        return 100.0

    active = [f for f in findings if not is_expired(f.get("expiration_date"))]

    if not active:
        return 100.0

    conformant = sum(1 for f in active if f.get("severity") == "info")
    simple_score = (conformant / len(active)) * 100

    total_risk = sum(f.get("risk_score") or 0.0 for f in active if f.get("severity") != "info")
    max_risk = 100.0 * len(active)
    weighted_score = (1 - total_risk / max_risk) * 100

    return round((simple_score + weighted_score) / 2, 1)
