"""
temporal_factor.py — SC2: urgency multiplier based on asset remaining lifetime.
Implementation: task SC2.

Factor range: 0.1 (low urgency) → 1.0 (maximum urgency).

Theory: A CRQC (Cryptographically Relevant Quantum Computer) is estimated to
arrive between 2030–2035 (ANSSI, NSA, NIST). Assets that will still exist at
that date must be migrated proactively. Assets expiring soon will be renewed
naturally, making them lower priority for immediate action.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional


def is_expired(expiration_date: datetime | str | None) -> bool:
    """Return True if expiration_date is in the past.

    Accepts ``datetime`` objects, ISO-format strings, or ``None``.
    Returns ``False`` on parse errors or when the value is ``None``.
    """
    if expiration_date is None:
        return False
    try:
        if isinstance(expiration_date, datetime):
            exp = expiration_date
        else:
            exp = datetime.fromisoformat(str(expiration_date))
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return exp < datetime.now(timezone.utc)
    except (ValueError, TypeError):
        return False


def temporal_factor(expiration_date: Optional[datetime]) -> float:
    """
    Return an urgency multiplier in [0.1, 1.0] based on time remaining.

    None        → 0.8   No expiry date (SSH key, config file): high urgency by default,
                        the vulnerability persists indefinitely until manually fixed.
    Expired     → 0.1   Already expired: likely no longer in active use.
    < 180 days  → 0.15  Imminent renewal: will be replaced before the CRQC horizon,
                        migration can happen naturally at renewal time.
    180–360 d   → 0.3   6–12 months: medium urgency, plan migration soon.
    360–540 d   → 0.5   12–18 months: medium urgency, plan migration soon.
    540–1080 d  → 0.75  18–36 months: inside the CRQC risk window,
                        proactive migration required.
    1080–1460 d → 0.85  36–48 months (~2030): inside the CRQC risk window,
                        proactive migration required.
    > 1460 days → 1.0   Beyond 2030: maximum urgency, asset will exist during the
                        peak CRQC threat period.
    """
    if expiration_date is None:
        return 0.8

    # Normalise naive datetimes to UTC to avoid comparison errors
    if expiration_date.tzinfo is None:
        expiration_date = expiration_date.replace(tzinfo=timezone.utc)

    now = datetime.now(timezone.utc)
    if expiration_date < now:
        return 0.1

    days_remaining = (expiration_date - now).days

    if days_remaining < 180:
        return 0.15   # imminent renewal
    if days_remaining < 360:
        return 0.3    # 6–12 months
    if days_remaining < 540:
        return 0.5    # 12–18 months
    if days_remaining < 1080:
        return 0.75   # 18–36 months
    if days_remaining < 1460:
        return 0.85   # 36–48 months (~2030)
    return 1.0        # beyond 2030 -> full CRQC risk window
