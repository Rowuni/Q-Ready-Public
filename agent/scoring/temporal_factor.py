"""
temporal_factor.py — Re-exports from qready_scoring for agent backward compatibility.

The canonical source of truth is shared/qready_scoring/temporal_factor.py.
Do not modify the logic here; update the shared package instead.
"""
from qready_scoring.temporal_factor import is_expired, temporal_factor  # noqa: F401
