"""
algo_severity.py — Re-exports from qready_scoring for agent backward compatibility.

The canonical source of truth is shared/qready_scoring/algo_severity.py.
Do not add entries here; update the shared package instead.
"""
from qready_scoring.algo_severity import (  # noqa: F401
    ALGO_SEVERITY,
    get_algo_severity,
)
