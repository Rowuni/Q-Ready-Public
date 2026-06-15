"""
conftest.py — pytest configuration for the backend test suite.

Adds agent/ to sys.path so that `from scoring.algo_severity import ...`
resolves correctly in the scoring-coherence tests.
"""
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent.parent  # Q-Ready/
AGENT_DIR = REPO_ROOT / "agent"

if str(AGENT_DIR) not in sys.path:
    sys.path.insert(0, str(AGENT_DIR))
