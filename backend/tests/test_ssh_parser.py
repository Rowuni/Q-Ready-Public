from __future__ import annotations

import sys
from pathlib import Path

import pytest

BACKEND_DIR = Path(__file__).parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from ssh_parser import parse_ssh_public_key  # noqa: E402


def test_rejects_openssh_private_key_payload() -> None:
    payload = b"""-----BEGIN OPENSSH PRIVATE KEY-----
ZmFrZQ==
-----END OPENSSH PRIVATE KEY-----
"""

    with pytest.raises(ValueError, match="Private keys are not accepted"):
        parse_ssh_public_key(payload, "id_test")
