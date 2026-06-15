"""
criticality_factor.py — SC3: business impact multiplier.
"""
from __future__ import annotations

import re
from enum import Enum
from typing import Optional


class Category(str, Enum):
    CERTIFICATE = "certificate"
    SSH_KEY = "ssh_key"
    CONFIG = "config"
    LIBRARY = "library"


_SOURCE_TO_CATEGORY: dict[str, Category] = {
    "cert_store": Category.CERTIFICATE,
    "import_cert": Category.CERTIFICATE,
    "ssh_key": Category.SSH_KEY,
    "ssh_keys": Category.SSH_KEY,
    "import_ssh": Category.SSH_KEY,
    "sshd_config": Category.CONFIG,
    "openssl_cnf": Category.CONFIG,
    "import_config": Category.CONFIG,
    "crypto_lib": Category.LIBRARY,
    "crypto_libs": Category.LIBRARY,
}


def category_from_source(source: Optional[str]) -> Category:
    """Return the asset Category corresponding to a finding source string."""
    if not source:
        return Category.LIBRARY
    return _SOURCE_TO_CATEGORY.get(source.lower(), Category.LIBRARY)


def _store_tokens(store_or_path: Optional[str]) -> set[str]:
    if not store_or_path:
        return set()
    tokens = re.split(r"[\\/]+", store_or_path.lower())
    return {token for token in tokens if token}


def criticality_factor(
    store_or_path: Optional[str],
    has_private_key: bool,
    category: Category,
) -> float:
    """
    Return the SC3 business-impact multiplier in [0.4, 1.0].

    Certificates stored in high-trust stores (root CA, personal with private key)
    score higher than those in lower-trust stores. SSH private keys score higher
    than their public counterparts. Config and library findings use fixed factors.
    """
    if category == Category.CERTIFICATE:
        tokens = _store_tokens(store_or_path)
        if "root" in tokens or "ca" in tokens:
            return 1.0
        if "my" in tokens or "personal" in tokens:
            return 0.9 if has_private_key else 0.6
        if "trustedpublisher" in tokens:
            return 0.7
        return 0.5

    if category == Category.SSH_KEY:
        return 0.9 if has_private_key else 0.5

    if category == Category.CONFIG:
        return 0.7

    return 0.4
