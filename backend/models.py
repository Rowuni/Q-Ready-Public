"""
Pydantic v2 models shared between the API layer and the database layer.
These types are the single source of truth — the TypeScript types in
frontend/src/types/api.ts must stay aligned with them.
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class FindingStatus(str, Enum):
    open = "open"
    acknowledged = "acknowledged"
    resolved = "resolved"


class ScanMode(str, Enum):
    auto = "auto"
    import_ = "import"


class FindingSource(str, Enum):
    cert_store = "cert_store"
    ssh_key = "ssh_key"
    sshd_config = "sshd_config"
    openssl_cnf = "openssl_cnf"
    crypto_lib = "crypto_lib"
    import_cert = "import_cert"
    import_ssh = "import_ssh"
    import_config = "import_config"


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------


class ScanRead(BaseModel):
    id: int
    hostname: str
    started_at: datetime
    finished_at: Optional[datetime] = None
    qr_score: Optional[float] = Field(None, ge=0, le=100)
    os_version: Optional[str] = None
    mode: ScanMode = ScanMode.auto

    model_config = {"from_attributes": True}


class ScanSummary(BaseModel):
    id: int
    timestamp: datetime
    machine_name: str
    qr_score: float | None
    nb_findings_by_severity: dict[str, int]

    model_config = {"from_attributes": True}


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

class FindingRead(BaseModel):
    id: int
    scan_id: int
    source: FindingSource
    algorithm: str
    severity: Severity
    name: Optional[str] = None
    key_size: Optional[int] = None
    expiration_date: Optional[datetime] = None
    store_or_path: Optional[str] = None
    risk_score: Optional[float] = Field(None, ge=0, le=100)
    recommendation: Optional[str] = None
    recommendation_url: Optional[str] = None
    detail: Optional[str] = None
    status: FindingStatus = FindingStatus.open
    created_at: datetime

    model_config = {"from_attributes": True}
