"""Data-access layer — all database queries live here, never in routers."""
from __future__ import annotations

import logging
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Sequence

from sqlalchemy import case, func
from sqlalchemy.orm import Session

from models import FindingStatus
from orm import FindingORM, ScanORM

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

def create_scan(db: Session, hostname: str, os_version: str | None = None, mode: str = "auto") -> ScanORM:
    logger.debug("create_scan: hostname=%r os_version=%r mode=%r", hostname, os_version, mode)
    scan = ScanORM(hostname=hostname, os_version=os_version, mode=mode)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def get_scan(db: Session, scan_id: int) -> ScanORM | None:
    return db.get(ScanORM, scan_id)


def update_scan_finished(db: Session, scan: ScanORM, qr_score: float) -> ScanORM:
    logger.debug("update_scan_finished: scan_id=%d qr_score=%s", scan.id, qr_score)
    scan.finished_at = datetime.now(timezone.utc)
    scan.qr_score = qr_score
    db.commit()
    db.refresh(scan)
    return scan


# ---------------------------------------------------------------------------
# Finding
# ---------------------------------------------------------------------------

def create_finding(db: Session, scan_id: int, **kwargs) -> FindingORM:
    logger.debug("create_finding: scan_id=%d source=%r", scan_id, kwargs.get("source"))
    finding = FindingORM(scan_id=scan_id, **kwargs)
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


def create_findings_bulk(db: Session, scan_id: int, finding_dicts: list[dict]) -> list[FindingORM]:
    logger.debug("create_findings_bulk: scan_id=%d count=%d", scan_id, len(finding_dicts))
    findings = [FindingORM(scan_id=scan_id, **fd) for fd in finding_dicts]
    db.add_all(findings)
    db.commit()
    for f in findings:
        db.refresh(f)
    return findings


_SEVERITY_ORDER = case(
    ("critical", 0),
    ("high", 1),
    ("medium", 2),
    ("low", 3),
    ("info", 4),
    value=FindingORM.severity,
    else_=5,
)


def get_findings_by_scan(
    db: Session, scan_id: int, filters: Mapping[str, str] | None = None, skip: int = 0, limit: int = 200
) -> Sequence[FindingORM]:
    query = db.query(FindingORM).filter(FindingORM.scan_id == scan_id)
    if filters:
        allowed_filters = {
            "status": FindingORM.status,
            "severity": FindingORM.severity,
        }
        for key, value in filters.items():
            column = allowed_filters.get(key)
            if column is None:
                logger.warning("get_findings_by_scan: unknown filter key %r ignored", key)
                continue
            query = query.filter(column == value)
    return (
        query
        .order_by(_SEVERITY_ORDER)
        .offset(skip)
        .limit(limit)
        .all()
    )


def update_finding_status(db: Session, finding_id: int, status: FindingStatus) -> FindingORM | None:
    finding = db.get(FindingORM, finding_id)
    if finding is None:
        logger.warning("update_finding_status: finding_id=%d not found", finding_id)
        return None

    logger.debug("update_finding_status: finding_id=%d → %r", finding_id, status.value)
    finding.status = status.value
    db.commit()
    db.refresh(finding)
    return finding


def list_scans(
    db: Session,
    page: int = 1,
    limit: int = 20,
) -> list[dict]:
    skip = (page - 1) * limit

    scans = (
        db.query(ScanORM)
        .order_by(ScanORM.started_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )

    if not scans:
        return []

    scan_ids = [s.id for s in scans]

    counts = (
        db.query(FindingORM.scan_id, FindingORM.severity, func.count().label("n"))
        .filter(FindingORM.scan_id.in_(scan_ids))
        .group_by(FindingORM.scan_id, FindingORM.severity)
        .all()
    )

    counts_by_scan: dict[int, dict[str, int]] = {s.id: {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0} for s in scans}
    for scan_id, severity, n in counts:
        counts_by_scan[scan_id][severity] = n

    return [
        {
            "id": scan.id,
            "timestamp": scan.started_at,
            "machine_name": scan.hostname,
            "qr_score": scan.qr_score,
            "nb_findings_by_severity": counts_by_scan[scan.id],
        }
        for scan in scans
    ]
