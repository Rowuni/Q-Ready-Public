"""POST /scans/ -- triggers the agent and persists results."""
import json
import logging
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session


from database import get_db
from models import ScanRead, ScanSummary, FindingRead, Severity, FindingStatus, FindingSource
from repository import create_scan, get_scan as _get_scan, list_scans, create_findings_bulk, update_scan_finished
from repository import get_findings_by_scan

logger = logging.getLogger(__name__)

router = APIRouter()

# ---------------------------------------------------------------------------
# Agent configuration
# ---------------------------------------------------------------------------

# Resolved from backend/routers/scan.py -> backend/routers/ -> backend/ -> Q-Ready/ -> agent/
_AGENT_DIR = Path(__file__).parent.parent.parent / "agent"
_AGENT_SCRIPT = _AGENT_DIR / "scan.py"
_AGENT_TIMEOUT = int(os.getenv("AGENT_TIMEOUT", "120"))
# POC demo default: testset mode uses fixture files instead of a real scan.
# Set AGENT_TESTSET=false to run against the actual machine.
_AGENT_TESTSET = os.getenv("AGENT_TESTSET", "true").lower() == "true"

# Fields from the agent JSON that map directly to FindingORM columns
_ALLOWED_FINDING_FIELDS = frozenset({
    "source", "algorithm", "severity", "name", "key_size",
    "expiration_date", "store_or_path", "risk_score",
    "recommendation", "recommendation_url", "detail",
})

# Agent may output plural source names; normalise to FindingSource enum values
_SOURCE_ALIASES: dict[str, str] = {
    "ssh_keys": "ssh_key",
    "crypto_libs": "crypto_lib",
}

_VALID_SOURCES = frozenset(s.value for s in FindingSource)


def _agent_python() -> str:
    """Return the Python interpreter for the agent venv (Windows-only POC path)."""
    venv_python = _AGENT_DIR / ".venv" / "Scripts" / "python.exe"
    if venv_python.exists():
        return str(venv_python)
    return sys.executable


def _parse_datetime(value: object) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value))
    except (ValueError, TypeError):
        return None


def _map_finding(raw: dict) -> dict | None:
    """Convert a raw agent finding dict to a FindingORM-compatible dict.

    Returns None if the source value is not a recognised FindingSource.
    """
    source = raw.get("source", "")
    source = _SOURCE_ALIASES.get(source, source)
    if source not in _VALID_SOURCES:
        logger.warning("_map_finding: unknown source %r skipped", source)
        return None
    fd: dict = {"source": source}
    for field in _ALLOWED_FINDING_FIELDS - {"source"}:
        val = raw.get(field)
        if val is not None:
            fd[field] = val
    if "expiration_date" in fd:
        fd["expiration_date"] = _parse_datetime(fd["expiration_date"])
    return fd


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/", response_model=ScanRead, status_code=201)
def start_scan(db: Session = Depends(get_db)) -> ScanRead:
    """
    Trigger a full scan of the local machine.
    Invokes agent/scan.py synchronously, parses the JSON output, persists
    the scan and its findings, then returns the completed ScanRead.
    """
    cmd = [_agent_python(), str(_AGENT_SCRIPT), "--output", "json"]
    if _AGENT_TESTSET:
        cmd.append("--testset")

    logger.info("start_scan: launching agent timeout=%ds testset=%s", _AGENT_TIMEOUT, _AGENT_TESTSET)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=_AGENT_TIMEOUT,
            cwd=str(_AGENT_DIR),
        )
    except subprocess.TimeoutExpired:
        logger.error("start_scan: agent timed out after %ds", _AGENT_TIMEOUT)
        raise HTTPException(status_code=504, detail="Agent timed out")
    except OSError as exc:
        logger.error("start_scan: cannot launch agent: %s", exc)
        raise HTTPException(status_code=500, detail="Agent could not be launched")

    if proc.returncode != 0:
        logger.error(
            "start_scan: agent exited %d stderr=%r",
            proc.returncode,
            proc.stderr[:500],
        )
        raise HTTPException(
            status_code=500,
            detail=f"Agent exited with code {proc.returncode}",
        )

    raw_stdout = proc.stdout.strip()
    if not raw_stdout:
        logger.error("start_scan: agent produced no output stderr=%r", proc.stderr[:500])
        raise HTTPException(status_code=500, detail="Agent produced no output")

    try:
        agent_data: dict = json.loads(raw_stdout)
    except json.JSONDecodeError as exc:
        logger.error("start_scan: invalid JSON from agent: %s", exc)
        raise HTTPException(status_code=500, detail="Agent output is not valid JSON")

    # Persist scan with data reported by the agent
    # mode "testset" is treated as "auto": it simulates a real scan using fixtures
    hostname: str = agent_data.get("machine_name") or "unknown"
    os_version: str | None = agent_data.get("os_version")
    scan = create_scan(db, hostname=hostname, os_version=os_version, mode="auto")
    logger.info("start_scan: scan created id=%d hostname=%r", scan.id, hostname)

    # Map and persist findings; roll back the scan row on any failure
    try:
        raw_findings: list = agent_data.get("findings") or []
        finding_dicts = [
            fd
            for f in raw_findings
            if isinstance(f, dict) and f.get("algorithm")
            for fd in (_map_finding(f),)
            if fd is not None
        ]
        if finding_dicts:
            create_findings_bulk(db, scan.id, finding_dicts)
        logger.info("start_scan: persisted %d findings", len(finding_dicts))

        qr_score = agent_data.get("qr_score")
        if qr_score is not None:
            scan = update_scan_finished(db, scan, float(qr_score))
    except Exception as exc:
        logger.error("start_scan: failed to persist results, rolling back scan id=%d: %s", scan.id, exc)
        try:
            db.delete(scan)
            db.commit()
        except Exception:
            pass
        raise HTTPException(status_code=500, detail="Failed to persist scan results")

    logger.info("start_scan: done scan_id=%d qr_score=%s", scan.id, qr_score)
    return ScanRead.model_validate(scan)


@router.get("/", response_model=list[ScanSummary])
async def get_scans(
    page: int = Query(1, ge=1),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
) -> list[ScanSummary]:

    scans = list_scans(
        db,
        page=page,
        limit=limit,
    )

    return [ScanSummary.model_validate(s) for s in scans]


@router.get("/{scan_id}", response_model=ScanRead)
async def get_scan(scan_id: int, db: Session = Depends(get_db)) -> ScanRead:
    scan = _get_scan(db, scan_id)
    if scan is None:
        logger.warning("get_scan: scan_id=%d not found", scan_id)
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanRead.model_validate(scan)


@router.get("/{scan_id}/findings", response_model=list[FindingRead])
async def get_findings(
    scan_id: int,
    severity: Severity | None = Query(None),
    status: FindingStatus | None = Query(None),
    db: Session = Depends(get_db),
) -> list[FindingRead]:
    scan = _get_scan(db, scan_id)
    if scan is None:
        logger.warning("get_findings: scan_id=%d not found", scan_id)
        raise HTTPException(status_code=404, detail="Scan not found")

    filters: dict[str, str] = {}
    if severity is not None:
        filters["severity"] = severity.value
    if status is not None:
        filters["status"] = status.value

    findings = get_findings_by_scan(db, scan_id, filters=filters)
    return [FindingRead.model_validate(f) for f in findings]
