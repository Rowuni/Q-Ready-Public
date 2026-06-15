"""POST /import/* — manual upload of artefacts (certs, SSH keys, configs)."""
import logging
import os

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from sqlalchemy.orm import Session

from cert_parser import parse_certificate_file
from config_parser import detect_config_type, detect_config_type_from_content, parse_openssl_cnf, parse_sshd_config
from ssh_parser import parse_ssh_public_key
from database import get_db
from models import FindingRead
import repository

logger = logging.getLogger(__name__)

router = APIRouter()

_MAX_CERT_SIZE = 10 * 1024 * 1024  # 10 MB

_ALLOWED_CERT_EXTENSIONS = {".pem", ".cer", ".crt", ".der", ".p12", ".pfx"}


def _validate_cert_upload(file: UploadFile) -> str:
    """Validate certificate upload by extension only.

    Content-Type is intentionally not checked: browsers and curl commonly send
    'application/octet-stream' for binary certificates, and enforcing a specific
    MIME type would produce false positives for legitimate files.
    """
    filename = file.filename or ""
    _, ext = os.path.splitext(filename)
    if not filename or ext.lower() not in _ALLOWED_CERT_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail="Unsupported certificate file type. Allowed: .pem, .cer, .crt, .der, .p12, .pfx",
        )
    return filename


@router.post("/cert", response_model=list[FindingRead], status_code=201)
async def import_cert(
    file: UploadFile = File(...),
    password: str | None = Form(None),
    db: Session = Depends(get_db),
) -> list[FindingRead]:
    """
    Parse an uploaded certificate file (.pem, .cer, .crt, .p12, .pfx)
    and persist the extracted findings.

    Supported formats: PEM (single or chain), DER, PKCS#12.
    The `password` form field is optional and only used for .p12/.pfx files.
    """
    filename = _validate_cert_upload(file)

    content = await file.read(_MAX_CERT_SIZE + 1)
    if len(content) > _MAX_CERT_SIZE:
        raise HTTPException(status_code=413, detail="File too large (max 10 MB)")

    password_bytes = password.encode() if password else None

    try:
        finding_dicts = parse_certificate_file(content, filename, password_bytes)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if not finding_dicts:
        raise HTTPException(status_code=400, detail="No valid certificate found in the uploaded file")

    scan = repository.create_scan(db, hostname="import", mode="import")

    findings = repository.create_findings_bulk(db, scan.id, finding_dicts)

    logger.info("import_cert: persisted %d finding(s) from %r (scan_id=%d)", len(findings), filename, scan.id)
    return findings


@router.post("/ssh", response_model=list[FindingRead], status_code=201)
async def import_ssh(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
) -> list[FindingRead]:
    """
    Parse an uploaded SSH public key file (.pub, authorized_keys) and return the findings.
    Private keys are rejected with HTTP 400.
    """
    content = await file.read(_MAX_CERT_SIZE + 1)
    if len(content) > _MAX_CERT_SIZE:
        raise HTTPException(status_code=413, detail="File too large (max 10 MB)")

    filename = file.filename or "uploaded_ssh_key"

    try:
        finding_dicts = parse_ssh_public_key(content, filename)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    if not finding_dicts:
        raise HTTPException(status_code=400, detail="No valid SSH key found in the uploaded file")

    scan = repository.create_scan(db, hostname="import", mode="import")
    findings = repository.create_findings_bulk(db, scan.id, finding_dicts)

    logger.info("import_ssh: persisted %d finding(s) from %r (scan_id=%d)", len(findings), filename, scan.id)
    return findings


@router.post("/config", response_model=list[FindingRead], status_code=201)
async def import_config(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
) -> list[FindingRead]:
    """
    Parse an uploaded sshd_config or openssl.cnf file and return the findings.
    The config type is auto-detected from the filename
    (sshd_config → sshd, openssl*.cnf → openssl).
    """
    content = await file.read(_MAX_CERT_SIZE + 1)
    if len(content) > _MAX_CERT_SIZE:
        raise HTTPException(status_code=413, detail="File too large (max 10 MB)")

    filename = file.filename or "uploaded_config"
    config_type = detect_config_type(filename)
    if config_type is None:
        config_type = detect_config_type_from_content(content)
    if config_type is None:
        raise HTTPException(
            status_code=400,
            detail=(
                "Cannot detect config type. "
                "Use a file named 'sshd_config' or 'openssl*.cnf' or 'openssl*.conf', "
                "or ensure the file contains recognisable SSH/OpenSSL directives."
            ),
        )

    try:
        if config_type == "sshd":
            finding_dicts = parse_sshd_config(content, filename)
        else:
            finding_dicts = parse_openssl_cnf(content, filename)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    scan = repository.create_scan(db, hostname="import", mode="import")
    findings = repository.create_findings_bulk(db, scan.id, finding_dicts)

    logger.info(
        "import_config: persisted %d finding(s) from %r (scan_id=%d, type=%s)",
        len(findings), filename, scan.id, config_type,
    )
    return findings
