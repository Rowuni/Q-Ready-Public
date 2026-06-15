# backend/tests — Q-Ready backend test suite

Integration tests for the FastAPI backend endpoints. They verify that file parsing,
scoring computation, and database persistence work correctly end-to-end,
**with no Docker or external server required**.

---

## Contents

```
backend/tests/
├── conftest.py                  # Adds agent/ to sys.path (required by TestScoringCoherence)
└── test_import_endpoints.py     # E2E tests for POST /import/cert and POST /import/ssh
```

---

## What these tests cover

### Import endpoints (`test_import_endpoints.py`)

| Class | Scenario |
|---|---|
| `TestImportCertPEM` | PEM import — HTTP 201, finding structure, valid severity, score 0–100, PQC recommendation present |
| `TestImportCertDER` | DER import (`.cer`) |
| `TestImportCertEC` | EC P-256 certificate — severity `high`, score ≤ 85, `recommendation_url` set |
| `TestImportCertP12NoPassword` | PKCS#12 without password (`.p12`) |
| `TestImportCertPFXWithPassword` | PKCS#12 with password — correct password → 201, wrong password → 400 |
| `TestImportCertEdgeCases` | Empty file → 400, unknown extension → 400, random binary data → 400 |
| `TestImportSSH` | SSH key import — HTTP 201, required fields present, `source == "import_ssh"` |
| `TestImportSSHEdgeCases` | Empty file → 400, invalid data → 400 or 422 |
| `TestImportSSHPrivateKeyRejection` | OPENSSH and RSA private keys → HTTP 400 with actionable message (regression guard) |
| `TestScoringCoherence` | Direct unit checks on `qready_scoring`: expected values for RSA-2048, EC P-256, fallback, temporal factor. Also verifies that the `agent/scoring/algo_severity` wrapper re-exports **the exact same object** as the shared package (regression guard against duplication) |
| `TestImportConfigSshd` | sshd_config upload — HTTP 201, `source == "import_config"`, `store_or_path` prefixed with `uploaded:`, weak KexAlgorithms and Ciphers detected, clean config → `[]` |
| `TestImportConfigOpenssl` | openssl.cnf upload — `SECLEVEL=0` → `critical`, strong config → `[]`, `source == "import_config"` |
| `TestImportConfigEdgeCases` | Unknown filename → 400, empty sshd_config → `[]` |

### Technical approach

- **FastAPI TestClient**: HTTP requests go through the real FastAPI stack (routing, Pydantic validation, middleware)
- **In-memory SQLite with `StaticPool`**: all connections share the same instance; tables are created before the tests and destroyed when the process exits
- **Real fixtures**: test files are the actual certificates and SSH keys located in `agent/tests/`
- **No business-logic mocks**: the certificate parser (`cert_parser.py`), the scoring engine (`qready_scoring`), and the persistence layer (`repository.py`) all run for real

---

## Prerequisites

Install these packages **once**:

```bash
# Shared scoring package (single source of truth)
pip install -e ./shared

# Test dependencies
pip install pytest httpx

# Backend dependencies (if not already installed)
pip install -r backend/requirements.txt
```

---

## Running the tests

From the **repository root**:

```bash
# All tests, verbose
pytest backend/tests/ -v

# A single test
pytest backend/tests/test_import_endpoints.py::TestImportCertPEM::test_status_201 -v

# An entire class
pytest backend/tests/test_import_endpoints.py::TestScoringCoherence -v
```

## Fixtures

| Path | Description |
|---|---|
| `agent/tests/import/certs/test_cert.pem` | Self-signed RSA certificate (PEM) |
| `agent/tests/import/certs/test_cert.cer` | Same certificate in DER format |
| `agent/tests/import/certs/test_cert.crt` | EC P-256 certificate (PEM) |
| `agent/tests/import/certs/test_cert.p12` | PKCS#12 without password |
| `agent/tests/import/certs/test_cert.pfx` | PKCS#12 with password `test` |
| `agent/tests/ssh/ssh_key_test` | OpenSSH public key |
| `agent/tests/import/configs/sshd_config` | sshd_config with weak KexAlgorithms, Ciphers, MACs |
| `agent/tests/import/configs/sshd_config_clean` | sshd_config with strong settings only (expects no findings) |
| `agent/tests/fixtures/test_openssl_critical.cnf` | openssl.cnf with `SECLEVEL=0` (critical finding) |
| `agent/tests/fixtures/test_openssl_strong.cnf` | openssl.cnf with strong settings only (expects no findings) |

---

## Manual testing

Start the backend locally:

```bash
cd backend && uvicorn main:app --reload
```

Then from another terminal (**Linux / macOS / Git Bash**):

```bash
curl -F "file=@agent/tests/import/configs/sshd_config" http://localhost:8000/import/config
curl -F "file=@agent/tests/fixtures/test_openssl_critical.cnf" http://localhost:8000/import/config
```

> **Windows PowerShell**: `curl` is an alias for `Invoke-WebRequest` and does not support `-F`.
> Use `curl.exe` (shipped natively with Windows 10/11) instead:
>
> ```powershell
> curl.exe -F "file=@agent/tests/import/configs/sshd_config" http://localhost:8000/import/config
> curl.exe -F "file=@agent/tests/fixtures/test_openssl_critical.cnf" http://localhost:8000/import/config
> ```
