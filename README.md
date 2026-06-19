<div align="center">

# Q-Ready - Public Version

**Post-Quantum Cryptography Migration Assistant**

![Status](https://img.shields.io/badge/status-in_development-yellow)
![Version](https://img.shields.io/badge/version-v0.7.0-blue)
![Python](https://img.shields.io/badge/python-3.12+-blue?logo=python&logoColor=white)
![NIST](https://img.shields.io/badge/NIST-FIPS_203%2F204%2F205-purple)
![Platform](https://img.shields.io/badge/agent-Windows_only-0078D4?logo=windows)

</div>

---

## What is Q-Ready?

Many organisations still rely on classical cryptographic mechanisms without a clear picture of their dependencies or a remediation strategy. With the "store now, decrypt later" threat growing steadily and a Cryptographically Relevant Quantum Computer (CRQC) estimated operational around **2030/2031**, everyone needs a way to measure how exposed their data is and how to act on it.

Q-Ready is a **proof-of-concept post-quantum cryptography migration assistant** that:
1. **Scans** Windows machines for cryptographic assets (certificates, SSH keys, TLS configs, crypto libraries)
2. **Scores** each asset with a quantum risk index (QR Score) based on algorithm, temporal urgency, and system criticality
3. **Recommends** migration paths to NIST-standardised post-quantum algorithms (ML-KEM, ML-DSA, SLH-DSA)
4. **Visualises** results in a React dashboard
5. **Demonstrates** hybrid key exchange (ECDH P-256 + ML-KEM-768) in an interactive Lab view

---

## Key Features

| Feature | Description |
|---|---|
| **5 Scanners** | Windows Certificate Store, SSH keys, `sshd_config`, `openssl.cnf`, installed crypto libraries |
| **QR Score** | Composite 0–100 score — algorithmic weakness × temporal urgency × system criticality |
| **PQC Recommendations** | Migration paths aligned to FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA) |
| **Manual Import** | Upload certificates (PEM/DER/PKCS#12), SSH public keys, or config files via the API |
| **REST API** | FastAPI backend with full OpenAPI documentation at `/docs` |
| **Demo Snapshot** | Pre-populated `fixtures/demo.db` for instant demonstrations without re-scanning |
| **Hybrid Lab** | Interactive ECDH P-256 + ML-KEM-768 key exchange demonstrator |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Browser                                                        │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Frontend — React 18 + Vite + TypeScript                 │   │
│  │  Dashboard / Findings / Import / Lab                     │   │
│  │  React Query (data fetching) + recharts (charts)         │   │
│  └────────────────────┬─────────────────────────────────────┘   │
└───────────────────────│─────────────────────────────────────────┘
                        │ HTTP /api/* (Vite proxy in dev, nginx in prod)
┌───────────────────────▼─────────────────────────────────────────┐
│  Backend — FastAPI + Python 3.12                                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────────┐   │
│  │ POST /scans/ │  │ GET /scans/  │  │ POST /import/{type}  │   │
│  │              │  │ GET /findings│  │ GET  /findings/{id}  │   │
│  └──────┬───────┘  └──────┬───────┘  └──────────────────────┘   │
│         │                 │                                     │
│  ┌──────▼─────────────────▼──────────────────────────────────┐  │
│  │  SQLite — data/qready.db (SQLAlchemy)                     │  │
│  └───────────────────────────────────────────────────────────┘  │
└───────────────────────┬─────────────────────────────────────────┘
                        │ Python subprocess
┌───────────────────────▼─────────────────────────────────────────┐
│  Agent — Python 3.12 (Windows only)                             │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌──────────┐   │
│  │ cert_store  │ │  ssh_keys   │ │ sshd_config │ │openssl_  │   │
│  │ (wincert.)  │ │ (~/.ssh/)   │ │ /etc/ssh/   │ │cnf       │   │
│  └─────────────┘ └─────────────┘ └─────────────┘ └──────────┘   │
│  ┌─────────────┐ ┌──────────────────────────────────────────┐   │
│  │crypto_libs  │ │  Scoring engine (SC1–SC6)                │   │
│  │(SChannel,   │ │  QR Score + Recommendations + Aggregator │   │
│  │ OpenSSL)    │ └──────────────────────────────────────────┘   │
│  └─────────────┘                                                │
└─────────────────────────────────────────────────────────────────┘
```

---

## Tech Stack

### Backend
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)
![Pydantic](https://img.shields.io/badge/Pydantic-v2-E92063?logo=pydantic&logoColor=white)
![SQLAlchemy](https://img.shields.io/badge/SQLAlchemy-2.x-red)
![SQLite](https://img.shields.io/badge/SQLite-3-003B57?logo=sqlite&logoColor=white)

### Agent
![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![cryptography](https://img.shields.io/badge/cryptography-46.0-yellow)
![paramiko](https://img.shields.io/badge/paramiko-5.0-lightgrey)

### Frontend
![React](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=black)
![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?logo=typescript&logoColor=white)
![Vite](https://img.shields.io/badge/Vite-5-646CFF?logo=vite&logoColor=white)
![TailwindCSS](https://img.shields.io/badge/Tailwind_CSS-v4-06B6D4?logo=tailwindcss&logoColor=white)

### Infrastructure
![Docker](https://img.shields.io/badge/Docker_Compose-v2-2496ED?logo=docker&logoColor=white)

---

## Quick Start (Docker)

> **Prerequisites:** Docker Desktop 4.x, Git

```bash
git clone https://github.com/your-github-org/q-ready.git
cd q-ready
cp .env.example .env
docker compose up --build
```

| Service | URL |
|---|---|
| Dashboard | http://localhost:5173 |
| API | http://localhost:8000 |
| Swagger docs | http://localhost:8000/docs |

To load demo data instead of running a real scan:
```bash
python scripts/restore_demo.py
```

---

## Manual Setup (Local Dev)

### Shared package (required first)
```bash
pip install -e ./shared
```

### Backend
```bash
cd backend
python -m venv .venv && .venv\Scripts\activate   # Windows
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

### Frontend

> **Requires Node.js 20+**

```bash
cd frontend
npm install
npm run dev   # → http://localhost:5173
```

### Agent (Windows only)
```bash
cd agent
python -m venv .venv && .venv\Scripts\activate
pip install -r requirements.txt
python scan.py              # scan the local machine
python scan.py --testset    # use fixture files (no real scan)
python scan.py --output json > results.json
```

The agent writes to `agent/scan_results.md` and `agent/scan_results.json` after each run.

> The agent requires Windows to access the Certificate Store (`wincertstore`) and SChannel registry keys.

---

## Scoring Model

The QR Score aggregates three independent factors per finding:

| Factor | Weight | Description |
|---|---|---|
| **SC1** — Algorithmic severity | 50 % | Is the algorithm breakable by Shor's or Grover's algorithm? RSA/ECDSA score high; ML-KEM scores 0. |
| **SC2** — Temporal urgency | 25 % | Will the asset still be in service when a CRQC arrives (~2031)? Expires in 3 months → low urgency. Permanent (SSH keys) → high urgency. |
| **SC3** — System criticality | 25 % | Where is the asset used? Root CA certificate → maximum impact. User application certificate → lower impact. |

```
risk_score = round(((SC1/100 × 0.5) + (SC2 × 0.25) + (SC3 × 0.25)) × 100, 1)
```

**Guard D2:** expired assets receive `risk_score = 0.0` — they will no longer be in service when the threat materialises.

The **global QR Score** (0–100) combines a conformance ratio and a weighted risk average across all active (non-expired) findings:
```
simple_score   = PQC-conformant findings / total active × 100
weighted_score = (1 − total_risk / max_risk) × 100
qr_score       = round((simple_score + weighted_score) / 2, 1)
```

A score of **100** means every active asset is already post-quantum safe.

---

## NIST Post-Quantum Standards

Q-Ready maps every finding to the relevant NIST post-quantum standard:

| NIST Standard | Algorithm | Replaces |
|---|---|---|
| **FIPS 203** | ML-KEM (Kyber) | RSA-OAEP, ECDH (key encapsulation) |
| **FIPS 204** | ML-DSA (Dilithium) | RSA-PSS, ECDSA (digital signature) |
| **FIPS 205** | SLH-DSA (SPHINCS+) | RSA, ECDSA (stateless hash-based signature) |

Recommended migration strategy: **hybrid** (classical + PQC in parallel) during the transition period. The Lab view in the dashboard demonstrates a live ECDH P-256 + ML-KEM-768 hybrid key exchange.

---

## API Reference

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/ping` | Health check |
| `POST` | `/scans/` | Trigger a full scan (invokes agent as subprocess, persists results) |
| `GET` | `/scans/` | List past scans with severity breakdown (`?page=1&limit=20`) |
| `GET` | `/scans/{id}` | Get a single scan |
| `GET` | `/scans/{id}/findings` | List findings for a scan (`?severity=high&status=open`) |
| `POST` | `/import/cert` | Upload a certificate (PEM / DER / PKCS#12) |
| `POST` | `/import/ssh` | Upload an SSH public key or `authorized_keys` |
| `POST` | `/import/config` | Upload an `sshd_config` or `openssl.cnf` (auto-detected) |

Full interactive documentation at **http://localhost:8000/docs** (Swagger UI).

---

## Project Structure

```
q-ready/
├── agent/                  → Windows scanner + scoring engine
│   ├── scan.py             → CLI entry point
│   ├── scanners/           → cert_store, ssh_keys, sshd_config, openssl_cnf, crypto_libs
│   ├── scoring/            → Wrappers re-exporting qready_scoring symbols
│   └── tests/              → Fixture files for --testset mode
├── backend/                → FastAPI REST API
│   ├── main.py             → App + CORS + routers
│   ├── routers/            → scan.py, imports.py
│   ├── models.py           → Pydantic schemas
│   ├── orm.py              → SQLAlchemy table definitions
│   ├── repository.py       → All database queries
│   ├── cert_parser.py      → PEM / DER / PKCS#12 certificate parser
│   ├── ssh_parser.py       → SSH public key / authorized_keys parser
│   ├── config_parser.py    → sshd_config / openssl.cnf parser
│   └── tests/              → 92 integration tests (FastAPI TestClient + in-memory SQLite)
├── frontend/               → React 18 + Vite + TypeScript dashboard
│   └── src/                → Pages: Dashboard, Findings, Import, Lab
├── shared/                 → Internal pip package `qready_scoring`
│   └── qready_scoring/     → algo_severity, temporal_factor, recommendation
├── data/                   → Live SQLite DB (gitignored)
├── fixtures/               → demo.db — pre-populated snapshot for demos
├── scripts/                → restore_demo.py, save_demo.py
├── docs/                   → PROJET.md (technical spec), SETUP.md
├── docker-compose.yml
├── .env.example
└── AGENTS.md               → AI agent directives
```

---

## Tests

```bash
# From backend/
pytest                          # run all 92 tests
pytest -v                       # verbose output
pytest tests/test_scan_endpoints.py   # scan endpoints only
pytest tests/test_import_endpoints.py # import endpoints only
```

Tests use **FastAPI TestClient + in-memory SQLite** (`StaticPool`). No Docker, no external services required. The agent subprocess is mocked.

Coverage areas:
- `POST /scans/` — happy path, agent errors (timeout, non-zero exit, invalid JSON)
- `GET /scans/` — pagination, ordering, severity counts
- `POST /import/cert` — PEM, DER, PKCS#12, edge cases
- `POST /import/ssh` — public keys, `authorized_keys`, private key rejection
- `POST /import/config` — `sshd_config`, `openssl.cnf`, content-based auto-detection
- Scoring coherence — `qready_scoring` package re-export consistency

---

## Database Management

The project uses `SQLAlchemy` with auto-creation at startup. No migrations to run for a fresh install.

```bash
# Reset local DB after a schema change
del data\qready.db          # Windows
uvicorn main:app --reload   # from backend/

# Demo snapshot management
python scripts/restore_demo.py   # restore known demo state before a presentation
python scripts/save_demo.py      # save current DB as new demo snapshot
```

---

## Git Workflow

- `main`, highly protected, only push on it for releases. Requires the review of the repo owner.
- `develop`, protected, requires one review of someone with write access.
- Feature branches: `feat/fe2-dashboard`, `fix/sc4-aggregator`
- Commit format enforced by **Husky + commitlint** (`npm install` at root activates hooks)

```
feat(backend): add content-based config detection
fix: correct QR score edge case for all-expired findings
docs: update PROJET.md with scan endpoint tests
```

Types: `feat` `fix` `refactor` `docs` `test` `chore` `perf` `ci`

---

## Versions

See [CHANGELOG.md](CHANGELOG.md) for the full version history.

---

## Roadmap

We have ideas for the future of our project, here are some of the features we are considering:

- Linux support
- Scheduled re-scans with delta tracking
- PDF report export
- .exe file to run the app on Windows
- Automatic migration of the assets

---

## Contributors

<table>
  <tr>
    <td align="center">
      <a href="https://github.com/Lutow">
        <img src="https://github.com/Lutow.png?size=80" width="80" style="border-radius:50%"/><br/>
        <b>Lutow</b>
      </a><br/>
      <sub>CEO</sub>
    </td>
    <td align="center">
      <a href="https://github.com/Rowuni">
        <img src="https://github.com/Rowuni.png?size=80" width="80" style="border-radius:50%"/><br/>
        <b>Rowuni</b>
      </a><br/>
      <sub>CTO</sub>
    </td>
    <td align="center">
      <a href="https://github.com/GorgorQ">
        <img src="https://github.com/GorgorQ.png?size=80" width="80" style="border-radius:50%"/><br/>
        <b>GorgorQ</b>
      </a><br/>
      <sub>Full Stack Developer</sub>
    </td>
    <td align="center">
      <a href="https://github.com/Brmstone">
        <img src="https://github.com/Brmstone.png?size=80" width="80" style="border-radius:50%"/><br/>
        <b>Brimstone</b>
      </a><br/>
      <sub>Full Stack Developer</sub>
    </td>
    <td align="center">
      <a href="https://github.com/matthieu86">
        <img src="https://github.com/matthieu86.png?size=80" width="80" style="border-radius:50%"/><br/>
        <b>matthieu86</b>
      </a><br/>
      <sub>Cybersecurity Expert</sub>
    </td>
  </tr>
</table>

## License

This project is licensed under the [Apache License 2.0](LICENSE).
