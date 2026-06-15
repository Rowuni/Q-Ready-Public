#!/usr/bin/env python3
"""
scan.py — CLI entrypoint for the Q-Ready agent.
Implementation: task A1.

Usage:
    python scan.py --host <hostname> --output <json|stdout>
    python scan.py --help

host and output format are optional (defaults to current hostname and Markdown report to stdout)

Scan with the test fixtures:
    python scan.py --testset

Scan with test data for SSH keys and sshd_config (path might change in the future):
    from the repository root:
         python agent/scan.py --ssh-dir agent/tests/ssh
    from within agent/:
         python scan.py --ssh-dir tests/ssh
"""
from __future__ import annotations

import argparse
import json
import logging
import pathlib
import platform
import re
import socket
from collections import Counter
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone

from scanners.cert_store import scan_cert_store
from scanners.ssh_keys import scan_ssh_keys
from scanners.sshd_config import scan_sshd_config
from scanners.openssl_cnf import scan_openssl_cnf
from scanners.crypto_libs import scan_crypto_libs
from scoring.algo_severity import get_algo_severity
from scoring.criticality_factor import Category, category_from_source, criticality_factor
from scoring.qr_score import compute_qr_score
from scoring.recommendations import get_recommendation
from scoring.risk_score import compute_risk_score
from scoring.temporal_factor import is_expired, temporal_factor as _temporal_factor

_OUTPUT_DIR = pathlib.Path(__file__).parent / "scan_results"
_REPORT_PATH = _OUTPUT_DIR / "scan_results.md"
_JSON_PATH = _OUTPUT_DIR / "scan_results.json"
_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_SEV_LABEL = {"critical": "[CRIT]", "high": "[HIGH]", "medium": "[MED]", "low": "[LOW]", "info": "[INFO]"}

logger = logging.getLogger(__name__)


def write_markdown_report(results: dict, output_path: pathlib.Path) -> None:
    """Write a human-readable Markdown report, overwriting output_path on each call."""
    hostname = results.get("hostname", "unknown")
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    scanners = {k: v for k, v in results.items() if k not in ("hostname", "qr_score")}

    qr_score = results.get("qr_score")
    qr_display = f"{qr_score} / 100" if qr_score is not None else "—"

    lines: list[str] = [
        "# Q-Ready — Rapport de scan",
        "",
        f"**Machine :** {hostname}  ",
        f"**Date :** {now}  ",
        f"**QR Score :** {qr_display}  ",
        "",
        "---",
        "",
        "## Résumé",
        "",
        "| Scanner | Findings | Critical | High | Medium | Low | Info |",
        "|---------|----------|----------|------|--------|-----|------|",
    ]

    for s_name, findings in scanners.items():
        c = Counter(f.get("severity") or "info" for f in findings)
        if not findings:
            lines.append(f"| {s_name} | 0 | — | — | — | — | — |")
        else:
            lines.append(
                f"| {s_name} | {len(findings)}"
                f" | {c.get('critical', 0)}"
                f" | {c.get('high', 0)}"
                f" | {c.get('medium', 0)}"
                f" | {c.get('low', 0)}"
                f" | {c.get('info', 0)} |"
            )

    lines += ["", "---", ""]

    for s_name, findings in scanners.items():
        lines.append(f"## {s_name} ({len(findings)} finding(s))")
        lines.append("")
        if not findings:
            lines.append("_Aucun finding._")
            lines.append("")
            continue

        lines += [
            "| Severity | Algorithm | SC1 | SC2 | SC3 | Risk Score | Store / Path | Name | Expiration |",
            "|----------|-----------|-----|-----|-----|------------|--------------|------|------------|",
        ]
        for f in sorted(findings, key=lambda x: _SEV_ORDER.get(x.get("severity") or "info", 99)):
            sev = f.get("severity", "info")
            algo = f.get("algorithm") or "—"
            # Prefer values stored by _enrich_risk_scores; fall back to recomputation
            # for imported findings or findings without algorithm.
            sc1_score = f.get("sc1")
            if sc1_score is None and algo != "—":
                sc1_entry = get_algo_severity(algo, f.get("key_size"))
                sc1_score = sc1_entry["score"] if sc1_entry else None
            sc2_factor = f.get("sc2")
            if sc2_factor is None:
                sc2_factor = _temporal_factor(f.get("expiration_date"))
            sc3_factor = f.get("sc3")
            if sc3_factor is None:
                source = f.get("source") or s_name
                category = category_from_source(source)
                store_or_path = f.get("store_or_path") or f.get("key_path") or f.get("path") or ""
                if not isinstance(store_or_path, str):
                    store_or_path = str(store_or_path)
                sc3_factor = criticality_factor(store_or_path, _infer_has_private_key(f, category), category)
            sc1_str = f"{sc1_score}" if sc1_score is not None else "—"
            sc2_str = f"{sc2_factor:.2f}"
            sc3_str = f"{sc3_factor:.2f}"
            risk = f.get("risk_score")
            risk_str = f"{risk}/100" if risk is not None else "—"
            store = f.get("store_or_path") or f.get("key_path") or f.get("path") or "—"
            name = str(f.get("name") or "—")[:50]
            exp = f.get("expiration_date")
            lines.append(
                f"| {_SEV_LABEL.get(sev, sev.upper())} {sev.upper()}"
                f" | {algo}"
                f" | {sc1_str}"
                f" | {sc2_str}"
                f" | {sc3_str}"
                f" | {risk_str}"
                f" | {store}"
                f" | {name}"
                f" | {str(exp)[:10] if exp else '—'} |"
            )
        lines.append("")

    output_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_json_report(results: dict, output_path: pathlib.Path) -> None:
    """Write the scan results as JSON, overwriting output_path on each call."""
    output_path.write_text(json.dumps(results, indent=2, default=str) + "\n", encoding="utf-8")


def _infer_has_private_key(finding: dict, category: Category) -> bool:
    value = finding.get("has_private_key")
    if isinstance(value, bool):
        return value

    if category == Category.SSH_KEY:
        key_type = finding.get("type")
        if key_type == "private":
            return True
        if key_type == "public":
            return False
        # Fallback: path heuristic when scanner type is unavailable
        key_path = finding.get("key_path") or finding.get("path")
        if key_path is not None:
            key_path_str = str(key_path)
            return not key_path_str.lower().endswith(".pub")
        return False

    if category == Category.CERTIFICATE:
        store = finding.get("store_or_path")
        if store is not None:
            tokens = re.split(r"[\\/]+", str(store).lower())
            return any(token in {"my", "personal"} for token in tokens)
        return False

    return False


def _enrich_risk_scores(results: dict) -> None:
    """Populate risk_score and severity on each finding using SC4 (weighted average of SC1, SC2, SC3)."""
    for source_key, findings in results.items():
        if not isinstance(findings, list):
            continue
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            if finding.get("risk_score") is not None:
                continue
            algorithm = finding.get("algorithm")
            if not algorithm:
                continue
            entry = get_algo_severity(algorithm, finding.get("key_size"))
            temporal = _temporal_factor(finding.get("expiration_date"))
            source = finding.get("source") or source_key
            category = category_from_source(source)
            store_or_path = (
                finding.get("store_or_path")
                or finding.get("key_path")
                or finding.get("path")
                or ""
            )
            if not isinstance(store_or_path, str):
                store_or_path = str(store_or_path)
            has_private_key = _infer_has_private_key(finding, category)
            impact = criticality_factor(store_or_path, has_private_key, category)
            finding["sc1"] = entry["score"]
            finding["sc2"] = temporal
            finding["sc3"] = impact
            score, severity = compute_risk_score(
                algorithm,
                finding.get("key_size"),
                finding.get("expiration_date"),
                store_or_path,
                has_private_key,
                category,
            )
            finding["risk_score"] = score
            finding["severity"] = severity


def _enrich_recommendations(results: dict) -> None:
    """Add recommendation text to any finding that does not already have one (SC5)."""
    for source_key, findings in results.items():
        if not isinstance(findings, list):
            continue
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            if finding.get("recommendation"):
                continue
            algorithm = finding.get("algorithm")
            if not algorithm:
                continue
            source = finding.get("source") or source_key
            category = category_from_source(source)
            key_size = finding.get("key_size")
            exp_raw = finding.get("expiration_date")
            # expiration_date preserves its type after asdict() (datetime or None);
            # for imported data it may be a pre-serialised ISO string.
            rec_text, rec_url = get_recommendation(
                algorithm, category, key_size=key_size, is_expired=is_expired(exp_raw)
            )
            finding["recommendation"] = rec_text
            if rec_url is not None and not finding.get("recommendation_url"):
                finding["recommendation_url"] = rec_url


def _is_permission_error(exc: Exception) -> bool:
    if isinstance(exc, PermissionError):
        return True
    if isinstance(exc, OSError) and getattr(exc, "winerror", None) == 5:
        return True
    msg = str(exc).lower()
    return "access is denied" in msg or "permission denied" in msg


def _coerce_findings(findings: list[object] | None, scanner_name: str) -> list[dict]:
    if not findings:
        return []
    coerced: list[dict] = []
    for item in findings:
        if is_dataclass(item):
            coerced.append(asdict(item))
        elif isinstance(item, dict):
            coerced.append(item)
        else:
            logger.warning("scan_%s: unexpected finding type %s", scanner_name, type(item).__name__)
    return coerced


def _run_scanner(scanner_name: str, scan_fn, *args, **kwargs) -> list[dict]:
    try:
        findings = scan_fn(*args, **kwargs)
    except Exception as exc:
        if scanner_name == "cert_store" and _is_permission_error(exc):
            logger.warning("WARN: accès refusé au store LocalMachine, droits admin requis")
        elif isinstance(exc, FileNotFoundError):
            logger.info("scan_%s: file not found, skipping: %s", scanner_name, exc)
        else:
            logger.warning("scan_%s: failed: %s", scanner_name, exc)
        return []
    return _coerce_findings(findings, scanner_name)


def _run_openssl_scans(openssl_cnf_path: pathlib.Path | list[pathlib.Path] | None) -> list[dict]:
    if openssl_cnf_path is None:
        return []
    if isinstance(openssl_cnf_path, list):
        findings: list[dict] = []
        for path in openssl_cnf_path:
            findings.extend(_run_scanner("openssl_cnf", scan_openssl_cnf, path))
        return findings
    return _run_scanner("openssl_cnf", scan_openssl_cnf, openssl_cnf_path)


_INTERNAL_FIELDS = frozenset({"sc1", "sc2", "sc3"})


def _build_normalized_output(results: dict, mode: str) -> dict:
    findings = [
        {k: v for k, v in f.items() if k not in _INTERNAL_FIELDS}
        for key, val in results.items()
        if key not in ("hostname", "qr_score") and isinstance(val, list)
        for f in val
        if isinstance(f, dict)
    ]
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "machine_name": platform.node(),
        "os_version": platform.version(),
        "mode": mode,
        "qr_score": results.get("qr_score"),
        "findings": findings,
    }


def run_scan(
    hostname: str,
    openssl_cnf_path: pathlib.Path | list[pathlib.Path] | None = None,
    ssh_dir_path: pathlib.Path | None = None,
) -> dict:
    """Run all scanners and aggregate results."""
    openssl_findings = _run_openssl_scans(openssl_cnf_path)

    sshd_config_paths = [ssh_dir_path] if ssh_dir_path else None

    results = {
        "hostname": hostname,
        "cert_store": _run_scanner("cert_store", scan_cert_store),
        "ssh_keys": _run_scanner("ssh_keys", scan_ssh_keys, ssh_dir_path),
        "sshd_config": _run_scanner("sshd_config", scan_sshd_config, sshd_config_paths),
        "openssl_cnf": openssl_findings,
        "crypto_libs": _run_scanner("crypto_libs", scan_crypto_libs),
    }
    _enrich_risk_scores(results)
    _enrich_recommendations(results)
    all_findings = [
        f
        for key, val in results.items()
        if key != "hostname" and isinstance(val, list)
        for f in val
        if isinstance(f, dict)
    ]
    results["qr_score"] = compute_qr_score(all_findings)
    return results


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="[%(levelname)s] %(message)s",
    )

    parser = argparse.ArgumentParser(description="Q-Ready — post-quantum scan agent")
    parser.add_argument(
        "--host",
        default=socket.gethostname(),
        help="Hostname to report (default: current machine)",
    )
    parser.add_argument(
        "--output",
        choices=["stdout", "json"],
        default="stdout",
        help="Output format",
    )
    _scan_mode = parser.add_mutually_exclusive_group()
    _scan_mode.add_argument(
        "--testset",
        nargs="?",
        const="all",
        default=None,
        metavar="NAME",
        help=(
            "Use a named test fixture (tests/fixtures/test_openssl_<NAME>.cnf). "
            "Without a name, scans all fixtures at once."
        ),
    )
    _scan_mode.add_argument(
        "--openssl-cnf",
        type=pathlib.Path,
        default=None,
        dest="openssl_cnf",
        help="Path to a specific openssl.cnf file to scan (overrides auto-detection).",
    )
    parser.add_argument(
        "--ssh-dir",
        type=pathlib.Path,
        default=None,
        help="Path to a directory to scan for SSH keys and sshd_config (overrides auto-detection)",
    )
    args = parser.parse_args()

    _fixture_dir = pathlib.Path(__file__).parent / "tests" / "fixtures"
    openssl_cnf_path: pathlib.Path | list[pathlib.Path] | None = None
    if args.testset:
        if args.testset == "all":
            fixtures = sorted(_fixture_dir.glob("test_openssl_*.cnf"))
            if not fixtures:
                parser.error(f"--testset: no test fixtures found in {_fixture_dir}")
            openssl_cnf_path = fixtures
        else:
            fixture = _fixture_dir / f"test_openssl_{args.testset}.cnf"
            if not fixture.is_file():
                parser.error(f"--testset: fixture not found: {fixture}")
            openssl_cnf_path = fixture
    elif args.openssl_cnf:
        if not args.openssl_cnf.is_file():
            parser.error(f"--openssl-cnf: file not found: {args.openssl_cnf}")
        openssl_cnf_path = args.openssl_cnf

    # When --testset is active, fall back to tests/ssh so ssh_keys and
    # sshd_config scanners use the bundled fixtures instead of system paths.
    ssh_dir_path = args.ssh_dir
    if args.testset and ssh_dir_path is None:
        _ssh_dir = pathlib.Path(__file__).parent / "tests" / "ssh"
        if _ssh_dir.exists():
            ssh_dir_path = _ssh_dir

    _OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    results = run_scan(args.host, openssl_cnf_path=openssl_cnf_path, ssh_dir_path=ssh_dir_path)
    write_markdown_report(results, _REPORT_PATH)

    normalized = _build_normalized_output(results, mode="testset" if args.testset else "auto")
    write_json_report(normalized, _JSON_PATH)

    if args.output == "json":
        print(json.dumps(normalized, indent=2, default=str))
        return

    print(f"[Q-Ready] Scan completed for {args.host}")
    for key, findings in results.items():
        if key in ("hostname", "qr_score"):
            continue
        print(f"  {key}: {len(findings)} finding(s)")
    print(f"  -> Markdown report: {_REPORT_PATH}")
    print(f"  -> JSON report    : {_JSON_PATH}")


if __name__ == "__main__":
    main()
