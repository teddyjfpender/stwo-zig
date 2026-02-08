#!/usr/bin/env python3
"""Std-shims behavior parity harness.

Verifies that `interop_cli` standard verify mode and `verify_std_shims` mode
produce equivalent acceptance/rejection behavior over deterministic
prove-checkpoint artifacts.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CHECKPOINTS = ROOT / "vectors" / "reports" / "prove_checkpoints_report.json"
DEFAULT_REPORT = ROOT / "vectors" / "reports" / "std_shims_behavior_report.json"

REJECTION_CLASS_VERIFIER = "verifier_semantic"
REJECTION_CLASS_PARSER = "parser"
REJECTION_CLASS_METADATA = "metadata_policy"
REJECTION_CLASS_OTHER = "other"


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def trim_tail(text: str, limit: int = 2000) -> str:
    if len(text) <= limit:
        return text
    return text[-limit:]


def classify_rejection(stdout_tail: str, stderr_tail: str) -> str:
    combined = f"{stdout_tail}\n{stderr_tail}".lower()

    parser_markers = (
        "syntaxerror",
        "unexpectedtoken",
        "expected value at line",
        "line 1 column 1",
    )
    if any(marker in combined for marker in parser_markers):
        return REJECTION_CLASS_PARSER

    metadata_markers = (
        "unsupportedupstreamcommit",
        "unsupported upstream commit",
        "unsupportedgenerator",
        "unsupported generator",
        "unknown artifact generator",
        "unsupported prove mode",
        "unsupportedprovemode",
    )
    if any(marker in combined for marker in metadata_markers):
        return REJECTION_CLASS_METADATA

    verifier_markers = (
        "oodsnotmatching",
        "statementnotsatisfied",
        "statement not satisfied",
        "invalidproofshape",
        "invalid proof shape",
        "deep-ali",
        "verify failed",
        "verification failed",
        "not matching",
        "witnesstooshort",
        "merkleverificationerror",
        "fri verification",
        "root mismatch",
        "witness is too short",
    )
    if any(marker in combined for marker in verifier_markers):
        return REJECTION_CLASS_VERIFIER

    return REJECTION_CLASS_OTHER


def run_verify(mode: str, artifact: Path) -> dict[str, Any]:
    cmd = [
        "zig",
        "run",
        "src/interop_cli.zig",
        "--",
        "--mode",
        mode,
        "--artifact",
        str(artifact),
    ]
    started = time.perf_counter()
    proc = subprocess.run(
        cmd,
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    seconds = time.perf_counter() - started
    out = {
        "mode": mode,
        "return_code": proc.returncode,
        "status": "ok" if proc.returncode == 0 else "failed",
        "seconds": round(seconds, 6),
        "stdout_tail": trim_tail(proc.stdout),
        "stderr_tail": trim_tail(proc.stderr),
    }
    if proc.returncode != 0:
        out["rejection_class"] = classify_rejection(out["stdout_tail"], out["stderr_tail"])
    return out


def expected_checks_for_case(case: dict[str, Any]) -> list[tuple[str, Path, bool, str | None]]:
    artifacts = case.get("artifacts")
    if not isinstance(artifacts, dict):
        raise RuntimeError(f"missing artifacts for case {case.get('case_id')}")

    def must_path(key: str) -> Path:
        value = artifacts.get(key)
        if not isinstance(value, str):
            raise RuntimeError(f"missing artifact key '{key}' for case {case.get('case_id')}")
        return ROOT / value

    return [
        ("prove", must_path("prove"), True, None),
        ("prove_ex", must_path("prove_ex"), True, None),
        ("tampered_proof", must_path("tampered_proof"), False, REJECTION_CLASS_VERIFIER),
        ("tampered_statement", must_path("tampered_statement"), False, REJECTION_CLASS_VERIFIER),
        ("tampered_mode", must_path("tampered_mode"), False, REJECTION_CLASS_METADATA),
    ]


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Std-shims behavior parity harness")
    parser.add_argument(
        "--prove-checkpoints-report",
        type=Path,
        default=DEFAULT_CHECKPOINTS,
        help="Path to prove checkpoints report JSON",
    )
    parser.add_argument(
        "--report-out",
        type=Path,
        default=DEFAULT_REPORT,
        help="Path for JSON report output",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.prove_checkpoints_report.exists():
        raise RuntimeError(f"missing prove checkpoints report: {rel(args.prove_checkpoints_report)}")

    checkpoints = json.loads(args.prove_checkpoints_report.read_text(encoding="utf-8"))
    if checkpoints.get("status") != "ok":
        raise RuntimeError("prove checkpoints report is not ok; run prove_checkpoints first")

    cases = checkpoints.get("cases")
    if not isinstance(cases, list):
        raise RuntimeError("invalid prove checkpoints report: missing cases list")

    checks: list[dict[str, Any]] = []
    failures: list[str] = []
    started_at = time.time()

    for case in cases:
        case_id = str(case.get("case_id", "unknown"))
        for check_name, artifact_path, expect_success, expected_rejection_class in expected_checks_for_case(case):
            standard = run_verify("verify", artifact_path)
            std_shims = run_verify("verify_std_shims", artifact_path)

            mismatch_reasons: list[str] = []
            standard_ok = standard["status"] == "ok"
            std_shims_ok = std_shims["status"] == "ok"
            if standard_ok != expect_success:
                mismatch_reasons.append(
                    f"standard verify expected {'ok' if expect_success else 'failed'} got {standard['status']}"
                )
            if std_shims_ok != expect_success:
                mismatch_reasons.append(
                    f"std_shims verify expected {'ok' if expect_success else 'failed'} got {std_shims['status']}"
                )
            if standard_ok != std_shims_ok:
                mismatch_reasons.append("standard and std_shims disagree on acceptance")

            if not expect_success:
                standard_class = standard.get("rejection_class")
                std_shims_class = std_shims.get("rejection_class")
                if expected_rejection_class and standard_class != expected_rejection_class:
                    mismatch_reasons.append(
                        f"standard rejection class {standard_class} != expected {expected_rejection_class}"
                    )
                if expected_rejection_class and std_shims_class != expected_rejection_class:
                    mismatch_reasons.append(
                        f"std_shims rejection class {std_shims_class} != expected {expected_rejection_class}"
                    )
                if standard_class != std_shims_class:
                    mismatch_reasons.append("standard and std_shims rejection class mismatch")

            status = "ok" if not mismatch_reasons else "failed"
            check_entry = {
                "case_id": case_id,
                "check": check_name,
                "artifact": rel(artifact_path),
                "expect_success": expect_success,
                "expected_rejection_class": expected_rejection_class,
                "status": status,
                "mismatch_reasons": mismatch_reasons,
                "standard": standard,
                "std_shims": std_shims,
            }
            checks.append(check_entry)

            if mismatch_reasons:
                failures.append(f"{case_id}:{check_name}: " + "; ".join(mismatch_reasons))

    status = "ok" if not failures else "failed"
    report = {
        "status": status,
        "source_report": rel(args.prove_checkpoints_report),
        "summary": {
            "checks_total": len(checks),
            "checks_passed": len([c for c in checks if c["status"] == "ok"]),
            "checks_failed": len([c for c in checks if c["status"] == "failed"]),
            "failure_count": len(failures),
        },
        "checks": checks,
        "failures": failures,
        "generated_at_unix": int(started_at),
        "duration_seconds": round(time.time() - started_at, 6),
    }

    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    latest = args.report_out.parent / "latest_std_shims_behavior_report.json"
    if latest != args.report_out:
        shutil.copyfile(args.report_out, latest)

    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
