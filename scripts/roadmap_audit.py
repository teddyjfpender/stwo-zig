#!/usr/bin/env python3
"""Audit closure state for CONFORMANCE section 15 roadmap rows."""

from __future__ import annotations

import argparse
import json
import shutil
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
CONFORMANCE = ROOT / "CONFORMANCE.md"
HANDOFF = ROOT / "handoff.md"
DEFAULT_REPORT = ROOT / "vectors" / "reports" / "roadmap_closure_report.json"

ROADMAP_SECTION_START = "### 15.1 Roadmap Table"
ROADMAP_SECTION_END = "### 15.2 Required Sequencing"

EXPECTED_CRATES = {
    "`crates/stwo`",
    "`crates/constraint-framework`",
    "`crates/air-utils`",
    "`crates/air-utils-derive`",
    "`crates/examples`",
    "`crates/std-shims`",
}


def parse_roadmap_rows(markdown: str) -> list[dict[str, str]]:
    start = markdown.find(ROADMAP_SECTION_START)
    end = markdown.find(ROADMAP_SECTION_END)
    if start < 0 or end < 0 or end <= start:
        raise RuntimeError("failed to locate CONFORMANCE.md section 15.1 table")

    section = markdown[start:end]
    lines = [line.strip() for line in section.splitlines() if line.strip().startswith("|")]
    table_rows = [line for line in lines if not line.startswith("|---")]
    if len(table_rows) < 2:
        raise RuntimeError("invalid section 15.1 roadmap table shape")

    out: list[dict[str, str]] = []
    for line in table_rows[1:]:
        parts = [part.strip() for part in line.strip("|").split("|")]
        if len(parts) != 5:
            raise RuntimeError(f"invalid roadmap row: {line}")
        out.append(
            {
                "rust_crate": parts[0],
                "zig_target_area": parts[1],
                "current_status": parts[2],
                "remaining_required_scope": parts[3],
                "hard_exit_criteria": parts[4],
            }
        )
    return out


def read_report(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    if not isinstance(data, dict):
        return None
    return data


def status_ok(path: Path) -> tuple[bool, str]:
    report = read_report(path)
    if report is None:
        return False, f"missing/invalid report: {path.relative_to(ROOT)}"
    status = report.get("status")
    if status != "ok":
        return False, f"report status not ok: {path.relative_to(ROOT)} ({status})"
    return True, "ok"


def check_examples_coverage(path: Path) -> tuple[bool, str]:
    report = read_report(path)
    if report is None:
        return False, f"missing/invalid report: {path.relative_to(ROOT)}"
    summary = report.get("summary")
    if not isinstance(summary, dict):
        return False, "missing summary in interop report"
    examples = summary.get("examples")
    required = {"blake", "plonk", "poseidon", "state_machine", "wide_fibonacci", "xor"}
    if not isinstance(examples, list):
        return False, "interop summary.examples missing"
    seen = {str(v) for v in examples}
    missing = sorted(required - seen)
    if missing:
        return False, f"interop examples missing: {', '.join(missing)}"
    return True, "ok"


def crate_evidence_checks(crate: str) -> list[tuple[bool, str]]:
    reports = ROOT / "vectors" / "reports"
    checks: list[tuple[bool, str]] = []

    if crate == "`crates/stwo`":
        checks.append(status_ok(reports / "latest_e2e_interop_report.json"))
        checks.append(status_ok(reports / "latest_prove_checkpoints_report.json"))
        checks.append(status_ok(reports / "latest_release_evidence.json"))
        handoff_text = HANDOFF.read_text(encoding="utf-8")
        phrase = "no open high-severity functional/api divergence records"
        checks.append((phrase in handoff_text.lower(), "handoff divergence signoff present"))

    elif crate == "`crates/constraint-framework`":
        checks.append(((ROOT / "vectors" / "constraint_expr.json").exists(), "constraint_expr vectors present"))
        checks.append(((ROOT / "tools" / "stwo-cf-vector-gen" / "Cargo.toml").exists(), "constraint vector generator present"))

    elif crate == "`crates/air-utils`":
        checks.append(((ROOT / "src" / "core" / "air" / "utils.zig").exists(), "air utils module present"))
        checks.append(((ROOT / "src" / "core" / "air" / "trace" / "component_trace.zig").exists(), "air trace component module present"))
        checks.append(((ROOT / "src" / "core" / "air" / "trace" / "row_iterator.zig").exists(), "air trace row iterator module present"))

    elif crate == "`crates/air-utils-derive`":
        checks.append(((ROOT / "vectors" / "air_derive.json").exists(), "air derive vectors present"))
        checks.append(((ROOT / "tools" / "stwo-air-derive-vector-gen" / "Cargo.toml").exists(), "air derive vector generator present"))

    elif crate == "`crates/examples`":
        checks.append(status_ok(reports / "latest_e2e_interop_report.json"))
        checks.append(check_examples_coverage(reports / "latest_e2e_interop_report.json"))
        checks.append(status_ok(reports / "latest_examples_parity_report.json"))

    elif crate == "`crates/std-shims`":
        checks.append(status_ok(reports / "latest_std_shims_behavior_report.json"))
        checks.append(((ROOT / "src" / "std_shims_freestanding.zig").exists(), "freestanding std_shims entrypoint present"))

    else:
        checks.append((False, f"unexpected crate row: {crate}"))

    return checks


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit roadmap closure status")
    parser.add_argument(
        "--allow-partial",
        action="store_true",
        help="Allow Partial statuses (still validates evidence and emits gaps)",
    )
    parser.add_argument(
        "--report-out",
        type=Path,
        default=DEFAULT_REPORT,
        help="Path for roadmap closure report",
    )
    args = parser.parse_args()

    conformance_text = CONFORMANCE.read_text(encoding="utf-8")
    rows = parse_roadmap_rows(conformance_text)

    failures: list[str] = []
    row_entries: list[dict[str, Any]] = []

    seen_crates = {row["rust_crate"] for row in rows}
    missing_crates = sorted(EXPECTED_CRATES - seen_crates)
    extra_crates = sorted(seen_crates - EXPECTED_CRATES)
    if missing_crates:
        failures.append("missing roadmap rows: " + ", ".join(missing_crates))
    if extra_crates:
        failures.append("unexpected roadmap rows: " + ", ".join(extra_crates))

    for row in rows:
        crate = row["rust_crate"]
        status = row["current_status"].strip()
        checks = []

        for ok, detail in crate_evidence_checks(crate):
            checks.append({"ok": ok, "detail": detail})
            if not ok:
                failures.append(f"{crate}: {detail}")

        if not row["remaining_required_scope"].strip():
            failures.append(f"{crate}: empty remaining_required_scope")
        if not row["hard_exit_criteria"].strip():
            failures.append(f"{crate}: empty hard_exit_criteria")

        if not args.allow_partial and status.lower() != "complete":
            failures.append(f"{crate}: status is '{status}', expected Complete")

        row_entries.append(
            {
                "rust_crate": crate,
                "current_status": status,
                "checks": checks,
                "checks_failed": sum(1 for c in checks if not c["ok"]),
            }
        )

    status = "ok" if not failures else "failed"
    report = {
        "schema_version": 1,
        "generated_at_unix": int(time.time()),
        "status": status,
        "allow_partial": args.allow_partial,
        "summary": {
            "rows_total": len(rows),
            "rows_complete": sum(1 for row in rows if row["current_status"].lower() == "complete"),
            "rows_partial": sum(1 for row in rows if row["current_status"].lower() == "partial"),
            "failure_count": len(failures),
        },
        "rows": row_entries,
        "failures": failures,
    }

    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    latest = args.report_out.parent / "latest_roadmap_closure_report.json"
    if latest != args.report_out:
        shutil.copyfile(args.report_out, latest)

    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
