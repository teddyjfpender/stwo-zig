#!/usr/bin/env python3
"""Capture a deterministic roadmap baseline snapshot for closure tracking."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
CONFORMANCE = ROOT / "CONFORMANCE.md"
DEFAULT_OUT = ROOT / "vectors" / "reports" / "roadmap_baseline.json"

ROADMAP_SECTION_START = "### 15.1 Roadmap Table"
ROADMAP_SECTION_END = "### 15.2 Required Sequencing"

KEY_REPORTS = [
    "latest_release_evidence.json",
    "latest_e2e_interop_report.json",
    "latest_prove_checkpoints_report.json",
    "latest_std_shims_behavior_report.json",
    "latest_examples_parity_report.json",
    "latest_benchmark_smoke_report.json",
    "latest_benchmark_full_report.json",
]


def run(cmd: list[str]) -> str:
    proc = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, check=True)
    return proc.stdout.strip()


def parse_roadmap_rows(markdown: str) -> list[dict[str, str]]:
    start = markdown.find(ROADMAP_SECTION_START)
    end = markdown.find(ROADMAP_SECTION_END)
    if start < 0 or end < 0 or end <= start:
        raise RuntimeError("failed to locate CONFORMANCE.md section 15.1 table")

    section = markdown[start:end]
    lines = [line.strip() for line in section.splitlines() if line.strip().startswith("|")]
    # Drop header and separator rows.
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


def file_sha256(path: Path) -> str | None:
    if not path.exists() or not path.is_file():
        return None
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def build_snapshot() -> dict[str, Any]:
    conformance_text = CONFORMANCE.read_text(encoding="utf-8")
    rows = parse_roadmap_rows(conformance_text)

    head_sha = run(["git", "rev-parse", "HEAD"])
    branch = run(["git", "rev-parse", "--abbrev-ref", "HEAD"])
    status_lines = [line for line in run(["git", "status", "--short"]).splitlines() if line.strip()]

    reports_dir = ROOT / "vectors" / "reports"
    report_hashes: dict[str, str | None] = {}
    for name in KEY_REPORTS:
        report_hashes[name] = file_sha256(reports_dir / name)

    return {
        "schema_version": 1,
        "generated_at_unix": int(time.time()),
        "git": {
            "head_sha": head_sha,
            "branch": branch,
            "is_dirty": bool(status_lines),
            "dirty_files": status_lines,
        },
        "roadmap": {
            "rows": rows,
            "status_counts": {
                "complete": sum(1 for row in rows if row["current_status"].lower() == "complete"),
                "partial": sum(1 for row in rows if row["current_status"].lower() == "partial"),
                "other": sum(
                    1
                    for row in rows
                    if row["current_status"].lower() not in {"complete", "partial"}
                ),
            },
        },
        "reports": {
            "dir": str(reports_dir.relative_to(ROOT)),
            "sha256": report_hashes,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture roadmap baseline snapshot")
    parser.add_argument(
        "--out",
        type=Path,
        default=DEFAULT_OUT,
        help="Output JSON path",
    )
    args = parser.parse_args()

    snapshot = build_snapshot()
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    latest = args.out.parent / "latest_roadmap_baseline.json"
    if latest != args.out:
        shutil.copyfile(args.out, latest)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
