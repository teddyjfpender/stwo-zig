#!/usr/bin/env python3
"""Index checked saved-original -> in-proof-closed root observations.

This verifies measurement/artifact provenance, not STARKs. These rows exclude
original source proving and must not be relabelled complete-block timings.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
from pathlib import Path
from v8_saved_union_root import validate_report


def record(folder: Path) -> dict | None:
    path = folder / "report.json"
    if not path.is_file():
        return None
    report = json.loads(path.read_text())
    if report.get("schema") != "stwo-v8-saved-original-closed-root-v1":
        return None
    invocation = json.loads((folder / "invocation.json").read_text())
    if invocation.get("returncode") != 0 or invocation.get("report_checked") is not True:
        raise ValueError(f"{folder}: unchecked observation")
    capture = {key: report[key] for key in ("window", "elf_sha256", "incoming_sha256", "outgoing_sha256")}
    validate_report(report, capture, invocation["source_proof_sha256"], invocation["metadata_sha256"], report["worker_count"], folder)
    row = dict(case=folder.name, **{key: value for key, value in report.items() if not isinstance(value, dict)})
    row.update(cycles=report["window"]["cycles"], skip_cycles=report["window"]["skip_cycles"])
    row.update({"recursive_" + key: value for key, value in report["recursive"].items()})
    row.update(binary_sha256=invocation["binary_sha256"], build_manifest_sha256=invocation["build_manifest_sha256"],
               capture_sha256=invocation["capture_sha256"], report_sha256=hashlib.sha256(path.read_bytes()).hexdigest())
    return row


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-dir", type=Path, required=True)
    args = parser.parse_args()
    rows = [row for folder in sorted(args.report_dir.iterdir()) if folder.is_dir() and (row := record(folder)) is not None]
    if not rows:
        raise ValueError("no checked V8 closed-root observations")
    fields = list(dict.fromkeys(key for row in rows for key in row))
    with (args.report_dir / "saved-original-v8-closed-root-times.csv").open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    print(f"indexed {len(rows)} checked saved-original V8 closed roots; source proving excluded")


if __name__ == "__main__":
    main()
