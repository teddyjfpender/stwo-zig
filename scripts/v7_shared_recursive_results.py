#!/usr/bin/env python3
"""Index checked shared-original recursive windows without relabelling failures.

This validates measurement/artifact provenance, not STARKs. Cryptographic
qualification belongs to the recorded prover and independent receiver run.
"""
from __future__ import annotations
import argparse
import csv
import hashlib
import json
from pathlib import Path


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def record(case: Path) -> dict | None:
    report_path = case / "report.json"
    if not report_path.exists():
        return None
    report = json.loads(report_path.read_text())
    if report.get("schema") != "stwo-real-window-shared-union-root-v1":
        return None
    detail_path = case / "union-root-verification.json"
    detail = json.loads(detail_path.read_text())
    invocation = json.loads((case / "invocation.json").read_text())
    if invocation.get("returncode") != 0 or invocation.get("report_checked") is not True:
        raise ValueError(f"{case}: invocation was not independently checked")
    for key in ("canonical_security", "complete_global_closure", "complete_recursive_root", "verified", "union_proof"):
        if report.get(key) is not True:
            raise ValueError(f"{case}: incomplete theorem boundary: {key}")
    if report.get("ethereum_block") is not False or report.get("skipped_prefix_proved") is not False or report.get("query_count") != 70 or report.get("pow_bits") != 26:
        raise ValueError(f"{case}: incorrect security or complete-block label")
    if report.get("scope") != "declared_nonterminal_window_to_shared_recursive_root" or detail.get("scope") != report["scope"] or detail.get("verified", {}).get("scope") != "declared_window":
        raise ValueError(f"{case}: incorrect window scope")
    for key in ("original_proofs_destroyed", "producer_capture_destroyed", "producer_parent_rows_destroyed", "independent_fixed_key_reconstructed"):
        if detail.get(key) is not True:
            raise ValueError(f"{case}: missing receiver boundary: {key}")
    for name, size_key, hash_key in (("root.proof", "root_bytes", "root_sha256"), ("union.claims", "claims_bytes", "claims_sha256"), ("union-public.json", "metadata_bytes", "metadata_sha256")):
        path = case / name
        if path.stat().st_size != detail.get(size_key) or digest(path) != detail.get(hash_key):
            raise ValueError(f"{case}: artifact mismatch: {name}")
    if detail.get("source_stark_count") != 1 or detail.get("recursive_stark_count") != 1:
        raise ValueError(f"{case}: unexpected proof roster")
    stats = detail["recursive"]
    plan = report["stats"].get("ram_component_plan") or {}
    row = dict(case=case.name, cycles=report["window"]["cycles"], skip_cycles=report["window"]["skip_cycles"],
               native_segments=report["stats"]["segments"], callers=report["stats"]["callers"], logical_ram_accesses=report["stats"]["events"],
               ram_components=plan.get("components", "legacy_fixed"), ram_events_per_component=plan.get("events_per_component", 32768),
               worker_count=report["worker_count"], native_layout=report["native_layout_mode"], query_count=70, pow_bits=26,
               scope=report["scope"], whole_request_ns=report["whole_request_ns"], source_phase_ns=report["stats"]["whole_ns"],
               original_verification_ns=detail["original_verification_ns"], recursive_production_ns=detail["recursive_production_ns"],
               fresh_recursive_verification_including_key_setup_ns=detail["fresh_verification_ns"],
               charged_peak_bytes=report["charged_peak_including_detached_verification"], root_bytes=detail["root_bytes"],
               root_sha256=detail["root_sha256"], metadata_bytes=detail["metadata_bytes"], claims_bytes=detail["claims_bytes"],
               binary_sha256=invocation["binary_sha256"], report_sha256=digest(report_path), receiver_report_sha256=digest(detail_path),
               capture_sha256=invocation["capture_sha256"])
    row.update({"source_" + key: value for key, value in report["stats"].items()
                if key.endswith("_ns")})
    row.update({"memory_preparation_" + key: value for key, value in report["stats"].get("memory_preparation", {}).items()})
    row.update({"recursive_" + key: value for key, value in stats.items()})
    return row


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-dir", type=Path, required=True)
    args = parser.parse_args()
    rows = [row for case in sorted(args.report_dir.iterdir()) if case.is_dir() and (row := record(case)) is not None]
    if not rows:
        raise ValueError("no qualified shared recursive windows")
    # Substage clocks were added after the first qualified runs. Missing
    # observations remain empty; no zero-duration measurements are invented.
    fields = list(dict.fromkeys(key for row in rows for key in row))
    with (args.report_dir / "shared-recursive-window-times.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    print(f"indexed {len(rows)} qualified shared recursive windows")


if __name__ == "__main__":
    main()
