#!/usr/bin/env python3
"""Collect checked shared-original measurements, separately from recursive roots."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
from pathlib import Path

from v7_real_window_results import peak_rss_bytes


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def collect(base: Path, inputs: dict, builds: dict) -> list[dict]:
    selected = {c["capture_manifest_sha256"]: c for c in inputs["cases"]}
    rows = []
    for path in sorted(base.glob("*/report.json")):
        report = json.loads(path.read_text())
        if report.get("schema") != "stwo-real-window-shared-union-v1":
            continue
        folder = path.parent
        invocation = json.loads((folder / "invocation.json").read_text())
        build = builds[invocation["build_manifest_sha256"]]
        case = selected[invocation["capture_sha256"]]
        if invocation["returncode"] != 0 or invocation.get("report_checked") is not True or invocation.get("shared_original_union") is not True or invocation["binary_sha256"] != build["binary_sha256"]:
            raise ValueError(f"{folder.name}: unqualified invocation")
        if report.get("scope") != "declared_nonterminal_window_to_shared_original_stark" or report.get("query_count") != 70 or report.get("pow_bits") != 26:
            raise ValueError(f"{folder.name}: wrong theorem/security")
        if not all(report.get(k) is True for k in ("verified", "canonical_security", "complete_global_closure")) or any(report.get(k) is not False for k in ("complete_recursive_root", "ethereum_block", "skipped_prefix_proved")):
            raise ValueError(f"{folder.name}: invalid closure boundary")
        if report["window"] != case["window"] or any(report[k] != case[k] for k in ("elf_sha256", "incoming_sha256", "outgoing_sha256")):
            raise ValueError(f"{folder.name}: different selected input")
        detail = json.loads((folder / "union-verification.json").read_text())
        proof = folder / "union.proof"
        if detail.get("producer_proof_destroyed") is not True or detail["verified"]["scope"] != "declared_window" or report["artifacts"]["proof_count"] != 1 or sha(proof) != detail["proof_sha256"] or proof.stat().st_size != detail["proof_bytes"]:
            raise ValueError(f"{folder.name}: detached proof mismatch")
        row = dict(case=folder.name, input_case=case["case"], scope=report["scope"],
                   diagnostic=True, recursive_root=False, cycles=case["window"]["cycles"],
                   segment_cycles=report["segment_cycles"], layout=report["native_layout_mode"],
                   worker_count=report["worker_count"], queries=report["query_count"], pow_bits=report["pow_bits"],
                   whole_request_ns=report["whole_request_ns"], verification_ns=detail["verification_ns"],
                   charged_peak_bytes=report["charged_peak_including_detached_verification"],
                   rss_peak_bytes=peak_rss_bytes((folder / "qualification.log").read_text()),
                   proof_bytes=detail["proof_bytes"], proof_sha256=detail["proof_sha256"],
                   binary_sha256=build["binary_sha256"], capture_sha256=invocation["capture_sha256"],
                   report_sha256=sha(path), metadata_bytes=None, metadata_sha256=None)
        if "metadata_sha256" in detail:
            metadata = folder / "union-public.json"
            if detail.get("producer_metadata_destroyed") is not True or sha(metadata) != detail["metadata_sha256"] or metadata.stat().st_size != detail["metadata_bytes"]:
                raise ValueError(f"{folder.name}: detached metadata mismatch")
            row.update(metadata_bytes=detail["metadata_bytes"], metadata_sha256=detail["metadata_sha256"], metadata_transport_ns=detail["metadata_transport_ns"])
        for key, value in report["stats"].items():
            if not isinstance(value, (dict, list)):
                row["source_" + key] = value
        rows.append(row)
    return rows


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report-dir", type=Path, required=True)
    parser.add_argument("--inputs", type=Path, required=True)
    parser.add_argument("--build-manifest", type=Path, action="append", required=True)
    args = parser.parse_args()
    builds = {sha(p): json.loads(p.read_text()) for p in args.build_manifest}
    rows = collect(args.report_dir, json.loads(args.inputs.read_text()), builds)
    fields = list(dict.fromkeys(k for row in rows for k in row))
    with (args.report_dir / "shared-original-window-times.csv").open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    print(f"Recorded {len(rows)} checked shared original proofs; no recursive roots.")


if __name__ == "__main__":
    main()
