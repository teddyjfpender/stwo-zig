#!/usr/bin/env python3
"""Join an exact H200 campaign cohort with independently verified 5090 trials."""

import argparse
import csv
import json
from pathlib import Path
import re


PHASE = re.compile(r"cairo-cuda-memory-phase phase=([^ ]+) elapsed_ns=(\d+)")


def phase_seconds(path: Path) -> dict[str, float]:
    if not path.exists():
        return {}
    events = {name: int(ns) / 1e9 for name, ns in PHASE.findall(path.read_text())}
    pairs = {
        "trace_s": ("proof_begin", "trace_generation_end"),
        "relation_s": ("main_commit_end", "relation_end"),
        "constraint_s": ("trace_commit_end", "constraint_evaluation_end"),
        "fri_s": ("constraint_stage_end", "fri_commit_end"),
        "decommit_s": ("fri_commit_end", "decommit_end"),
    }
    return {key: round(events[end] - events[start], 6)
            for key, (start, end) in pairs.items() if start in events and end in events}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sample", type=Path, required=True)
    parser.add_argument("--h200-analysis", type=Path, required=True)
    parser.add_argument("--trials", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    with args.h200_analysis.open(newline="") as source:
        campaign = list(csv.DictReader(source))
    index = {row["pie_name"]: (position, row)
             for position, row in enumerate(campaign, 1)}
    rows = []
    for sample in json.loads(args.sample.read_text()):
        name = sample["pie"]
        position, h200 = index[name]
        target = args.trials / name
        result_path = target / "result.json"
        result = json.loads(result_path.read_text()) if result_path.exists() else {}
        if result and result.get("input_sha256") != sample["input_sha256"]:
            raise ValueError(f"{name}: result uses a different adapted input")
        row = {
            "pie": name,
            "campaign_position": position,
            "within_first_64": position <= 64,
            "within_first_128": position <= 128,
            "steps": sample["steps"],
            "blocks": sample["blocks"],
            "transactions": sample["transactions"],
            "ec_ops": sample["ec_ops"],
            "pedersen_ops": sample["pedersen_ops"],
            "keccak_ops": sample["keccak_ops"],
            "adapted_bytes": sample["input_bytes"],
            "adapted_sha256": sample["input_sha256"],
            "h200_service_ingress_s": h200["ingress_s"],
            "h200_service_cairo_prove_s": h200["cairo_prove_s"],
            "h200_service_circuit_wrap_s": h200["circuit_wrap_s"],
            "h200_service_verify_publish_s": h200["verify_publish_s"],
            "rtx5090_status": result.get("status", "pending"),
            "rtx5090_policy": json.dumps(result.get("policy_env", {}), sort_keys=True),
            "rtx5090_cold_full_command_s": result.get("full_command_s", ""),
            "rtx5090_cold_input_to_cairo_proof_s": result.get("publication_s", ""),
            "rtx5090_cold_ingress_s": result.get("ingress_s", ""),
            "rtx5090_cairo_proof_execute_decode_s": result.get("proof_s", ""),
            "rtx5090_whole_device_peak_bytes": result.get("device_peak_bytes", ""),
            "rtx5090_process_tree_rss_peak_bytes": result.get("host_rss_peak_bytes", ""),
            "rtx5090_cairo_proof_sha256": result.get("proof_sha256", ""),
        }
        row.update(phase_seconds(target / "process.log"))
        rows.append(row)
    keys = list(rows[0])
    for row in rows:
        for key in row:
            if key not in keys:
                keys.append(key)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=keys, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    print(f"{len(rows)} cohort rows; {sum(row['rtx5090_status'] == 'verified' for row in rows)} verified")


if __name__ == "__main__":
    main()
