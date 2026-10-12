#!/usr/bin/env python3
"""Regenerate the normalized experiment table from the immutable trial receipts."""

import csv
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent
GIB = 1024**3
NS = 10**9
FIELDS = [
    "device", "trial", "pie_id", "os_steps", "transactions", "pedersen",
    "ec_op", "policy", "exit_code", "ingress_s", "proof_s",
    "input_to_publication_s", "full_command_s", "planned_arena_gib",
    "device_peak_gib", "proof_sha256", "binary_sha256", "receipt",
]


def seconds(value):
    return f"{value / NS:.6f}" if value is not None else ""


def gib(value):
    return f"{value / GIB:.4f}" if value is not None else ""


def pie_id_for(command):
    for index, item in enumerate(command[:-1]):
        if item == "--input":
            return Path(command[index + 1]).stem
    return ""


rows = []
for receipt in sorted((ROOT / "receipts").glob("*/*/summary.json")):
    summary = json.loads(receipt.read_text())
    trial_dir = receipt.parent
    pie_id = pie_id_for(summary["command"])
    metadata_path = ROOT / "source-metadata" / f"{pie_id}.json"
    meta = json.loads(metadata_path.read_text())["meta"] if metadata_path.exists() else {}
    report_path = trial_dir / "report.json"
    report = json.loads(report_path.read_text()) if report_path.exists() else {}
    completed = report.get("completed_trials", [])
    proof = completed[0] if len(completed) == 1 else {}
    policy = summary.get("policy_env", {})
    row = {
        "device": receipt.parents[1].name,
        "trial": trial_dir.name,
        "pie_id": pie_id,
        "os_steps": meta.get("os_steps", ""),
        "transactions": meta.get("txs", ""),
        "pedersen": meta.get("builtins", {}).get("pedersen", ""),
        "ec_op": meta.get("builtins", {}).get("ec_op", ""),
        "policy": ";".join(f"{key}={value}" for key, value in sorted(policy.items())),
        "exit_code": summary.get("exit_code", ""),
        "ingress_s": seconds(proof.get("ingress_ns")),
        "proof_s": seconds(proof.get("proof_execute_and_decode_ns")),
        "input_to_publication_s": seconds(proof.get("adapted_input_until_publication_ns")),
        "full_command_s": seconds(summary.get("elapsed_ns")),
        "planned_arena_gib": gib(proof.get("planned_arena_bytes")),
        "device_peak_gib": gib(summary.get("whole_device_peak_bytes")),
        "proof_sha256": bytes(proof["proof_sha256"]).hex() if "proof_sha256" in proof else "",
        "binary_sha256": summary.get("binary_sha256", ""),
        "receipt": str(receipt.relative_to(ROOT)),
    }
    rows.append(row)

with (ROOT / "results.tsv").open("w", newline="") as output:
    writer = csv.DictWriter(output, fieldnames=FIELDS, dialect="excel-tab", lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)

print(f"Wrote {len(rows)} trials to {ROOT / 'results.tsv'}")
