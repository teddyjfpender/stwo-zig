#!/usr/bin/env python3
"""Summarize exact-proof A100 trials from the heavy H200 512-PIE cohort."""

import argparse
import csv
import json
from pathlib import Path
import re

from build_gpu_economics import SOURCE, read_trial


ARENA_MODE = re.compile(r"cuda prepared arena mode=(\w+)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--trials", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--usd-per-hour", type=float, default=1.59)
    args = parser.parse_args()
    if args.usd_per_hour <= 0:
        parser.error("hourly rental rate must be positive")

    rows = []
    for case in json.loads(args.manifest.read_text()):
        pie = case["pie"]
        result = read_trial(args.trials, pie, case["input_sha256"])
        if result is None or result["proof_sha256"] != case["expected_proof_sha256"]:
            raise ValueError(f"{pie}: missing or nonmatching independently verified proof")
        log = (args.trials / pie / "process.log").read_text()
        mode = ARENA_MODE.search(log)
        if mode is None:
            raise ValueError(f"{pie}: missing arena mode")
        seconds = result["publication_s"]
        rows.append({
            "pie": pie,
            "steps": case["steps"],
            "blocks": case["blocks"],
            "transactions": case["transactions"],
            "ec_ops": case["ec_ops"],
            "pedersen_ops": case["pedersen_ops"],
            "adapted_bytes": case["input_bytes"],
            "adapted_sha256": case["input_sha256"],
            "source_commit": SOURCE,
            "planned_arena_bytes": result["planned_arena_bytes"],
            "arena_mode": mode.group(1),
            "cold_input_to_cairo_proof_s": round(seconds, 6),
            "cold_ingress_s": round(result["ingress_s"], 6),
            "cairo_proof_s": round(result["proof_s"], 6),
            "full_command_s": round(result["full_command_s"], 6),
            "whole_device_peak_bytes": result["device_peak_bytes"],
            "process_rss_peak_bytes": result["host_rss_peak_bytes"],
            "proof_sha256": result["proof_sha256"],
            "independent_rust_verified": True,
            "usd_per_hour": args.usd_per_hour,
            "gpu_rental_usd_per_proof": round(seconds * args.usd_per_hour / 3600, 8),
        })

    with args.out.open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    print(f"{len(rows)} exact-hash, independently verified A100 PIEs")


if __name__ == "__main__":
    main()
