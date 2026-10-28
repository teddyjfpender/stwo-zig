#!/usr/bin/env python3
"""Build the source-matched, exact-proof GPU rental comparison."""

import argparse
import csv
import hashlib
import json
from pathlib import Path
import re


SOURCE = "271debb91b4ad08954bac9d6c9ff3de1720d529a"
CLEAN_DIFF = hashlib.sha256(b"").hexdigest()
ARENA = re.compile(r"cairo-cuda arena reservation bytes=(\d+)")
ARENA_MODE = re.compile(r"cuda prepared arena mode=(\w+)")
GPUS = ("rtx5090", "l40s", "a100", "h200")


def read_trial(root: Path, pie: str, input_sha256: str) -> dict | None:
    directory = root / pie
    path = directory / "result.json"
    if not path.exists():
        return None
    result = json.loads(path.read_text())
    if result.get("status") != "verified":
        return None
    if result["input_sha256"] != input_sha256:
        raise ValueError(f"{pie}: adapted CPI hash differs in {root}")
    if result.get("verifier_exit_code") != 0:
        raise ValueError(f"{pie}: independent Rust verifier did not pass in {root}")
    verdict = json.loads((directory / "official-verdict.json").read_text())
    if not verdict.get("verified"):
        raise ValueError(f"{pie}: independent verifier receipt is false in {root}")
    summary = json.loads((directory / "summary.json").read_text())
    source = summary["source"]
    if source["git_head"] != SOURCE or source["git_diff_sha256"] != CLEAN_DIFF:
        raise ValueError(f"{pie}: source is not clean {SOURCE} in {root}")
    log = (directory / "process.log").read_text()
    arena = ARENA.search(log)
    mode = ARENA_MODE.search(log)
    if not arena or not mode:
        raise ValueError(f"{pie}: missing planned arena or arena mode in {root}")
    result["planned_arena_bytes"] = int(arena.group(1))
    result["arena_mode"] = mode.group(1)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--comparison", required=True, type=Path)
    for gpu in GPUS:
        parser.add_argument(f"--{gpu}-trials", required=True, type=Path)
        parser.add_argument(f"--{gpu}-usd-per-hour", type=float,
                            default={"rtx5090": 0.69, "l40s": 1.09,
                                     "a100": 1.59, "h200": 4.59}[gpu])
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    roots = {gpu: getattr(args, f"{gpu}_trials") for gpu in GPUS}
    rates = {gpu: getattr(args, f"{gpu}_usd_per_hour") for gpu in GPUS}
    if any(rate <= 0 for rate in rates.values()):
        raise ValueError("GPU rental rates must be positive")
    with args.comparison.open(newline="") as source:
        campaign = list(csv.DictReader(source))
    rows = []
    for case in campaign:
        pie = case["pie"]
        trials = {gpu: read_trial(root, pie, case["adapted_sha256"])
                  for gpu, root in roots.items()}
        if any(trial is None for trial in trials.values()):
            continue
        hashes = {trial["proof_sha256"] for trial in trials.values()}
        arenas = {trial["planned_arena_bytes"] for trial in trials.values()}
        if len(hashes) != 1 or len(arenas) != 1:
            raise ValueError(f"{pie}: proof or arena differs across GPUs")
        h200_seconds = trials["h200"]["publication_s"]
        h200_cost = h200_seconds * rates["h200"] / 3600
        row = {
            "pie": pie,
            "steps": case["steps"],
            "blocks": case["blocks"],
            "adapted_bytes": case["adapted_bytes"],
            "adapted_sha256": case["adapted_sha256"],
            "source_commit": SOURCE,
            "planned_arena_bytes": arenas.pop(),
            "proof_sha256": hashes.pop(),
            "historical_h200_warm_ingress_plus_cairo_s": round(
                float(case["h200_service_ingress_s"]) +
                float(case["h200_service_cairo_prove_s"]), 6
            ),
        }
        for gpu in GPUS:
            trial = trials[gpu]
            seconds = trial["publication_s"]
            cost = seconds * rates[gpu] / 3600
            row.update({
                f"{gpu}_cold_input_to_cairo_proof_s": round(seconds, 6),
                f"{gpu}_cold_ingress_s": round(trial["ingress_s"], 6),
                f"{gpu}_cairo_proof_s": round(trial["proof_s"], 6),
                f"{gpu}_whole_device_peak_bytes": trial["device_peak_bytes"],
                f"{gpu}_arena_mode": trial["arena_mode"],
                f"{gpu}_process_rss_peak_bytes": trial["host_rss_peak_bytes"],
                f"{gpu}_policy_env": json.dumps(trial["policy_env"], sort_keys=True),
                f"{gpu}_usd_per_hour": rates[gpu],
                f"{gpu}_gpu_rental_usd_per_proof": round(cost, 8),
                f"{gpu}_to_h200_time_ratio": round(seconds / h200_seconds, 3),
                f"{gpu}_h200_break_even_time_ratio": round(rates["h200"] / rates[gpu], 3),
                f"{gpu}_to_h200_cost_ratio": round(cost / h200_cost, 3),
                f"{gpu}_beats_h200_rental_cost": cost <= h200_cost,
            })
        rows.append(row)
    if not rows:
        raise ValueError("no complete source-matched four-GPU cohort")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="") as output:
        writer = csv.DictWriter(output, fieldnames=list(rows[0]), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    print(f"{len(rows)} clean-source, identical-proof four-GPU PIEs")


if __name__ == "__main__":
    main()
