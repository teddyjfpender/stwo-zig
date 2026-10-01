#!/usr/bin/env python3
"""Summarize measured PIE proving latency and memory by OS steps and block span."""

import argparse
import csv
from collections import defaultdict
from pathlib import Path


STEP_EDGES = (0, 2, 4, 8, 12, 16, 20, 24, 28, 32, 36)
BLOCK_EDGES = (1, 2, 6, 11, 21, 41)
FIELDS = (
    "step_bin_million", "block_bin", "catalog_pies", "adapted_pies",
    "gpu_trials", "gpu_verified", "gpu_failed",
    "publication_p10_s", "publication_median_s", "publication_p90_s",
    "gpu_peak_p10_gb", "gpu_peak_median_gb", "gpu_peak_p90_gb",
    "proof_median_s", "source_ingress_median_s", "fixed_load_median_s",
    "rust_verify_median_s", "adaptation_median_s",
)


def bin_label(value: int, edges: tuple[int, ...]) -> str:
    for lower, upper in zip(edges, edges[1:]):
        if lower <= value < upper:
            return f"{lower}-{upper}"
    return f"{edges[-1]}+"


def percentile(values: list[float], fraction: float) -> str:
    if not values:
        return ""
    ordered = sorted(values)
    position = fraction * (len(ordered) - 1)
    low = int(position)
    high = min(low + 1, len(ordered) - 1)
    value = ordered[low] + (ordered[high] - ordered[low]) * (position - low)
    return f"{value:.3f}"


def numbers(rows: list[dict], field: str, divisor: float = 1.0) -> list[float]:
    return [float(row[field]) / divisor for row in rows if row.get(field)]


def summarize(source: Path, output: Path) -> None:
    groups = defaultdict(list)
    with source.open(newline="") as stream:
        for row in csv.DictReader(stream):
            key = (bin_label(int(row["os_steps"]) // 1_000_000, STEP_EDGES),
                   bin_label(int(row["n_blocks"]), BLOCK_EDGES))
            groups[key].append(row)
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", newline="") as stream:
        writer = csv.DictWriter(stream, fieldnames=FIELDS, lineterminator="\n")
        writer.writeheader()
        for key, rows in sorted(groups.items(), key=lambda item:
                                (int(item[0][0].split("-")[0].rstrip("+")),
                                 int(item[0][1].split("-")[0].rstrip("+")))):
            attempted = [row for row in rows if row["proof_status"]]
            verified = [row for row in attempted if row["proof_status"] == "verified"]
            latency = numbers(verified, "proof_publication_s")
            memory = numbers(verified, "proof_gpu_peak_used_bytes", 1e9)
            writer.writerow(dict(zip(FIELDS, (
                *key, len(rows), sum(row["adapt_status"] == "adapted" for row in rows),
                len(attempted), len(verified), len(attempted) - len(verified),
                percentile(latency, .1), percentile(latency, .5), percentile(latency, .9),
                percentile(memory, .1), percentile(memory, .5), percentile(memory, .9),
                percentile(numbers(verified, "proof_execute_finish_s"), .5),
                percentile(numbers(verified, "proof_ingress_source_s"), .5),
                percentile(numbers(verified, "proof_fixed_preprocessed_load_s"), .5),
                percentile(numbers(verified, "proof_rust_verify_s"), .5),
                percentile(numbers(verified, "adapt_wall_s"), .5),
            ))))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    summarize(args.input, args.out)


if __name__ == "__main__":
    main()
