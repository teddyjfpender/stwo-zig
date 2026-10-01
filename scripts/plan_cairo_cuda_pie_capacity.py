#!/usr/bin/env python3
"""Gate adapted Cairo PIEs using the exact CUDA resident plan."""

import argparse
import csv
import os
from pathlib import Path
import re
import subprocess


RESIDENT = re.compile(
    r"^resident pie=(\S+) logical_bytes=(\d+) peak_live_bytes=(\d+) "
    r"allocated_bytes=(\d+) request_arena_bytes=(\d+) "
    r"coefficient_cells=(\d+) evaluation_cells=(\d+)$",
    re.MULTILINE,
)
FIELDS = ("pie", "input", "variant", "status", "allocated_bytes", "request_arena_bytes", "peak_live_bytes",
          "logical_bytes", "coefficient_cells", "evaluation_cells",
          "device_bytes", "reserve_bytes", "admission_limit_bytes", "error")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--geometry-tool", type=Path, required=True)
    parser.add_argument("--device-bytes", type=int, required=True)
    parser.add_argument("--reserve-bytes", type=int, default=6_000_000_000)
    parser.add_argument("--variant", choices=("canonical", "canonical_small",
                                                "canonical_without_pedersen"),
                        default="canonical")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("inputs", nargs="+", type=Path)
    args = parser.parse_args()
    if args.device_bytes <= 0 or not 0 <= args.reserve_bytes < args.device_bytes:
        parser.error("reserve must be nonnegative and below device capacity")
    limit = args.device_bytes - args.reserve_bytes
    rows = []
    for source in args.inputs:
        environment = dict(os.environ, STWO_CAIRO_CUDA_PREPROCESSED_VARIANT=args.variant)
        result = subprocess.run([str(args.geometry_tool.resolve()), str(source.resolve())],
                                capture_output=True, text=True, env=environment)
        matches = RESIDENT.findall(result.stderr)
        row = dict(pie=source.stem, input=str(source), variant=args.variant,
                   device_bytes=args.device_bytes, reserve_bytes=args.reserve_bytes,
                   admission_limit_bytes=limit, error="")
        if result.returncode or len(matches) != 1 or matches[0][0] != source.stem:
            row.update(status="geometry_failed", error=result.stderr[-500:])
        else:
            _, logical, peak, allocated, request_arena, coefficients, evaluations = matches[0]
            row.update(status="admit_candidate" if int(allocated) <= limit
                       else "oversized", logical_bytes=logical,
                       peak_live_bytes=peak, allocated_bytes=allocated,
                       request_arena_bytes=request_arena,
                       coefficient_cells=coefficients, evaluation_cells=evaluations)
        rows.append(row)
        print(f"{row['pie']}: {row['status']} plan={row.get('allocated_bytes', '')}",
              flush=True)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", newline="") as sink:
        writer = csv.DictWriter(sink, fieldnames=FIELDS, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    if any(row["status"] == "geometry_failed" for row in rows):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
