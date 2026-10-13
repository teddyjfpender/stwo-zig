#!/usr/bin/env python3
"""Run one proof command and persist its wall time and sampled device peak."""

import argparse
import csv
import json
import os
import subprocess
import time
from pathlib import Path


def device_mib():
    result = subprocess.run(
        ["nvidia-smi", "--query-gpu=memory.used,memory.free", "--format=csv,noheader,nounits"],
        capture_output=True,
        text=True,
        check=True,
    )
    return tuple(int(value.strip()) for value in result.stdout.splitlines()[0].split(","))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--receipt", required=True)
    parser.add_argument("--log", required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("missing command")
    used_before, free_before = device_mib()
    start = time.monotonic_ns()
    samples = []
    with open(args.log, "w", encoding="utf-8") as log:
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
        while process.poll() is None:
            try:
                used, free = device_mib()
                samples.append((time.monotonic_ns() - start, used, free))
            except (OSError, ValueError, subprocess.CalledProcessError):
                pass
            time.sleep(0.2)
        result = process.wait()
    end = time.monotonic_ns()
    receipt = {
        "label": args.label,
        "command": command,
        "exit_code": result,
        "wall_seconds": (end - start) / 1e9,
        "gpu_used_before_mib": used_before,
        "gpu_free_before_mib": free_before,
        "gpu_peak_used_mib": max((sample[1] for sample in samples), default=used_before),
        "gpu_min_free_mib": min((sample[2] for sample in samples), default=free_before),
        "gpu_samples": len(samples),
        "gpu_samples_csv": str(Path(args.receipt).with_suffix(".samples.csv")),
        "source_commit": os.environ.get("STWO_SOURCE_COMMIT", "unknown"),
    }
    with open(receipt["gpu_samples_csv"], "w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(("elapsed_ns", "gpu_used_mib", "gpu_free_mib"))
        writer.writerows(samples)
    Path(args.receipt).write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt))


if __name__ == "__main__":
    main()
