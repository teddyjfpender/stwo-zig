#!/usr/bin/env python3
"""Run one CUDA proof command and sample whole-device and process memory."""

import argparse
import csv
import json
from pathlib import Path
import subprocess
import time


def resident_bytes(pid: int) -> int | None:
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    except FileNotFoundError:
        pass
    return None


def gpu_used_bytes() -> int | None:
    try:
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=memory.used", "--format=csv,noheader,nounits"],
            capture_output=True, text=True, check=False,
        )
    except FileNotFoundError:
        return None
    if result.returncode != 0:
        return None
    values = result.stdout.strip().splitlines()
    if len(values) != 1:
        return None
    return int(values[0].strip()) * 1024 * 1024


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--interval-ms", type=int, default=250)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.interval_ms < 100 or not args.command or args.command[0] != "--":
        parser.error("use --interval-ms >= 100 and pass the proof command after --")
    command = args.command[1:]
    if not command:
        parser.error("missing proof command")
    args.out.mkdir(parents=True, exist_ok=True)
    started_ns = time.monotonic_ns()
    with (args.out / "process.log").open("wb") as log, \
            (args.out / "memory.csv").open("w", newline="") as memory_file:
        writer = csv.writer(memory_file)
        writer.writerow(("elapsed_ns", "gpu_used_bytes", "process_rss_bytes"))
        process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT)
        gpu_peak = 0
        rss_peak = 0
        samples = 0
        while True:
            gpu = gpu_used_bytes()
            rss = resident_bytes(process.pid)
            writer.writerow((time.monotonic_ns() - started_ns, gpu, rss))
            if gpu is not None:
                gpu_peak = max(gpu_peak, gpu)
            if rss is not None:
                rss_peak = max(rss_peak, rss)
            samples += 1
            if process.poll() is not None:
                break
            time.sleep(args.interval_ms / 1000)
        exit_code = process.returncode
    summary = {
        "schema": "stwo.cairo-cuda-memory-trial.v1",
        "command": command,
        "exit_code": exit_code,
        "elapsed_ns": time.monotonic_ns() - started_ns,
        "samples": samples,
        "whole_device_peak_bytes": gpu_peak,
        "process_rss_peak_bytes": rss_peak,
    }
    (args.out / "summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary))
    raise SystemExit(exit_code)


if __name__ == "__main__":
    main()
