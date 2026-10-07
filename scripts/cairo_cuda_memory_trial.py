#!/usr/bin/env python3
"""Run one CUDA proof command and sample whole-device and process memory."""

import argparse
import csv
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time


POLICY_ENV = (
    "STWO_CAIRO_CUDA_PREPROCESSED_VARIANT",
    "STWO_CUDA_MANAGED_ARENA",
    "STWO_CUDA_COMPACT_DEVICE_PROFILE",
    "STWO_CUDA_MANAGED_PLACEMENT",
    "STWO_CUDA_CAPACITY_HBM_SLOT",
    "STWO_CUDA_CAPACITY_KEEP_LOOKUP",
    "STWO_CUDA_SELECTIVE_HOST_PERCENT",
    "STWO_CUDA_SELECTIVE_MAIN_HOST_PERCENT",
    "STWO_CUDA_SELECTIVE_HOST_TAIL",
    "STWO_CUDA_HOST_MAIN_COEFF_PERCENT",
    "STWO_CUDA_HOST_PREPROCESSED_HASHES",
    "STWO_CUDA_HOST_PREPROCESSED_HASH_PERCENT",
    "STWO_CUDA_HOST_TRACE_HASHES",
)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def source_receipt() -> dict[str, str | None]:
    def git(*args: str) -> bytes | None:
        result = subprocess.run(("git", *args), capture_output=True, check=False)
        return result.stdout if result.returncode == 0 else None

    head = git("rev-parse", "HEAD")
    diff = git("diff", "--binary", "HEAD")
    return {
        "git_head": head.decode().strip() if head is not None else None,
        "git_diff_sha256": hashlib.sha256(diff).hexdigest() if diff is not None else None,
    }


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
    executable = Path(command[0])
    binary_sha256 = sha256_file(executable) if executable.is_file() else None
    source = source_receipt()
    policy = {name: os.environ[name] for name in POLICY_ENV if name in os.environ}
    started_ns = time.monotonic_ns()
    with (args.out / "process.log").open("wb") as log, \
            (args.out / "memory.csv").open("w", newline="") as memory_file:
        writer = csv.writer(memory_file, lineterminator="\n")
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
        "binary_sha256": binary_sha256,
        "source": source,
        "policy_env": policy,
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
