#!/usr/bin/env python3
"""Targeted kernel benchmark harness for eval-at-point/folding/fft hotspots."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List


ROOT = Path(__file__).resolve().parent.parent
RUNNER = ROOT / "src" / "bench_kernels.zig"
ZIG_BIN = ROOT / "vectors" / ".bench_kernels"
REPORT_DEFAULT = ROOT / "vectors" / "reports" / "benchmark_kernels_report.json"
LATEST_REPORT = ROOT / "vectors" / "reports" / "latest_benchmark_kernels_report.json"

SUPPORTED_ZIG_OPT_MODES = ("Debug", "ReleaseSafe", "ReleaseFast", "ReleaseSmall")

WORKLOADS: List[Dict[str, Any]] = [
    {
        "name": "eval_at_point",
        "log_size": 11,
        "iterations": 20000,
    },
    {
        "name": "eval_at_point_by_folding",
        "log_size": 11,
        "iterations": 20000,
    },
    {
        "name": "fft",
        "log_size": 10,
        "iterations": 64,
    },
]


def run(cmd: List[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


def canonical_hash(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def parse_json_stdout_any(stdout: str) -> Any:
    for line in reversed(stdout.splitlines()):
        stripped = line.strip()
        if not stripped:
            continue
        return json.loads(stripped)
    raise RuntimeError("missing JSON payload in kernel benchmark output")


def ensure_binary(zig_opt_mode: str, zig_cpu: str) -> None:
    cmd = [
        "zig",
        "build-exe",
        str(RUNNER),
        "-O",
        zig_opt_mode,
        "-femit-bin=" + str(ZIG_BIN),
    ]
    if zig_cpu != "baseline":
        cmd.append("-mcpu=" + zig_cpu)
    proc = run(cmd)
    if proc.returncode != 0:
        raise RuntimeError(f"failed building kernel benchmark runner:\n{proc.stderr}")


def list_kernels() -> List[str]:
    proc = run([str(ZIG_BIN), "--mode", "list-kernels"])
    if proc.returncode != 0:
        raise RuntimeError(f"failed listing kernels:\n{proc.stderr}")
    payload = parse_json_stdout_any(proc.stdout)
    if not isinstance(payload, list):
        raise RuntimeError("kernel list payload is not an array")
    if not all(isinstance(item, str) for item in payload):
        raise RuntimeError("kernel list payload contains non-string items")
    return list(payload)


def bench_once(name: str, log_size: int, iterations: int) -> Dict[str, Any]:
    proc = run(
        [
            str(ZIG_BIN),
            "--mode",
            "bench",
            "--kernel",
            name,
            "--log-size",
            str(log_size),
            "--iterations",
            str(iterations),
        ]
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"kernel bench failed for '{name}'\n"
            f"stderr:\n{proc.stderr}"
        )
    payload = parse_json_stdout_any(proc.stdout)
    if not isinstance(payload, dict):
        raise RuntimeError(f"kernel payload for '{name}' is not an object")
    return payload


def summarize_runs(
    *,
    name: str,
    log_size: int,
    iterations: int,
    warmups: int,
    repeats: int,
) -> Dict[str, Any]:
    if repeats <= 0:
        raise ValueError("--repeats must be positive")
    if warmups < 0:
        raise ValueError("--warmups must be non-negative")

    checksums: List[List[int]] = []
    samples: List[float] = []

    for i in range(warmups + repeats):
        run_payload = bench_once(name, log_size, iterations)
        checksum = run_payload.get("checksum")
        if not isinstance(checksum, list) or len(checksum) != 4:
            raise RuntimeError(f"invalid checksum payload for kernel '{name}'")
        checksums.append([int(v) for v in checksum])
        if i >= warmups:
            samples.append(float(run_payload.get("seconds", 0.0)))

    first_checksum = checksums[0]
    if any(checksum != first_checksum for checksum in checksums[1:]):
        raise RuntimeError(f"non-deterministic checksum observed for kernel '{name}'")

    avg_seconds = sum(samples) / len(samples)
    return {
        "name": name,
        "log_size": log_size,
        "iterations": iterations,
        "warmups": warmups,
        "repeats": repeats,
        "checksum": first_checksum,
        "summary": {
            "avg_seconds": round(avg_seconds, 9),
            "min_seconds": round(min(samples), 9),
            "max_seconds": round(max(samples), 9),
            "samples_seconds": [round(v, 9) for v in samples],
        },
    }


def run_self_test() -> None:
    names = [workload["name"] for workload in WORKLOADS]
    if len(names) != len(set(names)):
        raise RuntimeError("kernel workload names must be unique")
    if "eval_at_point" not in names:
        raise RuntimeError("missing eval_at_point workload")
    if "eval_at_point_by_folding" not in names:
        raise RuntimeError("missing eval_at_point_by_folding workload")
    if "fft" not in names:
        raise RuntimeError("missing fft workload")

    digest_a = canonical_hash({"a": 1, "b": [2, 3]})
    digest_b = canonical_hash({"b": [2, 3], "a": 1})
    if digest_a != digest_b:
        raise RuntimeError("canonical hash must be stable under key order")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Targeted kernel benchmark harness")
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument(
        "--zig-opt-mode",
        default="ReleaseFast",
        choices=SUPPORTED_ZIG_OPT_MODES,
        help="Zig optimization level used for kernel benchmark binary build.",
    )
    parser.add_argument(
        "--zig-cpu",
        default="native",
        help="Zig CPU target. Use 'baseline' to omit -mcpu, or 'native' for tuned local runs.",
    )
    parser.add_argument(
        "--report-label",
        default="benchmark_kernels",
        help="Logical label used in emitted report metadata.",
    )
    parser.add_argument(
        "--report-out",
        type=Path,
        default=REPORT_DEFAULT,
        help="Path for JSON report output",
    )
    parser.add_argument(
        "--self-check",
        action="store_true",
        help="Run internal harness self-checks only.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.self_check:
        run_self_test()
        print(json.dumps({"status": "ok", "self_check": True}, sort_keys=True))
        return 0

    ensure_binary(args.zig_opt_mode, args.zig_cpu)

    listed_kernels = list_kernels()
    expected_kernels = [workload["name"] for workload in WORKLOADS]
    if listed_kernels != expected_kernels:
        raise RuntimeError(
            "kernel registry mismatch between benchmark_kernels.py and src/bench/kernels.zig\n"
            f"expected: {expected_kernels}\n"
            f"actual:   {listed_kernels}"
        )

    kernels_report: List[Dict[str, Any]] = []
    failures: List[str] = []

    for workload in WORKLOADS:
        try:
            kernels_report.append(
                summarize_runs(
                    name=workload["name"],
                    log_size=int(workload["log_size"]),
                    iterations=int(workload["iterations"]),
                    warmups=args.warmups,
                    repeats=args.repeats,
                )
            )
        except Exception as exc:  # noqa: BLE001
            failures.append(f"{workload['name']}: {exc}")

    avg_seconds = [kernel["summary"]["avg_seconds"] for kernel in kernels_report]
    settings = {
        "warmups": args.warmups,
        "repeats": args.repeats,
        "zig_opt_mode": args.zig_opt_mode,
        "zig_cpu": args.zig_cpu,
        "report_label": args.report_label,
    }
    status = "ok" if not failures else "failed"

    report = {
        "schema_version": 1,
        "generated_at_unix": int(time.time()),
        "status": status,
        "protocol": "kernel_matrix_v1",
        "settings": settings,
        "settings_hash": canonical_hash({"settings": settings, "workloads": WORKLOADS}),
        "workload_matrix_hash": canonical_hash(WORKLOADS),
        "summary": {
            "kernels": len(kernels_report),
            "avg_seconds": round(sum(avg_seconds) / len(avg_seconds), 9) if avg_seconds else 0.0,
            "min_seconds": min(avg_seconds) if avg_seconds else 0.0,
            "max_seconds": max(avg_seconds) if avg_seconds else 0.0,
            "failure_count": len(failures),
        },
        "kernels": kernels_report,
        "failures": failures,
    }

    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.report_out != LATEST_REPORT:
        shutil.copyfile(args.report_out, LATEST_REPORT)

    print(json.dumps({"status": status, "failures": failures}, sort_keys=True))
    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
