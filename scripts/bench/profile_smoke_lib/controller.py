#!/usr/bin/env python3
"""Profiling harness with hotspot attribution for Rust/Zig proving workloads."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from .catalog import (
    BASE_WORKLOADS,
    COMMON_CONFIG_ARGS,
    LARGE_WORKLOADS,
    LONG_WORKLOADS,
    SUPPORTED_BLAKE2_BACKENDS,
    SUPPORTED_ZIG_OPT_MODES,
)

try:
    from scripts.benchmark_product_contract_lib import aggregate_diagnostic_scope
except ModuleNotFoundError:
    from benchmark_product_contract_lib import aggregate_diagnostic_scope

try:
    from interop_cli_lib.command import build_command, installed_binary
except ModuleNotFoundError:
    from scripts.interop_cli_lib.command import build_command, installed_binary

try:
    from process_resources_lib import (
        WALL_CLOCK_MEASUREMENT,
        collector_label,
        measurement_command,
        measurement_environment,
        measurement_for_platform,
        parse_process_resources,
    )
except ModuleNotFoundError:
    from scripts.process_resources_lib import (
        WALL_CLOCK_MEASUREMENT,
        collector_label,
        measurement_command,
        measurement_environment,
        measurement_for_platform,
        parse_process_resources,
    )


ROOT = Path(__file__).resolve().parents[2]
REPORT_DEFAULT = ROOT / "vectors" / "reports" / "profile_smoke_report.json"

RUST_MANIFEST = ROOT / "tools" / "stwo-interop-rs" / "Cargo.toml"
RUST_BIN = ROOT / "tools" / "stwo-interop-rs" / "target" / "release" / "stwo-interop-rs"
ZIG_BIN = installed_binary(ROOT)
ARTIFACT_DIR = ROOT / "vectors" / ".profile_artifacts"
SAMPLE_DIR = ROOT / "vectors" / ".profile_samples"

RUST_TOOLCHAIN_DEFAULT = "nightly-2025-07-14"
SAMPLE_BIN = Path("/usr/bin/sample")

HOTSPOT_LINE_RE = re.compile(r"^\s*(.+?)\s+\(in [^)]+\)\s+(\d+)\s*$")

def merged_env(extra_env: Optional[Dict[str, str]]) -> Optional[Dict[str, str]]:
    if not extra_env:
        return None
    env = dict(os.environ)
    env.update(extra_env)
    return env


def parse_workload_set(raw: str) -> Set[str]:
    return {item.strip() for item in raw.split(",") if item.strip()}


def run(cmd: List[str], env: Optional[Dict[str, str]] = None) -> None:
    subprocess.run(cmd, cwd=ROOT, check=True, env=merged_env(env))


def canonical_hash(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def workload_matrix(workloads: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [
        {
            "name": workload["name"],
            "example": workload["example"],
            "args": workload["args"],
        }
        for workload in workloads
    ]


def ensure_binaries(rust_toolchain: str, zig_opt_mode: str, zig_cpu: str) -> None:
    run(
        [
            "cargo",
            f"+{rust_toolchain}",
            "build",
            "--release",
            "--manifest-path",
            str(RUST_MANIFEST),
        ]
    )
    run(build_command(zig_opt_mode, zig_cpu))


def runtime_cmd(runtime: str) -> List[str]:
    if runtime == "rust":
        return [str(RUST_BIN)]
    if runtime == "zig":
        return [str(ZIG_BIN)]
    raise ValueError(f"unknown runtime {runtime}")


def run_profiled_once(cmd: List[str], env: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
    start = time.perf_counter()
    measured_cmd, measurement = measurement_command(cmd)
    if measurement != WALL_CLOCK_MEASUREMENT:
        proc = subprocess.run(
            measured_cmd,
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
            env=measurement_environment(env),
        )
        resources = parse_process_resources(proc.stderr, measurement)
        metrics = {
            "peak_rss_kb": resources["peak_rss_kib"],
            "instructions_retired": resources["instructions_retired"],
            "cycles_elapsed": resources["cycles_elapsed"],
            "peak_memory_footprint_bytes": resources["peak_memory_footprint_bytes"],
        }
    else:
        subprocess.run(cmd, cwd=ROOT, check=True, env=merged_env(env))
        proc = None
        metrics = {
            "peak_rss_kb": None,
            "instructions_retired": None,
            "cycles_elapsed": None,
            "peak_memory_footprint_bytes": None,
        }
    elapsed = time.perf_counter() - start
    return {
        "seconds": round(elapsed, 6),
        **metrics,
        "stderr_tail": proc.stderr.splitlines()[-8:] if proc else [],
    }


def run_profiled_samples(
    cmd: List[str],
    repeats: int,
    artifact_path: Path,
    env: Optional[Dict[str, str]] = None,
) -> List[Dict[str, Any]]:
    runs: List[Dict[str, Any]] = []
    for _ in range(repeats):
        artifact_path.unlink(missing_ok=True)
        runs.append(run_profiled_once(cmd, env))
    return runs


def parse_hotspots(sample_text: str, top_n: int) -> List[Dict[str, Any]]:
    marker = "Sort by top of stack, same collapsed"
    start = sample_text.find(marker)
    if start < 0:
        return []

    lines = sample_text[start:].splitlines()[1:]
    hotspots: List[Dict[str, Any]] = []
    for line in lines:
        if not line.strip():
            continue
        if line.startswith("Binary Images:"):
            break
        match = HOTSPOT_LINE_RE.match(line)
        if not match:
            continue
        symbol = match.group(1).strip()
        samples = int(match.group(2))
        hotspots.append({"symbol": symbol, "samples": samples})
        if len(hotspots) >= top_n:
            break
    return hotspots


def sample_hotspots(
    *,
    cmd: List[str],
    sample_file: Path,
    duration_seconds: int,
    top_n: int,
    env: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    if not SAMPLE_BIN.exists():
        return {"available": False, "sample_file": None, "hotspots": []}

    with subprocess.Popen(
        cmd,
        cwd=ROOT,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=merged_env(env),
    ) as proc:
        sample_cmd = [
            str(SAMPLE_BIN),
            str(proc.pid),
            str(duration_seconds),
            "-mayDie",
            "-file",
            str(sample_file),
        ]
        sample_proc = subprocess.run(
            sample_cmd,
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        proc.wait()
        if sample_proc.returncode != 0:
            return {
                "available": True,
                "sample_file": str(sample_file.relative_to(ROOT)),
                "hotspots": [],
                "sample_error": sample_proc.stderr.splitlines()[-8:],
            }

    sample_text = sample_file.read_text(encoding="utf-8")
    return {
        "available": True,
        "sample_file": str(sample_file.relative_to(ROOT)),
        "hotspots": parse_hotspots(sample_text, top_n=top_n),
    }


def hotspot_hints(hotspots: List[Dict[str, Any]]) -> List[str]:
    hints: List[str] = []

    def add_hint(msg: str) -> None:
        if msg not in hints:
            hints.append(msg)

    for hotspot in hotspots:
        symbol = hotspot["symbol"].lower()
        if "frianswers" in symbol or "compute_fri_quotients" in symbol or "quotient" in symbol:
            add_hint("Prioritize quotient/FRI loop optimization and allocation reuse in PCS decommit paths.")
        if "blake2" in symbol or "merkle" in symbol or "hash" in symbol:
            add_hint("Investigate hashing/Merkle batching and vectorized digest paths.")
        if "mmap" in symbol or "munmap" in symbol or "alloc" in symbol or "free_" in symbol:
            add_hint("Reduce allocator churn by reusing large buffers across prove stages.")
        if "circlepoint" in symbol or "::mul" in symbol:
            add_hint("Target field/circle multiplication hot loops for SIMD-friendly batching.")
    return hints[:4]


def avg(values: List[float]) -> float:
    return (sum(values) / len(values)) if values else 0.0


def profile_runtime_workload(
    *,
    runtime: str,
    workload: Dict[str, Any],
    repeats: int,
    sample_duration_seconds: int,
    hotspot_top_n: int,
    zig_blake2_backend: str,
    merkle_workers: Optional[int],
    merkle_pool_reuse: bool,
    merkle_pool_reuse_workloads: Set[str],
) -> Dict[str, Any]:
    artifact_path = ARTIFACT_DIR / f"{runtime}_{workload['name']}.json"
    backend_args = (
        ["--blake2-backend", zig_blake2_backend]
        if runtime == "zig"
        else []
    )
    runtime_env: Optional[Dict[str, str]] = None
    if runtime == "zig":
        runtime_env = {}
        if merkle_workers is not None:
            runtime_env["STWO_ZIG_MERKLE_WORKERS"] = str(merkle_workers)
        enable_pool_reuse = merkle_pool_reuse or workload["name"] in merkle_pool_reuse_workloads
        if enable_pool_reuse:
            runtime_env["STWO_ZIG_MERKLE_POOL_REUSE"] = "1"
        if not runtime_env:
            runtime_env = None
    cmd = (
        runtime_cmd(runtime)
        + [
            "--mode",
            "generate",
            "--example",
            workload["example"],
            "--artifact",
            str(artifact_path),
        ]
        + backend_args
        + COMMON_CONFIG_ARGS
        + workload["args"]
    )

    runs = run_profiled_samples(cmd, repeats, artifact_path, runtime_env)
    sample_file = SAMPLE_DIR / f"{runtime}_{workload['name']}.sample.txt"
    artifact_path.unlink(missing_ok=True)
    hotspot_info = sample_hotspots(
        cmd=cmd,
        sample_file=sample_file,
        duration_seconds=sample_duration_seconds,
        top_n=hotspot_top_n,
        env=runtime_env,
    )

    seconds = [float(run["seconds"]) for run in runs]
    peak_rss_values = [int(run["peak_rss_kb"]) for run in runs if run["peak_rss_kb"] is not None]
    instructions = [
        int(run["instructions_retired"])
        for run in runs
        if run["instructions_retired"] is not None
    ]
    cycles = [int(run["cycles_elapsed"]) for run in runs if run["cycles_elapsed"] is not None]

    hotspots = hotspot_info.get("hotspots", [])
    return {
        "runtime": runtime,
        "workload": workload["name"],
        "example": workload["example"],
        "command": cmd,
        "repeats": repeats,
        "runs": runs,
        "summary": {
            "avg_seconds": round(avg(seconds), 6),
            "max_seconds": round(max(seconds), 6) if seconds else 0.0,
            "min_seconds": round(min(seconds), 6) if seconds else 0.0,
            "avg_peak_rss_kb": round(avg([float(v) for v in peak_rss_values]), 2)
            if peak_rss_values
            else None,
            "max_peak_rss_kb": max(peak_rss_values) if peak_rss_values else None,
            "avg_instructions_retired": round(avg([float(v) for v in instructions]), 2)
            if instructions
            else None,
            "avg_cycles_elapsed": round(avg([float(v) for v in cycles]), 2)
            if cycles
            else None,
        },
        "hotspots": hotspots,
        "hotspot_hints": hotspot_hints(hotspots),
        "sample": hotspot_info,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Profiling harness with hotspot attribution")
    parser.add_argument("--rust-toolchain", default=RUST_TOOLCHAIN_DEFAULT)
    parser.add_argument("--repeats", type=int, default=2)
    parser.add_argument("--sample-duration-seconds", type=int, default=1)
    parser.add_argument("--hotspot-top-n", type=int, default=8)
    parser.add_argument(
        "--include-large",
        action="store_true",
        help="Include larger contrast workloads (wide_fibonacci fib500, plonk_deep).",
    )
    parser.add_argument(
        "--include-long",
        action="store_true",
        help="Include long-running contrast workloads (deeper poseidon/blake and fib2000/fib5000).",
    )
    parser.add_argument(
        "--zig-opt-mode",
        default="ReleaseFast",
        choices=SUPPORTED_ZIG_OPT_MODES,
        help="Zig optimization level used for interop profile binary build.",
    )
    parser.add_argument(
        "--zig-cpu",
        default="baseline",
        help="Zig CPU target. Use 'baseline' to omit -mcpu, or 'native' for tuned local runs.",
    )
    parser.add_argument(
        "--blake2-backend",
        default="auto",
        choices=SUPPORTED_BLAKE2_BACKENDS,
        help="Blake2 backend selector for Zig runtime profile runs.",
    )
    parser.add_argument(
        "--merkle-workers",
        type=int,
        default=None,
        help="Optional STWO_ZIG_MERKLE_WORKERS override for Zig runtime profile runs.",
    )
    parser.add_argument(
        "--merkle-pool-reuse",
        action="store_true",
        help="Enable STWO_ZIG_MERKLE_POOL_REUSE=1 for Zig runtime profile runs.",
    )
    parser.add_argument(
        "--merkle-pool-reuse-workloads",
        default="",
        help="Comma-separated workload names where STWO_ZIG_MERKLE_POOL_REUSE=1 is enabled for Zig runs.",
    )
    parser.add_argument(
        "--report-label",
        default="profile_smoke",
        help="Logical label used in emitted report metadata.",
    )
    parser.add_argument(
        "--report-out",
        type=Path,
        default=REPORT_DEFAULT,
        help="Path for JSON report output",
    )
    args = parser.parse_args()

    if args.repeats <= 0:
        raise ValueError("--repeats must be positive")
    if args.sample_duration_seconds <= 0:
        raise ValueError("--sample-duration-seconds must be positive")
    if args.merkle_workers is not None and args.merkle_workers <= 0:
        raise ValueError("--merkle-workers must be positive when provided")
    merkle_pool_reuse_workloads = parse_workload_set(args.merkle_pool_reuse_workloads)

    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    SAMPLE_DIR.mkdir(parents=True, exist_ok=True)

    ensure_binaries(args.rust_toolchain, args.zig_opt_mode, args.zig_cpu)

    workloads = list(BASE_WORKLOADS)
    if args.include_large:
        workloads.extend(LARGE_WORKLOADS)
    if args.include_long:
        workloads.extend(LONG_WORKLOADS)

    profiles: List[Dict[str, Any]] = []
    failures: List[str] = []

    for workload in workloads:
        for runtime in ("rust", "zig"):
            entry = profile_runtime_workload(
                runtime=runtime,
                workload=workload,
                repeats=args.repeats,
                sample_duration_seconds=args.sample_duration_seconds,
                hotspot_top_n=args.hotspot_top_n,
                zig_blake2_backend=args.blake2_backend,
                merkle_workers=args.merkle_workers,
                merkle_pool_reuse=args.merkle_pool_reuse,
                merkle_pool_reuse_workloads=merkle_pool_reuse_workloads,
            )
            profiles.append(entry)
            if SAMPLE_BIN.exists() and not entry["hotspots"]:
                avg_seconds = float(entry["summary"]["avg_seconds"])
                if avg_seconds >= (0.8 * float(args.sample_duration_seconds)):
                    failures.append(f"{runtime}/{workload['name']} produced no hotspot attribution")

    by_runtime: Dict[str, List[float]] = {"rust": [], "zig": []}
    for entry in profiles:
        by_runtime[entry["runtime"]].append(entry["summary"]["avg_seconds"])

    status = "ok" if not failures else "failed"
    settings = {
        "repeats": args.repeats,
        "sample_duration_seconds": args.sample_duration_seconds,
        "hotspot_top_n": args.hotspot_top_n,
        "rust_toolchain": args.rust_toolchain,
        "zig_opt_mode": args.zig_opt_mode,
        "zig_cpu": args.zig_cpu,
        "blake2_backend": args.blake2_backend,
        "report_label": args.report_label,
    }
    if args.merkle_workers is not None:
        settings["merkle_workers"] = args.merkle_workers
    if args.merkle_pool_reuse:
        settings["merkle_pool_reuse"] = True
    if merkle_pool_reuse_workloads:
        settings["merkle_pool_reuse_workloads"] = sorted(merkle_pool_reuse_workloads)
    if args.include_large:
        settings["include_large"] = True
    if args.include_long:
        settings["include_long"] = True
    settings_hash = canonical_hash(
        {
            "collector": collector_label(
                measurement_for_platform(),
                sample=SAMPLE_BIN.exists(),
            ),
            "common_config_args": COMMON_CONFIG_ARGS,
            "workloads": workloads,
            "settings": settings,
        }
    )

    report = {
        "schema_version": 2,
        "generated_at_unix": int(time.time()),
        "status": status,
        "product_scope": aggregate_diagnostic_scope("profile_smoke"),
        "collector": collector_label(
            measurement_for_platform(),
            sample=SAMPLE_BIN.exists(),
        ),
        "settings_hash": settings_hash,
        "workload_matrix_hash": canonical_hash(workload_matrix(workloads)),
        "settings": settings,
        "summary": {
            "profiles": len(profiles),
            "avg_seconds_rust": round(avg(by_runtime["rust"]), 6) if by_runtime["rust"] else 0.0,
            "avg_seconds_zig": round(avg(by_runtime["zig"]), 6) if by_runtime["zig"] else 0.0,
            "failure_count": len(failures),
        },
        "profiles": profiles,
        "failures": failures,
    }

    out = args.report_out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    latest = out.parent / "latest_profile_smoke_report.json"
    if latest != out:
        shutil.copyfile(out, latest)

    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
