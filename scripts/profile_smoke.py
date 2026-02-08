#!/usr/bin/env python3
"""Profiling harness with hotspot attribution for Rust/Zig proving workloads."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List


ROOT = Path(__file__).resolve().parent.parent
REPORT_DEFAULT = ROOT / "vectors" / "reports" / "profile_smoke_report.json"

RUST_MANIFEST = ROOT / "tools" / "stwo-interop-rs" / "Cargo.toml"
RUST_BIN = ROOT / "tools" / "stwo-interop-rs" / "target" / "release" / "stwo-interop-rs"
ZIG_BIN = ROOT / "vectors" / ".bench.zig_interop"
ARTIFACT_DIR = ROOT / "vectors" / ".profile_artifacts"
SAMPLE_DIR = ROOT / "vectors" / ".profile_samples"

RUST_TOOLCHAIN_DEFAULT = "nightly-2025-07-14"
TIME_BIN = Path("/usr/bin/time")
SAMPLE_BIN = Path("/usr/bin/sample")

RSS_RE = re.compile(r"^\s*(\d+)\s+maximum resident set size\s*$", re.MULTILINE)
INSTR_RE = re.compile(r"^\s*(\d+)\s+instructions retired\s*$", re.MULTILINE)
CYCLES_RE = re.compile(r"^\s*(\d+)\s+cycles elapsed\s*$", re.MULTILINE)
PEAK_FOOTPRINT_RE = re.compile(r"^\s*(\d+)\s+peak memory footprint\s*$", re.MULTILINE)
HOTSPOT_LINE_RE = re.compile(r"^\s*(.+?)\s+\(in [^)]+\)\s+(\d+)\s*$")

COMMON_CONFIG_ARGS = [
    "--pow-bits",
    "0",
    "--fri-log-blowup",
    "1",
    "--fri-log-last-layer",
    "0",
    "--fri-n-queries",
    "3",
]

BASE_WORKLOADS: List[Dict[str, Any]] = [
    {
        "name": "state_machine_deep",
        "example": "state_machine",
        "args": [
            "--sm-log-n-rows",
            "15",
            "--sm-initial-0",
            "9",
            "--sm-initial-1",
            "3",
        ],
    },
    {
        "name": "xor_deep",
        "example": "xor",
        "args": [
            "--xor-log-size",
            "15",
            "--xor-log-step",
            "3",
            "--xor-offset",
            "5",
        ],
    },
]

LARGE_WORKLOADS: List[Dict[str, Any]] = [
    {
        "name": "wide_fibonacci_fib500",
        "example": "wide_fibonacci",
        "args": [
            "--wf-log-n-rows",
            "10",
            "--wf-sequence-len",
            "500",
        ],
    },
    {
        "name": "plonk_deep",
        "example": "plonk",
        "args": [
            "--plonk-log-n-rows",
            "12",
        ],
    },
]

LONG_WORKLOADS: List[Dict[str, Any]] = [
    {
        "name": "poseidon_deep",
        "example": "poseidon",
        "args": [
            "--poseidon-log-n-instances",
            "12",
        ],
    },
    {
        "name": "blake_deep",
        "example": "blake",
        "args": [
            "--blake-log-n-rows",
            "11",
            "--blake-n-rounds",
            "16",
        ],
    },
    {
        "name": "wide_fibonacci_fib2000",
        "example": "wide_fibonacci",
        "args": [
            "--wf-log-n-rows",
            "12",
            "--wf-sequence-len",
            "2000",
        ],
    },
    {
        "name": "wide_fibonacci_fib5000",
        "example": "wide_fibonacci",
        "args": [
            "--wf-log-n-rows",
            "13",
            "--wf-sequence-len",
            "5000",
        ],
    },
]

SUPPORTED_ZIG_OPT_MODES = ("Debug", "ReleaseSafe", "ReleaseFast", "ReleaseSmall")


def run(cmd: List[str]) -> None:
    subprocess.run(cmd, cwd=ROOT, check=True)


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
    zig_cmd = [
        "zig",
        "build-exe",
        "src/interop_cli.zig",
        "-O",
        zig_opt_mode,
        "-femit-bin=" + str(ZIG_BIN),
    ]
    if zig_cpu != "baseline":
        zig_cmd.append("-mcpu=" + zig_cpu)
    run(zig_cmd)


def runtime_cmd(runtime: str) -> List[str]:
    if runtime == "rust":
        return [str(RUST_BIN)]
    if runtime == "zig":
        return [str(ZIG_BIN)]
    raise ValueError(f"unknown runtime {runtime}")


def parse_time_metrics(stderr: str) -> Dict[str, Any]:
    rss = RSS_RE.search(stderr)
    instructions = INSTR_RE.search(stderr)
    cycles = CYCLES_RE.search(stderr)
    peak_footprint = PEAK_FOOTPRINT_RE.search(stderr)
    return {
        "peak_rss_kb": int(rss.group(1)) if rss else None,
        "instructions_retired": int(instructions.group(1)) if instructions else None,
        "cycles_elapsed": int(cycles.group(1)) if cycles else None,
        "peak_memory_footprint_bytes": int(peak_footprint.group(1))
        if peak_footprint
        else None,
    }


def run_profiled_once(cmd: List[str]) -> Dict[str, Any]:
    start = time.perf_counter()
    if TIME_BIN.exists():
        proc = subprocess.run(
            [str(TIME_BIN), "-l", *cmd],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
        )
        metrics = parse_time_metrics(proc.stderr)
    else:
        subprocess.run(cmd, cwd=ROOT, check=True)
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
) -> Dict[str, Any]:
    if not SAMPLE_BIN.exists():
        return {"available": False, "sample_file": None, "hotspots": []}

    with subprocess.Popen(cmd, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as proc:
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
) -> Dict[str, Any]:
    cmd = (
        runtime_cmd(runtime)
        + [
            "--mode",
            "generate",
            "--example",
            workload["example"],
            "--artifact",
            str(ARTIFACT_DIR / f"{runtime}_{workload['name']}.json"),
        ]
        + COMMON_CONFIG_ARGS
        + workload["args"]
    )

    runs = [run_profiled_once(cmd) for _ in range(repeats)]
    sample_file = SAMPLE_DIR / f"{runtime}_{workload['name']}.sample.txt"
    hotspot_info = sample_hotspots(
        cmd=cmd,
        sample_file=sample_file,
        duration_seconds=sample_duration_seconds,
        top_n=hotspot_top_n,
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
        "report_label": args.report_label,
    }
    if args.include_large:
        settings["include_large"] = True
    if args.include_long:
        settings["include_long"] = True
    settings_hash = canonical_hash(
        {
            "collector": "time -l + sample" if SAMPLE_BIN.exists() else "time -l",
            "common_config_args": COMMON_CONFIG_ARGS,
            "workloads": workloads,
            "settings": settings,
        }
    )

    report = {
        "schema_version": 2,
        "generated_at_unix": int(time.time()),
        "status": status,
        "collector": "time -l + sample" if SAMPLE_BIN.exists() else "time -l",
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
