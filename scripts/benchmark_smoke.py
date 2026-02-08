#!/usr/bin/env python3
"""Comparable Rust-vs-Zig benchmark protocol for interop example workloads.

This harness measures prove/verify latency on matched workloads for both runtimes
and records proof-size/decommit shape metrics from exchanged artifacts.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List
import re


ROOT = Path(__file__).resolve().parent.parent
REPORT_DEFAULT = ROOT / "vectors" / "reports" / "benchmark_smoke_report.json"

RUST_MANIFEST = ROOT / "tools" / "stwo-interop-rs" / "Cargo.toml"
RUST_BIN = ROOT / "tools" / "stwo-interop-rs" / "target" / "release" / "stwo-interop-rs"
ZIG_BIN = ROOT / "vectors" / ".bench.zig_interop"
ARTIFACT_DIR = ROOT / "vectors" / ".bench_artifacts"

RUST_TOOLCHAIN_DEFAULT = "nightly-2025-07-14"
TIME_BIN = Path("/usr/bin/time")
RSS_RE = re.compile(r"^\s*(\d+)\s+maximum resident set size\s*$", re.MULTILINE)

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
        "name": "state_machine_default",
        "example": "state_machine",
        "args": [
            "--sm-log-n-rows",
            "5",
            "--sm-initial-0",
            "1",
            "--sm-initial-1",
            "1",
        ],
    },
]

MEDIUM_WORKLOADS: List[Dict[str, Any]] = [
    {
        "name": "state_machine_medium",
        "example": "state_machine",
        "args": [
            "--sm-log-n-rows",
            "6",
            "--sm-initial-0",
            "3",
            "--sm-initial-1",
            "5",
        ],
    },
]

LARGE_WORKLOADS: List[Dict[str, Any]] = [
    {
        "name": "poseidon_large",
        "example": "poseidon",
        "args": [
            "--poseidon-log-n-instances",
            "10",
        ],
    },
    {
        "name": "blake_large",
        "example": "blake",
        "args": [
            "--blake-log-n-rows",
            "9",
            "--blake-n-rounds",
            "10",
        ],
    },
    {
        "name": "wide_fibonacci_fib100",
        "example": "wide_fibonacci",
        "args": [
            "--wf-log-n-rows",
            "9",
            "--wf-sequence-len",
            "100",
        ],
    },
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
        "name": "wide_fibonacci_fib1000",
        "example": "wide_fibonacci",
        "args": [
            "--wf-log-n-rows",
            "11",
            "--wf-sequence-len",
            "1000",
        ],
    },
    {
        "name": "plonk_large",
        "example": "plonk",
        "args": [
            "--plonk-log-n-rows",
            "12",
        ],
    },
]

SUPPORTED_ZIG_OPT_MODES = ("Debug", "ReleaseSafe", "ReleaseFast", "ReleaseSmall")


def run(cmd: List[str]) -> None:
    subprocess.run(cmd, cwd=ROOT, check=True)


def run_timed(cmd: List[str]) -> Dict[str, Any]:
    start = time.perf_counter()
    if TIME_BIN.exists():
        proc = subprocess.run(
            [str(TIME_BIN), "-l", *cmd],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=True,
        )
        match = RSS_RE.search(proc.stderr)
        peak_rss_kb = int(match.group(1)) if match else None
    else:
        subprocess.run(cmd, cwd=ROOT, check=True)
        peak_rss_kb = None
    elapsed = time.perf_counter() - start
    return {
        "seconds": elapsed,
        "peak_rss_kb": peak_rss_kb,
    }


def summarize_samples(name: str, cmd: List[str], warmups: int, repeats: int) -> Dict[str, Any]:
    if repeats <= 0:
        raise ValueError("--repeats must be positive")
    if warmups < 0:
        raise ValueError("--warmups must be non-negative")

    raw_runs: List[Dict[str, Any]] = []
    samples: List[float] = []
    rss_samples: List[int] = []

    for i in range(warmups + repeats):
        run_result = run_timed(cmd)
        raw_runs.append(
            {
                "kind": "warmup" if i < warmups else "sample",
                "seconds": round(run_result["seconds"], 6),
                "peak_rss_kb": run_result["peak_rss_kb"],
            }
        )
        if i >= warmups:
            samples.append(run_result["seconds"])
            if run_result["peak_rss_kb"] is not None:
                rss_samples.append(int(run_result["peak_rss_kb"]))

    avg_seconds = sum(samples) / len(samples)
    result: Dict[str, Any] = {
        "name": name,
        "command": cmd,
        "warmups": warmups,
        "repeats": repeats,
        "samples_seconds": [round(v, 6) for v in samples],
        "min_seconds": round(min(samples), 6),
        "max_seconds": round(max(samples), 6),
        "avg_seconds": round(avg_seconds, 6),
        "raw_runs": raw_runs,
    }
    if rss_samples:
        result["rss_samples_kb"] = rss_samples
        result["rss_avg_kb"] = round(sum(rss_samples) / len(rss_samples), 2)
        result["rss_peak_kb"] = max(rss_samples)
    return result


def proof_metrics(artifact_path: Path) -> Dict[str, Any]:
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    proof_hex = artifact["proof_bytes_hex"]
    proof_bytes = bytes.fromhex(proof_hex)
    proof = json.loads(proof_bytes.decode("utf-8"))

    trace_decommit_hashes = sum(
        len(decommitment["hash_witness"]) for decommitment in proof["decommitments"]
    )
    fri_first_hashes = len(proof["fri_proof"]["first_layer"]["decommitment"]["hash_witness"])
    fri_inner_hashes = sum(
        len(layer["decommitment"]["hash_witness"]) for layer in proof["fri_proof"]["inner_layers"]
    )

    return {
        "artifact_bytes": artifact_path.stat().st_size,
        "proof_wire_bytes": len(proof_bytes),
        "commitments_count": len(proof["commitments"]),
        "decommitments_count": len(proof["decommitments"]),
        "trace_decommit_hashes": trace_decommit_hashes,
        "fri_inner_layers_count": len(proof["fri_proof"]["inner_layers"]),
        "fri_first_layer_witness_len": len(proof["fri_proof"]["first_layer"]["fri_witness"]),
        "fri_last_layer_poly_len": len(proof["fri_proof"]["last_layer_poly"]),
        "fri_decommit_hashes_total": fri_first_hashes + fri_inner_hashes,
    }


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


def benchmark_runtime(
    *,
    runtime: str,
    workload: Dict[str, Any],
    warmups: int,
    repeats: int,
) -> Dict[str, Any]:
    prefix = runtime_cmd(runtime)
    artifact_path = ARTIFACT_DIR / f"{runtime}_{workload['name']}.json"

    generate_cmd = (
        prefix
        + [
            "--mode",
            "generate",
            "--example",
            workload["example"],
            "--artifact",
            str(artifact_path),
        ]
        + COMMON_CONFIG_ARGS
        + workload["args"]
    )
    verify_cmd = prefix + ["--mode", "verify", "--artifact", str(artifact_path)]

    prove_stats = summarize_samples(
        f"{runtime}_{workload['name']}_prove",
        generate_cmd,
        warmups,
        repeats,
    )
    metrics = proof_metrics(artifact_path)
    verify_stats = summarize_samples(
        f"{runtime}_{workload['name']}_verify",
        verify_cmd,
        warmups,
        repeats,
    )

    return {
        "runtime": runtime,
        "artifact": str(artifact_path.relative_to(ROOT)),
        "prove": prove_stats,
        "verify": verify_stats,
        "proof_metrics": metrics,
    }


def ratio(numerator: float, denominator: float) -> float:
    if denominator <= 0:
        return 0.0
    return numerator / denominator


def main() -> int:
    parser = argparse.ArgumentParser(description="Comparable Rust-vs-Zig benchmark protocol")
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--rust-toolchain", default=RUST_TOOLCHAIN_DEFAULT)
    parser.add_argument("--max-zig-over-rust", type=float, default=1.50)
    parser.add_argument(
        "--zig-opt-mode",
        default="ReleaseFast",
        choices=SUPPORTED_ZIG_OPT_MODES,
        help="Zig optimization level used for interop benchmark binary build.",
    )
    parser.add_argument(
        "--zig-cpu",
        default="baseline",
        help="Zig CPU target. Use 'baseline' to omit -mcpu, or 'native' for tuned local runs.",
    )
    parser.add_argument(
        "--report-label",
        default="benchmark_smoke",
        help="Logical label used in emitted report metadata.",
    )
    parser.add_argument(
        "--include-medium",
        action="store_true",
        help="Include medium-size workloads (stricter, may be slower).",
    )
    parser.add_argument(
        "--include-large",
        action="store_true",
        help="Include larger contrast workloads (wide_fibonacci fib(100/500/1000), plonk_large).",
    )
    parser.add_argument(
        "--report-out",
        type=Path,
        default=REPORT_DEFAULT,
        help="Path for JSON report output",
    )
    args = parser.parse_args()

    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)

    ensure_binaries(args.rust_toolchain, args.zig_opt_mode, args.zig_cpu)

    workloads = list(BASE_WORKLOADS)
    if args.include_medium:
        workloads.extend(MEDIUM_WORKLOADS)
    if args.include_large:
        workloads.extend(LARGE_WORKLOADS)

    workloads_report: List[Dict[str, Any]] = []
    failures: List[str] = []

    for workload in workloads:
        rust = benchmark_runtime(
            runtime="rust",
            workload=workload,
            warmups=args.warmups,
            repeats=args.repeats,
        )
        zig = benchmark_runtime(
            runtime="zig",
            workload=workload,
            warmups=args.warmups,
            repeats=args.repeats,
        )

        prove_ratio = ratio(zig["prove"]["avg_seconds"], rust["prove"]["avg_seconds"])
        verify_ratio = ratio(zig["verify"]["avg_seconds"], rust["verify"]["avg_seconds"])
        proof_size_ratio = ratio(
            float(zig["proof_metrics"]["proof_wire_bytes"]),
            float(rust["proof_metrics"]["proof_wire_bytes"]),
        )

        if prove_ratio > args.max_zig_over_rust:
            failures.append(
                f"{workload['name']} prove ratio {prove_ratio:.6f} exceeds {args.max_zig_over_rust:.2f}"
            )
        if verify_ratio > args.max_zig_over_rust:
            failures.append(
                f"{workload['name']} verify ratio {verify_ratio:.6f} exceeds {args.max_zig_over_rust:.2f}"
            )
        if rust["proof_metrics"]["commitments_count"] != zig["proof_metrics"]["commitments_count"]:
            failures.append(f"{workload['name']} commitments_count mismatch")
        if rust["proof_metrics"]["decommitments_count"] != zig["proof_metrics"]["decommitments_count"]:
            failures.append(f"{workload['name']} decommitments_count mismatch")

        workloads_report.append(
            {
                "name": workload["name"],
                "example": workload["example"],
                "params": workload["args"],
                "rust": rust,
                "zig": zig,
                "ratios": {
                    "zig_over_rust_prove": round(prove_ratio, 6),
                    "zig_over_rust_verify": round(verify_ratio, 6),
                    "zig_over_rust_proof_wire_bytes": round(proof_size_ratio, 6),
                },
            }
        )

    prove_ratios = [w["ratios"]["zig_over_rust_prove"] for w in workloads_report]
    verify_ratios = [w["ratios"]["zig_over_rust_verify"] for w in workloads_report]
    status = "ok" if not failures else "failed"

    workload_tier = "base_only"
    if args.include_medium:
        workload_tier = "base_plus_medium"
    if args.include_large:
        workload_tier = "base_plus_medium_plus_large" if args.include_medium else "base_plus_large"

    settings = {
        "warmups": args.warmups,
        "repeats": args.repeats,
        "rust_toolchain": args.rust_toolchain,
        "include_medium": args.include_medium,
        "workload_tier": workload_tier,
        "collector": "time -l" if TIME_BIN.exists() else "wall-clock-only",
        "zig_opt_mode": args.zig_opt_mode,
        "zig_cpu": args.zig_cpu,
        "report_label": args.report_label,
    }
    if args.include_large:
        settings["include_large"] = True
    thresholds = {
        "max_zig_over_rust_ratio": args.max_zig_over_rust,
        "conformance_reference": "CONFORMANCE.md Section 9.2",
    }

    settings_hash_payload: Dict[str, Any] = {
        "common_config_args": COMMON_CONFIG_ARGS,
        "base_workloads": BASE_WORKLOADS,
        "medium_workloads": MEDIUM_WORKLOADS,
        "settings": settings,
        "thresholds": thresholds,
    }
    if args.include_large:
        settings_hash_payload["large_workloads"] = LARGE_WORKLOADS

    settings_hash = canonical_hash(settings_hash_payload)

    report = {
        "schema_version": 2,
        "generated_at_unix": int(time.time()),
        "status": status,
        "protocol": "matched_workload_matrix_v1",
        "settings_hash": settings_hash,
        "workload_matrix_hash": canonical_hash(workload_matrix(workloads)),
        "thresholds": thresholds,
        "settings": settings,
        "summary": {
            "workloads": len(workloads_report),
            "max_zig_over_rust_prove": max(prove_ratios) if prove_ratios else 0.0,
            "max_zig_over_rust_verify": max(verify_ratios) if verify_ratios else 0.0,
            "avg_zig_over_rust_prove": round(sum(prove_ratios) / len(prove_ratios), 6)
            if prove_ratios
            else 0.0,
            "avg_zig_over_rust_verify": round(sum(verify_ratios) / len(verify_ratios), 6)
            if verify_ratios
            else 0.0,
            "failure_count": len(failures),
        },
        "workloads": workloads_report,
        "failures": failures,
    }

    out = args.report_out
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    latest = out.parent / "latest_benchmark_smoke_report.json"
    if latest != out:
        shutil.copyfile(out, latest)

    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
