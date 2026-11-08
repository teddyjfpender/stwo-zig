#!/usr/bin/env python3
"""Full 11-family benchmark parity harness (Rust vs Zig)."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .catalog import UPSTREAM_FAMILIES, WORKLOADS

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
        measurement_command,
        measurement_environment,
        parse_process_resources,
    )
except ModuleNotFoundError:
    from scripts.process_resources_lib import (
        WALL_CLOCK_MEASUREMENT,
        measurement_command,
        measurement_environment,
        parse_process_resources,
    )


ROOT = Path(__file__).resolve().parents[2]
REPORT_DEFAULT = ROOT / "vectors" / "reports" / "benchmark_full_report.json"
ARTIFACT_DIR = ROOT / "vectors" / ".bench_full_artifacts"

RUST_MANIFEST = ROOT / "tools" / "stwo-interop-rs" / "Cargo.toml"
RUST_BIN = ROOT / "tools" / "stwo-interop-rs" / "target" / "release" / "stwo-interop-rs"
ZIG_BIN = installed_binary(ROOT)

RUST_TOOLCHAIN_DEFAULT = "nightly-2025-07-14"
SUPPORTED_BENCH_PROOF_CODECS = ("json", "binary")
FAMILY_RUNNER = ROOT / "src" / "bench" / "full_runner.zig"

def merged_env(extra_env: dict[str, str] | None) -> dict[str, str] | None:
    if not extra_env:
        return None
    env = dict(os.environ)
    env.update(extra_env)
    return env


def run(cmd: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        env=merged_env(env),
    )


def run_timed(
    cmd: list[str],
    env: dict[str, str] | None = None,
) -> tuple[subprocess.CompletedProcess[str], int | None]:
    measured_cmd, measurement = measurement_command(cmd)
    if measurement != WALL_CLOCK_MEASUREMENT:
        proc = subprocess.run(
            measured_cmd,
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
            env=measurement_environment(env),
        )
        resources = parse_process_resources(proc.stderr, measurement)
        peak_rss_kb = resources["peak_rss_kib"]
        return proc, peak_rss_kb
    proc = run(cmd, env=env)
    return proc, None


def ratio(a: float, b: float) -> float:
    return a / b if b != 0.0 else float("inf")


def parse_json_stdout(stdout: str) -> dict[str, Any]:
    for line in reversed(stdout.splitlines()):
        line = line.strip()
        if not line:
            continue
        return json.loads(line)
    raise RuntimeError("missing JSON payload in command stdout")


def ensure_binaries(rust_toolchain: str) -> None:
    rust_build = run(
        [
            "cargo",
            f"+{rust_toolchain}",
            "build",
            "--release",
            "--manifest-path",
            str(RUST_MANIFEST),
        ]
    )
    if rust_build.returncode != 0:
        raise RuntimeError(f"rust benchmark binary build failed:\n{rust_build.stderr}")

    zig_build = run(build_command("ReleaseFast"))
    if zig_build.returncode != 0:
        raise RuntimeError(f"zig benchmark binary build failed:\n{zig_build.stderr}")


def list_runner_families() -> tuple[str, ...]:
    proc = run(
        [
            "zig",
            "run",
            str(FAMILY_RUNNER),
            "--",
            "--mode",
            "list-families",
        ]
    )
    if proc.returncode != 0:
        raise RuntimeError(f"failed to read family list from runner:\n{proc.stderr}")
    payload = parse_json_stdout(proc.stdout)
    if not isinstance(payload, list) or not all(isinstance(item, str) for item in payload):
        raise RuntimeError("invalid family payload from full_runner")
    return tuple(payload)


def bench_runtime(
    *,
    runtime: str,
    family: str,
    workload: dict[str, Any],
    warmups: int,
    repeats: int,
    zig_bench_proof_codec: str,
    merkle_workers: int | None,
    merkle_pool_reuse: bool,
) -> dict[str, Any]:
    artifact = ARTIFACT_DIR / f"{runtime}_{family}.json"
    binary = str(RUST_BIN if runtime == "rust" else ZIG_BIN)
    cmd = [
        binary,
        "--mode",
        "bench",
        "--example",
        str(workload["example"]),
        "--artifact",
        str(artifact),
        "--prove-mode",
        str(workload["prove_mode"]),
        "--include-all-preprocessed-columns",
        str(workload["include_all_preprocessed_columns"]),
        "--bench-warmups",
        str(warmups),
        "--bench-repeats",
        str(repeats),
    ] + [str(arg) for arg in workload["args"]]
    if runtime == "zig":
        cmd.extend(["--bench-proof-codec", zig_bench_proof_codec])

    runtime_env: dict[str, str] | None = None
    if runtime == "zig":
        runtime_env = {}
        if merkle_workers is not None:
            runtime_env["STWO_ZIG_MERKLE_WORKERS"] = str(merkle_workers)
        if merkle_pool_reuse:
            runtime_env["STWO_ZIG_MERKLE_POOL_REUSE"] = "1"
        if not runtime_env:
            runtime_env = None

    proc, peak_rss_kb = run_timed(cmd, env=runtime_env)

    if proc.returncode != 0:
        raise RuntimeError(
            f"{runtime} bench failed for family '{family}'\n"
            f"command: {' '.join(cmd)}\n"
            f"stderr:\n{proc.stderr}"
        )
    payload = parse_json_stdout(proc.stdout)
    if not isinstance(payload, dict):
        raise RuntimeError(f"{runtime} bench payload for family '{family}' is not an object")
    payload["peak_rss_kb"] = peak_rss_kb
    return payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Full upstream-family benchmark parity harness")
    parser.add_argument("--rust-toolchain", default=RUST_TOOLCHAIN_DEFAULT)
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--max-zig-over-rust", type=float, default=10.0)
    parser.add_argument(
        "--zig-bench-proof-codec",
        default="json",
        choices=SUPPORTED_BENCH_PROOF_CODECS,
        help="Internal proof codec for Zig bench runs.",
    )
    parser.add_argument(
        "--merkle-workers",
        type=int,
        default=None,
        help="Optional STWO_ZIG_MERKLE_WORKERS override for Zig runtime runs.",
    )
    parser.add_argument(
        "--merkle-pool-reuse",
        action="store_true",
        help="Enable STWO_ZIG_MERKLE_POOL_REUSE=1 for Zig runtime runs.",
    )
    parser.add_argument(
        "--check-families",
        action="store_true",
        help="Validate family registry only (no benchmark execution).",
    )
    parser.add_argument(
        "--report-out",
        type=Path,
        default=REPORT_DEFAULT,
        help="Path for JSON report output",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.merkle_workers is not None and args.merkle_workers <= 0:
        raise ValueError("--merkle-workers must be positive when provided")

    runner_families = list_runner_families()
    if runner_families != UPSTREAM_FAMILIES:
        raise RuntimeError(
            "family registry mismatch between benchmark_full.py and src/bench/full_runner.zig\n"
            f"expected: {UPSTREAM_FAMILIES}\n"
            f"actual:   {runner_families}"
        )

    if args.check_families:
        print(json.dumps({"status": "ok", "families": list(UPSTREAM_FAMILIES)}, sort_keys=True))
        return 0

    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    ensure_binaries(args.rust_toolchain)

    families_report: list[dict[str, Any]] = []
    failures: list[str] = []

    for family in UPSTREAM_FAMILIES:
        workload = WORKLOADS[family]
        rust = bench_runtime(
            runtime="rust",
            family=family,
            workload=workload,
            warmups=args.warmups,
            repeats=args.repeats,
            zig_bench_proof_codec=args.zig_bench_proof_codec,
            merkle_workers=args.merkle_workers,
            merkle_pool_reuse=args.merkle_pool_reuse,
        )
        zig = bench_runtime(
            runtime="zig",
            family=family,
            workload=workload,
            warmups=args.warmups,
            repeats=args.repeats,
            zig_bench_proof_codec=args.zig_bench_proof_codec,
            merkle_workers=args.merkle_workers,
            merkle_pool_reuse=args.merkle_pool_reuse,
        )

        prove_ratio = ratio(
            float(zig["prove"]["avg_seconds"]),
            float(rust["prove"]["avg_seconds"]),
        )
        verify_ratio = ratio(
            float(zig["verify"]["avg_seconds"]),
            float(rust["verify"]["avg_seconds"]),
        )
        proof_size_ratio = ratio(
            float(zig["proof_metrics"]["proof_wire_bytes"]),
            float(rust["proof_metrics"]["proof_wire_bytes"]),
        )
        peak_rss_ratio = ratio(
            float(zig.get("peak_rss_kb") or 0.0),
            float(rust.get("peak_rss_kb") or 0.0),
        )

        if prove_ratio > args.max_zig_over_rust:
            failures.append(
                f"{family}: prove ratio {prove_ratio:.6f} exceeds {args.max_zig_over_rust:.2f}"
            )
        if verify_ratio > args.max_zig_over_rust:
            failures.append(
                f"{family}: verify ratio {verify_ratio:.6f} exceeds {args.max_zig_over_rust:.2f}"
            )
        if rust["proof_metrics"]["commitments_count"] != zig["proof_metrics"]["commitments_count"]:
            failures.append(f"{family}: commitments_count mismatch")
        if rust["proof_metrics"]["decommitments_count"] != zig["proof_metrics"]["decommitments_count"]:
            failures.append(f"{family}: decommitments_count mismatch")

        families_report.append(
            {
                "family": family,
                "mapped_workload": {
                    "example": workload["example"],
                    "args": workload["args"],
                    "prove_mode": workload["prove_mode"],
                    "include_all_preprocessed_columns": workload["include_all_preprocessed_columns"],
                },
                "rust": rust,
                "zig": zig,
                "ratios": {
                    "zig_over_rust_prove": round(prove_ratio, 6),
                    "zig_over_rust_verify": round(verify_ratio, 6),
                    "zig_over_rust_proof_wire_bytes": round(proof_size_ratio, 6),
                    "zig_over_rust_peak_rss_kb": round(peak_rss_ratio, 6),
                },
            }
        )

    prove_ratios = [entry["ratios"]["zig_over_rust_prove"] for entry in families_report]
    verify_ratios = [entry["ratios"]["zig_over_rust_verify"] for entry in families_report]
    rss_ratios = [entry["ratios"]["zig_over_rust_peak_rss_kb"] for entry in families_report]
    status = "ok" if not failures else "failed"

    report = {
        "status": status,
        "protocol": "upstream_family_matrix_v1",
        "product_scope": aggregate_diagnostic_scope("benchmark_full"),
        "upstream_families": list(UPSTREAM_FAMILIES),
        "settings": {
            "warmups": args.warmups,
            "repeats": args.repeats,
            "rust_toolchain": args.rust_toolchain,
            "max_zig_over_rust": args.max_zig_over_rust,
            "zig_bench_proof_codec": args.zig_bench_proof_codec,
            "merkle_workers": args.merkle_workers,
            "merkle_pool_reuse": args.merkle_pool_reuse,
        },
        "summary": {
            "families": len(families_report),
            "max_zig_over_rust_prove": max(prove_ratios) if prove_ratios else 0.0,
            "max_zig_over_rust_verify": max(verify_ratios) if verify_ratios else 0.0,
            "avg_zig_over_rust_prove": round(sum(prove_ratios) / len(prove_ratios), 6)
            if prove_ratios
            else 0.0,
            "avg_zig_over_rust_verify": round(sum(verify_ratios) / len(verify_ratios), 6)
            if verify_ratios
            else 0.0,
            "max_zig_over_rust_peak_rss_kb": max(rss_ratios) if rss_ratios else 0.0,
            "avg_zig_over_rust_peak_rss_kb": round(sum(rss_ratios) / len(rss_ratios), 6)
            if rss_ratios
            else 0.0,
            "failure_count": len(failures),
        },
        "families": families_report,
        "failures": failures,
    }

    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    latest = args.report_out.parent / "latest_benchmark_full_report.json"
    if latest != args.report_out:
        shutil.copyfile(args.report_out, latest)

    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
