#!/usr/bin/env python3
"""Capture and compare optimization baseline/evidence for stwo-zig."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, Tuple


ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = ROOT / "vectors" / "reports"

BASELINE_DEFAULT = REPORTS_DIR / "optimization_baseline.json"
COMPARE_REPORT_DEFAULT = REPORTS_DIR / "optimization_compare_report.json"
LATEST_COMPARE_REPORT = REPORTS_DIR / "latest_optimization_compare_report.json"

BENCHMARK_REPORT_DEFAULT = REPORTS_DIR / "benchmark_smoke_report.json"
PROFILE_REPORT_DEFAULT = REPORTS_DIR / "profile_smoke_report.json"


class CompareError(RuntimeError):
    pass


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def run_capture(cmd: list[str]) -> str:
    proc = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, check=False)
    return proc.stdout.strip() if proc.returncode == 0 else ""


def load_json(path: Path, *, name: str) -> Dict[str, Any]:
    if not path.exists():
        raise CompareError(f"missing required {name}: {rel(path)}")
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise CompareError(f"invalid {name} payload at {rel(path)}")
    return payload


def canonical_hash(payload: Any) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def benchmark_workload_matrix_hash(report: Dict[str, Any]) -> str:
    existing = report.get("workload_matrix_hash")
    if isinstance(existing, str) and existing:
        return existing

    workloads = report.get("workloads", [])
    matrix = [
        {
            "name": str(workload.get("name", "unknown")),
            "example": str(workload.get("example", "unknown")),
            "params": workload.get("params", []),
        }
        for workload in workloads
    ]
    return canonical_hash(matrix)


def profile_workload_matrix_hash(report: Dict[str, Any]) -> str:
    existing = report.get("workload_matrix_hash")
    if isinstance(existing, str) and existing:
        return existing

    profiles = report.get("profiles", [])
    matrix = [
        {
            "runtime": str(profile.get("runtime", "unknown")),
            "workload": str(profile.get("workload", "unknown")),
            "example": str(profile.get("example", "unknown")),
            "command": profile.get("command", []),
        }
        for profile in profiles
    ]
    return canonical_hash(matrix)


def workload_ratios(report: Dict[str, Any]) -> Dict[str, Dict[str, float]]:
    out: Dict[str, Dict[str, float]] = {}
    for workload in report.get("workloads", []):
        name = str(workload.get("name", "unknown"))
        ratios = workload.get("ratios", {})
        out[name] = {
            "zig_over_rust_prove": float(ratios.get("zig_over_rust_prove", 0.0)),
            "zig_over_rust_verify": float(ratios.get("zig_over_rust_verify", 0.0)),
            "zig_over_rust_proof_wire_bytes": float(ratios.get("zig_over_rust_proof_wire_bytes", 0.0)),
        }
    return out


def zig_profile_seconds(report: Dict[str, Any]) -> Dict[str, float]:
    out: Dict[str, float] = {}
    for profile in report.get("profiles", []):
        if profile.get("runtime") != "zig":
            continue
        workload = str(profile.get("workload", "unknown"))
        summary = profile.get("summary", {})
        out[workload] = float(summary.get("avg_seconds", 0.0))
    return out


def pct_delta(base: float, current: float) -> float:
    if base == 0.0:
        return 0.0
    return ((current - base) / base) * 100.0


def capture_baseline(
    *,
    baseline_out: Path,
    benchmark_report_path: Path,
    profile_report_path: Path,
) -> Dict[str, Any]:
    benchmark_report = load_json(benchmark_report_path, name="benchmark report")
    profile_report = load_json(profile_report_path, name="profile report")

    benchmark_settings_hash = benchmark_report.get("settings_hash")
    profile_settings_hash = profile_report.get("settings_hash")
    if not benchmark_settings_hash:
        raise CompareError("benchmark report missing settings_hash")
    if not profile_settings_hash:
        raise CompareError("profile report missing settings_hash")

    baseline = {
        "schema_version": 2,
        "created_at_unix": int(time.time()),
        "git_head_sha": run_capture(["git", "rev-parse", "HEAD"]),
        "benchmark": {
            "settings_hash": benchmark_settings_hash,
            "workload_matrix_hash": benchmark_workload_matrix_hash(benchmark_report),
            "report_path": rel(benchmark_report_path),
            "summary": benchmark_report.get("summary", {}),
            "thresholds": benchmark_report.get("thresholds", {}),
            "workload_ratios": workload_ratios(benchmark_report),
        },
        "profile": {
            "settings_hash": profile_settings_hash,
            "workload_matrix_hash": profile_workload_matrix_hash(profile_report),
            "report_path": rel(profile_report_path),
            "summary": profile_report.get("summary", {}),
            "zig_avg_seconds_by_workload": zig_profile_seconds(profile_report),
        },
    }

    baseline_out.parent.mkdir(parents=True, exist_ok=True)
    baseline_out.write_text(json.dumps(baseline, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return baseline


def evaluate_comparison(
    *,
    baseline: Dict[str, Any],
    benchmark_report: Dict[str, Any],
    profile_report: Dict[str, Any],
    require_prove_improvement_pct: float,
    max_prove_regression_pct: float,
    max_verify_regression_pct: float,
    max_zig_profile_regression_pct: float,
) -> Tuple[str, list[str], Dict[str, Any]]:
    failures: list[str] = []

    baseline_bench = baseline.get("benchmark", {})
    baseline_profile = baseline.get("profile", {})

    baseline_bench_hash = baseline_bench.get("settings_hash")
    baseline_profile_hash = baseline_profile.get("settings_hash")
    current_bench_hash = benchmark_report.get("settings_hash")
    current_profile_hash = profile_report.get("settings_hash")
    baseline_bench_matrix_hash = baseline_bench.get("workload_matrix_hash")
    baseline_profile_matrix_hash = baseline_profile.get("workload_matrix_hash")
    current_bench_matrix_hash = benchmark_workload_matrix_hash(benchmark_report)
    current_profile_matrix_hash = profile_workload_matrix_hash(profile_report)

    if baseline_bench_hash != current_bench_hash:
        failures.append("benchmark settings hash mismatch versus baseline")
    if baseline_profile_hash != current_profile_hash:
        failures.append("profile settings hash mismatch versus baseline")
    if baseline_bench_matrix_hash and baseline_bench_matrix_hash != current_bench_matrix_hash:
        failures.append("benchmark workload matrix hash mismatch versus baseline")
    if baseline_profile_matrix_hash and baseline_profile_matrix_hash != current_profile_matrix_hash:
        failures.append("profile workload matrix hash mismatch versus baseline")

    base_summary = baseline_bench.get("summary", {})
    curr_summary = benchmark_report.get("summary", {})

    base_max_prove = float(base_summary.get("max_zig_over_rust_prove", 0.0))
    base_max_verify = float(base_summary.get("max_zig_over_rust_verify", 0.0))
    curr_max_prove = float(curr_summary.get("max_zig_over_rust_prove", 0.0))
    curr_max_verify = float(curr_summary.get("max_zig_over_rust_verify", 0.0))

    prove_improvement_pct = -pct_delta(base_max_prove, curr_max_prove)
    prove_regression_pct = max(pct_delta(base_max_prove, curr_max_prove), 0.0)
    verify_regression_pct = max(pct_delta(base_max_verify, curr_max_verify), 0.0)

    if prove_regression_pct > max_prove_regression_pct:
        failures.append(
            f"prove regression {prove_regression_pct:.4f}% exceeds {max_prove_regression_pct:.4f}%"
        )
    if verify_regression_pct > max_verify_regression_pct:
        failures.append(
            f"verify regression {verify_regression_pct:.4f}% exceeds {max_verify_regression_pct:.4f}%"
        )
    if require_prove_improvement_pct > 0.0 and prove_improvement_pct < require_prove_improvement_pct:
        failures.append(
            f"prove improvement {prove_improvement_pct:.4f}% below required {require_prove_improvement_pct:.4f}%"
        )

    base_zig_avg = float((baseline_profile.get("summary", {}) or {}).get("avg_seconds_zig", 0.0))
    curr_zig_avg = float((profile_report.get("summary", {}) or {}).get("avg_seconds_zig", 0.0))
    zig_profile_regression_pct = max(pct_delta(base_zig_avg, curr_zig_avg), 0.0)
    if zig_profile_regression_pct > max_zig_profile_regression_pct:
        failures.append(
            f"zig profile avg_seconds regression {zig_profile_regression_pct:.4f}% exceeds {max_zig_profile_regression_pct:.4f}%"
        )

    per_workload_deltas: Dict[str, Dict[str, float]] = {}
    base_workloads = baseline_bench.get("workload_ratios", {})
    curr_workloads = workload_ratios(benchmark_report)
    for name, base_ratios in base_workloads.items():
        if name not in curr_workloads:
            failures.append(f"missing workload in current benchmark report: {name}")
            continue
        current_ratios = curr_workloads[name]
        per_workload_deltas[name] = {
            "prove_delta_pct": round(
                pct_delta(
                    float(base_ratios.get("zig_over_rust_prove", 0.0)),
                    float(current_ratios.get("zig_over_rust_prove", 0.0)),
                ),
                6,
            ),
            "verify_delta_pct": round(
                pct_delta(
                    float(base_ratios.get("zig_over_rust_verify", 0.0)),
                    float(current_ratios.get("zig_over_rust_verify", 0.0)),
                ),
                6,
            ),
        }

    details = {
        "baseline_benchmark_workload_matrix_hash": baseline_bench_matrix_hash,
        "current_benchmark_workload_matrix_hash": current_bench_matrix_hash,
        "baseline_profile_workload_matrix_hash": baseline_profile_matrix_hash,
        "current_profile_workload_matrix_hash": current_profile_matrix_hash,
        "baseline_max_zig_over_rust_prove": base_max_prove,
        "current_max_zig_over_rust_prove": curr_max_prove,
        "baseline_max_zig_over_rust_verify": base_max_verify,
        "current_max_zig_over_rust_verify": curr_max_verify,
        "prove_improvement_pct": round(prove_improvement_pct, 6),
        "prove_regression_pct": round(prove_regression_pct, 6),
        "verify_regression_pct": round(verify_regression_pct, 6),
        "baseline_avg_zig_profile_seconds": base_zig_avg,
        "current_avg_zig_profile_seconds": curr_zig_avg,
        "zig_profile_regression_pct": round(zig_profile_regression_pct, 6),
        "per_workload_deltas": per_workload_deltas,
    }

    status = "ok" if not failures else "failed"
    return status, failures, details


def run_self_test() -> None:
    baseline = {
        "benchmark": {
            "settings_hash": "h1",
            "summary": {
                "max_zig_over_rust_prove": 1.50,
                "max_zig_over_rust_verify": 1.20,
            },
            "workload_ratios": {
                "w": {
                    "zig_over_rust_prove": 1.50,
                    "zig_over_rust_verify": 1.20,
                    "zig_over_rust_proof_wire_bytes": 1.0,
                }
            },
        },
        "profile": {
            "settings_hash": "h2",
            "summary": {
                "avg_seconds_zig": 1.0,
            },
        },
    }

    improved_bench = {
        "settings_hash": "h1",
        "summary": {
            "max_zig_over_rust_prove": 1.40,
            "max_zig_over_rust_verify": 1.19,
        },
        "workloads": [
            {
                "name": "w",
                "ratios": {
                    "zig_over_rust_prove": 1.40,
                    "zig_over_rust_verify": 1.19,
                    "zig_over_rust_proof_wire_bytes": 1.0,
                },
            }
        ],
    }
    improved_profile = {
        "settings_hash": "h2",
        "summary": {
            "avg_seconds_zig": 0.97,
        },
        "profiles": [
            {"runtime": "zig", "workload": "w", "summary": {"avg_seconds": 0.97}},
        ],
    }

    status, failures, _ = evaluate_comparison(
        baseline=baseline,
        benchmark_report=improved_bench,
        profile_report=improved_profile,
        require_prove_improvement_pct=2.0,
        max_prove_regression_pct=0.0,
        max_verify_regression_pct=0.0,
        max_zig_profile_regression_pct=0.0,
    )
    if status != "ok" or failures:
        raise CompareError("self-test failed to accept improved run")

    regressed_bench = dict(improved_bench)
    regressed_bench["summary"] = {
        "max_zig_over_rust_prove": 1.60,
        "max_zig_over_rust_verify": 1.30,
    }
    regressed_bench["workloads"] = [
        {
            "name": "w",
            "ratios": {
                "zig_over_rust_prove": 1.60,
                "zig_over_rust_verify": 1.30,
                "zig_over_rust_proof_wire_bytes": 1.0,
            },
        }
    ]

    status, failures, _ = evaluate_comparison(
        baseline=baseline,
        benchmark_report=regressed_bench,
        profile_report=improved_profile,
        require_prove_improvement_pct=0.0,
        max_prove_regression_pct=0.0,
        max_verify_regression_pct=0.0,
        max_zig_profile_regression_pct=0.0,
    )
    if status != "failed" or not failures:
        raise CompareError("self-test failed to detect regression")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Compare optimization runs against baseline")
    parser.add_argument("--baseline", type=Path, default=BASELINE_DEFAULT)
    parser.add_argument("--benchmark-report", type=Path, default=BENCHMARK_REPORT_DEFAULT)
    parser.add_argument("--profile-report", type=Path, default=PROFILE_REPORT_DEFAULT)
    parser.add_argument("--compare-out", type=Path, default=COMPARE_REPORT_DEFAULT)
    parser.add_argument(
        "--capture-baseline",
        action="store_true",
        help="Capture baseline metadata from benchmark/profile reports and exit.",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run built-in comparator acceptance/regression checks.",
    )
    parser.add_argument("--require-prove-improvement-pct", type=float, default=0.0)
    parser.add_argument("--max-prove-regression-pct", type=float, default=0.0)
    parser.add_argument("--max-verify-regression-pct", type=float, default=0.0)
    parser.add_argument("--max-zig-profile-regression-pct", type=float, default=0.0)
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if args.self_test:
        run_self_test()
        print(json.dumps({"status": "ok", "self_test": True}, sort_keys=True))
        return 0

    if args.capture_baseline:
        baseline = capture_baseline(
            baseline_out=args.baseline,
            benchmark_report_path=args.benchmark_report,
            profile_report_path=args.profile_report,
        )
        print(
            json.dumps(
                {
                    "status": "ok",
                    "mode": "capture_baseline",
                    "baseline": rel(args.baseline),
                    "benchmark_settings_hash": baseline["benchmark"]["settings_hash"],
                    "profile_settings_hash": baseline["profile"]["settings_hash"],
                },
                sort_keys=True,
            )
        )
        return 0

    baseline = load_json(args.baseline, name="optimization baseline")
    benchmark_report = load_json(args.benchmark_report, name="benchmark report")
    profile_report = load_json(args.profile_report, name="profile report")

    status, failures, details = evaluate_comparison(
        baseline=baseline,
        benchmark_report=benchmark_report,
        profile_report=profile_report,
        require_prove_improvement_pct=args.require_prove_improvement_pct,
        max_prove_regression_pct=args.max_prove_regression_pct,
        max_verify_regression_pct=args.max_verify_regression_pct,
        max_zig_profile_regression_pct=args.max_zig_profile_regression_pct,
    )

    report = {
        "schema_version": 1,
        "status": status,
        "baseline_path": rel(args.baseline),
        "benchmark_report_path": rel(args.benchmark_report),
        "profile_report_path": rel(args.profile_report),
        "params": {
            "require_prove_improvement_pct": args.require_prove_improvement_pct,
            "max_prove_regression_pct": args.max_prove_regression_pct,
            "max_verify_regression_pct": args.max_verify_regression_pct,
            "max_zig_profile_regression_pct": args.max_zig_profile_regression_pct,
        },
        "details": details,
        "failures": failures,
    }

    args.compare_out.parent.mkdir(parents=True, exist_ok=True)
    args.compare_out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.compare_out != LATEST_COMPARE_REPORT:
        shutil.copyfile(args.compare_out, LATEST_COMPARE_REPORT)

    print(json.dumps({"status": status, "failures": failures}, sort_keys=True))
    return 0 if status == "ok" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except CompareError as exc:
        print(json.dumps({"status": "failed", "error": str(exc)}, sort_keys=True))
        raise SystemExit(1)
