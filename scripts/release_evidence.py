#!/usr/bin/env python3
"""Generate canonical release evidence manifest from gate reports."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
REPORTS_DIR = ROOT / "vectors" / "reports"
REPORT_DEFAULT = REPORTS_DIR / "release_evidence.json"
LATEST_DEFAULT = REPORTS_DIR / "latest_release_evidence.json"

INTEROP_REPORT_DEFAULT = REPORTS_DIR / "e2e_interop_report.json"
BENCHMARK_REPORT_DEFAULT = REPORTS_DIR / "benchmark_smoke_report.json"
PROFILE_REPORT_DEFAULT = REPORTS_DIR / "profile_smoke_report.json"
PROVE_CHECKPOINTS_REPORT_DEFAULT = REPORTS_DIR / "prove_checkpoints_report.json"
STD_SHIMS_BEHAVIOR_REPORT_DEFAULT = REPORTS_DIR / "std_shims_behavior_report.json"
BENCHMARK_OPT_REPORT_DEFAULT = REPORTS_DIR / "benchmark_opt_report.json"
PROFILE_OPT_REPORT_DEFAULT = REPORTS_DIR / "profile_opt_report.json"
OPT_COMPARE_REPORT_DEFAULT = REPORTS_DIR / "optimization_compare_report.json"

SCHEMA_VERSION = 1
MANIFEST_TYPE = "release_evidence_v1"
CONFORMANCE_REF = "CONFORMANCE.md"


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def run_capture(cmd: list[str]) -> str:
    proc = subprocess.run(
        cmd,
        cwd=ROOT,
        check=False,
        text=True,
        capture_output=True,
    )
    if proc.returncode != 0:
        return ""
    return proc.stdout.strip()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_report(path: Path, *, name: str) -> tuple[dict[str, Any], dict[str, Any]]:
    if not path.exists():
        raise RuntimeError(f"missing required report: {rel(path)}")

    raw = path.read_text(encoding="utf-8")
    parsed = json.loads(raw)
    if not isinstance(parsed, dict):
        raise RuntimeError(f"invalid report payload for {name}: {rel(path)}")

    status = str(parsed.get("status", "unknown"))
    return parsed, {
        "name": name,
        "path": rel(path),
        "sha256": sha256_file(path),
        "status": status,
    }


def load_optional_report(path: Path, *, name: str) -> tuple[dict[str, Any], dict[str, Any]] | None:
    if not path.exists():
        return None
    return load_report(path, name=name)


def gate_steps(gate_mode: str) -> list[dict[str, str]]:
    benchmark_cmd = (
        "python3 scripts/benchmark_smoke.py --include-medium --warmups 3 --repeats 11"
        if gate_mode == "strict"
        else "python3 scripts/benchmark_smoke.py"
    )
    steps = [
        {"name": "fmt", "command": "zig fmt --check build.zig src tools"},
        {"name": "test", "command": "zig test src/stwo.zig"},
        {"name": "api_parity", "command": "python3 scripts/check_api_parity.py"},
        {"name": "vectors_fields", "command": "python3 scripts/parity_fields.py --skip-zig"},
        {"name": "vectors_constraint", "command": "python3 scripts/parity_constraint_expr.py --skip-zig"},
        {"name": "vectors_air_derive", "command": "python3 scripts/parity_air_derive.py --skip-zig"},
        {"name": "interop", "command": "python3 scripts/e2e_interop.py"},
        {"name": "benchmark", "command": benchmark_cmd},
        {"name": "profile", "command": "python3 scripts/profile_smoke.py"},
    ]
    if gate_mode == "strict":
        steps.insert(3, {"name": "deep_gate", "command": "zig test src/stwo_deep.zig"})
        steps.insert(8, {"name": "prove_checkpoints", "command": "python3 scripts/prove_checkpoints.py"})
        steps.append(
            {
                "name": "std_shims",
                "command": "zig build-lib src/std_shims_freestanding.zig -target wasm32-freestanding -O ReleaseSmall -femit-bin=/tmp/stwo-zig-std-shims-verifier.wasm",
            }
        )
        steps.append(
            {
                "name": "std_shims_behavior",
                "command": "python3 scripts/std_shims_behavior.py",
            }
        )
    return steps


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate release evidence manifest")
    parser.add_argument(
        "--gate-mode",
        choices=("base", "strict"),
        default="strict",
        help="Gate matrix mode represented in the manifest",
    )
    parser.add_argument(
        "--report-out",
        type=Path,
        default=REPORT_DEFAULT,
        help="Path for JSON evidence manifest output",
    )
    parser.add_argument(
        "--interop-report",
        type=Path,
        default=INTEROP_REPORT_DEFAULT,
        help="Interop report path",
    )
    parser.add_argument(
        "--benchmark-report",
        type=Path,
        default=BENCHMARK_REPORT_DEFAULT,
        help="Benchmark report path",
    )
    parser.add_argument(
        "--profile-report",
        type=Path,
        default=PROFILE_REPORT_DEFAULT,
        help="Profile report path",
    )
    parser.add_argument(
        "--prove-checkpoints-report",
        type=Path,
        default=PROVE_CHECKPOINTS_REPORT_DEFAULT,
        help="Prove/prove_ex checkpoints report path",
    )
    parser.add_argument(
        "--std-shims-behavior-report",
        type=Path,
        default=STD_SHIMS_BEHAVIOR_REPORT_DEFAULT,
        help="Std-shims behavior parity report path",
    )
    parser.add_argument(
        "--benchmark-opt-report",
        type=Path,
        default=BENCHMARK_OPT_REPORT_DEFAULT,
        help="Optimization-track benchmark report path (optional)",
    )
    parser.add_argument(
        "--profile-opt-report",
        type=Path,
        default=PROFILE_OPT_REPORT_DEFAULT,
        help="Optimization-track profile report path (optional)",
    )
    parser.add_argument(
        "--optimization-compare-report",
        type=Path,
        default=OPT_COMPARE_REPORT_DEFAULT,
        help="Optimization comparator report path (optional)",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    generated_at = int(time.time())

    interop_report, interop_manifest = load_report(args.interop_report, name="interop")
    benchmark_report, benchmark_manifest = load_report(args.benchmark_report, name="benchmark")
    profile_report, profile_manifest = load_report(args.profile_report, name="profile")

    reports = [interop_manifest, benchmark_manifest, profile_manifest]
    if args.gate_mode == "strict":
        _, prove_checkpoints_manifest = load_report(
            args.prove_checkpoints_report,
            name="prove_checkpoints",
        )
        _, std_shims_behavior_manifest = load_report(
            args.std_shims_behavior_report,
            name="std_shims_behavior",
        )
        reports.append(prove_checkpoints_manifest)
        reports.append(std_shims_behavior_manifest)

    optimization_track: dict[str, Any] | None = None
    maybe_opt_bench = load_optional_report(args.benchmark_opt_report, name="benchmark_opt")
    maybe_opt_profile = load_optional_report(args.profile_opt_report, name="profile_opt")
    maybe_opt_compare = load_optional_report(args.optimization_compare_report, name="optimization_compare")
    if maybe_opt_bench and maybe_opt_profile and maybe_opt_compare:
        opt_bench_report, opt_bench_manifest = maybe_opt_bench
        opt_profile_report, opt_profile_manifest = maybe_opt_profile
        opt_compare_report, opt_compare_manifest = maybe_opt_compare
        reports.append(opt_bench_manifest)
        reports.append(opt_profile_manifest)
        reports.append(opt_compare_manifest)
        optimization_track = {
            "present": True,
            "benchmark_report": opt_bench_manifest["path"],
            "profile_report": opt_profile_manifest["path"],
            "compare_report": opt_compare_manifest["path"],
            "compare_status": opt_compare_manifest["status"],
            "compare_details": opt_compare_report.get("details", {}),
            "baseline_path": opt_compare_report.get("baseline_path"),
            "benchmark_settings_hash": opt_bench_report.get("settings_hash"),
            "profile_settings_hash": opt_profile_report.get("settings_hash"),
        }
    else:
        optimization_track = {"present": False}

    failures: list[str] = []

    for report in reports:
        if report["status"] != "ok":
            failures.append(f"{report['name']} report status is {report['status']}")

    benchmark_settings = benchmark_report.get("settings", {})
    include_medium = bool(benchmark_settings.get("include_medium", False))
    if args.gate_mode == "strict" and not include_medium:
        failures.append("strict mode requires benchmark report with include_medium=true")
    if args.gate_mode == "base" and include_medium:
        failures.append("base mode requires benchmark report with include_medium=false")

    git_head = run_capture(["git", "rev-parse", "HEAD"])
    if not git_head:
        failures.append("unable to resolve git HEAD")
    git_branch = run_capture(["git", "rev-parse", "--abbrev-ref", "HEAD"])
    git_dirty = bool(run_capture(["git", "status", "--porcelain"]))

    rust_toolchain = str(interop_report.get("rust_toolchain", "nightly-2025-07-14"))
    rustc_version = run_capture(["rustc", f"+{rust_toolchain}", "--version"])
    if not rustc_version:
        rustc_version = run_capture(["rustc", "--version"])
    zig_version = run_capture(["zig", "version"])

    status = "ok" if not failures else "failed"
    manifest = {
        "status": status,
        "schema_version": SCHEMA_VERSION,
        "manifest_type": MANIFEST_TYPE,
        "generated_at_unix": generated_at,
        "conformance_reference": CONFORMANCE_REF,
        "git": {
            "head_sha": git_head,
            "branch": git_branch,
            "dirty": git_dirty,
        },
        "pins": {
            "upstream_commit": interop_report.get("upstream_commit"),
        },
        "toolchain": {
            "zig_version": zig_version,
            "rust_toolchain": rust_toolchain,
            "rustc_version": rustc_version,
        },
        "gate": {
            "name": "release-gate-strict" if args.gate_mode == "strict" else "release-gate",
            "mode": args.gate_mode,
            "fail_fast": True,
            "commands": gate_steps(args.gate_mode),
        },
        "reports": reports,
        "summary": {
            "reports_total": len(reports),
            "reports_ok": len([report for report in reports if report["status"] == "ok"]),
            "failure_count": len(failures),
            "failures": failures,
        },
        "optimization_track": optimization_track,
    }

    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    if args.report_out != LATEST_DEFAULT:
        shutil.copyfile(args.report_out, LATEST_DEFAULT)

    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
