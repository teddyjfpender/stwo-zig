#!/usr/bin/env python3
"""Deterministic deep-workload stress harness for Merkle worker settings.

Checks:
1. Default Zig behavior artifact verifies.
2. Opt-in pool reuse (`STWO_ZIG_MERKLE_POOL_REUSE=1`) with workers {2,4,8} verifies.
3. Proof bytes are identical across worker counts and match default output.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List


ROOT = Path(__file__).resolve().parent.parent
ZIG_BIN = ROOT / "vectors" / ".merkle_stress.zig_interop"
REPORT_DEFAULT = ROOT / "vectors" / "reports" / "merkle_worker_stress_report.json"
ARTIFACT_DIR_DEFAULT = ROOT / "vectors" / "reports" / "merkle_worker_stress_artifacts"

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

CASES: List[Dict[str, Any]] = [
    {
        "name": "state_machine_deep",
        "example": "state_machine",
        "args": [
            "--sm-log-n-rows",
            "12",
            "--sm-initial-0",
            "9",
            "--sm-initial-1",
            "3",
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
]


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def run(
    cmd: List[str],
    *,
    env: Dict[str, str] | None = None,
    cwd: Path = ROOT,
) -> subprocess.CompletedProcess[str]:
    merged_env = None
    if env:
        merged_env = dict(os.environ)
        merged_env.update(env)
    return subprocess.run(
        cmd,
        cwd=cwd,
        text=True,
        capture_output=True,
        check=False,
        env=merged_env,
    )


def run_step(
    *,
    name: str,
    cmd: List[str],
    steps: List[Dict[str, Any]],
    env: Dict[str, str] | None = None,
) -> None:
    start = time.perf_counter()
    proc = run(cmd, env=env)
    elapsed = time.perf_counter() - start
    step: Dict[str, Any] = {
        "name": name,
        "command": cmd,
        "seconds": round(elapsed, 6),
        "status": "ok" if proc.returncode == 0 else "failed",
        "return_code": proc.returncode,
        "stdout_tail": proc.stdout[-1600:],
        "stderr_tail": proc.stderr[-1600:],
    }
    if env:
        step["env"] = env
    steps.append(step)
    if proc.returncode != 0:
        raise RuntimeError(f"{name} failed with return code {proc.returncode}")


def read_artifact(path: Path) -> Dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"invalid artifact payload: {rel(path)}")
    return payload


def artifact_proof_hex(path: Path) -> str:
    payload = read_artifact(path)
    value = payload.get("proof_bytes_hex")
    if not isinstance(value, str) or not value:
        raise ValueError(f"missing proof_bytes_hex in {rel(path)}")
    return value


def ensure_binary(steps: List[Dict[str, Any]]) -> None:
    run_step(
        name="build_zig_interop_binary",
        cmd=[
            "zig",
            "build-exe",
            "src/interop_cli.zig",
            "-O",
            "ReleaseFast",
            "-femit-bin=" + str(ZIG_BIN),
        ],
        steps=steps,
    )


def case_commands(
    *,
    artifact: Path,
    example: str,
    prove_mode: str,
    args: List[str],
) -> tuple[List[str], List[str]]:
    generate_cmd = [
        str(ZIG_BIN),
        "--mode",
        "generate",
        "--example",
        example,
        "--artifact",
        str(artifact),
        "--prove-mode",
        prove_mode,
        "--blake2-backend",
        "auto",
    ] + COMMON_CONFIG_ARGS + args
    verify_cmd = [
        str(ZIG_BIN),
        "--mode",
        "verify",
        "--artifact",
        str(artifact),
        "--blake2-backend",
        "auto",
    ]
    return generate_cmd, verify_cmd


def run_case(
    *,
    case: Dict[str, Any],
    prove_mode: str,
    artifact_dir: Path,
    steps: List[Dict[str, Any]],
) -> Dict[str, Any]:
    case_name = str(case["name"])
    example = str(case["example"])
    args = [str(v) for v in case["args"]]

    default_artifact = artifact_dir / f"{case_name}_{prove_mode}_default.json"
    default_gen_cmd, default_verify_cmd = case_commands(
        artifact=default_artifact,
        example=example,
        prove_mode=prove_mode,
        args=args,
    )
    run_step(
        name=f"{case_name}:{prove_mode}:generate_default",
        cmd=default_gen_cmd,
        steps=steps,
    )
    run_step(
        name=f"{case_name}:{prove_mode}:verify_default",
        cmd=default_verify_cmd,
        steps=steps,
    )
    baseline_hex = artifact_proof_hex(default_artifact)

    worker_rows: List[Dict[str, Any]] = []
    mismatches: List[str] = []
    for workers in (2, 4, 8):
        artifact = artifact_dir / f"{case_name}_{prove_mode}_workers_{workers}.json"
        gen_cmd, verify_cmd = case_commands(
            artifact=artifact,
            example=example,
            prove_mode=prove_mode,
            args=args,
        )
        env = {
            "STWO_ZIG_MERKLE_WORKERS": str(workers),
            "STWO_ZIG_MERKLE_POOL_REUSE": "1",
        }
        run_step(
            name=f"{case_name}:{prove_mode}:generate_workers_{workers}",
            cmd=gen_cmd,
            steps=steps,
            env=env,
        )
        run_step(
            name=f"{case_name}:{prove_mode}:verify_workers_{workers}",
            cmd=verify_cmd,
            steps=steps,
            env=env,
        )
        worker_hex = artifact_proof_hex(artifact)
        equal_to_default = worker_hex == baseline_hex
        if not equal_to_default:
            mismatches.append(f"workers={workers}")
        worker_rows.append(
            {
                "workers": workers,
                "artifact": rel(artifact),
                "equal_to_default": equal_to_default,
            }
        )

    return {
        "case": case_name,
        "example": example,
        "prove_mode": prove_mode,
        "default_artifact": rel(default_artifact),
        "worker_rows": worker_rows,
        "status": "ok" if not mismatches else "failed",
        "mismatches": mismatches,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Deterministic stress harness for opt-in Merkle worker pool reuse",
    )
    parser.add_argument(
        "--report-out",
        type=Path,
        default=REPORT_DEFAULT,
        help="Path for JSON report output",
    )
    parser.add_argument(
        "--artifact-dir",
        type=Path,
        default=ARTIFACT_DIR_DEFAULT,
        help="Directory for generated artifacts",
    )
    parser.add_argument(
        "--prove-modes",
        default="prove,prove_ex",
        help="Comma-separated prove modes to test (prove,prove_ex).",
    )
    return parser.parse_args()


def parse_prove_modes(raw: str) -> List[str]:
    modes = [m.strip() for m in raw.split(",") if m.strip()]
    allowed = {"prove", "prove_ex"}
    for mode in modes:
        if mode not in allowed:
            raise ValueError(f"unsupported prove mode '{mode}'")
    if not modes:
        raise ValueError("at least one prove mode is required")
    return modes


def main() -> int:
    args = parse_args()
    prove_modes = parse_prove_modes(args.prove_modes)
    args.artifact_dir.mkdir(parents=True, exist_ok=True)

    steps: List[Dict[str, Any]] = []
    case_rows: List[Dict[str, Any]] = []
    failures: List[str] = []

    try:
        ensure_binary(steps)
        for case in CASES:
            for mode in prove_modes:
                row = run_case(
                    case=case,
                    prove_mode=mode,
                    artifact_dir=args.artifact_dir,
                    steps=steps,
                )
                case_rows.append(row)
                if row["status"] != "ok":
                    failures.append(f"{row['case']}:{row['prove_mode']} proof mismatch across workers")
    except Exception as exc:
        failures.append(str(exc))

    status = "ok" if not failures else "failed"
    report = {
        "schema_version": 1,
        "generated_at_unix": int(time.time()),
        "status": status,
        "workload_profile": "deep_worker_pool_reuse_soak_v1",
        "worker_counts": [2, 4, 8],
        "prove_modes": prove_modes,
        "cases_total": len(case_rows),
        "cases_ok": len([row for row in case_rows if row.get("status") == "ok"]),
        "failures": failures,
        "cases": case_rows,
        "steps": steps,
        "artifacts": {
            "artifact_dir": rel(args.artifact_dir),
        },
    }

    args.report_out.parent.mkdir(parents=True, exist_ok=True)
    args.report_out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    latest = args.report_out.parent / "latest_merkle_worker_stress_report.json"
    if latest != args.report_out:
        shutil.copyfile(args.report_out, latest)

    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
