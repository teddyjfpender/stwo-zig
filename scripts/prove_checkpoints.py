#!/usr/bin/env python3
"""Deterministic prove/prove_ex checkpoint harness.

Checks performed per case:
1. Rust-generated artifact verifies in Zig.
2. Rust-generated artifact verifies in Rust.
3. prove and prove_ex emit identical proof bytes for same statement/config.
4. Tampered proof bytes and tampered statements are rejected semantically.
5. Invalid prove_mode metadata is rejected by both verifiers.

Outputs machine-readable report at vectors/reports/prove_checkpoints_report.json.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parent.parent
RUST_MANIFEST = ROOT / "tools" / "stwo-interop-rs" / "Cargo.toml"
REPORT_DEFAULT = ROOT / "vectors" / "reports" / "prove_checkpoints_report.json"
ARTIFACT_DIR_DEFAULT = ROOT / "vectors" / "reports" / "prove_checkpoints_artifacts"
RUST_TOOLCHAIN_DEFAULT = "nightly-2025-07-14"
M31_MODULUS = 2147483647

REJECTION_CLASS_VERIFIER = "verifier_semantic"
REJECTION_CLASS_PARSER = "parser"
REJECTION_CLASS_METADATA = "metadata_policy"


@dataclass(frozen=True)
class Case:
    case_id: str
    example: str
    args: dict[str, str]


CASES = (
    Case(
        case_id="plonk_base",
        example="plonk",
        args={
            "pow-bits": "0",
            "fri-log-blowup": "1",
            "fri-log-last-layer": "0",
            "fri-n-queries": "3",
            "plonk-log-n-rows": "5",
        },
    ),
    Case(
        case_id="xor_base",
        example="xor",
        args={
            "pow-bits": "0",
            "fri-log-blowup": "1",
            "fri-log-last-layer": "0",
            "fri-n-queries": "3",
            "xor-log-size": "5",
            "xor-log-step": "2",
            "xor-offset": "3",
        },
    ),
    Case(
        case_id="state_machine_base",
        example="state_machine",
        args={
            "pow-bits": "0",
            "fri-log-blowup": "1",
            "fri-log-last-layer": "0",
            "fri-n-queries": "3",
            "sm-log-n-rows": "5",
            "sm-initial-0": "9",
            "sm-initial-1": "3",
        },
    ),
    Case(
        case_id="wide_fibonacci_base",
        example="wide_fibonacci",
        args={
            "pow-bits": "0",
            "fri-log-blowup": "1",
            "fri-log-last-layer": "0",
            "fri-n-queries": "3",
            "wf-log-n-rows": "5",
            "wf-sequence-len": "16",
        },
    ),
    Case(
        case_id="plonk_blowup2",
        example="plonk",
        args={
            "pow-bits": "0",
            "fri-log-blowup": "2",
            "fri-log-last-layer": "0",
            "fri-n-queries": "3",
            "plonk-log-n-rows": "5",
        },
    ),
    Case(
        case_id="xor_blowup2",
        example="xor",
        args={
            "pow-bits": "0",
            "fri-log-blowup": "2",
            "fri-log-last-layer": "0",
            "fri-n-queries": "3",
            "xor-log-size": "5",
            "xor-log-step": "2",
            "xor-offset": "3",
        },
    ),
    Case(
        case_id="state_machine_blowup2",
        example="state_machine",
        args={
            "pow-bits": "0",
            "fri-log-blowup": "2",
            "fri-log-last-layer": "0",
            "fri-n-queries": "3",
            "sm-log-n-rows": "5",
            "sm-initial-0": "9",
            "sm-initial-1": "3",
        },
    ),
    Case(
        case_id="wide_fibonacci_blowup2",
        example="wide_fibonacci",
        args={
            "pow-bits": "0",
            "fri-log-blowup": "2",
            "fri-log-last-layer": "0",
            "fri-n-queries": "3",
            "wf-log-n-rows": "5",
            "wf-sequence-len": "16",
        },
    ),
)


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def trim_tail(text: str, limit: int = 2000) -> str:
    if len(text) <= limit:
        return text
    return text[-limit:]


def classify_rejection(stdout_tail: str, stderr_tail: str) -> str:
    combined = f"{stdout_tail}\n{stderr_tail}".lower()

    parser_markers = (
        "syntaxerror",
        "unexpectedtoken",
        "expected value at line",
        "line 1 column 1",
    )
    if any(marker in combined for marker in parser_markers):
        return REJECTION_CLASS_PARSER

    metadata_markers = (
        "unsupportedupstreamcommit",
        "unsupported upstream commit",
        "unsupportedgenerator",
        "unsupported generator",
        "unknown artifact generator",
        "unsupported prove mode",
        "unsupportedprovemode",
        "unsupportedprovemode",
        "unsupportedprovemode",
    )
    if any(marker in combined for marker in metadata_markers):
        return REJECTION_CLASS_METADATA

    return REJECTION_CLASS_VERIFIER


def run_step(
    *,
    name: str,
    cmd: list[str],
    steps: list[dict[str, Any]],
    expect_failure: bool = False,
    required_rejection_class: str | None = None,
) -> dict[str, Any]:
    start = time.perf_counter()
    proc = subprocess.run(cmd, cwd=ROOT, text=True, capture_output=True, check=False)
    elapsed = time.perf_counter() - start
    succeeded = (proc.returncode != 0) if expect_failure else (proc.returncode == 0)

    step: dict[str, Any] = {
        "name": name,
        "command": cmd,
        "cwd": ".",
        "seconds": round(elapsed, 6),
        "expect_failure": expect_failure,
        "return_code": proc.returncode,
        "status": "ok" if succeeded else "failed",
        "stdout_tail": trim_tail(proc.stdout),
        "stderr_tail": trim_tail(proc.stderr),
    }
    if expect_failure:
        step["rejection_class"] = classify_rejection(step["stdout_tail"], step["stderr_tail"])
    steps.append(step)

    if not succeeded:
        expectation = "non-zero exit code" if expect_failure else "zero exit code"
        raise RuntimeError(
            f"{name} failed (expected {expectation}, got {proc.returncode})"
        )
    if required_rejection_class and step.get("rejection_class") != required_rejection_class:
        raise RuntimeError(
            f"{name} rejected with class {step.get('rejection_class')}, expected {required_rejection_class}"
        )
    return step


def parse_artifact(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        obj = json.load(f)
    if not isinstance(obj, dict):
        raise ValueError(f"artifact root is not an object: {path}")
    return obj


def write_artifact(path: Path, artifact: dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(artifact, f, indent=2, sort_keys=True)
        f.write("\n")


def tamper_statement(artifact_path: Path, out_path: Path, example: str) -> None:
    artifact = parse_artifact(artifact_path)
    if example == "plonk":
        stmt = artifact.get("plonk_statement")
        if not isinstance(stmt, dict) or "log_n_rows" not in stmt:
            raise ValueError("missing plonk_statement.log_n_rows")
        stmt["log_n_rows"] = int(stmt["log_n_rows"]) + 1
    elif example == "xor":
        stmt = artifact.get("xor_statement")
        if not isinstance(stmt, dict) or "offset" not in stmt:
            raise ValueError("missing xor statement offset")
        stmt["offset"] = int(stmt["offset"]) + 1
    elif example == "state_machine":
        stmt = artifact.get("state_machine_statement")
        if not isinstance(stmt, dict):
            raise ValueError("missing state_machine_statement")
        stmt1 = stmt.get("stmt1")
        if not isinstance(stmt1, dict):
            raise ValueError("missing stmt1")
        claim = stmt1.get("x_axis_claimed_sum")
        if not (isinstance(claim, list) and len(claim) == 4):
            raise ValueError("missing x_axis_claimed_sum")
        claim[0] = (int(claim[0]) + 1) % M31_MODULUS
    elif example == "wide_fibonacci":
        stmt = artifact.get("wide_fibonacci_statement")
        if not isinstance(stmt, dict) or "sequence_len" not in stmt:
            raise ValueError("missing wide_fibonacci_statement.sequence_len")
        stmt["sequence_len"] = int(stmt["sequence_len"]) + 1
    else:
        raise ValueError(f"unsupported example {example}")
    write_artifact(out_path, artifact)


def tamper_proof_bytes_hex(artifact_path: Path, out_path: Path) -> None:
    artifact = parse_artifact(artifact_path)
    proof_hex = artifact.get("proof_bytes_hex")
    if not isinstance(proof_hex, str):
        raise ValueError("missing proof_bytes_hex")

    proof_wire = json.loads(bytes.fromhex(proof_hex).decode("utf-8"))
    commitments = proof_wire.get("commitments")
    if not (isinstance(commitments, list) and commitments and isinstance(commitments[0], list) and commitments[0]):
        raise ValueError("proof wire missing commitments")
    commitments[0][0] = (int(commitments[0][0]) + 1) % 256

    artifact["proof_bytes_hex"] = json.dumps(proof_wire, separators=(",", ":")).encode("utf-8").hex()
    write_artifact(out_path, artifact)


def tamper_prove_mode(artifact_path: Path, out_path: Path) -> None:
    artifact = parse_artifact(artifact_path)
    artifact["prove_mode"] = "invalid_prove_mode"
    write_artifact(out_path, artifact)


def rust_generate_cmd(
    *,
    toolchain: str,
    example: str,
    artifact_path: Path,
    prove_mode: str,
    args: dict[str, str],
) -> list[str]:
    cmd = [
        "cargo",
        f"+{toolchain}",
        "run",
        "--manifest-path",
        str(RUST_MANIFEST),
        "--",
        "--mode",
        "generate",
        "--example",
        example,
        "--artifact",
        str(artifact_path),
        "--prove-mode",
        prove_mode,
    ]
    for key, value in args.items():
        cmd.extend([f"--{key}", value])
    return cmd


def rust_verify_cmd(*, toolchain: str, artifact_path: Path) -> list[str]:
    return [
        "cargo",
        f"+{toolchain}",
        "run",
        "--manifest-path",
        str(RUST_MANIFEST),
        "--",
        "--mode",
        "verify",
        "--artifact",
        str(artifact_path),
    ]


def zig_verify_cmd(*, artifact_path: Path) -> list[str]:
    return [
        "zig",
        "run",
        "src/interop_cli.zig",
        "--",
        "--mode",
        "verify",
        "--artifact",
        str(artifact_path),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description="prove/prove_ex checkpoint harness")
    parser.add_argument("--rust-toolchain", default=RUST_TOOLCHAIN_DEFAULT)
    parser.add_argument("--report-out", type=Path, default=REPORT_DEFAULT)
    parser.add_argument("--artifact-dir", type=Path, default=ARTIFACT_DIR_DEFAULT)
    args = parser.parse_args()

    report_out: Path = args.report_out
    artifact_dir: Path = args.artifact_dir
    artifact_dir.mkdir(parents=True, exist_ok=True)

    steps: list[dict[str, Any]] = []
    case_reports: list[dict[str, Any]] = []

    for case in CASES:
        prove_artifact = artifact_dir / f"{case.case_id}_prove_rust.json"
        prove_ex_artifact = artifact_dir / f"{case.case_id}_prove_ex_rust.json"

        run_step(
            name=f"{case.case_id}_prove_generate_rust",
            cmd=rust_generate_cmd(
                toolchain=args.rust_toolchain,
                example=case.example,
                artifact_path=prove_artifact,
                prove_mode="prove",
                args=case.args,
            ),
            steps=steps,
        )
        run_step(
            name=f"{case.case_id}_prove_ex_generate_rust",
            cmd=rust_generate_cmd(
                toolchain=args.rust_toolchain,
                example=case.example,
                artifact_path=prove_ex_artifact,
                prove_mode="prove_ex",
                args=case.args,
            ),
            steps=steps,
        )

        run_step(
            name=f"{case.case_id}_prove_verify_zig",
            cmd=zig_verify_cmd(artifact_path=prove_artifact),
            steps=steps,
        )
        run_step(
            name=f"{case.case_id}_prove_verify_rust",
            cmd=rust_verify_cmd(toolchain=args.rust_toolchain, artifact_path=prove_artifact),
            steps=steps,
        )
        run_step(
            name=f"{case.case_id}_prove_ex_verify_zig",
            cmd=zig_verify_cmd(artifact_path=prove_ex_artifact),
            steps=steps,
        )
        run_step(
            name=f"{case.case_id}_prove_ex_verify_rust",
            cmd=rust_verify_cmd(toolchain=args.rust_toolchain, artifact_path=prove_ex_artifact),
            steps=steps,
        )

        prove_json = parse_artifact(prove_artifact)
        prove_ex_json = parse_artifact(prove_ex_artifact)
        prove_hex = prove_json.get("proof_bytes_hex")
        prove_ex_hex = prove_ex_json.get("proof_bytes_hex")
        if not isinstance(prove_hex, str) or not isinstance(prove_ex_hex, str):
            raise RuntimeError(f"{case.case_id} missing proof bytes")
        if prove_hex != prove_ex_hex:
            raise RuntimeError(f"{case.case_id} prove/prove_ex proof bytes diverged")

        proof_tampered = artifact_dir / f"{case.case_id}_prove_ex_tampered.json"
        statement_tampered = artifact_dir / f"{case.case_id}_prove_ex_statement_tampered.json"
        prove_mode_tampered = artifact_dir / f"{case.case_id}_prove_ex_mode_tampered.json"

        tamper_proof_bytes_hex(prove_ex_artifact, proof_tampered)
        tamper_statement(prove_ex_artifact, statement_tampered, case.example)
        tamper_prove_mode(prove_ex_artifact, prove_mode_tampered)

        run_step(
            name=f"{case.case_id}_tampered_proof_reject_zig",
            cmd=zig_verify_cmd(artifact_path=proof_tampered),
            steps=steps,
            expect_failure=True,
            required_rejection_class=REJECTION_CLASS_VERIFIER,
        )
        run_step(
            name=f"{case.case_id}_tampered_proof_reject_rust",
            cmd=rust_verify_cmd(toolchain=args.rust_toolchain, artifact_path=proof_tampered),
            steps=steps,
            expect_failure=True,
            required_rejection_class=REJECTION_CLASS_VERIFIER,
        )
        run_step(
            name=f"{case.case_id}_tampered_statement_reject_zig",
            cmd=zig_verify_cmd(artifact_path=statement_tampered),
            steps=steps,
            expect_failure=True,
            required_rejection_class=REJECTION_CLASS_VERIFIER,
        )
        run_step(
            name=f"{case.case_id}_tampered_statement_reject_rust",
            cmd=rust_verify_cmd(toolchain=args.rust_toolchain, artifact_path=statement_tampered),
            steps=steps,
            expect_failure=True,
            required_rejection_class=REJECTION_CLASS_VERIFIER,
        )
        run_step(
            name=f"{case.case_id}_tampered_mode_reject_zig",
            cmd=zig_verify_cmd(artifact_path=prove_mode_tampered),
            steps=steps,
            expect_failure=True,
            required_rejection_class=REJECTION_CLASS_METADATA,
        )
        run_step(
            name=f"{case.case_id}_tampered_mode_reject_rust",
            cmd=rust_verify_cmd(toolchain=args.rust_toolchain, artifact_path=prove_mode_tampered),
            steps=steps,
            expect_failure=True,
            required_rejection_class=REJECTION_CLASS_METADATA,
        )

        case_reports.append(
            {
                "case_id": case.case_id,
                "example": case.example,
                "args": case.args,
                "artifacts": {
                    "prove": rel(prove_artifact),
                    "prove_ex": rel(prove_ex_artifact),
                    "tampered_proof": rel(proof_tampered),
                    "tampered_statement": rel(statement_tampered),
                    "tampered_mode": rel(prove_mode_tampered),
                },
                "prove_vs_prove_ex_equal": True,
            }
        )

    report: dict[str, Any] = {
        "status": "ok",
        "toolchain": {
            "rust_toolchain": args.rust_toolchain,
        },
        "cases": case_reports,
        "summary": {
            "case_count": len(case_reports),
            "step_count": len(steps),
            "tamper_checks_per_case": 6,
        },
        "steps": steps,
    }

    report_out.parent.mkdir(parents=True, exist_ok=True)
    with report_out.open("w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=True)
        f.write("\n")

    latest = report_out.parent / "latest_prove_checkpoints_report.json"
    if latest != report_out:
        shutil.copyfile(report_out, latest)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
