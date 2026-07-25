#!/usr/bin/env python3
"""Deterministic prove/prove_ex checkpoint harness.

Checks performed per case and generator:
1. Rust- and Zig-generated artifacts verify in both runtimes.
2. prove and prove_ex emit identical proof bytes for the same runtime.
3. Rust and Zig emit the same canonical proof wire.
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

try:
    from interop_cli_command import run_command
except ModuleNotFoundError:
    from scripts.interop_cli_command import run_command


ROOT = Path(__file__).resolve().parent.parent
RUST_MANIFEST = ROOT / "tools" / "stwo-interop-rs" / "Cargo.toml"
REPORT_DEFAULT = ROOT / "vectors" / "reports" / "prove_checkpoints_report.json"
ARTIFACT_DIR_DEFAULT = ROOT / "vectors" / "reports" / "prove_checkpoints_artifacts"
RUST_TOOLCHAIN_DEFAULT = "nightly-2025-07-14"
UPSTREAM_COMMIT = "a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2"
SCHEMA_VERSION = 1
EXCHANGE_MODE = "proof_exchange_json_wire_v1"
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
        case_id="blake_base",
        example="blake",
        args={
            "pow-bits": "0",
            "fri-log-blowup": "1",
            "fri-log-last-layer": "0",
            "fri-n-queries": "3",
            "blake-log-n-rows": "5",
            "blake-n-rounds": "10",
        },
    ),
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
        case_id="poseidon_base",
        example="poseidon",
        args={
            "pow-bits": "0",
            "fri-log-blowup": "1",
            "fri-log-last-layer": "0",
            "fri-n-queries": "3",
            "poseidon-log-n-instances": "8",
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
        case_id="poseidon_blowup2",
        example="poseidon",
        args={
            "pow-bits": "0",
            "fri-log-blowup": "2",
            "fri-log-last-layer": "0",
            "fri-n-queries": "3",
            "poseidon-log-n-instances": "8",
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
    Case(
        case_id="blake_blowup2",
        example="blake",
        args={
            "pow-bits": "0",
            "fri-log-blowup": "2",
            "fri-log-last-layer": "0",
            "fri-n-queries": "3",
            "blake-log-n-rows": "5",
            "blake-n-rounds": "10",
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


def prepare_generated_artifact(path: Path) -> None:
    """Retire the prior harness-owned output before exclusive publication."""
    path.unlink(missing_ok=True)


def assert_artifact_metadata(
    artifact: dict[str, Any], *, generator: str, example: str, prove_mode: str
) -> None:
    expected = {
        "schema_version": SCHEMA_VERSION,
        "exchange_mode": EXCHANGE_MODE,
        "upstream_commit": UPSTREAM_COMMIT,
        "generator": generator,
        "example": example,
        "prove_mode": prove_mode,
    }
    for key, value in expected.items():
        if artifact.get(key) != value:
            raise RuntimeError(
                f"artifact {key} mismatch: expected {value!r}, got {artifact.get(key)!r}"
            )


def canonical_proof_wire(artifact: dict[str, Any]) -> dict[str, Any]:
    proof_hex = artifact.get("proof_bytes_hex")
    if not isinstance(proof_hex, str):
        raise RuntimeError("artifact is missing proof_bytes_hex")
    proof_wire = json.loads(bytes.fromhex(proof_hex).decode("utf-8"))
    if not isinstance(proof_wire, dict):
        raise RuntimeError("proof wire root is not an object")

    config = proof_wire.get("config")
    if not isinstance(config, dict):
        raise RuntimeError("proof wire is missing config")
    fri_config = config.get("fri_config")
    if not isinstance(fri_config, dict):
        raise RuntimeError("proof wire is missing config.fri_config")

    # The pinned Rust wire predates these Zig wire fields. Their Zig defaults
    # are the exact semantics used by that Rust revision.
    fri_config.setdefault("fold_step", 1)
    config.setdefault("lifting_log_size", None)
    return proof_wire


def tamper_statement(artifact_path: Path, out_path: Path, example: str) -> None:
    artifact = parse_artifact(artifact_path)
    if example == "blake":
        stmt = artifact.get("blake_statement")
        stmt1 = stmt.get("stmt1") if isinstance(stmt, dict) else None
        claim = stmt1.get("scheduler_claimed_sum") if isinstance(stmt1, dict) else None
        if not (isinstance(claim, list) and len(claim) == 4):
            raise ValueError(
                "missing blake_statement.stmt1.scheduler_claimed_sum"
            )
        claim[0] = (int(claim[0]) + 1) % M31_MODULUS
    elif example == "plonk":
        stmt = artifact.get("plonk_statement")
        if not isinstance(stmt, dict) or "log_n_rows" not in stmt:
            raise ValueError("missing plonk_statement.log_n_rows")
        stmt["log_n_rows"] = int(stmt["log_n_rows"]) + 1
    elif example == "poseidon":
        stmt = artifact.get("poseidon_statement")
        if not isinstance(stmt, dict) or "log_n_instances" not in stmt:
            raise ValueError("missing poseidon_statement.log_n_instances")
        stmt["log_n_instances"] = int(stmt["log_n_instances"]) + 1
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


def generate_cmd(
    *,
    generator: str,
    toolchain: str,
    example: str,
    artifact_path: Path,
    prove_mode: str,
    args: dict[str, str],
) -> list[str]:
    arguments = [
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
        arguments.extend([f"--{key}", value])
    if generator == "rust":
        return [
            "cargo",
            f"+{toolchain}",
            "run",
            "--manifest-path",
            str(RUST_MANIFEST),
            "--",
            *arguments,
        ]
    if generator == "zig":
        return run_command(*arguments)
    raise ValueError(f"unsupported checkpoint generator {generator}")


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
    return run_command(
        "--mode",
        "verify",
        "--artifact",
        str(artifact_path),
    )


def verify_with_both(
    *,
    name: str,
    artifact_path: Path,
    rust_toolchain: str,
    steps: list[dict[str, Any]],
) -> None:
    run_step(
        name=f"{name}_verify_zig",
        cmd=zig_verify_cmd(artifact_path=artifact_path),
        steps=steps,
    )
    run_step(
        name=f"{name}_verify_rust",
        cmd=rust_verify_cmd(toolchain=rust_toolchain, artifact_path=artifact_path),
        steps=steps,
    )


def tamper_checks(
    *,
    case: Case,
    generator: str,
    prove_ex_artifact: Path,
    artifact_dir: Path,
    rust_toolchain: str,
    steps: list[dict[str, Any]],
) -> dict[str, Path]:
    prefix = f"{case.case_id}_{generator}_prove_ex"
    outputs = {
        "tampered_proof": artifact_dir / f"{prefix}_tampered.json",
        "tampered_statement": artifact_dir / f"{prefix}_statement_tampered.json",
        "tampered_mode": artifact_dir / f"{prefix}_mode_tampered.json",
    }
    tamper_proof_bytes_hex(prove_ex_artifact, outputs["tampered_proof"])
    tamper_statement(prove_ex_artifact, outputs["tampered_statement"], case.example)
    tamper_prove_mode(prove_ex_artifact, outputs["tampered_mode"])

    for tamper_name, rejection_class in (
        ("tampered_proof", REJECTION_CLASS_VERIFIER),
        ("tampered_statement", REJECTION_CLASS_VERIFIER),
        ("tampered_mode", REJECTION_CLASS_METADATA),
    ):
        artifact_path = outputs[tamper_name]
        run_step(
            name=f"{case.case_id}_{generator}_{tamper_name}_reject_zig",
            cmd=zig_verify_cmd(artifact_path=artifact_path),
            steps=steps,
            expect_failure=True,
            required_rejection_class=rejection_class,
        )
        run_step(
            name=f"{case.case_id}_{generator}_{tamper_name}_reject_rust",
            cmd=rust_verify_cmd(toolchain=rust_toolchain, artifact_path=artifact_path),
            steps=steps,
            expect_failure=True,
            required_rejection_class=rejection_class,
        )
    return outputs


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
        rust_prove = artifact_dir / f"{case.case_id}_prove_rust.json"
        rust_prove_ex = artifact_dir / f"{case.case_id}_prove_ex_rust.json"
        zig_prove = artifact_dir / f"{case.case_id}_prove_zig.json"
        zig_prove_ex = artifact_dir / f"{case.case_id}_prove_ex_zig.json"

        artifacts = {
            "rust": {"prove": rust_prove, "prove_ex": rust_prove_ex},
            "zig": {"prove": zig_prove, "prove_ex": zig_prove_ex},
        }
        parsed: dict[str, dict[str, dict[str, Any]]] = {}
        for generator, generator_artifacts in artifacts.items():
            parsed[generator] = {}
            for prove_mode, artifact_path in generator_artifacts.items():
                prepare_generated_artifact(artifact_path)
                run_step(
                    name=f"{case.case_id}_{generator}_{prove_mode}_generate",
                    cmd=generate_cmd(
                        generator=generator,
                        toolchain=args.rust_toolchain,
                        example=case.example,
                        artifact_path=artifact_path,
                        prove_mode=prove_mode,
                        args=case.args,
                    ),
                    steps=steps,
                )
                artifact = parse_artifact(artifact_path)
                assert_artifact_metadata(
                    artifact,
                    generator=generator,
                    example=case.example,
                    prove_mode=prove_mode,
                )
                parsed[generator][prove_mode] = artifact
                verify_with_both(
                    name=f"{case.case_id}_{generator}_{prove_mode}",
                    artifact_path=artifact_path,
                    rust_toolchain=args.rust_toolchain,
                    steps=steps,
                )

        rust_prove_wire = canonical_proof_wire(parsed["rust"]["prove"])
        rust_prove_ex_wire = canonical_proof_wire(parsed["rust"]["prove_ex"])
        zig_prove_wire = canonical_proof_wire(parsed["zig"]["prove"])
        zig_prove_ex_wire = canonical_proof_wire(parsed["zig"]["prove_ex"])
        if rust_prove_wire != rust_prove_ex_wire:
            raise RuntimeError(f"{case.case_id} Rust prove/prove_ex proof wire diverged")
        if zig_prove_wire != zig_prove_ex_wire:
            raise RuntimeError(f"{case.case_id} Zig prove/prove_ex proof wire diverged")
        if rust_prove_wire != zig_prove_wire:
            raise RuntimeError(f"{case.case_id} Rust/Zig canonical proof wire diverged")

        rust_tampers = tamper_checks(
            case=case,
            generator="rust",
            prove_ex_artifact=rust_prove_ex,
            artifact_dir=artifact_dir,
            rust_toolchain=args.rust_toolchain,
            steps=steps,
        )
        zig_tampers = tamper_checks(
            case=case,
            generator="zig",
            prove_ex_artifact=zig_prove_ex,
            artifact_dir=artifact_dir,
            rust_toolchain=args.rust_toolchain,
            steps=steps,
        )

        case_reports.append(
            {
                "case_id": case.case_id,
                "example": case.example,
                "args": case.args,
                "artifacts": {
                    "prove": rel(rust_prove),
                    "prove_ex": rel(rust_prove_ex),
                    "tampered_proof": rel(rust_tampers["tampered_proof"]),
                    "tampered_statement": rel(rust_tampers["tampered_statement"]),
                    "tampered_mode": rel(rust_tampers["tampered_mode"]),
                    "zig_prove": rel(zig_prove),
                    "zig_prove_ex": rel(zig_prove_ex),
                    "zig_tampered_proof": rel(zig_tampers["tampered_proof"]),
                    "zig_tampered_statement": rel(zig_tampers["tampered_statement"]),
                    "zig_tampered_mode": rel(zig_tampers["tampered_mode"]),
                },
                "prove_vs_prove_ex_equal": True,
                "rust_prove_vs_prove_ex_equal": True,
                "zig_prove_vs_prove_ex_equal": True,
                "rust_vs_zig_canonical_proof_equal": True,
            }
        )

    report: dict[str, Any] = {
        "status": "ok",
        "upstream_commit": UPSTREAM_COMMIT,
        "toolchain": {
            "rust_toolchain": args.rust_toolchain,
        },
        "cases": case_reports,
        "summary": {
            "case_count": len(case_reports),
            "step_count": len(steps),
            "positive_verifications_per_case": 8,
            "tamper_checks_per_case": 12,
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
