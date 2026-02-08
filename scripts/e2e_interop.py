#!/usr/bin/env python3
"""Cross-language interoperability gate for proof exchange artifacts.

This gate enforces true bidirectional exchange for the `xor` and `state_machine`
example wrappers:
1. Rust-generated proof artifact verifies in Zig.
2. Zig-generated proof artifact verifies in Rust.
3. Tampered artifacts are rejected in both directions.

A machine-readable report is emitted under vectors/reports/.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Optional


ROOT = Path(__file__).resolve().parent.parent
REPORT_DEFAULT = ROOT / "vectors" / "reports" / "e2e_interop_report.json"
ARTIFACT_DIR_DEFAULT = ROOT / "vectors" / "reports" / "interop_artifacts"
RUST_MANIFEST = ROOT / "tools" / "stwo-interop-rs" / "Cargo.toml"

RUST_TOOLCHAIN_DEFAULT = "nightly-2025-07-14"
UPSTREAM_COMMIT = "a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2"
SCHEMA_VERSION = 1
EXCHANGE_MODE = "proof_exchange_json_wire_v1"
SUPPORTED_EXAMPLES = ("xor", "state_machine")
M31_MODULUS = 2147483647


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def trim_tail(text: str, limit: int = 2000) -> str:
    if len(text) <= limit:
        return text
    return text[-limit:]


def run_step(
    *,
    name: str,
    cmd: list[str],
    steps: list[dict[str, Any]],
    expect_failure: bool = False,
) -> None:
    start = time.perf_counter()
    proc = subprocess.run(
        cmd,
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
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
    steps.append(step)
    if succeeded:
        return

    expectation = "non-zero exit code" if expect_failure else "zero exit code"
    raise RuntimeError(
        f"{name} failed (expected {expectation}, got {proc.returncode})"
    )


def assert_artifact_metadata(artifact_path: Path, *, expected_generator: str, example: str) -> None:
    data = json.loads(artifact_path.read_text(encoding="utf-8"))

    schema_version = int(data.get("schema_version", -1))
    exchange_mode = data.get("exchange_mode")
    upstream_commit = data.get("upstream_commit")
    generator = data.get("generator")
    artifact_example = data.get("example")

    if schema_version != SCHEMA_VERSION:
        raise RuntimeError(
            f"{rel(artifact_path)} schema_version mismatch: expected {SCHEMA_VERSION}, got {schema_version}"
        )
    if exchange_mode != EXCHANGE_MODE:
        raise RuntimeError(
            f"{rel(artifact_path)} exchange_mode mismatch: expected {EXCHANGE_MODE}, got {exchange_mode}"
        )
    if upstream_commit != UPSTREAM_COMMIT:
        raise RuntimeError(
            f"{rel(artifact_path)} upstream_commit mismatch: expected {UPSTREAM_COMMIT}, got {upstream_commit}"
        )
    if generator != expected_generator:
        raise RuntimeError(
            f"{rel(artifact_path)} generator mismatch: expected {expected_generator}, got {generator}"
        )
    if artifact_example != example:
        raise RuntimeError(
            f"{rel(artifact_path)} example mismatch: expected {example}, got {artifact_example}"
        )


def tamper_proof_bytes_hex(src: Path, dst: Path) -> None:
    artifact = json.loads(src.read_text(encoding="utf-8"))
    proof_hex = artifact.get("proof_bytes_hex")
    if not isinstance(proof_hex, str) or len(proof_hex) == 0:
        raise RuntimeError(f"{rel(src)} missing proof_bytes_hex")

    # Deterministic one-nibble mutation that preserves hex encoding.
    first = proof_hex[0]
    replacement = "0" if first != "0" else "1"
    artifact["proof_bytes_hex"] = replacement + proof_hex[1:]

    dst.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def tamper_statement(src: Path, dst: Path, *, example: str) -> None:
    artifact = json.loads(src.read_text(encoding="utf-8"))

    if example == "xor":
        stmt = artifact.get("xor_statement")
        if not isinstance(stmt, dict):
            raise RuntimeError(f"{rel(src)} missing xor_statement")
        stmt["offset"] = int(stmt.get("offset", 0)) + 1
    elif example == "state_machine":
        stmt = artifact.get("state_machine_statement")
        if not isinstance(stmt, dict):
            raise RuntimeError(f"{rel(src)} missing state_machine_statement")
        public_input = stmt.get("public_input")
        if not isinstance(public_input, list) or len(public_input) < 2:
            raise RuntimeError(f"{rel(src)} invalid state_machine_statement.public_input")
        if not isinstance(public_input[1], list) or len(public_input[1]) < 1:
            raise RuntimeError(f"{rel(src)} invalid state_machine_statement.public_input[1]")
        public_input[1][0] = (int(public_input[1][0]) + 1) % M31_MODULUS
    else:
        raise RuntimeError(f"unsupported example for statement tamper: {example}")

    dst.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def run_example_case(
    *,
    example: str,
    artifact_dir: Path,
    rust_toolchain: str,
    all_steps: list[dict[str, Any]],
) -> dict[str, Any]:
    rust_artifact = artifact_dir / f"{example}_rust_to_zig.json"
    zig_artifact = artifact_dir / f"{example}_zig_to_rust.json"
    rust_statement_tampered = artifact_dir / f"{example}_rust_to_zig_statement_tampered.json"
    rust_tampered = artifact_dir / f"{example}_rust_to_zig_tampered.json"
    zig_statement_tampered = artifact_dir / f"{example}_zig_to_rust_statement_tampered.json"
    zig_tampered = artifact_dir / f"{example}_zig_to_rust_tampered.json"

    start_index = len(all_steps)

    run_step(
        name=f"{example}_rust_generate",
        cmd=[
            "cargo",
            f"+{rust_toolchain}",
            "run",
            "--manifest-path",
            str(RUST_MANIFEST),
            "--",
            "--mode",
            "generate",
            "--example",
            example,
            "--artifact",
            str(rust_artifact),
        ],
        steps=all_steps,
    )
    assert_artifact_metadata(rust_artifact, expected_generator="rust", example=example)

    run_step(
        name=f"{example}_rust_to_zig_verify",
        cmd=[
            "zig",
            "run",
            "src/interop_cli.zig",
            "--",
            "--mode",
            "verify",
            "--artifact",
            str(rust_artifact),
        ],
        steps=all_steps,
    )

    tamper_statement(rust_artifact, rust_statement_tampered, example=example)
    run_step(
        name=f"{example}_rust_to_zig_statement_tamper_reject",
        cmd=[
            "zig",
            "run",
            "src/interop_cli.zig",
            "--",
            "--mode",
            "verify",
            "--artifact",
            str(rust_statement_tampered),
        ],
        steps=all_steps,
        expect_failure=True,
    )

    tamper_proof_bytes_hex(rust_artifact, rust_tampered)
    run_step(
        name=f"{example}_rust_to_zig_tamper_reject",
        cmd=[
            "zig",
            "run",
            "src/interop_cli.zig",
            "--",
            "--mode",
            "verify",
            "--artifact",
            str(rust_tampered),
        ],
        steps=all_steps,
        expect_failure=True,
    )

    run_step(
        name=f"{example}_zig_generate",
        cmd=[
            "zig",
            "run",
            "src/interop_cli.zig",
            "--",
            "--mode",
            "generate",
            "--example",
            example,
            "--artifact",
            str(zig_artifact),
        ],
        steps=all_steps,
    )
    assert_artifact_metadata(zig_artifact, expected_generator="zig", example=example)

    run_step(
        name=f"{example}_zig_to_rust_verify",
        cmd=[
            "cargo",
            f"+{rust_toolchain}",
            "run",
            "--manifest-path",
            str(RUST_MANIFEST),
            "--",
            "--mode",
            "verify",
            "--artifact",
            str(zig_artifact),
        ],
        steps=all_steps,
    )

    tamper_statement(zig_artifact, zig_statement_tampered, example=example)
    run_step(
        name=f"{example}_zig_to_rust_statement_tamper_reject",
        cmd=[
            "cargo",
            f"+{rust_toolchain}",
            "run",
            "--manifest-path",
            str(RUST_MANIFEST),
            "--",
            "--mode",
            "verify",
            "--artifact",
            str(zig_statement_tampered),
        ],
        steps=all_steps,
        expect_failure=True,
    )

    tamper_proof_bytes_hex(zig_artifact, zig_tampered)
    run_step(
        name=f"{example}_zig_to_rust_tamper_reject",
        cmd=[
            "cargo",
            f"+{rust_toolchain}",
            "run",
            "--manifest-path",
            str(RUST_MANIFEST),
            "--",
            "--mode",
            "verify",
            "--artifact",
            str(zig_tampered),
        ],
        steps=all_steps,
        expect_failure=True,
    )

    return {
        "example": example,
        "status": "ok",
        "artifacts": {
            "rust_to_zig": rel(rust_artifact),
            "rust_to_zig_statement_tampered": rel(rust_statement_tampered),
            "rust_to_zig_tampered": rel(rust_tampered),
            "zig_to_rust": rel(zig_artifact),
            "zig_to_rust_statement_tampered": rel(zig_statement_tampered),
            "zig_to_rust_tampered": rel(zig_tampered),
        },
        "steps": [step["name"] for step in all_steps[start_index:]],
    }


def write_report(report_out: Path, report: dict[str, Any]) -> None:
    report_out.parent.mkdir(parents=True, exist_ok=True)
    report_out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    latest = report_out.parent / "latest_e2e_interop_report.json"
    if latest != report_out:
        shutil.copyfile(report_out, latest)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Cross-language proof exchange gate")
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
        help="Directory where generated/tampered artifacts are written",
    )
    parser.add_argument(
        "--rust-toolchain",
        default=RUST_TOOLCHAIN_DEFAULT,
        help="Rust nightly toolchain used for stwo prover builds",
    )
    parser.add_argument(
        "--examples",
        nargs="+",
        default=list(SUPPORTED_EXAMPLES),
        choices=SUPPORTED_EXAMPLES,
        help="Examples to include in the exchange matrix",
    )

    # Retained for compatibility with previous harness invocations.
    parser.add_argument("--count", type=int, default=256, help=argparse.SUPPRESS)
    parser.add_argument(
        "--skip-upstream-examples-check",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    steps: list[dict[str, Any]] = []
    cases: list[dict[str, Any]] = []
    failure: Optional[dict[str, Any]] = None
    started_at = time.time()

    artifact_dir = args.artifact_dir
    artifact_dir.mkdir(parents=True, exist_ok=True)

    try:
        run_step(
            name="rust_interop_tool_check",
            cmd=[
                "cargo",
                f"+{args.rust_toolchain}",
                "check",
                "--manifest-path",
                str(RUST_MANIFEST),
            ],
            steps=steps,
        )

        run_step(
            name="zig_interop_proof_wire_test",
            cmd=[
                "zig",
                "test",
                "src/stwo.zig",
                "--test-filter",
                "interop proof wire:",
            ],
            steps=steps,
        )
        run_step(
            name="zig_interop_artifact_test",
            cmd=[
                "zig",
                "test",
                "src/stwo.zig",
                "--test-filter",
                "interop artifact:",
            ],
            steps=steps,
        )

        for example in args.examples:
            case = run_example_case(
                example=example,
                artifact_dir=artifact_dir,
                rust_toolchain=args.rust_toolchain,
                all_steps=steps,
            )
            cases.append(case)

        status = "ok"
    except Exception as exc:  # pylint: disable=broad-except
        status = "failed"
        failure = {"message": str(exc)}

    report = {
        "status": status,
        "schema_version": SCHEMA_VERSION,
        "exchange_mode": EXCHANGE_MODE,
        "upstream_commit": UPSTREAM_COMMIT,
        "rust_toolchain": args.rust_toolchain,
        "summary": {
            "examples": args.examples,
            "cases_total": len(args.examples) * 2,
            "cases_passed": len(cases) * 2 if status == "ok" else len(cases) * 2,
            "tamper_cases_total": len(args.examples) * 4,
            "tamper_cases_passed": len(cases) * 4 if status == "ok" else len(cases) * 4,
            "steps_total": len(steps),
        },
        "cases": cases,
        "steps": steps,
        "artifacts": {
            "artifact_dir": rel(artifact_dir),
        },
        "failure": failure,
        "generated_at_unix": int(started_at),
        "duration_seconds": round(time.time() - started_at, 6),
    }

    write_report(args.report_out, report)
    return 0 if status == "ok" else 1


if __name__ == "__main__":
    raise SystemExit(main())
