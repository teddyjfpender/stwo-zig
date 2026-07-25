#!/usr/bin/env python3
"""Cross-language interoperability gate for proof exchange artifacts.

This gate enforces true bidirectional exchange for the `blake`, `plonk`,
`poseidon`, `xor`, `state_machine`, and `wide_fibonacci` example wrappers:
1. Rust-generated proof artifact verifies in Zig.
2. Zig-generated proof artifact verifies in Rust.
3. Tampered artifacts are rejected in both directions.

The exact upstream Plonk/LogUp protocol is additionally gated Zig-to-Rust:
the production Native CPU CLI generates the proof and pinned Rust Stwo
independently accepts it and rejects statement, shape, and proof mutations.

A machine-readable report is emitted under vectors/reports/.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

from typing import Any, Optional

try:
    from zig_protocol_lib.command import test_command
except ModuleNotFoundError:
    from scripts.zig_protocol_lib.command import test_command

try:
    from e2e_interop_lib import (
        ACTIVE_MUTATIONS,
        PLONK_LOGUP_ORACLE_MUTATIONS,
        archive_receipt,
        collect_provenance,
        coverage_manifest,
        mutate_artifact,
        plonk_logup_oracle_coverage_manifest,
        mutations_for_example,
        register_artifact,
    )
    from interop_cli_lib.command import build_command, installed_binary
except ModuleNotFoundError:
    from scripts.e2e_interop_lib import (
        ACTIVE_MUTATIONS,
        PLONK_LOGUP_ORACLE_MUTATIONS,
        archive_receipt,
        collect_provenance,
        coverage_manifest,
        mutate_artifact,
        plonk_logup_oracle_coverage_manifest,
        mutations_for_example,
        register_artifact,
    )
    from scripts.interop_cli_lib.command import build_command, installed_binary


ROOT = Path(
    os.environ.get("STWO_ZIG_EXECUTION_ROOT", Path(__file__).resolve().parents[2])
).resolve()
REPORT_DEFAULT = ROOT / "vectors" / "reports" / "e2e_interop_report.json"
ARTIFACT_DIR_DEFAULT = ROOT / "vectors" / "reports" / "interop_artifacts"
ARCHIVE_DIR_DEFAULT = ROOT / "vectors" / "reports" / "interop_history"
RUST_MANIFEST = ROOT / "tools" / "stwo-interop-rs" / "Cargo.toml"


def default_rust_binary() -> Path:
    """Where cargo actually writes the oracle: CARGO_TARGET_DIR wins when the
    harness (ci_scope_run.py warm cache) redirects the target directory."""
    target = os.environ.get("CARGO_TARGET_DIR")
    base = Path(target) if target else ROOT / "tools" / "stwo-interop-rs" / "target"
    return (base / "release" / "stwo-interop-rs").resolve()

RUST_TOOLCHAIN_DEFAULT = "nightly-2025-07-14"
UPSTREAM_COMMIT = "a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2"
SCHEMA_VERSION = 1
EXCHANGE_MODE = "proof_exchange_json_wire_v1"
SUPPORTED_EXAMPLES = ("blake", "plonk", "poseidon", "xor", "state_machine", "wide_fibonacci")
REJECTION_CLASS_VERIFIER = "verifier_semantic"
REJECTION_CLASS_PARSER = "parser"
REJECTION_CLASS_METADATA = "metadata_policy"
REJECTION_CLASS_ROBUSTNESS = "verifier_robustness"
REJECTION_CLASS_OTHER = "other"


def rel(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def trim_tail(text: str, limit: int = 2000) -> str:
    if len(text) <= limit:
        return text
    return text[-limit:]


def failure_diagnostics(report: dict[str, Any], report_path: Path) -> str:
    """Render the bounded evidence needed to diagnose a failed hosted gate."""
    failure = report.get("failure")
    message = failure.get("message") if isinstance(failure, dict) else None
    lines = [
        f"interop gate failed: {message or 'no failure message recorded'}",
        f"interop report: {report_path}",
    ]

    failed_steps = [
        step
        for step in report.get("steps", [])
        if isinstance(step, dict) and step.get("status") == "failed"
    ]
    if not failed_steps:
        lines.append("failed step: none recorded")
        return "\n".join(lines)

    step = failed_steps[-1]
    lines.append(
        "failed step: "
        f"{step.get('name', 'unknown')} return_code={step.get('return_code', 'unknown')}"
    )
    for stream_name in ("stdout_tail", "stderr_tail"):
        output = str(step.get(stream_name, "")).strip()
        if output:
            lines.extend((f"{stream_name}:", output))
    return "\n".join(lines)


def run_step(
    *,
    name: str,
    cmd: list[str],
    steps: list[dict[str, Any]],
    expect_failure: bool = False,
    required_rejection_class: Optional[str] = None,
) -> dict[str, Any]:
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
        "stdout_sha256": hashlib.sha256(proc.stdout.encode("utf-8")).hexdigest(),
        "stderr_sha256": hashlib.sha256(proc.stderr.encode("utf-8")).hexdigest(),
    }
    if expect_failure:
        step["rejection_class"] = classify_rejection(
            step["stdout_tail"],
            step["stderr_tail"],
            return_code=proc.returncode,
        )
        step["required_rejection_class"] = required_rejection_class
        if step["rejection_class"] == REJECTION_CLASS_ROBUSTNESS:
            succeeded = False
            step["status"] = "failed"
    steps.append(step)
    if succeeded:
        if required_rejection_class and step.get("rejection_class") != required_rejection_class:
            step["status"] = "failed"
            raise RuntimeError(
                f"{name} rejected with class {step.get('rejection_class')}, expected {required_rejection_class}"
            )
        return step

    expectation = "non-zero exit code" if expect_failure else "zero exit code"
    raise RuntimeError(
        f"{name} failed (expected {expectation}, got {proc.returncode})"
    )


def classify_rejection(
    stdout_tail: str,
    stderr_tail: str,
    *,
    return_code: int | None = None,
) -> str:
    combined = f"{stdout_tail}\n{stderr_tail}".lower()

    crash_markers = (
        "panicked at",
        "index out of bounds",
        "called `option::unwrap()` on a `none` value",
        "segmentation fault",
        "abort trap",
        "stack overflow",
    )
    if return_code is not None and (return_code < 0 or return_code == 101):
        return REJECTION_CLASS_ROBUSTNESS
    if any(marker in combined for marker in crash_markers):
        return REJECTION_CLASS_ROBUSTNESS

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
        "unsupportedprovemode",
        "unsupported prove mode",
    )
    if any(marker in combined for marker in metadata_markers):
        return REJECTION_CLASS_METADATA

    verifier_markers = (
        "oodsnotmatching",
        "statementnotsatisfied",
        "statement not satisfied",
        "invalidproofshape",
        "invalid proof shape",
        "invalidlogsize",
        "invalid log size",
        "invalid statement shape",
        "invalid state_machine statement",
        "invalid plonk_logup log_n_rows",
        "invalidclaimedsum",
        "invalid xor claimed_sum",
        "proofconfigmismatch",
        "proof pcs config does not match artifact pcs config",
        "deep-ali",
        "verify failed",
        "verification failed",
        "oods evaluation does not match",
        "not matching",
        "witnesstooshort",
        "merkleverificationerror",
        "fri verification",
        "verifier safety boundary",
        "unsupported pcs fold_step",
        "unsupported pcs lifting_log_size",
    )
    if any(marker in combined for marker in verifier_markers):
        return REJECTION_CLASS_VERIFIER

    return REJECTION_CLASS_OTHER


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


def runtime_command(binary: Path, *, mode: str, artifact: Path, example: str | None = None) -> list[str]:
    command = [str(binary), "--mode", mode]
    if example is not None:
        command.extend(("--example", example))
    command.extend(("--artifact", str(artifact)))
    return command


def prepare_generated_artifact(path: Path) -> None:
    """Retire output owned by a prior gate run before exclusive publication."""
    path.unlink(missing_ok=True)


def run_negative_matrix(
    *,
    example: str,
    direction: str,
    source_artifact: Path,
    verifier_binary: Path,
    artifact_dir: Path,
    all_steps: list[dict[str, Any]],
    artifact_records: list[dict[str, Any]],
    mutations: tuple[Any, ...] | None = None,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    applicable = mutations if mutations is not None else mutations_for_example(example)
    for spec in applicable:
        mutated = artifact_dir / f"{example}_{direction}_{spec.mutation_id}_tampered.json"
        mutate_artifact(source_artifact, mutated, spec, example=example)
        record = register_artifact(
            mutated,
            example=example,
            direction=direction,
            role="negative_mutation",
            mutation_id=spec.mutation_id,
        )
        artifact_records.append(record)
        step = run_step(
            name=f"{example}_{direction}_{spec.mutation_id}_tamper_reject",
            cmd=runtime_command(verifier_binary, mode="verify", artifact=mutated),
            steps=all_steps,
            expect_failure=True,
            required_rejection_class=spec.required_rejection_class,
        )
        step.update(
            {
                "mutation_id": spec.mutation_id,
                "mutation_category": spec.category,
                "artifact_sha256": record["artifact_sha256"],
            }
        )
        results.append(
            {
                "mutation_id": spec.mutation_id,
                "category": spec.category,
                "field_path": spec.field_path,
                "status": "rejected",
                "rejection_class": step["rejection_class"],
                "artifact": rel(mutated),
                "artifact_sha256": record["artifact_sha256"],
                "proof_sha256": record["proof_sha256"],
            }
        )
    return results


def run_plonk_logup_oracle_case(
    *,
    artifact_dir: Path,
    native_cpu_binary: Path,
    rust_binary: Path,
    all_steps: list[dict[str, Any]],
    artifact_records: list[dict[str, Any]],
) -> dict[str, Any]:
    example = "plonk_logup"
    direction = "zig_to_rust"
    artifact = artifact_dir / f"{example}_{direction}.json"
    prepare_generated_artifact(artifact)
    run_step(
        name=f"{example}_zig_generate",
        cmd=[
            str(native_cpu_binary),
            "prove",
            "--example",
            example,
            "--log-n-rows",
            "4",
            "--protocol",
            "smoke",
            "--output",
            str(artifact),
        ],
        steps=all_steps,
    )
    assert_artifact_metadata(artifact, expected_generator="zig", example=example)
    record = register_artifact(
        artifact,
        example=example,
        direction=direction,
        role="accepted_proof",
    )
    artifact_records.append(record)
    verify_step = run_step(
        name=f"{example}_{direction}_verify",
        cmd=runtime_command(rust_binary, mode="verify", artifact=artifact),
        steps=all_steps,
    )
    verify_step["artifact_sha256"] = record["artifact_sha256"]
    negative_matrix = run_negative_matrix(
        example=example,
        direction=direction,
        source_artifact=artifact,
        verifier_binary=rust_binary,
        artifact_dir=artifact_dir,
        all_steps=all_steps,
        artifact_records=artifact_records,
        mutations=PLONK_LOGUP_ORACLE_MUTATIONS,
    )
    return {
        "example": example,
        "status": "ok",
        "directions": [
            {
                "direction": direction,
                "artifact": rel(artifact),
                "artifact_sha256": record["artifact_sha256"],
                "proof_sha256": record["proof_sha256"],
                "negative_matrix": negative_matrix,
            }
        ],
    }


def run_exchange_direction(
    *,
    example: str,
    direction: str,
    generator: str,
    generator_binary: Path,
    verifier_binary: Path,
    artifact_dir: Path,
    all_steps: list[dict[str, Any]],
    artifact_records: list[dict[str, Any]],
) -> dict[str, Any]:
    artifact = artifact_dir / f"{example}_{direction}.json"
    prepare_generated_artifact(artifact)
    command = runtime_command(
        generator_binary,
        mode="generate",
        artifact=artifact,
        example=example,
    )
    if example == "blake":
        command.extend(("--pow-bits", "10"))
    run_step(
        name=f"{example}_{generator}_generate",
        cmd=command,
        steps=all_steps,
    )
    assert_artifact_metadata(artifact, expected_generator=generator, example=example)
    record = register_artifact(
        artifact,
        example=example,
        direction=direction,
        role="accepted_proof",
    )
    artifact_records.append(record)
    verify_step = run_step(
        name=f"{example}_{direction}_verify",
        cmd=runtime_command(verifier_binary, mode="verify", artifact=artifact),
        steps=all_steps,
    )
    verify_step["artifact_sha256"] = record["artifact_sha256"]
    negative_matrix = run_negative_matrix(
        example=example,
        direction=direction,
        source_artifact=artifact,
        verifier_binary=verifier_binary,
        artifact_dir=artifact_dir,
        all_steps=all_steps,
        artifact_records=artifact_records,
    )
    return {
        "direction": direction,
        "artifact": rel(artifact),
        "artifact_sha256": record["artifact_sha256"],
        "proof_sha256": record["proof_sha256"],
        "negative_matrix": negative_matrix,
    }


def run_example_case(
    *,
    example: str,
    artifact_dir: Path,
    zig_binary: Path,
    rust_binary: Path,
    all_steps: list[dict[str, Any]],
    artifact_records: list[dict[str, Any]],
) -> dict[str, Any]:
    start_index = len(all_steps)
    rust_to_zig = run_exchange_direction(
        example=example,
        direction="rust_to_zig",
        generator="rust",
        generator_binary=rust_binary,
        verifier_binary=zig_binary,
        artifact_dir=artifact_dir,
        all_steps=all_steps,
        artifact_records=artifact_records,
    )
    zig_to_rust = run_exchange_direction(
        example=example,
        direction="zig_to_rust",
        generator="zig",
        generator_binary=zig_binary,
        verifier_binary=rust_binary,
        artifact_dir=artifact_dir,
        all_steps=all_steps,
        artifact_records=artifact_records,
    )
    return {
        "example": example,
        "status": "ok",
        "directions": [rust_to_zig, zig_to_rust],
        "steps": [step["name"] for step in all_steps[start_index:]],
    }


def write_report(report_out: Path, report: dict[str, Any]) -> None:
    report_out.parent.mkdir(parents=True, exist_ok=True)
    report_out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    latest = report_out.parent / "latest_e2e_interop_report.json"
    if latest != report_out:
        shutil.copyfile(report_out, latest)


def compute_summary(
    *,
    examples: list[str],
    steps: list[dict[str, Any]],
    include_plonk_logup_oracle: bool = False,
) -> dict[str, Any]:
    step_by_name = {str(step.get("name", "")): step for step in steps}

    cases_total = len(examples) * 2 + int(include_plonk_logup_oracle)
    cases_executed = 0
    cases_passed = 0
    for example in examples:
        for name in (
            f"{example}_rust_to_zig_verify",
            f"{example}_zig_to_rust_verify",
        ):
            step = step_by_name.get(name)
            if step is None:
                continue
            cases_executed += 1
            if step.get("status") == "ok":
                cases_passed += 1
    if include_plonk_logup_oracle:
        plonk_logup_step = step_by_name.get("plonk_logup_zig_to_rust_verify")
        if plonk_logup_step is not None:
            cases_executed += 1
            if plonk_logup_step.get("status") == "ok":
                cases_passed += 1
    cases_failed = cases_executed - cases_passed

    tamper_steps = [step for step in steps if step.get("expect_failure")]
    tamper_rejection_counts: dict[str, int] = {}
    for step in tamper_steps:
        rejection_class = str(step.get("rejection_class", REJECTION_CLASS_OTHER))
        tamper_rejection_counts[rejection_class] = tamper_rejection_counts.get(rejection_class, 0) + 1

    tamper_cases_total = sum(
        len(mutations_for_example(example)) * 2 for example in examples
    )
    if include_plonk_logup_oracle:
        tamper_cases_total += len(PLONK_LOGUP_ORACLE_MUTATIONS)
    tamper_cases_executed = len(tamper_steps)
    tamper_cases_passed = len([step for step in tamper_steps if step.get("status") == "ok"])
    tamper_cases_failed = tamper_cases_executed - tamper_cases_passed

    return {
        "examples": [
            *examples,
            *(["plonk_logup"] if include_plonk_logup_oracle else []),
        ],
        "cases_total": cases_total,
        "cases_executed": cases_executed,
        "cases_passed": cases_passed,
        "cases_failed": cases_failed,
        "tamper_cases_total": tamper_cases_total,
        "tamper_cases_executed": tamper_cases_executed,
        "tamper_cases_passed": tamper_cases_passed,
        "tamper_cases_failed": tamper_cases_failed,
        "tamper_rejection_classes": tamper_rejection_counts,
        "steps_total": len(steps),
    }


def combined_mutation_coverage(examples: list[str]) -> dict[str, Any]:
    coverage = coverage_manifest(examples)
    exact = plonk_logup_oracle_coverage_manifest()
    coverage["applicable"].extend(exact["applicable"])
    coverage["not_applicable"].extend(exact["not_applicable"])
    coverage["required_cases"] += exact["required_cases"]
    return coverage


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
        "--archive-dir",
        type=Path,
        default=ARCHIVE_DIR_DEFAULT,
        help="Content-addressed directory for exact gated artifacts and receipts",
    )
    parser.add_argument(
        "--rust-toolchain",
        default=RUST_TOOLCHAIN_DEFAULT,
        help="Rust nightly toolchain used for stwo prover builds",
    )
    parser.add_argument(
        "--rust-binary",
        type=Path,
        default=None,
        help="Prebuilt content-addressed Rust oracle; skips Cargo compilation",
    )
    parser.add_argument(
        "--zig-optimize",
        default="ReleaseFast",
        choices=("ReleaseFast", "ReleaseSafe"),
        help="Optimization mode for the exact Zig verifier binary",
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
    artifact_records: list[dict[str, Any]] = []
    failure: Optional[dict[str, Any]] = None
    provenance: Optional[dict[str, Any]] = None
    started_at = time.time()

    artifact_dir = args.artifact_dir
    artifact_dir.mkdir(parents=True, exist_ok=True)

    try:
        rust_binary = args.rust_binary.resolve() if args.rust_binary is not None else default_rust_binary()
        if args.rust_binary is None:
            run_step(
                name="rust_interop_tool_build",
                cmd=[
                    "cargo",
                    f"+{args.rust_toolchain}",
                    "build",
                    "--release",
                    "--locked",
                    "--manifest-path",
                    str(RUST_MANIFEST),
                ],
                steps=steps,
            )
        run_step(
            name="zig_interop_tool_build",
            cmd=build_command(args.zig_optimize),
            steps=steps,
        )
        run_step(
            name="zig_native_cpu_product_build",
            cmd=["zig", "build", "stwo-native-cpu", f"-Doptimize={args.zig_optimize}"],
            steps=steps,
        )
        zig_binary = installed_binary(ROOT)
        native_cpu_binary = (ROOT / "zig-out/bin/stwo-zig-native-cpu").resolve()
        if (
            not zig_binary.is_file()
            or not native_cpu_binary.is_file()
            or not rust_binary.is_file()
        ):
            raise RuntimeError("interop build did not produce every exact verifier binary")

        run_step(
            name="zig_interop_proof_wire_test",
            cmd=test_command("src/stwo.zig", "--test-filter", "interop proof wire:"),
            steps=steps,
        )
        run_step(
            name="zig_interop_artifact_test",
            cmd=test_command("src/stwo.zig", "--test-filter", "interop artifact:"),
            steps=steps,
        )

        gate_sources = {
            Path(__file__).resolve(),
            ROOT / "scripts/e2e_interop_lib/evidence.py",
            ROOT / "scripts/e2e_interop_lib/mutations.py",
            ROOT / "src/interop/examples_artifact.zig",
            ROOT / "src/interop/examples_artifact_verifier.zig",
            ROOT / "src/interop/proof_wire.zig",
            ROOT / "src/examples/plonk_logup.zig",
            *list((ROOT / "src/examples/plonk_logup").glob("*.zig")),
            ROOT / "src/products/native_cpu/app.zig",
            ROOT / "src/products/native_cpu/cli.zig",
            ROOT / "src/tools/interop/artifact.zig",
            ROOT / "tools/stwo-interop-rs/Cargo.toml",
            ROOT / "tools/stwo-interop-rs/Cargo.lock",
            *list((ROOT / "tools/stwo-interop-rs/src").rglob("*.rs")),
            ROOT / "tools/stwo-interop-rs/upstream_blake_provenance.json",
        }
        provenance = collect_provenance(
            root=ROOT,
            rust_toolchain=args.rust_toolchain,
            upstream_commit=UPSTREAM_COMMIT,
            zig_optimize=args.zig_optimize,
            zig_binary=zig_binary,
            native_cpu_binary=native_cpu_binary,
            rust_binary=rust_binary,
            gate_sources=gate_sources,
        )
        if not provenance["repository"]["clean"]:
            raise RuntimeError("formal interop evidence requires a clean repository")
        for example in args.examples:
            case = run_example_case(
                example=example,
                artifact_dir=artifact_dir,
                zig_binary=zig_binary,
                rust_binary=rust_binary,
                all_steps=steps,
                artifact_records=artifact_records,
            )
            cases.append(case)
        cases.append(
            run_plonk_logup_oracle_case(
                artifact_dir=artifact_dir,
                native_cpu_binary=native_cpu_binary,
                rust_binary=rust_binary,
                all_steps=steps,
                artifact_records=artifact_records,
            )
        )

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
        "summary": compute_summary(
            examples=list(args.examples),
            steps=steps,
            include_plonk_logup_oracle=True,
        ),
        "mutation_coverage": combined_mutation_coverage(list(args.examples)),
        "cases": cases,
        "steps": steps,
        "artifacts": {
            "artifact_dir": rel(artifact_dir),
        },
        "failure": failure,
        "generated_at_unix": int(started_at),
        "duration_seconds": round(time.time() - started_at, 6),
    }

    if provenance is not None:
        try:
            report["archive"] = archive_receipt(
                archive_dir=args.archive_dir,
                report=report,
                artifact_records=artifact_records,
                provenance=provenance,
                path_replacements={
                    str(artifact_dir.resolve()): "$ARTIFACT_DIR",
                    str(args.archive_dir.resolve()): "$ARCHIVE_DIR",
                    str(args.report_out.resolve()): "$REPORT_OUT",
                    str(ROOT.resolve()): ".",
                },
            )
        except Exception as exc:  # pylint: disable=broad-except
            report["status"] = "failed"
            report["failure"] = {"message": f"evidence archive failed: {exc}"}
            report["archive"] = None
    else:
        report["archive"] = None

    write_report(args.report_out, report)
    if report["status"] != "ok":
        print(failure_diagnostics(report, args.report_out), file=sys.stderr, flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
