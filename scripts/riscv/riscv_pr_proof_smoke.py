#!/usr/bin/env python3
"""Produce and independently verify a bounded RISC-V proof corpus for PR CI.

This is a correctness gate, not a performance benchmark. The selected programs
exercise branch, memory, cross-shard, and crypto shapes while keeping the warm
CI path short. Pinned Sail/Spike evidence owns the external ISA boundary; AIR
soundness and proof acceptance remain separate obligations.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.riscv import riscv_cli_admission  # noqa: E402
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAX_OUTPUT_BYTES = 1 << 20
COMMAND_TIMEOUT_SECONDS = 120


class SmokeError(ValueError):
    pass


@dataclass(frozen=True)
class Workload:
    name: str
    elf: str
    expected_steps: int
    structural_role: str
    input_path: str | None = None


WORKLOADS = (
    Workload(
        "branch_fib",
        "vectors/riscv_elfs/branch_fib.elf",
        144,
        "branch control-flow and multi-family composition",
    ),
    Workload(
        "memcpy_loop",
        "vectors/riscv_elfs/memcpy_loop.elf",
        2_126,
        "load/store and memory-commitment composition",
    ),
    Workload(
        "multi_shard_addi",
        "vectors/riscv_elfs/multi_shard_addi.elf",
        131_078,
        "cross-shard state and LogUp placement",
    ),
    Workload(
        "sha2_input_128B",
        "vectors/riscv_elfs/crypto/sha2_input.elf",
        14_034,
        "wide crypto execution and high-log polynomial evaluation",
        "vectors/riscv_elfs/crypto/inputs/msg_128.bin",
    ),
)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def strict_json_bytes(raw: bytes, label: str) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise SmokeError(f"{label} repeats JSON field {key!r}")
            value[key] = item
        return value

    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SmokeError(f"{label} is not valid UTF-8 JSON: {error}") from error
    if not isinstance(value, dict):
        raise SmokeError(f"{label} root is not an object")
    return value


def strict_json_file(path: Path, label: str) -> dict[str, Any]:
    if not path.is_file() or path.stat().st_size > MAX_OUTPUT_BYTES:
        raise SmokeError(f"{label} is missing or oversized")
    return strict_json_bytes(path.read_bytes(), label)


def require_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise SmokeError(f"{label} is not a lowercase SHA-256 digest")
    return value


def run_command(argv: list[str]) -> tuple[subprocess.CompletedProcess[bytes], int]:
    started = time.monotonic_ns()
    try:
        result = subprocess.run(
            argv,
            cwd=ROOT,
            check=False,
            capture_output=True,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    except subprocess.TimeoutExpired as error:
        raise SmokeError(f"command timed out: {' '.join(argv)}") from error
    duration_ns = time.monotonic_ns() - started
    if len(result.stdout) > MAX_OUTPUT_BYTES or len(result.stderr) > MAX_OUTPUT_BYTES:
        raise SmokeError(f"command output is oversized: {' '.join(argv)}")
    if result.returncode != 0:
        diagnostic = (result.stderr or result.stdout).decode(errors="replace").strip()
        raise SmokeError(
            f"command failed ({result.returncode}): {' '.join(argv)}\n{diagnostic[-4096:]}"
        )
    return result, duration_ns


def require_fields(value: dict[str, Any], expected: dict[str, Any]) -> None:
    for key, item in expected.items():
        if type(value.get(key)) is not type(item) or json.dumps(value[key], sort_keys=True) != json.dumps(item, sort_keys=True):
            raise SmokeError(f"full-width {key} drifted")


def full_width_fields(value: dict[str, Any], workload: Workload) -> None:
    # Actual full-width serializers, not the retained artifact4/5 JSON envelopes.
    if any(key in value for key in ("transcript_state_blake2s", "transcript_receipt", "statement_sha256",
                                    "artifact_kind", "artifact_schema_version")):
        raise SmokeError("mixed full-width and retained report fields")
    require_fields(value, dict(proof_suite="blake3", artifact_magic="B3RVART1",
        execution_profile="rv32im_zkvm_v1", release_status="experimental_full_width",
        security_policy="functional", total_steps=workload.expected_steps,
        csp_ecdsa=False, signer_calls=0, keccak_calls=0, halt_flag=True,
        elf_sha256=sha256_file(ROOT / workload.elf),
        input_sha256=sha256_file(ROOT / workload.input_path) if workload.input_path else sha256_bytes(b"")))
    config = value.get("pcs_config")
    if not isinstance(config, dict):
        raise SmokeError("full-width PCS configuration missing")
    normalized = {"lifting_log_size": None, **config}
    expected = dict(pow_bits=10, lifting_log_size=None, fri_config=dict(log_blowup_factor=1,
        log_last_layer_degree_bound=0, n_queries=3, fold_step=1))
    if json.dumps(normalized, sort_keys=True) != json.dumps(expected, sort_keys=True):
        raise SmokeError("full-width functional PCS configuration drifted")
    for key in ("statement_blake3", "transcript_digest_blake3", "proof_sha256", "executable_sha256", "output_sha256"):
        require_sha256(value.get(key), key)
    for key in ("proof_bytes", "output_len"):
        if type(value.get(key)) is not int or value[key] < (1 if key == "proof_bytes" else 0):
            raise SmokeError(f"full-width {key} invalid")


def validate_full_width_report(report, workload, commit, allow_dirty, admission) -> tuple[str, str]:
    full_width_fields(report, workload)
    require_fields(report, dict(schema="riscv_full_width_execution_v2", mode="prove", backend="cpu",
        experimental=admission.experimental, verified_in_process=True, recursion_enabled=False,
        warmups=0, samples=1, verified_samples=1, profiled=False, profile_kind="phase_timings",
        implementation_commit=commit, timing_unit="nanoseconds",
        timing_partition="execution+witness+admission+proving+artifact_encoding+fresh_verification"))
    if report.get("implementation_dirty") is not False and (not allow_dirty or report.get("implementation_dirty") is not True):
        raise SmokeError("full-width dirty implementation")
    phases = ("execution_ns", "witness_ns", "admission_ns", "proving_ns", "artifact_encoding_ns", "fresh_verification_ns")
    timings = report.get("timings")
    if not isinstance(timings, list) or len(timings) != 1 or not isinstance(timings[0], dict):
        raise SmokeError("full-width timing sample count invalid")
    sample = timings[0]
    if (set(sample) != {*phases, "total_ns"} or any(type(v) is not int or v < 0 for v in sample.values())
            or any(sample[p] <= 0 for p in ("proving_ns", "fresh_verification_ns", "total_ns"))
            or sum(sample[p] for p in phases) != sample["total_ns"]):
        raise SmokeError("full-width timing partition invalid")
    median = report.get("median_seconds")
    if (type(median) not in (int, float) or not math.isfinite(median)
            or not math.isclose(median, sample["total_ns"] / 1e9, rel_tol=1e-12, abs_tol=1e-12)):
        raise SmokeError("full-width timing median invalid")
    if json.dumps(report.get("proof_device_counts"), sort_keys=True) != json.dumps([{"dispatches": 0, "cpu_fallbacks": 0}], sort_keys=True):
        raise SmokeError("full-width CPU proof claims device work")
    return report["statement_blake3"], report["transcript_digest_blake3"]


def verify_pairing(report: dict[str, Any]) -> tuple[str, int]:
    if report.get("schema") == "riscv_prove_v1":
        return "riscv_verify_v1", 4
    if report.get("schema") == "riscv_prove_v2":
        return "riscv_verify_v2", 5
    raise SmokeError("unexpected prove-report schema")


def transcript_digest(value: dict[str, Any], modern: bool) -> str:
    if any(key in value for key in ("transcript_digest_blake3", "statement_blake3", "artifact_magic")):
        raise SmokeError("mixed retained and full-width report fields")
    legacy, receipt = value.get("transcript_state_blake2s"), value.get("transcript_receipt")
    if modern:
        if (legacy is not None or not isinstance(receipt, dict)
                or receipt.get("suite") != "blake3"
                or type(receipt.get("version")) is not int or receipt["version"] != 2):
            raise SmokeError("invalid transcript_receipt suite/version or mixed transcript fields")
        return require_sha256(receipt.get("digest"), "transcript_receipt digest")
    if receipt is not None:
        raise SmokeError("mixed or unexpected transcript_receipt")
    return require_sha256(legacy, "transcript_state_blake2s")


def validate_prove_report(
    report: dict[str, Any], workload: Workload, commit: str, allow_dirty: bool,
    admission: riscv_cli_admission.Admission,
) -> tuple[str, str]:
    if report.get("schema") == "riscv_full_width_execution_v2":
        return validate_full_width_report(report, workload, commit, allow_dirty, admission)
    _, artifact_version = verify_pairing(report)
    if (
        report.get("release_status") != admission.release_status
        or report.get("experimental") is not admission.experimental
    ):
        raise SmokeError(f"{workload.name}: PR smoke admission differs from CLI registry")
    if report.get("verified_in_process") is not True:
        raise SmokeError(f"{workload.name}: prover did not complete its in-process verification")
    if report.get("total_steps") != workload.expected_steps:
        raise SmokeError(
            f"{workload.name}: step count drifted: "
            f"expected {workload.expected_steps}, got {report.get('total_steps')}"
        )
    components = report.get("n_components")
    if not isinstance(components, int) or components < 2:
        raise SmokeError(f"{workload.name}: proof did not exercise a component composition")
    if report.get("implementation_commit") != commit:
        raise SmokeError(f"{workload.name}: prove report is not bound to HEAD")
    if report.get("implementation_dirty") is not False and not allow_dirty:
        raise SmokeError(f"{workload.name}: CI prover reports a dirty implementation")
    statement = require_sha256(report.get("statement_sha256"), f"{workload.name} statement")
    transcript = transcript_digest(report, artifact_version == 5)
    require_sha256(report.get("executable_sha256"), f"{workload.name} executable")
    for field in ("proving_seconds", "verification_seconds", "total_seconds"):
        value = report.get(field)
        if not isinstance(value, (int, float)) or value <= 0:
            raise SmokeError(f"{workload.name}: invalid {field}")
    return statement, transcript


def validate_verify_receipt(
    receipt: dict[str, Any], report: dict[str, Any], statement: str, transcript: str,
    workload: Workload, commit: str, allow_dirty: bool,
    admission: riscv_cli_admission.Admission,
) -> None:
    if report.get("schema") == "riscv_full_width_execution_v2":
        if validate_full_width_report(report, workload, commit, allow_dirty, admission) != (statement, transcript):
            raise SmokeError("full-width validated report digests drifted")
        full_width_fields(receipt, workload)
        require_fields(receipt, dict(schema="riscv_full_width_verify_v1", status="verified"))
        require_fields(receipt, {key: report[key] for key in ("statement_blake3", "transcript_digest_blake3",
            "implementation_commit", "executable_sha256", "implementation_dirty", "proof_bytes", "proof_sha256",
            "output_len", "output_sha256")})
        return
    schema, artifact_version = verify_pairing(report)
    if transcript_digest(report, artifact_version == 5) != transcript:
        raise SmokeError(f"{workload.name}: validated report transcript drifted")
    expected = {
        "schema": schema,
        "status": "verified",
        "artifact_kind": "stwo_riscv_proof",
        "artifact_schema_version": artifact_version,
        "release_status": admission.release_status,
        "security_policy": "functional",
        "statement_sha256": statement,
        "implementation_commit": commit,
        "executable_sha256": report["executable_sha256"],
    }
    for field, value in expected.items():
        if receipt.get(field) != value:
            raise SmokeError(f"{workload.name}: verify receipt field {field} drifted")
    if type(receipt.get("artifact_schema_version")) is not int:
        raise SmokeError(f"{workload.name}: invalid artifact_schema_version")
    if transcript_digest(receipt, artifact_version == 5) != transcript:
        raise SmokeError(f"{workload.name}: verify receipt transcript_state_blake2s/transcript_receipt drifted")
    if receipt.get("implementation_dirty") is not False and not allow_dirty:
        raise SmokeError(f"{workload.name}: verifier reports a dirty implementation")
    proof_bytes = receipt.get("proof_bytes")
    if not isinstance(proof_bytes, int) or proof_bytes <= 0:
        raise SmokeError(f"{workload.name}: verifier reported an empty proof")
    require_sha256(receipt.get("proof_sha256"), f"{workload.name} proof")


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_bytes(encoded)
    os.replace(temporary, path)


def run_workload(
    cli: Path, workload: Workload, artifact_dir: Path, commit: str, allow_dirty: bool,
    admission: riscv_cli_admission.Admission,
) -> dict[str, Any]:
    elf = ROOT / workload.elf
    input_path = ROOT / workload.input_path if workload.input_path else None
    for path in (elf, input_path):
        if path is not None and not path.is_file():
            raise SmokeError(f"{workload.name}: missing input {path}")

    proof_path = artifact_dir / f"{workload.name}.proof.json"
    prove_report_path = artifact_dir / f"{workload.name}.prove.json"
    verify_receipt_path = artifact_dir / f"{workload.name}.verify.json"
    prove_command = [
        str(cli), "prove", "--elf", str(elf), "--backend", "cpu",
        "--protocol", "functional", "--output", str(proof_path),
        "--report-out", str(prove_report_path), *admission.arguments,
    ]
    if input_path is not None:
        prove_command.extend(["--input", str(input_path)])
    prove_result, prove_duration_ns = run_command(prove_command)
    report = strict_json_file(prove_report_path, f"{workload.name} prove report")
    statement, transcript = validate_prove_report(
        report, workload, commit, allow_dirty, admission,
    )
    if not proof_path.is_file() or proof_path.stat().st_size == 0:
        raise SmokeError(f"{workload.name}: prover did not retain a proof artifact")

    verify_command = [
        str(cli), "verify", "--artifact", str(proof_path),
        "--elf", str(elf),
        "--protocol", "functional", "--expect-statement-digest", statement,
    ]
    if input_path is not None:
        verify_command.extend(["--input", str(input_path)])
    if report.get("schema") == "riscv_full_width_execution_v2":
        if report["proof_bytes"] != proof_path.stat().st_size or report["proof_sha256"] != sha256_file(proof_path):
            raise SmokeError(f"{workload.name}: retained artifact differs from prove report")
    verify_result, verify_duration_ns = run_command(verify_command)
    verify_receipt_path.write_bytes(verify_result.stdout)
    receipt = strict_json_bytes(verify_result.stdout, f"{workload.name} verify receipt")
    validate_verify_receipt(
        receipt, report, statement, transcript, workload, commit, allow_dirty,
        admission,
    )
    return {
        "name": workload.name,
        "structural_role": workload.structural_role,
        "elf": workload.elf,
        "elf_sha256": sha256_file(elf),
        "input": workload.input_path,
        "input_sha256": sha256_file(input_path) if input_path is not None else None,
        "expected_steps": workload.expected_steps,
        "statement_sha256": statement,
        "proof_artifact_sha256": sha256_file(proof_path),
        "proof_bytes_sha256": receipt["proof_sha256"],
        "prove_duration_ns": prove_duration_ns,
        "verify_duration_ns": verify_duration_ns,
        "prove_stdout_sha256": sha256_bytes(prove_result.stdout),
        "prove_stderr_sha256": sha256_bytes(prove_result.stderr),
        "verify_stdout_sha256": sha256_bytes(verify_result.stdout),
        "verify_stderr_sha256": sha256_bytes(verify_result.stderr),
        "proof_path": proof_path.name,
        "prove_report_path": prove_report_path.name,
        "verify_receipt_path": verify_receipt_path.name,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--report-out", type=Path, required=True)
    parser.add_argument(
        "--workload", action="append", choices=[item.name for item in WORKLOADS],
        help="run only the named workload; repeat to select multiple",
    )
    parser.add_argument("--allow-dirty", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)

    try:
        cli = args.cli.resolve(strict=True)
        if not cli.is_file():
            raise SmokeError("CLI is not a regular file")
        admission = riscv_cli_admission.resolve(cli, cwd=ROOT)
        artifact_dir = args.artifact_dir.resolve()
        artifact_dir.mkdir(parents=True, exist_ok=False)
        commit_result, _ = run_command(["git", "rev-parse", "HEAD"])
        commit = commit_result.stdout.decode().strip()
        if SHA256_RE.fullmatch(commit) is None and re.fullmatch(r"[0-9a-f]{40}", commit) is None:
            raise SmokeError("HEAD is not a Git commit digest")
        selected_names = set(args.workload or ())
        selected = [item for item in WORKLOADS if not selected_names or item.name in selected_names]
        rows = []
        started = time.monotonic_ns()
        for index, workload in enumerate(selected, 1):
            print(f"riscv proof smoke [{index}/{len(selected)}]: {workload.name}", flush=True)
            rows.append(run_workload(
                cli, workload, artifact_dir, commit, args.allow_dirty, admission,
            ))
        report = {
            "schema": "riscv_pr_proof_smoke_v1",
            "status": "PASS",
            "commit": commit,
            "cli": str(cli),
            "cli_sha256": sha256_file(cli),
            "protocol": "functional",
            "release_status": admission.release_status,
            "experimental": admission.experimental,
            "oracle_boundary": (
                "independent Zig artifact verification plus separately gated pinned "
                "Sail/Spike corpus evidence; finite ISA agreement is not universal "
                "AIR refinement or independent proof-system verification"
            ),
            "duration_ns": time.monotonic_ns() - started,
            "workloads": rows,
        }
        atomic_json(args.report_out.resolve(), report)
    except (
        OSError,
        SmokeError,
        riscv_cli_admission.AdmissionError,
        subprocess.SubprocessError,
    ) as error:
        print(f"riscv proof smoke: FAIL: {error}", file=sys.stderr)
        return 1
    print(f"riscv proof smoke: PASS ({len(rows)} independently verified proofs)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
