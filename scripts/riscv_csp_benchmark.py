#!/usr/bin/env python3
"""Run the pinned EthProofs CSP hash suite through the RISC-V CPU product.

The ordinary benchmark is self-contained: committed inputs and RV32IM guest
ELFs are authenticated by ``vectors/riscv_csp/manifest-v1.json``.  Passing
``--audit-csp-source`` additionally checks an external checkout of the pinned
CSP repository and regenerates every canonical input with its own utility.

The CSP-compatible proving duration is execution + witness construction + proof
generation.  Verification is reported separately.  The production CLI still
self-verifies every sample before publication; its internal stage timers keep
that mandatory verification out of the proving-duration metric.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import re
import struct
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import riscv_cli_admission  # noqa: E402


SCHEMA = "stwo_riscv_csp_benchmark_v1"
MANIFEST = ROOT / "vectors" / "riscv_csp" / "manifest-v1.json"
DEFAULT_REPORT = ROOT / "vectors" / "reports" / "riscv_csp_benchmark_report.json"
DEFAULT_CLI = ROOT / "zig-out" / "bin" / "stwo-zig-riscv-cpu"
DEFAULT_TRACE_CLI = ROOT / "zig-out" / "bin" / "riscv-trace-dump"
TARGET_ORDER = ("sha256", "keccak")
CANONICAL_SIZES = (128, 256, 512, 1024, 2048)
SECURE_PCS_CONFIG = {
    "pow_bits": 26,
    "fri_config": {
        "log_blowup_factor": 1,
        "log_last_layer_degree_bound": 0,
        "n_queries": 70,
        "fold_step": 1,
    },
    "lifting_log_size": None,
}
MAX_CAPTURE_BYTES = 16 * 1024 * 1024
HEX_32 = re.compile(r"^[0-9a-f]{64}$")
HEX_40 = re.compile(r"^[0-9a-f]{40}$")


class BenchmarkError(RuntimeError):
    """The suite cannot produce trustworthy benchmark evidence."""


@dataclass(frozen=True)
class Case:
    target: str
    input_size: int
    input_path: Path
    input_sha256: str
    expected_digest: str
    expected_cycles: int
    guest_path: Path
    guest_sha256: str
    guest_bytes: int
    uses_precompile: bool


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise BenchmarkError(f"JSON repeats field {key!r}")
        result[key] = value
    return result


def load_json(path: Path) -> Any:
    raw = path.read_bytes()
    if len(raw) > MAX_CAPTURE_BYTES:
        raise BenchmarkError(f"oversized JSON input: {path}")
    try:
        return json.loads(raw, object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BenchmarkError(f"invalid JSON in {path}: {error}") from error


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _repo_path(raw: Any, label: str) -> Path:
    if not isinstance(raw, str) or not raw or Path(raw).is_absolute():
        raise BenchmarkError(f"{label} is not a repository-relative path")
    resolved = (ROOT / raw).resolve()
    try:
        resolved.relative_to(ROOT.resolve())
    except ValueError as error:
        raise BenchmarkError(f"{label} escapes the repository") from error
    return resolved


def _exact_fields(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        raise BenchmarkError(
            f"{label} fields drifted "
            f"(missing={sorted(expected - actual)}, unknown={sorted(actual - expected)})"
        )


def validate_manifest(path: Path = MANIFEST) -> tuple[dict[str, Any], list[Case]]:
    manifest = load_json(path)
    if not isinstance(manifest, dict):
        raise BenchmarkError("CSP manifest root is not an object")
    _exact_fields(
        manifest,
        {
            "schema",
            "suite",
            "upstream",
            "vm_input_encoding",
            "targets",
            "unsupported_targets",
        },
        "CSP manifest",
    )
    if manifest["schema"] != "stwo_riscv_csp_suite_v1":
        raise BenchmarkError("unsupported CSP manifest schema")
    if manifest["suite"] != "ethproofs_client_side_proving":
        raise BenchmarkError("CSP suite identity drifted")

    upstream = manifest["upstream"]
    if not isinstance(upstream, dict):
        raise BenchmarkError("upstream manifest entry is not an object")
    commit = upstream.get("commit")
    if not isinstance(commit, str) or not HEX_40.fullmatch(commit):
        raise BenchmarkError("upstream CSP commit is not canonical")
    if upstream.get("repository") != "https://github.com/privacy-ethereum/csp-benchmarks":
        raise BenchmarkError("upstream CSP repository drifted")

    targets = manifest["targets"]
    if not isinstance(targets, dict) or tuple(targets) != TARGET_ORDER:
        raise BenchmarkError("CSP target order or membership drifted")

    cases: list[Case] = []
    shared_inputs: dict[int, tuple[Path, str]] = {}
    for target in TARGET_ORDER:
        spec = targets[target]
        if not isinstance(spec, dict):
            raise BenchmarkError(f"{target} target is not an object")
        _exact_fields(
            spec,
            {"guest", "uses_precompile", "output_encoding", "cases"},
            f"{target} target",
        )
        if spec["uses_precompile"] is not False:
            raise BenchmarkError(f"{target} must remain an explicit RV32IM workload")
        guest = spec["guest"]
        if not isinstance(guest, dict):
            raise BenchmarkError(f"{target} guest is not an object")
        required_guest_fields = {
            "path",
            "sha256",
            "bytes",
            "source_path",
            "source_sha256",
            "lockfile_path",
            "lockfile_sha256",
        }
        _exact_fields(guest, required_guest_fields, f"{target} guest")
        guest_path = _repo_path(guest["path"], f"{target} guest path")
        if not guest_path.is_file():
            raise BenchmarkError(f"missing {target} guest: {guest_path}")
        guest_bytes = guest_path.stat().st_size
        if guest_bytes != guest["bytes"]:
            raise BenchmarkError(f"{target} guest size differs from its manifest")
        guest_digest = sha256_file(guest_path)
        if guest_digest != guest["sha256"]:
            raise BenchmarkError(f"{target} guest digest differs from its manifest")

        raw_cases = spec["cases"]
        if not isinstance(raw_cases, list):
            raise BenchmarkError(f"{target} cases are not an array")
        sizes = tuple(case.get("input_size") for case in raw_cases if isinstance(case, dict))
        if sizes != CANONICAL_SIZES:
            raise BenchmarkError(f"{target} does not contain the canonical CSP size sweep")
        for index, raw_case in enumerate(raw_cases):
            if not isinstance(raw_case, dict):
                raise BenchmarkError(f"{target} case {index} is not an object")
            _exact_fields(
                raw_case,
                {
                    "input_size",
                    "input_path",
                    "input_sha256",
                    "expected_digest",
                    "expected_cycles",
                },
                f"{target} case {index}",
            )
            input_size = raw_case["input_size"]
            expected_cycles = raw_case["expected_cycles"]
            if (
                not isinstance(input_size, int)
                or isinstance(input_size, bool)
                or not isinstance(expected_cycles, int)
                or isinstance(expected_cycles, bool)
                or expected_cycles <= 0
            ):
                raise BenchmarkError(f"{target} case {index} has invalid numeric fields")
            input_path = _repo_path(raw_case["input_path"], f"{target} input path")
            if not input_path.is_file():
                raise BenchmarkError(f"missing CSP input: {input_path}")
            input_bytes = input_path.read_bytes()
            if len(input_bytes) != input_size + 4:
                raise BenchmarkError(f"{target}/{input_size}: VM input length drifted")
            if struct.unpack("<I", input_bytes[:4])[0] != input_size:
                raise BenchmarkError(f"{target}/{input_size}: input prefix drifted")
            input_digest = sha256_bytes(input_bytes)
            if input_digest != raw_case["input_sha256"]:
                raise BenchmarkError(f"{target}/{input_size}: input digest drifted")
            expected_digest = raw_case["expected_digest"]
            if not isinstance(expected_digest, str) or not HEX_32.fullmatch(expected_digest):
                raise BenchmarkError(f"{target}/{input_size}: expected digest is not canonical")
            shared = shared_inputs.setdefault(input_size, (input_path, input_digest))
            if shared != (input_path, input_digest):
                raise BenchmarkError(f"{target}/{input_size}: shared CSP input drifted")
            cases.append(
                Case(
                    target=target,
                    input_size=input_size,
                    input_path=input_path,
                    input_sha256=input_digest,
                    expected_digest=expected_digest,
                    expected_cycles=expected_cycles,
                    guest_path=guest_path,
                    guest_sha256=guest_digest,
                    guest_bytes=guest_bytes,
                    uses_precompile=False,
                )
            )

    unsupported = manifest["unsupported_targets"]
    if not isinstance(unsupported, dict) or set(unsupported) != {
        "ecdsa",
        "poseidon",
        "poseidon2",
    }:
        raise BenchmarkError("unsupported CSP target ledger drifted")
    if any(not isinstance(reason, str) or not reason.strip() for reason in unsupported.values()):
        raise BenchmarkError("unsupported CSP target has no reason")
    return manifest, cases


def _run(
    argv: Sequence[os.PathLike[str] | str],
    *,
    cwd: Path = ROOT,
    env: Mapping[str, str] | None = None,
    timeout: int = 3600,
) -> subprocess.CompletedProcess[bytes]:
    command = [os.fspath(value) for value in argv]
    try:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=None if env is None else dict(env),
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise BenchmarkError(f"cannot run {command[0]}: {error}") from error
    if completed.returncode != 0:
        stderr = completed.stderr.decode("utf-8", "replace")[-2000:]
        stdout = completed.stdout.decode("utf-8", "replace")[-2000:]
        raise BenchmarkError(
            f"command exited {completed.returncode}: {' '.join(command)}\n"
            f"{stderr or stdout}"
        )
    return completed


def _git_output(*args: str, cwd: Path = ROOT) -> str:
    return _run(["git", *args], cwd=cwd, timeout=30).stdout.decode().strip()


def _command_text(argv: Sequence[str], *, cwd: Path = ROOT) -> str:
    return _run(argv, cwd=cwd, timeout=30).stdout.decode("utf-8", "replace").strip()


def reconstruct_public_output(public_values: Mapping[str, Any]) -> bytes:
    if public_values.get("schema") != "riscv-public-values-diagnostic-v1":
        raise BenchmarkError("public-values diagnostic schema drifted")
    public_data = public_values.get("public_data")
    if not isinstance(public_data, dict):
        raise BenchmarkError("public-values diagnostic has no public_data object")
    io = public_data.get("io_entries")
    if not isinstance(io, dict):
        raise BenchmarkError("public-values diagnostic has no io_entries object")
    output_len = io.get("output_len")
    output_len_addr = io.get("output_len_addr")
    output_data_addr = io.get("output_data_addr")
    words = io.get("output_words")
    if (
        not isinstance(output_len, int)
        or isinstance(output_len, bool)
        or output_len < 0
        or not isinstance(output_len_addr, int)
        or not isinstance(output_data_addr, int)
        or not isinstance(words, list)
        or not words
    ):
        raise BenchmarkError("public output framing is invalid")
    length_word = words[0]
    if (
        not isinstance(length_word, dict)
        or length_word.get("addr") != output_len_addr
        or length_word.get("value") != output_len
    ):
        raise BenchmarkError("public output length word is invalid")
    expected_data_words = (output_len + 3) // 4
    if len(words) != expected_data_words + 1:
        raise BenchmarkError("public output word count is invalid")
    encoded = bytearray()
    for index, word in enumerate(words[1:]):
        if (
            not isinstance(word, dict)
            or word.get("addr") != output_data_addr + index * 4
            or not isinstance(word.get("value"), int)
            or isinstance(word.get("value"), bool)
            or not 0 <= word["value"] <= 0xFFFF_FFFF
        ):
            raise BenchmarkError("public output word is invalid")
        encoded.extend(struct.pack("<I", word["value"]))
    if any(encoded[output_len:]):
        raise BenchmarkError("public output padding is nonzero")
    return bytes(encoded[:output_len])


def execute_case(case: Case, trace_cli: Path, timeout: int) -> dict[str, Any]:
    completed = _run(
        [
            trace_cli,
            "--public-values",
            case.guest_path,
            "--input",
            case.input_path,
        ],
        timeout=timeout,
    )
    if len(completed.stdout) > MAX_CAPTURE_BYTES:
        raise BenchmarkError(f"{case.target}/{case.input_size}: public values are oversized")
    try:
        public_values = json.loads(completed.stdout, object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BenchmarkError(
            f"{case.target}/{case.input_size}: invalid public-values JSON"
        ) from error
    output = reconstruct_public_output(public_values)
    if output.hex() != case.expected_digest:
        raise BenchmarkError(f"{case.target}/{case.input_size}: digest mismatch")
    public_data = public_values["public_data"]
    cycles = public_data.get("clock")
    if cycles != case.expected_cycles:
        raise BenchmarkError(
            f"{case.target}/{case.input_size}: cycles={cycles}, "
            f"expected={case.expected_cycles}"
        )
    return {
        "cycles": cycles,
        "output_digest": output.hex(),
        "public_values_sha256": sha256_bytes(completed.stdout),
    }


def _phase_seconds(report: Mapping[str, Any]) -> tuple[float, float]:
    phase_names = (
        "mean_execution_seconds",
        "mean_witness_seconds",
        "mean_proving_seconds",
        "mean_verification_seconds",
    )
    phases: dict[str, float] = {}
    for name in phase_names:
        value = report.get(name)
        if (
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or value < 0
        ):
            raise BenchmarkError(f"benchmark report has invalid {name}")
        phases[name] = float(value)
    prove = (
        phases["mean_execution_seconds"]
        + phases["mean_witness_seconds"]
        + phases["mean_proving_seconds"]
    )
    return prove, phases["mean_verification_seconds"]


def _peak_memory(report: Mapping[str, Any]) -> tuple[int | None, str]:
    resources = report.get("resources")
    if not isinstance(resources, dict):
        return None, "benchmark report has no resources object"
    if resources.get("availability") != "available":
        reason = resources.get("unavailable_reason")
        return None, str(reason or "resource telemetry unavailable")
    after = resources.get("after_verified_samples")
    if not isinstance(after, dict):
        return None, "resource telemetry has no after-samples snapshot"
    value = after.get("lifetime_max_phys_footprint_bytes")
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        return None, "resource telemetry has no positive peak footprint"
    return value, str(resources.get("source") or "unknown")


def _validate_benchmark_report(
    report: Mapping[str, Any],
    case: Case,
    *,
    warmups: int,
    samples: int,
    admission: riscv_cli_admission.Admission,
) -> str:
    if report.get("schema") != "riscv_proof_v2" or report.get("mode") != "bench":
        raise BenchmarkError(f"{case.target}/{case.input_size}: report identity drifted")
    if (
        report.get("release_status") != admission.release_status
        or report.get("experimental") is not admission.experimental
        or report.get("warmups") != warmups
        or report.get("samples") != samples
        or report.get("verified_samples") != samples
        or report.get("total_steps") != case.expected_cycles
    ):
        raise BenchmarkError(f"{case.target}/{case.input_size}: report contract drifted")
    commit = report.get("implementation_commit")
    if not isinstance(commit, str) or not HEX_40.fullmatch(commit):
        raise BenchmarkError(f"{case.target}/{case.input_size}: implementation commit invalid")
    if report.get("implementation_dirty") is not False:
        raise BenchmarkError(f"{case.target}/{case.input_size}: executable identity is dirty")
    statement = report.get("statement_sha256")
    if not isinstance(statement, str) or not HEX_32.fullmatch(statement):
        raise BenchmarkError(f"{case.target}/{case.input_size}: statement digest invalid")
    return commit


def _validate_artifact(
    artifact: Mapping[str, Any],
    case: Case,
    *,
    admission: riscv_cli_admission.Admission,
) -> tuple[bytes, str]:
    if (
        artifact.get("schema_version") != 4
        or artifact.get("artifact_kind") != "stwo_riscv_proof"
        or artifact.get("exchange_mode") != "riscv_proof_json_wire_v4"
        or artifact.get("protocol") != "secure"
        or artifact.get("release_status") != admission.release_status
        or artifact.get("backend") != "cpu"
        or artifact.get("pcs_config") != SECURE_PCS_CONFIG
    ):
        raise BenchmarkError(f"{case.target}/{case.input_size}: proof artifact drifted")
    proof_hex = artifact.get("proof_bytes_hex")
    if (
        not isinstance(proof_hex, str)
        or len(proof_hex) % 2
        or proof_hex.lower() != proof_hex
    ):
        raise BenchmarkError(f"{case.target}/{case.input_size}: proof bytes are not canonical")
    try:
        proof_bytes = bytes.fromhex(proof_hex)
    except ValueError as error:
        raise BenchmarkError(
            f"{case.target}/{case.input_size}: proof bytes are not hexadecimal"
        ) from error
    if not proof_bytes:
        raise BenchmarkError(f"{case.target}/{case.input_size}: proof is empty")
    return proof_bytes, sha256_bytes(proof_bytes)


def _validate_verify_receipt(
    receipt: Mapping[str, Any],
    case: Case,
    *,
    statement_digest: str,
    proof_bytes: bytes,
    proof_sha256: str,
    implementation_commit: str,
) -> None:
    if (
        receipt.get("schema") != "riscv_verify_v1"
        or receipt.get("status") != "verified"
        or receipt.get("statement_sha256") != statement_digest
        or receipt.get("proof_bytes") != len(proof_bytes)
        or receipt.get("proof_sha256") != proof_sha256
        or receipt.get("implementation_commit") != implementation_commit
        or receipt.get("implementation_dirty") is not False
    ):
        raise BenchmarkError(
            f"{case.target}/{case.input_size}: retained-proof receipt drifted"
        )


def benchmark_case(
    case: Case,
    cli: Path,
    trace_cli: Path,
    *,
    warmups: int,
    samples: int,
    timeout: int,
    admission: riscv_cli_admission.Admission,
    env: Mapping[str, str],
    work_dir: Path,
) -> tuple[dict[str, Any], str]:
    execution = execute_case(case, trace_cli, timeout)
    stem = f"{case.target}_{case.input_size}"
    bench_path = work_dir / f"{stem}.bench.json"
    artifact_path = work_dir / f"{stem}.proof.json"
    command = [
        cli,
        "bench",
        "--elf",
        case.guest_path,
        "--input",
        case.input_path,
        "--backend",
        "cpu",
        "--protocol",
        "secure",
        *admission.arguments,
        "--warmups",
        str(warmups),
        "--samples",
        str(samples),
        "--proof-out",
        artifact_path,
        "--report-out",
        bench_path,
    ]
    wall_start = time.monotonic_ns()
    completed = _run(command, env=env, timeout=timeout)
    wall_duration_ns = time.monotonic_ns() - wall_start
    report = load_json(bench_path)
    if not isinstance(report, dict):
        raise BenchmarkError(f"{case.target}/{case.input_size}: report is not an object")
    implementation_commit = _validate_benchmark_report(
        report,
        case,
        warmups=warmups,
        samples=samples,
        admission=admission,
    )
    artifact = load_json(artifact_path)
    if not isinstance(artifact, dict):
        raise BenchmarkError(f"{case.target}/{case.input_size}: artifact is not an object")
    proof_bytes, proof_sha256 = _validate_artifact(
        artifact,
        case,
        admission=admission,
    )
    artifact_sha256 = sha256_file(artifact_path)
    if report.get("artifact_sha256") != artifact_sha256:
        raise BenchmarkError(f"{case.target}/{case.input_size}: artifact digest drifted")

    statement_digest = report["statement_sha256"]
    verify_start = time.monotonic_ns()
    verify = _run(
        [
            cli,
            "verify",
            "--artifact",
            artifact_path,
            "--elf",
            case.guest_path,
            "--protocol",
            "secure",
            "--expect-statement-digest",
            statement_digest,
        ],
        env=env,
        timeout=timeout,
    )
    retained_verify_wall_ns = time.monotonic_ns() - verify_start
    try:
        receipt = json.loads(verify.stdout, object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BenchmarkError(
            f"{case.target}/{case.input_size}: retained-proof receipt is invalid"
        ) from error
    if not isinstance(receipt, dict):
        raise BenchmarkError(
            f"{case.target}/{case.input_size}: retained-proof receipt is not an object"
        )
    _validate_verify_receipt(
        receipt,
        case,
        statement_digest=statement_digest,
        proof_bytes=proof_bytes,
        proof_sha256=proof_sha256,
        implementation_commit=implementation_commit,
    )

    prove_seconds, verify_seconds = _phase_seconds(report)
    peak_memory, memory_source = _peak_memory(report)
    sample_seconds = report.get("sample_seconds")
    if (
        not isinstance(sample_seconds, list)
        or len(sample_seconds) != samples
        or any(
            not isinstance(value, (int, float))
            or isinstance(value, bool)
            or value <= 0
            for value in sample_seconds
        )
    ):
        raise BenchmarkError(f"{case.target}/{case.input_size}: sample series drifted")
    row = {
        "system": "stwo-zig-riscv",
        "target": case.target,
        "input_size": case.input_size,
        "proof_duration": round(prove_seconds * 1_000_000_000),
        "verify_duration": round(verify_seconds * 1_000_000_000),
        "cycles": execution["cycles"],
        "proof_size": len(proof_bytes),
        "preprocessing_size": case.guest_bytes,
        "num_constraints": 0,
        "peak_memory": peak_memory,
        "uses_precompile": case.uses_precompile,
        "evidence": {
            "status": "verified",
            "input_sha256": case.input_sha256,
            "guest_sha256": case.guest_sha256,
            "output_digest": execution["output_digest"],
            "expected_output_digest": case.expected_digest,
            "public_values_sha256": execution["public_values_sha256"],
            "statement_sha256": statement_digest,
            "proof_sha256": proof_sha256,
            "artifact_sha256": artifact_sha256,
            "artifact_bytes": artifact_path.stat().st_size,
            "retained_verify_wall_ns": retained_verify_wall_ns,
            "retained_verify_receipt": receipt,
        },
        "timing": {
            "source": "production CLI internal stage timers",
            "proof_definition": "execution + witness + proof generation",
            "verify_definition": "production proof verification",
            "mean_execution_seconds": report["mean_execution_seconds"],
            "mean_witness_seconds": report["mean_witness_seconds"],
            "mean_proving_seconds": report["mean_proving_seconds"],
            "mean_verification_seconds": report["mean_verification_seconds"],
            "median_end_to_end_seconds": report["median_seconds"],
            "verified_end_to_end_sample_seconds": sample_seconds,
            "outer_command_wall_ns": wall_duration_ns,
        },
        "memory": {
            "source": memory_source,
            "scope": "self-process lifetime peak across verified samples",
            "includes_mandatory_self_verification": True,
        },
        "protocol": {
            "name": "secure",
            "pcs_config": SECURE_PCS_CONFIG,
        },
        "prover_log_sha256": sha256_bytes(completed.stdout + completed.stderr),
    }
    return row, implementation_commit


def _sysctl(name: str) -> str | None:
    try:
        value = subprocess.run(
            ["sysctl", "-n", name],
            capture_output=True,
            check=False,
            timeout=5,
            text=True,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return value.stdout.strip() if value.returncode == 0 and value.stdout.strip() else None


def collect_host() -> dict[str, Any]:
    cpu = _sysctl("machdep.cpu.brand_string") or platform.processor() or "unknown"
    memory_raw = _sysctl("hw.memsize")
    memory = int(memory_raw) if memory_raw and memory_raw.isdigit() else None
    logical_cpus = os.cpu_count()
    return {
        "hostname": platform.node(),
        "os": platform.system(),
        "os_version": platform.mac_ver()[0] or platform.release(),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "cpu": cpu,
        "logical_cpu_count": logical_cpus,
        "memory_bytes": memory,
        "python": platform.python_version(),
    }


def official_host_match(host: Mapping[str, Any]) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    if host.get("cpu") != "Apple M1":
        reasons.append("CSP publication host requires Apple M1")
    if host.get("logical_cpu_count") != 8:
        reasons.append("CSP publication host requires 8 logical CPUs")
    if host.get("memory_bytes") != 16 * 1024 * 1024 * 1024:
        reasons.append("CSP publication host requires 16 GiB RAM")
    return not reasons, reasons


def audit_csp_source(manifest: Mapping[str, Any], source: Path) -> dict[str, Any]:
    source = source.resolve()
    if not (source / ".git").exists():
        raise BenchmarkError(f"CSP source is not a Git checkout: {source}")
    expected_commit = manifest["upstream"]["commit"]
    actual_commit = _git_output("rev-parse", "HEAD", cwd=source)
    if actual_commit != expected_commit:
        raise BenchmarkError(
            f"CSP source is {actual_commit}, expected pinned {expected_commit}"
        )
    if _git_output("status", "--short", cwd=source):
        raise BenchmarkError("CSP source checkout is dirty")

    upstream = manifest["upstream"]
    bound_files = [
        upstream["input_generator"],
        upstream["size_metadata"],
        upstream["rust_toolchain"],
    ]
    for target in TARGET_ORDER:
        guest = manifest["targets"][target]["guest"]
        bound_files.extend(
            [
                {"path": guest["source_path"], "sha256": guest["source_sha256"]},
                {"path": guest["lockfile_path"], "sha256": guest["lockfile_sha256"]},
            ]
        )
    for binding in bound_files:
        path = (source / binding["path"]).resolve()
        try:
            path.relative_to(source)
        except ValueError as error:
            raise BenchmarkError("CSP source binding escapes its checkout") from error
        if not path.is_file() or sha256_file(path) != binding["sha256"]:
            raise BenchmarkError(f"CSP source binding drifted: {binding['path']}")

    utils = source / "target" / "release" / "utils"
    if not utils.is_file():
        raise BenchmarkError(
            "CSP utility is missing; run `cargo build --release --locked -p utils` "
            "inside the pinned checkout"
        )
    regenerated: dict[int, bytes] = {}
    for target in TARGET_ORDER:
        for case in manifest["targets"][target]["cases"]:
            size = case["input_size"]
            completed = _run(
                [utils, target, "--size", str(size)],
                cwd=source,
                timeout=60,
            )
            lines = completed.stdout.decode("ascii", "strict").splitlines()
            if len(lines) != 2:
                raise BenchmarkError(f"CSP utility output drifted for {target}/{size}")
            try:
                message = bytes.fromhex(lines[0])
            except ValueError as error:
                raise BenchmarkError(
                    f"CSP utility emitted invalid input for {target}/{size}"
                ) from error
            vm_input = struct.pack("<I", size) + message
            expected_file = _repo_path(case["input_path"], "CSP input path")
            if vm_input != expected_file.read_bytes():
                raise BenchmarkError(f"CSP input fixture drifted for {target}/{size}")
            if lines[1] != case["expected_digest"]:
                raise BenchmarkError(f"CSP expected digest drifted for {target}/{size}")
            prior = regenerated.setdefault(size, vm_input)
            if prior != vm_input:
                raise BenchmarkError(f"CSP targets generated different input for size {size}")
    return {
        "status": "passed",
        "source": str(source),
        "commit": actual_commit,
        "bound_file_count": len(bound_files),
        "regenerated_input_count": len(regenerated),
    }


def _parse_csv(raw: str, allowed: Iterable[str], label: str) -> tuple[str, ...]:
    values = tuple(item.strip() for item in raw.split(",") if item.strip())
    allowed_set = set(allowed)
    if not values or len(set(values)) != len(values) or any(v not in allowed_set for v in values):
        raise BenchmarkError(f"invalid {label}: {raw!r}")
    return values


def _parse_sizes(raw: str) -> tuple[int, ...]:
    try:
        sizes = tuple(int(item.strip()) for item in raw.split(",") if item.strip())
    except ValueError as error:
        raise BenchmarkError(f"invalid sizes: {raw!r}") from error
    if (
        not sizes
        or len(set(sizes)) != len(sizes)
        or any(size not in CANONICAL_SIZES for size in sizes)
    ):
        raise BenchmarkError(f"invalid sizes: {raw!r}")
    return sizes


def _atomic_write_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (json.dumps(value, indent=2, sort_keys=True) + "\n").encode()
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    if temporary.exists():
        raise BenchmarkError(f"temporary report already exists: {temporary}")
    try:
        with temporary.open("xb") as output:
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _summary(rows: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    return {
        "row_count": len(rows),
        "target_count": len({row["target"] for row in rows}),
        "all_outputs_match": all(
            row["evidence"]["output_digest"]
            == row["evidence"]["expected_output_digest"]
            for row in rows
        ),
        "all_proofs_verified": all(
            row["evidence"]["status"] == "verified" for row in rows
        ),
        "all_peak_memory_available": all(row["peak_memory"] is not None for row in rows),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=MANIFEST)
    parser.add_argument("--cli", type=Path, default=DEFAULT_CLI)
    parser.add_argument("--trace-cli", type=Path, default=DEFAULT_TRACE_CLI)
    parser.add_argument("--report-out", type=Path, default=DEFAULT_REPORT)
    parser.add_argument("--targets", default=",".join(TARGET_ORDER))
    parser.add_argument("--sizes", default=",".join(str(v) for v in CANONICAL_SIZES))
    parser.add_argument("--warmups", type=int, default=1)
    parser.add_argument("--samples", type=int, default=10)
    parser.add_argument("--workers", type=int)
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument("--audit-csp-source", type=Path)
    args = parser.parse_args(argv)

    if not 0 <= args.warmups <= 10:
        raise BenchmarkError("--warmups must be between 0 and 10")
    if not 1 <= args.samples <= 21:
        raise BenchmarkError("--samples must be between 1 and 21")
    if args.workers is not None and not 1 <= args.workers <= 32:
        raise BenchmarkError("--workers must be between 1 and 32")
    if args.timeout <= 0:
        raise BenchmarkError("--timeout must be positive")

    targets = _parse_csv(args.targets, TARGET_ORDER, "targets")
    sizes = _parse_sizes(args.sizes)
    manifest, all_cases = validate_manifest(args.manifest.resolve())
    selected = [
        case
        for case in all_cases
        if case.target in targets and case.input_size in sizes
    ]
    if not selected:
        raise BenchmarkError("benchmark selection is empty")

    cli = args.cli.resolve()
    trace_cli = args.trace_cli.resolve()
    for label, executable in (("RISC-V product", cli), ("trace diagnostic", trace_cli)):
        if not executable.is_file() or not os.access(executable, os.X_OK):
            raise BenchmarkError(f"{label} executable is missing: {executable}")
    admission = riscv_cli_admission.resolve(cli, cwd=ROOT)
    source_audit = (
        audit_csp_source(manifest, args.audit_csp_source)
        if args.audit_csp_source
        else {"status": "not_requested"}
    )

    host = collect_host()
    host_matches, host_mismatch = official_host_match(host)
    env = os.environ.copy()
    environment_overrides: dict[str, str] = {}
    if args.workers is not None:
        for name in ("STWO_ZIG_WORKERS", "STWO_ZIG_MERKLE_WORKERS"):
            env[name] = str(args.workers)
            environment_overrides[name] = str(args.workers)
    else:
        for name in ("STWO_ZIG_WORKERS", "STWO_ZIG_MERKLE_WORKERS"):
            if name in env:
                environment_overrides[name] = env[name]

    rows: list[dict[str, Any]] = []
    commits: set[str] = set()
    with tempfile.TemporaryDirectory(prefix="stwo-riscv-csp-") as temporary:
        work_dir = Path(temporary)
        for index, case in enumerate(selected, start=1):
            print(
                f"[{index}/{len(selected)}] {case.target}/{case.input_size}: "
                f"execute, prove, verify",
                flush=True,
            )
            row, commit = benchmark_case(
                case,
                cli,
                trace_cli,
                warmups=args.warmups,
                samples=args.samples,
                timeout=args.timeout,
                admission=admission,
                env=env,
                work_dir=work_dir,
            )
            commits.add(commit)
            rows.append(row)
            print(
                f"  prove={row['proof_duration'] / 1e9:.3f}s "
                f"verify={row['verify_duration'] / 1e9:.3f}s "
                f"proof={row['proof_size'] / 1024:.1f}KiB "
                f"rss={row['peak_memory'] / 1024**3:.2f}GiB"
                if row["peak_memory"] is not None
                else
                f"  prove={row['proof_duration'] / 1e9:.3f}s "
                f"verify={row['verify_duration'] / 1e9:.3f}s "
                f"proof={row['proof_size'] / 1024:.1f}KiB rss=unavailable",
                flush=True,
            )
    if len(commits) != 1:
        raise BenchmarkError(f"rows used multiple implementation commits: {sorted(commits)}")
    measurement_commit = commits.pop()
    repository_head = _git_output("rev-parse", "HEAD")
    if repository_head != measurement_commit:
        raise BenchmarkError(
            f"binary commit {measurement_commit} differs from repository HEAD {repository_head}"
        )

    complete_matrix = (
        targets == TARGET_ORDER
        and sizes == CANONICAL_SIZES
        and len(rows) == len(TARGET_ORDER) * len(CANONICAL_SIZES)
    )
    memory_available = all(row["peak_memory"] is not None for row in rows)
    official_comparable = host_matches and complete_matrix and memory_available
    limitations = [
        "The secure profile's 96-bit total is heuristic pending the external "
        "PCS/FRI/Fiat-Shamir accounting review.",
        "Peak footprint includes mandatory self-verification; proving dominates "
        "the observed peak, but this is conservative relative to CSP's prove-only "
        "memory process.",
        "No result is uploaded to EthProofs by this command.",
    ]
    if not host_matches:
        limitations.append(
            "This host differs from CSP's AWS mac2.metal Apple M1/8-core/16-GiB "
            "publication host, so timings are host-qualified and not directly "
            "rankable against published EthProofs rows."
        )

    captured_at = dt.datetime.now(dt.timezone.utc).astimezone().isoformat()
    report = {
        "schema": SCHEMA,
        "captured_at": captured_at,
        "measurement_commit": measurement_commit,
        "repository_head": repository_head,
        "suite_manifest": str(args.manifest.resolve().relative_to(ROOT)),
        "suite_manifest_sha256": sha256_file(args.manifest.resolve()),
        "upstream": manifest["upstream"],
        "source_audit": source_audit,
        "system": {
            "id": "stwo-zig-riscv",
            "proving_system": "Circle STARK",
            "field_curve": "M31",
            "iop": "Circle FRI",
            "pcs": "Circle-PCS",
            "arithm": "AIR",
            "is_zk": False,
            "is_zkvm": True,
            "security_bits": 96,
            "security_status": "heuristic_pending_external_review",
            "is_pq": True,
            "is_maintained": True,
            "is_audited": "not_audited",
            "isa": "RISC-V RV32IM",
        },
        "security": {
            "profile": "secure",
            "pcs_config": SECURE_PCS_CONFIG,
            "csp_minimum_bits": 96,
            "eligibility": "parameter_threshold_met_accounting_review_pending",
        },
        "methodology": {
            "canonical_inputs": True,
            "canonical_sizes": list(CANONICAL_SIZES),
            "uses_precompile": False,
            "proof_duration": "mean execution + witness + proof generation",
            "verify_duration": "mean production verification",
            "proof_size": "Postcard proof bytes, excluding schema-v4 JSON framing",
            "preprocessing_size": "retained RV32IM ELF bytes",
            "peak_memory": "production process lifetime physical-footprint peak",
            "num_constraints": "0 means not exposed; cycles are authoritative",
            "official_csp_host": {
                "provider": "AWS",
                "instance": "mac2.metal",
                "cpu": "Apple M1",
                "logical_cpu_count": 8,
                "memory_bytes": 16 * 1024 * 1024 * 1024,
            },
        },
        "host": host,
        "host_matches_official_csp": host_matches,
        "host_mismatch_reasons": host_mismatch,
        "result_class": (
            "official-host-comparable"
            if official_comparable
            else "host-qualified-non-comparable"
        ),
        "run": {
            "targets": list(targets),
            "sizes": list(sizes),
            "warmups": args.warmups,
            "samples": args.samples,
            "workers": args.workers,
            "environment_overrides": environment_overrides,
            "complete_matrix": complete_matrix,
            "release_status": admission.release_status,
            "experimental": admission.experimental,
        },
        "identities": {
            "prover_executable": str(cli.relative_to(ROOT)),
            "prover_executable_sha256": sha256_file(cli),
            "trace_executable": str(trace_cli.relative_to(ROOT)),
            "trace_executable_sha256": sha256_file(trace_cli),
            "zig_version": _command_text(["zig", "version"]),
        },
        "coverage": {
            "supported_targets": list(TARGET_ORDER),
            "unsupported_targets": manifest["unsupported_targets"],
        },
        "limitations": limitations,
        "summary": _summary(rows),
        "measurements": rows,
    }
    _atomic_write_json(args.report_out.resolve(), report)
    print(f"report: {args.report_out.resolve()}", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BenchmarkError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
