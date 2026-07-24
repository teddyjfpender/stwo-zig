#!/usr/bin/env python3
"""Fail-closed external parity gate for the Native CUDA proof product."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any

UPSTREAM_COMMIT = "a8fcf4bdde3778ae72f1e6cfe61a38e2911648d2"
EXCHANGE_MODE = "proof_exchange_json_wire_v1"
SCHEMA = "stwo-zig-cuda-parity-oracle-v1"
MAX_JSON_BYTES = 256 * 1024 * 1024
EXPECTED_CONFIG = {
    "pow_bits": 10,
    "fri_config": {
        "log_blowup_factor": 1,
        "log_last_layer_degree_bound": 0,
        "n_queries": 3,
        "fold_step": 1,
    },
    "lifting_log_size": None,
}


class GateError(RuntimeError):
    pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_bytes(path: Path, *, limit: int = MAX_JSON_BYTES) -> bytes:
    size = path.stat().st_size
    if size > limit:
        raise GateError(f"{path}: exceeds {limit} bytes")
    return path.read_bytes()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def require_digest(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(byte not in "0123456789abcdef" for byte in value)
    ):
        raise GateError(f"{label} must be a lowercase SHA-256 digest")
    return value


def require_executable(path: Path, label: str) -> Path:
    resolved = path.expanduser().resolve(strict=True)
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise GateError(f"{label} is not an executable regular file: {resolved}")
    return resolved


def load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(read_bytes(path))
    except (OSError, ValueError) as exc:
        raise GateError(f"{path}: invalid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise GateError(f"{path}: root must be an object")
    return value


def validate_artifact(
    path: Path, *, log_n_rows: int, sequence_len: int
) -> dict[str, Any]:
    artifact = load_object(path)
    expected = {
        "schema_version": 1,
        "upstream_commit": UPSTREAM_COMMIT,
        "exchange_mode": EXCHANGE_MODE,
        "example": "wide_fibonacci",
        "pcs_config": EXPECTED_CONFIG,
        "wide_fibonacci_statement": {
            "log_n_rows": log_n_rows,
            "sequence_len": sequence_len,
        },
    }
    for key, value in expected.items():
        if artifact.get(key) != value:
            raise GateError(f"{path}: invalid {key}")
    proof_hex = artifact.get("proof_bytes_hex")
    if not isinstance(proof_hex, str) or len(proof_hex) % 2:
        raise GateError(f"{path}: proof_bytes_hex must be even-length hex")
    try:
        proof = bytes.fromhex(proof_hex)
    except ValueError as exc:
        raise GateError(f"{path}: proof_bytes_hex is invalid") from exc
    if not proof or len(proof) > MAX_JSON_BYTES // 2:
        raise GateError(f"{path}: proof byte length is invalid")
    if proof_hex != proof.hex():
        raise GateError(f"{path}: proof_bytes_hex is not canonical lowercase hex")
    return {
        "path": str(path.resolve()),
        "artifact_sha256": sha256_file(path),
        "proof_bytes": len(proof),
        "proof_sha256": sha256_bytes(proof),
        "_proof": proof,
    }


def validate_cuda_report(
    path: Path,
    *,
    log_n_rows: int,
    sequence_len: int,
    repeat: int,
    execution_mode: str,
    proof: dict[str, Any],
) -> dict[str, Any]:
    report = load_object(path)
    required = {
        "schema_version": 6,
        "product": "stwo-native-cuda",
        "backend": "cuda",
        "application": "wide_fibonacci",
        "protocol": "raw-stwo-wide-v1",
        "execution_mode": execution_mode,
    }
    for key, value in required.items():
        if report.get(key) != value:
            raise GateError(f"{path}: invalid {key}")
    plan = report.get("plan")
    if not isinstance(plan, dict):
        raise GateError(f"{path}: CUDA proof plan is missing")
    program_sha256 = require_digest(
        plan.get("program_sha256"),
        f"{path}: CUDA full ProofProgram identity",
    )
    semantic_sha256 = require_digest(
        plan.get("semantic_sha256"),
        f"{path}: CUDA semantic ProofProgram identity",
    )
    cache_key_sha256 = require_digest(
        plan.get("cache_key_sha256"),
        f"{path}: CUDA plan-cache identity",
    )
    statement = report.get("statement")
    if not isinstance(statement, dict) or any(
        statement.get(key) != value
        for key, value in {
            "log_n_rows": log_n_rows,
            "sequence_len": sequence_len,
        }.items()
    ):
        raise GateError(f"{path}: statement does not match the challenge")
    proof_report = report.get("proof")
    if not isinstance(proof_report, dict) or any(
        proof_report.get(key) != value
        for key, value in {
            "canonical_bytes": proof["proof_bytes"],
            "canonical_sha256": proof["proof_sha256"],
            "upstream_commit": UPSTREAM_COMMIT,
            "zig_verified": True,
        }.items()
    ):
        raise GateError(f"{path}: proof identity or verification is invalid")
    residency = report.get("residency")
    if not isinstance(residency, dict) or any(
        residency.get(key) != value
        for key, value in {
            "resident": True,
            "strict_aot": True,
            "all_stages_complete_once": True,
            "terminal_d2h_operations": 1,
            "cpu_fallback_attempts": 0,
            "cpu_fallbacks_completed": 0,
        }.items()
    ):
        raise GateError(f"{path}: CUDA residency contract failed")
    if residency.get("device_timing_intervals") != 10:
        raise GateError(f"{path}: CUDA device timing coverage is incomplete")
    graph_launches = residency.get("graph_launches")
    graph_hits = residency.get("graph_cache_hits")
    graph_misses = residency.get("graph_cache_misses")
    persistent_bytes = residency.get("persistent_bytes")
    pool_used_bytes = residency.get("pool_used_bytes")
    if (
        not isinstance(graph_launches, int)
        or graph_launches < 0
        or not isinstance(graph_hits, int)
        or graph_hits < 0
        or not isinstance(graph_misses, int)
        or graph_misses < 0
        or not isinstance(persistent_bytes, int)
        or persistent_bytes <= 0
        or not isinstance(pool_used_bytes, int)
        or pool_used_bytes < persistent_bytes
    ):
        raise GateError(f"{path}: CUDA execution residency evidence is invalid")
    if execution_mode == "graphs":
        if graph_launches == 0 or graph_hits + graph_misses != graph_launches:
            raise GateError(f"{path}: CUDA graph residency evidence is invalid")
    elif execution_mode == "direct":
        if any(value != 0 for value in (graph_launches, graph_hits, graph_misses)):
            raise GateError(f"{path}: CUDA direct execution reported graph activity")
    else:
        raise GateError(f"{path}: unsupported CUDA execution mode")
    stage_timing = report.get("device_stage_timing_ns")
    if not isinstance(stage_timing, dict):
        raise GateError(f"{path}: CUDA device stage timing is missing")
    stage_names = {
        "ingress",
        "trace_generation",
        "trace_commit",
        "constraint_evaluation",
        "oods",
        "quotient",
        "fri_commit",
        "pow",
        "decommit",
        "proof_assembly",
    }
    if set(stage_timing) != stage_names | {"total"}:
        raise GateError(f"{path}: CUDA device stage timing fields are invalid")
    if any(
        not isinstance(stage_timing[name], int) or stage_timing[name] < 0
        for name in stage_names
    ):
        raise GateError(f"{path}: CUDA device stage timing values are invalid")
    if stage_timing["total"] != sum(stage_timing[name] for name in stage_names):
        raise GateError(f"{path}: CUDA device stage timing total is invalid")
    if residency.get("device_elapsed_ns") != stage_timing["total"]:
        raise GateError(f"{path}: CUDA device timing evidence disagrees")
    if not isinstance(residency.get("terminal_d2h_bytes"), int) or (
        residency["terminal_d2h_bytes"] <= 0
    ):
        raise GateError(f"{path}: terminal proof read is missing")
    repetition = report.get("process_repetition")
    if not isinstance(repetition, dict) or any(
        repetition.get(key) != value
        for key, value in {
            "count": repeat,
            "persistent_session": True,
            "all_canonical_bytes_identical": True,
            "stable_launch_topology": True,
            "request_allocations_released": True,
            "bounded_persistent_pool_usage": True,
        }.items()
    ):
        raise GateError(f"{path}: process-repetition evidence is invalid")
    expected_misses = graph_launches if execution_mode == "graphs" else 0
    expected_hits = (
        graph_launches * (repeat - 1) if execution_mode == "graphs" else 0
    )
    if (
        repetition.get("graph_cache_misses_total") != expected_misses
        or repetition.get("graph_cache_hits_total") != expected_hits
    ):
        raise GateError(f"{path}: CUDA execution-cache lifecycle is invalid")
    for key in ("resident_prove_ns", "terminal_decode_ns"):
        samples = repetition.get(key)
        if (
            not isinstance(samples, list)
            or len(samples) != repeat
            or any(not isinstance(value, int) or value < 0 for value in samples)
        ):
            raise GateError(f"{path}: invalid repetition samples for {key}")
    device_samples = repetition.get("device_elapsed_ns")
    proof_indices = repetition.get("runtime_proof_indices")
    if (
        not isinstance(device_samples, list)
        or len(device_samples) != repeat
        or any(not isinstance(value, int) or value <= 0 for value in device_samples)
    ):
        raise GateError(f"{path}: invalid device timing samples")
    if proof_indices != list(range(1, repeat + 1)):
        raise GateError(f"{path}: invalid persistent runtime proof sequence")
    return {
        "path": str(path.resolve()),
        "sha256": sha256_file(path),
        "resident": True,
        "strict_aot": True,
        "cpu_fallbacks": 0,
        "execution_mode": execution_mode,
        "program_sha256": program_sha256,
        "semantic_sha256": semantic_sha256,
        "cache_key_sha256": cache_key_sha256,
    }


def run_checked(argv: list[str], timeout: int) -> dict[str, Any]:
    try:
        result = subprocess.run(
            argv,
            check=False,
            capture_output=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GateError(f"command failed to execute: {argv[0]}: {exc}") from exc
    evidence = {
        "argv": argv,
        "exit_code": result.returncode,
        "stdout_sha256": sha256_bytes(result.stdout),
        "stderr_sha256": sha256_bytes(result.stderr),
    }
    if result.returncode != 0:
        raise GateError(
            f"command rejected evidence ({result.returncode}): {' '.join(argv)}"
        )
    return evidence


def binary_identity(path: Path) -> dict[str, Any]:
    return {
        "path": str(path),
        "bytes": path.stat().st_size,
        "sha256": sha256_file(path),
    }


def gate(args: argparse.Namespace) -> Path:
    if (
        args.log_n_rows < 1
        or args.sequence_len < 2
        or args.repeat < 3
        or args.repeat > 16
        or args.execution_mode not in ("graphs", "direct")
        or len(args.rust_verifier_sha256) != 64
        or any(
            byte not in "0123456789abcdefABCDEF"
            for byte in args.rust_verifier_sha256
        )
    ):
        raise GateError("invalid workload, repetition, or verifier pin")
    cuda = require_executable(args.cuda_product, "CUDA product")
    cpu = require_executable(args.native_cpu_product, "Native CPU product")
    rust = require_executable(args.rust_verifier, "Rust verifier")
    if len({cuda, cpu, rust}) != 3:
        raise GateError("CUDA product, CPU product, and Rust verifier must differ")
    rust_sha = sha256_file(rust)
    if rust_sha != args.rust_verifier_sha256.lower():
        raise GateError("Rust verifier SHA-256 does not match its explicit pin")

    out_dir = args.out_dir.expanduser()
    try:
        out_dir.mkdir(parents=True, exist_ok=False)
    except FileExistsError as exc:
        raise GateError(f"output directory already exists: {out_dir}") from exc
    cuda_artifact = out_dir / "cuda-proof.json"
    cuda_report = out_dir / "cuda-report.json"
    cpu_artifact = out_dir / "cpu-proof.json"

    commands = [
        run_checked(
            [
                str(cuda),
                "prove",
                "--air",
                "wide_fibonacci",
                "--backend",
                "cuda",
                "--protocol",
                "raw-stwo-wide-v1",
                "--log-n-rows",
                str(args.log_n_rows),
                "--sequence-len",
                str(args.sequence_len),
                "--output",
                str(cuda_artifact),
                "--report-out",
                str(cuda_report),
                "--repeat",
                str(args.repeat),
                "--execution-mode",
                args.execution_mode,
            ],
            args.timeout_seconds,
        )
    ]
    if args.cpu_artifact is None:
        commands.append(
            run_checked(
                [
                    str(cpu),
                    "prove",
                    "--example",
                    "wide_fibonacci",
                    "--log-n-rows",
                    str(args.log_n_rows),
                    "--sequence-len",
                    str(args.sequence_len),
                    "--protocol",
                    "functional",
                    "--output",
                    str(cpu_artifact),
                ],
                args.timeout_seconds,
            )
        )
        cpu_source = "generated"
    else:
        supplied = args.cpu_artifact.expanduser().resolve(strict=True)
        shutil.copyfile(supplied, cpu_artifact)
        cpu_source = "provided"

    cuda_proof = validate_artifact(
        cuda_artifact,
        log_n_rows=args.log_n_rows,
        sequence_len=args.sequence_len,
    )
    cpu_proof = validate_artifact(
        cpu_artifact,
        log_n_rows=args.log_n_rows,
        sequence_len=args.sequence_len,
    )
    if cuda_proof["_proof"] != cpu_proof["_proof"]:
        raise GateError("CUDA and CPU canonical proof bytes differ")
    cuda_residency = validate_cuda_report(
        cuda_report,
        log_n_rows=args.log_n_rows,
        sequence_len=args.sequence_len,
        repeat=args.repeat,
        execution_mode=args.execution_mode,
        proof=cuda_proof,
    )

    verifications = []
    for artifact in (cuda_artifact, cpu_artifact):
        verifications.append(
            {
                "verifier": "zig-native-cpu",
                "artifact": artifact.name,
                **run_checked(
                    [
                        str(cpu),
                        "verify",
                        "--artifact",
                        str(artifact),
                        "--protocol",
                        "functional",
                    ],
                    args.timeout_seconds,
                ),
            }
        )
        verifications.append(
            {
                "verifier": "pinned-rust-stwo",
                "artifact": artifact.name,
                **run_checked(
                    [str(rust), "--mode", "verify", "--artifact", str(artifact)],
                    args.timeout_seconds,
                ),
            }
        )

    del cuda_proof["_proof"]
    del cpu_proof["_proof"]
    receipt = {
        "schema": SCHEMA,
        "verdict": "pass",
        "challenge": {
            "air": "wide_fibonacci",
            "log_n_rows": args.log_n_rows,
            "sequence_len": args.sequence_len,
            "protocol": EXPECTED_CONFIG,
            "process_repetitions": args.repeat,
            "cuda_execution_mode": args.execution_mode,
        },
        "products": {
            "cuda": binary_identity(cuda),
            "native_cpu": binary_identity(cpu),
            "rust_verifier": binary_identity(rust),
        },
        "proofs": {
            "canonical_byte_parity": True,
            "cuda": cuda_proof,
            "cpu": {**cpu_proof, "source": cpu_source},
        },
        "cuda_residency": cuda_residency,
        "commands": commands,
        "verifications": verifications,
    }
    receipt_path = out_dir / "receipt.json"
    with receipt_path.open("x", encoding="utf-8") as output:
        json.dump(receipt, output, indent=2, sort_keys=True)
        output.write("\n")
    return receipt_path


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--cuda-product", type=Path, required=True)
    result.add_argument("--native-cpu-product", type=Path, required=True)
    result.add_argument("--cpu-artifact", type=Path)
    result.add_argument("--rust-verifier", type=Path, required=True)
    result.add_argument("--rust-verifier-sha256", required=True)
    result.add_argument("--log-n-rows", type=int, required=True)
    result.add_argument("--sequence-len", type=int, required=True)
    result.add_argument("--repeat", type=int, default=3)
    result.add_argument(
        "--execution-mode",
        choices=("graphs", "direct"),
        default="graphs",
    )
    result.add_argument("--out-dir", type=Path, required=True)
    result.add_argument("--timeout-seconds", type=int, default=300)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        receipt = gate(args)
    except (GateError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(receipt)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
