"""Fail-closed validation of the CSP benchmark's report, artifact, and receipt."""

from __future__ import annotations

from typing import Any, Mapping, Protocol

from scripts.riscv_csp_benchmark_lib.contract import (
    BenchmarkError,
    Case,
    HEX_32,
    HEX_40,
    SECURE_PCS_CONFIG,
    sha256_bytes,
)


class Admission(Protocol):
    """Structural view of the admission state these validators check against.

    The concrete state is ``scripts.riscv_cli_admission.Admission``, owned by
    the boundary layer; this package states only the fields it reads.
    """

    release_status: str
    experimental: bool


def validate_benchmark_report(
    report: Mapping[str, Any],
    case: Case,
    *,
    warmups: int,
    samples: int,
    admission: Admission,
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


def validate_artifact(
    artifact: Mapping[str, Any],
    case: Case,
    *,
    admission: Admission,
    expected_backend: str,
) -> tuple[bytes, str]:
    if (
        artifact.get("schema_version") != 4
        or artifact.get("artifact_kind") != "stwo_riscv_proof"
        or artifact.get("exchange_mode") != "riscv_proof_json_wire_v4"
        or artifact.get("protocol") != "secure"
        or artifact.get("release_status") != admission.release_status
        or artifact.get("backend") != expected_backend
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


def validate_verify_receipt(
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
