"""Phase-1 evidence contracts for Native matrix summaries."""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any

from .model import (
    INTEROP_UPSTREAM_COMMIT,
    RUST_ORACLE_SHA256,
    RUST_ORACLE_TOOLCHAIN,
    MatrixError,
)


SUMMARY_SCHEMA_VERSION = 6
SUMMARY_PROTOCOL = "native_proof_cross_backend_matrix_v6"
MIN_FORMAL_MEASURED_PROOFS = 10
PROCESS_RESOURCE_KEYS = {
    "measurement",
    "measurement_locale",
    "normalized_unit",
    "peak_rss_kib",
}
STABILITY_KEYS = {
    "required_verified_proofs_per_lane",
    "cpu_verified_proofs",
    "metal_verified_proofs",
    "cpu_byte_identical",
    "metal_byte_identical",
    "satisfied",
}
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def validate_process_resources(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != PROCESS_RESOURCE_KEYS:
        raise MatrixError(f"{context} has an invalid process-resource schema")
    if value["measurement"] not in {
        "darwin_usr_bin_time_l_v1",
        "gnu_usr_bin_time_v_v1",
    }:
        raise MatrixError(f"{context}.measurement is unsupported")
    if value["measurement_locale"] != "C":
        raise MatrixError(f"{context}.measurement_locale must be C")
    if value["normalized_unit"] != "KiB":
        raise MatrixError(f"{context}.normalized_unit must be KiB")
    peak = value["peak_rss_kib"]
    if isinstance(peak, bool) or not isinstance(peak, int) or peak <= 0:
        raise MatrixError(f"{context}.peak_rss_kib must be a positive integer")
    return value


def stability_evidence(
    cpu_report: dict[str, Any], metal_report: dict[str, Any]
) -> dict[str, Any]:
    cpu_proof = cpu_report["proof"]
    metal_proof = metal_report["proof"]
    cpu_verified = cpu_proof["verified_samples"]
    metal_verified = metal_proof["verified_samples"]
    cpu_identical = cpu_proof["all_samples_byte_identical"] is True
    metal_identical = metal_proof["all_samples_byte_identical"] is True
    return {
        "required_verified_proofs_per_lane": MIN_FORMAL_MEASURED_PROOFS,
        "cpu_verified_proofs": cpu_verified,
        "metal_verified_proofs": metal_verified,
        "cpu_byte_identical": cpu_identical,
        "metal_byte_identical": metal_identical,
        "satisfied": (
            cpu_verified >= MIN_FORMAL_MEASURED_PROOFS
            and metal_verified >= MIN_FORMAL_MEASURED_PROOFS
            and cpu_identical
            and metal_identical
        ),
    }


def validate_stability(value: Any, context: str) -> bool:
    if not isinstance(value, dict) or set(value) != STABILITY_KEYS:
        raise MatrixError(f"{context} has an invalid stability schema")
    if value["required_verified_proofs_per_lane"] != MIN_FORMAL_MEASURED_PROOFS:
        raise MatrixError(f"{context} has the wrong proof-count requirement")
    for field in ("cpu_verified_proofs", "metal_verified_proofs"):
        count = value[field]
        if isinstance(count, bool) or not isinstance(count, int) or count < 0:
            raise MatrixError(f"{context}.{field} must be nonnegative")
    for field in ("cpu_byte_identical", "metal_byte_identical", "satisfied"):
        if not isinstance(value[field], bool):
            raise MatrixError(f"{context}.{field} must be boolean")
    expected = (
        value["cpu_verified_proofs"] >= MIN_FORMAL_MEASURED_PROOFS
        and value["metal_verified_proofs"] >= MIN_FORMAL_MEASURED_PROOFS
        and value["cpu_byte_identical"]
        and value["metal_byte_identical"]
    )
    if value["satisfied"] != expected:
        raise MatrixError(f"{context}.satisfied is inconsistent")
    return expected


def _require_digest(value: Any, context: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise MatrixError(f"{context} must be a lowercase SHA-256 digest")
    return value


def validate_rust_oracle_receipt(
    value: Any,
    oracle_binary: Path,
    artifact: dict[str, Any],
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise MatrixError("Rust oracle receipt must be an object")
    required = {
        "status",
        "verified",
        "upstream_commit",
        "toolchain",
        "binary_path",
        "binary_sha256",
        "artifact_path",
        "artifact_sha256",
        "command",
        "elapsed_seconds",
        "stdout_sha256",
        "stderr_sha256",
    }
    if set(value) != required:
        raise MatrixError("Rust oracle receipt has the wrong schema")
    if value["status"] != "passed" or value["verified"] is not True:
        raise MatrixError("Rust oracle receipt does not record acceptance")
    if value["upstream_commit"] != INTEROP_UPSTREAM_COMMIT:
        raise MatrixError("Rust oracle receipt has the wrong upstream commit")
    if value["toolchain"] != RUST_ORACLE_TOOLCHAIN:
        raise MatrixError("Rust oracle receipt has the wrong Rust toolchain")
    if value["binary_path"] != str(oracle_binary):
        raise MatrixError("Rust oracle receipt has the wrong binary path")
    if value["binary_sha256"] != RUST_ORACLE_SHA256:
        raise MatrixError("Rust oracle receipt has the wrong binary digest")
    if value["artifact_path"] != str(artifact["path"]):
        raise MatrixError("Rust oracle receipt has the wrong artifact path")
    if value["artifact_sha256"] != artifact["sha256"]:
        raise MatrixError("Rust oracle receipt does not bind the accepted artifact")
    expected_command = [
        str(oracle_binary),
        "--mode",
        "verify",
        "--artifact",
        str(artifact["path"]),
    ]
    if value["command"] != expected_command:
        raise MatrixError("Rust oracle receipt has the wrong command")
    elapsed = value["elapsed_seconds"]
    if isinstance(elapsed, bool) or not isinstance(elapsed, (int, float)):
        raise MatrixError("Rust oracle receipt elapsed_seconds must be numeric")
    if not math.isfinite(float(elapsed)) or elapsed < 0:
        raise MatrixError("Rust oracle receipt elapsed_seconds must be finite and nonnegative")
    for field in ("stdout_sha256", "stderr_sha256"):
        if _require_digest(value[field], f"Rust oracle receipt {field}") != EMPTY_SHA256:
            raise MatrixError(f"Rust oracle receipt {field} is not the empty-stream digest")
    return value
