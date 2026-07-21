"""Fail-closed schemas and visible snapshots for the installed RISC-V CLI."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from typing import Any


HELP_SHA256 = {
    "root-help": "da4c10b0b6b0da94e05b2cab64892184c09143857cecb50837db9cdd6936dad3",
    "prove-help": "dfe3a1a6227d1002a0be02a381a9dc6903a6e614f2c5803df6f24d68f7a8d98f",
    "bench-help": "85829dc20d199d4d3a628ef6ac6de18284c899e5a03cbec9719395c5e58a09eb",
    "verify-help": "8a878cd538b6f27edca958362a1b24fb4a30a8070dc347446221e8e17a327ca5",
    "applications-help": "c375525c99ee84a5e51a3db048fc2ac61a44782536b4d0d8e9a55de826b8bf5b",
}

DIAGNOSTIC_SHA256 = {
    "missing-command": "fdd507078fd393037596c181b570ca9388b68fc382369810562753b24c381e8c",
    "unknown-command": "eead26a36dea31a85ed57b0be9f37e93abd0bc6d429ed196b68e94f756967498",
}

ARTIFACT_FIELDS = {
    "artifact_kind", "schema_version", "exchange_mode", "release_status",
    "generator", "air", "backend", "protocol", "source", "provenance",
    "pcs_config", "statement", "interaction_claim", "proof_bytes_hex",
}
PROVE_REPORT_FIELDS = {
    "schema", "release_status", "experimental", "verified_in_process",
    "total_steps", "n_components", "execution_seconds", "witness_seconds",
    "proving_seconds", "verification_seconds", "total_seconds",
    "statement_sha256", "transcript_state_blake2s", "implementation_commit",
    "implementation_dirty", "executable_sha256", "proof_path",
}
VERIFY_RECEIPT_FIELDS = {
    "schema", "status", "artifact_kind", "artifact_schema_version",
    "release_status", "security_policy", "statement_sha256", "proof_bytes",
    "proof_sha256", "transcript_state_blake2s", "implementation_commit",
    "implementation_dirty", "executable_sha256",
}
BENCHMARK_REPORT_FIELDS = {
    "schema", "release_status", "mode", "experimental", "profiled",
    "warmups", "samples", "verified_samples", "total_steps", "n_components",
    "throughput_numerator", "median_seconds", "throughput_mhz",
    "mean_execution_seconds", "mean_witness_seconds", "mean_proving_seconds",
    "mean_verification_seconds", "sample_seconds", "statement_sha256",
    "transcript_state_blake2s", "implementation_commit", "implementation_dirty",
    "executable_sha256", "artifact_sha256", "proof_path",
    "resources",
}
RESOURCE_SOURCE = "darwin.proc_pid_rusage.RUSAGE_INFO_V6"
RESOURCE_SCOPE = "self_process_lifetime"
RESOURCE_FIELDS = {
    "availability", "source", "scope", "unavailable_reason",
    "before_warmups", "after_verified_samples", "interval_delta",
}
RESOURCE_SNAPSHOT_FIELDS = {
    "lifetime_max_phys_footprint_bytes", "energy_nj", "instructions", "cycles",
}
RESOURCE_UNAVAILABLE_REASONS = {
    "unsupported_platform", "before_warmups_sampling_failed",
    "after_verified_samples_sampling_failed", "counter_regression",
}


class ContractError(ValueError):
    """A produced CLI value does not match its release contract."""


def sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def strict_json_object(value: str, label: str) -> dict[str, Any]:
    def object_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, item in pairs:
            if key in result:
                raise ContractError(f"{label}: duplicate JSON field {key}")
            result[key] = item
        return result

    try:
        parsed = json.loads(value, object_pairs_hook=object_pairs)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ContractError(f"{label}: invalid JSON: {error}") from error
    if not isinstance(parsed, dict):
        raise ContractError(f"{label}: expected one JSON object")
    return parsed


def exact_fields(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        unknown = sorted(actual - expected)
        raise ContractError(f"{label}: fields drifted (missing={missing}, unknown={unknown})")


def require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(
            byte not in "0123456789abcdef" for byte in value):
        raise ContractError(f"{label}: expected lowercase SHA-256")
    return value


def require_nonnegative_number(value: Any, label: str) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        raise ContractError(f"{label}: expected a non-negative number")


def require_nonnegative_integer(value: Any, label: str, *, positive: bool = False) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0 or (
            positive and value == 0):
        qualifier = "positive" if positive else "non-negative"
        raise ContractError(f"{label}: expected a {qualifier} integer")
    return value


def validate_resource_usage(
    payload: Mapping[str, Any], *, require_available: bool,
) -> None:
    exact_fields(payload, RESOURCE_FIELDS, "benchmark report.resources")
    if payload["source"] != RESOURCE_SOURCE or payload["scope"] != RESOURCE_SCOPE:
        raise ContractError("benchmark report.resources: source/scope drifted")
    if payload["availability"] == "unavailable":
        if payload["unavailable_reason"] not in RESOURCE_UNAVAILABLE_REASONS:
            raise ContractError("benchmark report.resources: unavailable reason drifted")
        if any(payload[field] is not None for field in (
                "before_warmups", "after_verified_samples", "interval_delta")):
            raise ContractError("benchmark report.resources: unavailable counters must be null")
        if require_available:
            raise ContractError("benchmark report.resources: Darwin V6 counters are required")
        return
    if payload["availability"] != "available" or payload["unavailable_reason"] is not None:
        raise ContractError("benchmark report.resources: availability state drifted")

    snapshots: list[dict[str, int]] = []
    for point in ("before_warmups", "after_verified_samples"):
        snapshot = payload[point]
        if not isinstance(snapshot, dict):
            raise ContractError(f"benchmark report.resources.{point}: expected object")
        exact_fields(snapshot, RESOURCE_SNAPSHOT_FIELDS, f"benchmark report.resources.{point}")
        snapshots.append({
            field: require_nonnegative_integer(
                snapshot[field], f"benchmark report.resources.{point}.{field}",
                positive=field == "lifetime_max_phys_footprint_bytes",
            )
            for field in RESOURCE_SNAPSHOT_FIELDS
        })
    before, after = snapshots
    for field in RESOURCE_SNAPSHOT_FIELDS:
        if after[field] < before[field]:
            raise ContractError(f"benchmark report.resources.{field}: counter regressed")

    delta = payload["interval_delta"]
    delta_fields = {"energy_nj", "instructions", "cycles"}
    if not isinstance(delta, dict):
        raise ContractError("benchmark report.resources.interval_delta: expected object")
    exact_fields(delta, delta_fields, "benchmark report.resources.interval_delta")
    for field in delta_fields:
        value = require_nonnegative_integer(
            delta[field], f"benchmark report.resources.interval_delta.{field}",
            positive=True,
        )
        if value != after[field] - before[field]:
            raise ContractError(
                f"benchmark report.resources.interval_delta.{field}: inconsistent"
            )


def validate_visible_snapshot(name: str, value: str, *, diagnostic: bool = False) -> str:
    expected = (DIAGNOSTIC_SHA256 if diagnostic else HELP_SHA256).get(name)
    if expected is None:
        raise ContractError(f"unknown visible snapshot {name}")
    actual = sha256_text(value)
    if actual != expected:
        raise ContractError(f"{name}: visible output drifted ({actual})")
    return actual


def validate_registry(payload: Mapping[str, Any], expected_status: str) -> None:
    exact_fields(
        payload,
        {
            "schema_version", "backend_availability", "product_matrix",
            "applications", "deferred_adapters",
        },
        "applications",
    )
    if payload["schema_version"] != 1:
        raise ContractError("applications: unsupported schema")
    availability = payload["backend_availability"]
    if not isinstance(availability, dict):
        raise ContractError("applications: missing backend availability")
    exact_fields(availability, {"cpu", "metal-hybrid"}, "applications.backend_availability")
    if availability["cpu"] is not True or not isinstance(availability["metal-hybrid"], bool):
        raise ContractError("applications: backend availability drifted")

    product_matrix = payload["product_matrix"]
    if not isinstance(product_matrix, dict):
        raise ContractError("applications: missing product matrix")
    exact_fields(product_matrix, {"native_cpu", "native_metal"}, "applications.product_matrix")
    native_cpu = product_matrix["native_cpu"]
    native_metal = product_matrix["native_metal"]
    if not isinstance(native_cpu, dict) or not isinstance(native_metal, dict):
        raise ContractError("applications: product matrix entries must be objects")
    exact_fields(native_cpu, {"product_id", "state"}, "applications.product_matrix.native_cpu")
    exact_fields(
        native_metal,
        {"product_id", "state", "selected"},
        "applications.product_matrix.native_metal",
    )
    if native_cpu != {"product_id": "stwo-native-cpu", "state": "released"}:
        raise ContractError("applications: Native CPU product matrix entry drifted")
    if (
        native_metal.get("product_id") != "stwo-native-metal"
        or native_metal.get("state") != "parity_gated"
        or native_metal.get("selected") is not availability["metal-hybrid"]
    ):
        raise ContractError("applications: Native Metal product matrix entry drifted")

    applications = payload["applications"]
    deferred = payload["deferred_adapters"]
    if not isinstance(applications, list) or not isinstance(deferred, list):
        raise ContractError("applications: adapter lists must be arrays")
    all_entries = [*applications, *deferred]
    matches = [entry for entry in all_entries
               if isinstance(entry, dict) and entry.get("adapter") == "stark-v-rv32im-elf"]
    if len(matches) != 1 or matches[0].get("status") != expected_status:
        raise ContractError("applications: RISC-V release status drifted")
    if matches[0].get("isa") != "rv32im" or matches[0].get("backends") != ["cpu"]:
        raise ContractError("applications: RISC-V capability declaration drifted")


def validate_artifact(
    payload: Mapping[str, Any], *, expected_status: str, expected_commit: str,
    expected_dirty: bool, elf_sha256: str, input_sha256: str, witness_layout_sha256: str,
) -> None:
    exact_fields(payload, ARTIFACT_FIELDS, "artifact")
    if (payload["artifact_kind"], payload["schema_version"], payload["exchange_mode"]) != (
            "stwo_riscv_proof", 3, "riscv_proof_json_wire_v3"):
        raise ContractError("artifact: schema-v3 identity drifted")
    if payload["release_status"] != expected_status or payload["backend"] != "cpu":
        raise ContractError("artifact: release/backend identity drifted")
    source = payload["source"]
    exact_fields(source, {"elf_sha256", "input_sha256"}, "artifact.source")
    if source != {"elf_sha256": elf_sha256, "input_sha256": input_sha256}:
        raise ContractError("artifact: source identity drifted")
    provenance = payload["provenance"]
    exact_fields(provenance, {
        "oracle_repository", "oracle_commit", "implementation_repository",
        "implementation_commit", "implementation_dirty", "witness_layout_sha256",
    }, "artifact.provenance")
    if provenance["implementation_commit"] != expected_commit or \
            provenance["implementation_dirty"] is not expected_dirty:
        raise ContractError("artifact: embedded implementation identity drifted")
    if provenance["witness_layout_sha256"] != witness_layout_sha256:
        raise ContractError("artifact: witness-layout identity drifted")
    proof_hex = payload["proof_bytes_hex"]
    if not isinstance(proof_hex, str) or not proof_hex or len(proof_hex) % 2 or any(
            byte not in "0123456789abcdef" for byte in proof_hex):
        raise ContractError("artifact: proof bytes are not canonical lowercase hex")


def validate_prove_report(
    payload: Mapping[str, Any], *, expected_status: str, experimental: bool,
    statement_sha256: str, proof_path: str, expected_commit: str,
    expected_dirty: bool, executable_sha256: str,
) -> None:
    exact_fields(payload, PROVE_REPORT_FIELDS, "prove report")
    if payload["schema"] != "riscv_prove_v1" or payload["release_status"] != expected_status:
        raise ContractError("prove report: schema/release status drifted")
    if payload["experimental"] is not experimental or payload["verified_in_process"] is not True:
        raise ContractError("prove report: admission or verification state drifted")
    if payload["statement_sha256"] != statement_sha256 or payload["proof_path"] != proof_path:
        raise ContractError("prove report: statement or proof path drifted")
    require_sha256(
        payload["transcript_state_blake2s"],
        "prove report.transcript_state_blake2s",
    )
    if payload["implementation_commit"] != expected_commit or \
            payload["implementation_dirty"] is not expected_dirty:
        raise ContractError("prove report: build identity drifted")
    if payload["executable_sha256"] != executable_sha256:
        raise ContractError("prove report: executable identity drifted")
    for field in (
        "execution_seconds", "witness_seconds", "proving_seconds",
        "verification_seconds", "total_seconds",
    ):
        require_nonnegative_number(payload[field], f"prove report.{field}")


def validate_verify_receipt(
    payload: Mapping[str, Any], *, expected_status: str, policy: str,
    statement_sha256: str, proof_bytes: bytes, transcript_state_blake2s: str,
    expected_commit: str, expected_dirty: bool, executable_sha256: str,
) -> None:
    exact_fields(payload, VERIFY_RECEIPT_FIELDS, "verify receipt")
    expected = {
        "schema": "riscv_verify_v1",
        "status": "verified",
        "artifact_kind": "stwo_riscv_proof",
        "artifact_schema_version": 3,
        "release_status": expected_status,
        "security_policy": policy,
        "statement_sha256": statement_sha256,
        "proof_bytes": len(proof_bytes),
        "proof_sha256": hashlib.sha256(proof_bytes).hexdigest(),
        "transcript_state_blake2s": transcript_state_blake2s,
        "implementation_commit": expected_commit,
        "implementation_dirty": expected_dirty,
        "executable_sha256": executable_sha256,
    }
    if payload != expected:
        raise ContractError("verify receipt: values drifted")


def validate_benchmark_report(
    payload: Mapping[str, Any], *, expected_status: str, experimental: bool,
    warmups: int, samples: int, proof_path: str, expected_commit: str,
    expected_dirty: bool, executable_sha256: str,
    require_resource_availability: bool = True,
) -> None:
    exact_fields(payload, BENCHMARK_REPORT_FIELDS, "benchmark report")
    if payload["schema"] != "riscv_proof_v2" or payload["mode"] != "bench":
        raise ContractError("benchmark report: schema/mode drifted")
    if payload["release_status"] != expected_status or payload["experimental"] is not experimental:
        raise ContractError("benchmark report: release/admission drifted")
    if payload["warmups"] != warmups or payload["samples"] != samples or \
            payload["verified_samples"] != samples:
        raise ContractError("benchmark report: sample accounting drifted")
    if payload["proof_path"] != proof_path or payload["throughput_numerator"] != "vm_steps":
        raise ContractError("benchmark report: artifact or throughput contract drifted")
    if not isinstance(payload["sample_seconds"], list) or len(payload["sample_seconds"]) != samples:
        raise ContractError("benchmark report: sample array drifted")
    require_sha256(payload["statement_sha256"], "benchmark report.statement_sha256")
    require_sha256(
        payload["transcript_state_blake2s"],
        "benchmark report.transcript_state_blake2s",
    )
    require_sha256(payload["artifact_sha256"], "benchmark report.artifact_sha256")
    if payload["implementation_commit"] != expected_commit or \
            payload["implementation_dirty"] is not expected_dirty:
        raise ContractError("benchmark report: build identity drifted")
    if payload["executable_sha256"] != executable_sha256:
        raise ContractError("benchmark report: executable identity drifted")
    resources = payload["resources"]
    if not isinstance(resources, dict):
        raise ContractError("benchmark report.resources: expected object")
    validate_resource_usage(
        resources, require_available=require_resource_availability,
    )
    for field in (
        "median_seconds", "throughput_mhz", "mean_execution_seconds",
        "mean_witness_seconds", "mean_proving_seconds", "mean_verification_seconds",
    ):
        require_nonnegative_number(payload[field], f"benchmark report.{field}")
