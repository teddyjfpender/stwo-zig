"""Fail-closed adapter for the persistent mixed-family CUDA service."""

from __future__ import annotations

import hashlib
import json
import math
import statistics
from pathlib import Path
from typing import Any

from scripts.native_cuda_diagnostic_lib.contract import validate_artifact
from scripts.native_cuda_diagnostic_lib.model import (
    EXCHANGE_MODE,
    UPSTREAM_COMMIT,
    DiagnosticError,
    PoseidonShape,
    ProductShape,
    Shape,
    StateMachineShape,
)

from .model import BenchmarkError


SCHEMA = "native_cuda_mixed_service_v1"
WORKLOAD_ID = "mixed_native_wide_poseidon_state_machine_v1"
FAMILIES = ("wide_fibonacci", "poseidon", "state_machine")
EXACT_PROTOCOL_AVAILABLE = False
UNAVAILABLE_REASON = (
    "mixed CUDA service includes legacy raw-stwo-state-machine-v1; "
    "exact raw-stwo-state-machine-v2 is not implemented"
)
SHAPES: dict[str, ProductShape] = {
    "wide_fibonacci": Shape(18, 37),
    "poseidon": PoseidonShape(13),
    "state_machine": StateMachineShape(16, 9, 3),
}
BLOCKERS = [
    "hardware exact-proof receipt package absent",
    "pinned Rust-oracle receipt package absent",
]

TOP_KEYS = {
    "schema",
    "schema_version",
    "product",
    "backend",
    "execution_mode",
    "workload",
    "product_identity",
    "promotion",
    "proof_contract",
    "runtime_contract",
    "service",
    "aggregate",
    "timing_ns",
    "requests",
}
IDENTITY_KEYS = {
    "schema_version",
    "identity_sha256",
    "implementation_repository",
    "implementation_commit",
    "implementation_dirty",
    "zig_version",
    "target_arch",
    "target_os",
    "optimize",
    "runtime_manifest",
    "aot_manifest",
}
SERVICE_KEYS = {
    "runtime_generation",
    "runtime_init_ns",
    "total_runtime_init_ns",
    "execution_lane_count",
    "admissions",
    "busy_rejections",
    "queue_capacity_rejections",
    "request_device_capacity_rejections",
    "queued_input_capacity_rejections",
    "poisoned_rejections",
    "stopped_rejections",
    "requests_started",
    "requests_completed",
    "requests_failed",
    "requests_canceled",
    "publications",
    "shape_hits",
    "shape_misses",
    "runtime_poisons",
    "queue_depth",
    "queue_high_water",
    "queued_input_bytes",
    "queued_input_high_water",
    "total_queue_wait_ns",
    "total_service_ns",
    "cold_service_ns",
}


def _object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise BenchmarkError(f"{label} must be an object")
    return value


def _exact(value: dict[str, Any], keys: set[str], label: str) -> None:
    if set(value) != keys:
        raise BenchmarkError(f"{label} has wrong fields")


def _integer(value: Any, label: str, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise BenchmarkError(f"{label} must be an integer >= {minimum}")
    return value


def _digest(value: Any, label: str, length: int = 64) -> str:
    if (
        not isinstance(value, str)
        or len(value) != length
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise BenchmarkError(f"{label} is not canonical lowercase hexadecimal")
    return value


def _summary(values: list[float]) -> dict[str, float]:
    if not values or any(not math.isfinite(value) for value in values):
        raise BenchmarkError("sustained CUDA metric vector is invalid")
    median = statistics.median(values)
    return {
        "median": median,
        "min": min(values),
        "max": max(values),
        "mad": statistics.median(abs(value - median) for value in values),
    }


def command(
    binary: Path,
    artifact_dir: Path,
    report_path: Path,
    cycles: int,
) -> list[str]:
    if not EXACT_PROTOCOL_AVAILABLE:
        raise BenchmarkError(UNAVAILABLE_REASON)
    return [
        str(binary),
        "sustain",
        "--backend",
        "cuda",
        "--output-dir",
        str(artifact_dir),
        "--report-out",
        str(report_path),
        "--cycles",
        str(cycles),
        "--execution-mode",
        "graphs",
    ]


def queue_digest(cycles: int) -> str:
    digest = hashlib.sha256()
    digest.update(WORKLOAD_ID.encode())
    digest.update(cycles.to_bytes(4, "little"))
    for ordinal in range(cycles * len(FAMILIES)):
        digest.update(FAMILIES[ordinal % len(FAMILIES)].encode())
    return digest.hexdigest()


def validate_invocation_cycles(cycles: int) -> int:
    """Admit one cold cycle or a public multi-cycle sustained run."""
    if (
        isinstance(cycles, bool)
        or not isinstance(cycles, int)
        or not 1 <= cycles <= 4
    ):
        raise BenchmarkError("CUDA service invocation cycles must be in [1, 4]")
    return cycles


def _expected_statement(family: str) -> dict[str, Any]:
    shape = SHAPES[family]
    if isinstance(shape, Shape):
        return {
            "family": family,
            "log_n_rows": shape.log_n_rows,
            "sequence_len": shape.sequence_len,
            "log_n_instances": None,
            "initial_x": None,
            "initial_y": None,
            "trace_rows": shape.trace_rows,
            "trace_cells": shape.trace_cells,
        }
    if isinstance(shape, PoseidonShape):
        return {
            "family": family,
            "log_n_rows": None,
            "sequence_len": None,
            "log_n_instances": shape.log_n_instances,
            "initial_x": None,
            "initial_y": None,
            "trace_rows": shape.trace_rows,
            "trace_cells": shape.trace_cells,
        }
    assert isinstance(shape, StateMachineShape)
    return {
        "family": family,
        "log_n_rows": shape.log_n_rows,
        "sequence_len": None,
        "log_n_instances": None,
        "initial_x": shape.initial_x,
        "initial_y": shape.initial_y,
        "trace_rows": shape.trace_rows,
        "trace_cells": shape.trace_cells,
    }


def _validate_identity(value: Any) -> dict[str, Any]:
    identity = _object(value, "sustained CUDA product identity")
    _exact(identity, IDENTITY_KEYS, "sustained CUDA product identity")
    expected = {
        "schema_version": 2,
        "implementation_repository": "https://github.com/teddyjfpender/stwo-zig",
        "runtime_manifest": "cuda-process-runtime-v1",
        "aot_manifest": "cuda-authenticated-native-pack-v1",
    }
    for key, value in expected.items():
        if identity[key] != value:
            raise BenchmarkError(f"sustained CUDA identity has invalid {key}")
    _digest(identity["identity_sha256"], "sustained CUDA identity digest")
    _digest(identity["implementation_commit"], "sustained CUDA commit", 40)
    if not isinstance(identity["implementation_dirty"], bool):
        raise BenchmarkError("sustained CUDA dirty state must be boolean")
    for key in ("zig_version", "target_arch", "target_os", "optimize"):
        if not isinstance(identity[key], str) or not identity[key]:
            raise BenchmarkError(f"sustained CUDA identity has empty {key}")
    return identity


def _validate_service(value: Any, count: int) -> dict[str, Any]:
    service = _object(value, "sustained CUDA service telemetry")
    _exact(service, SERVICE_KEYS, "sustained CUDA service telemetry")
    for key in SERVICE_KEYS:
        _integer(service[key], f"sustained CUDA service {key}")
    expected = {
        "runtime_generation": 1,
        "execution_lane_count": 1,
        "admissions": count,
        "requests_started": count,
        "requests_completed": count,
        "publications": count,
        "shape_hits": count,
        "busy_rejections": 0,
        "queue_capacity_rejections": 0,
        "request_device_capacity_rejections": 0,
        "queued_input_capacity_rejections": 0,
        "poisoned_rejections": 0,
        "stopped_rejections": 0,
        "requests_failed": 0,
        "requests_canceled": 0,
        "shape_misses": 0,
        "runtime_poisons": 0,
        "queue_depth": 0,
        "queued_input_bytes": 0,
    }
    for key, expected_value in expected.items():
        if service[key] != expected_value:
            raise BenchmarkError(f"sustained CUDA service has invalid {key}")
    if service["queue_high_water"] != count:
        raise BenchmarkError("sustained CUDA queue was not admitted as one batch")
    if service["runtime_init_ns"] < 1:
        raise BenchmarkError("sustained CUDA runtime initialization is absent")
    return service


def _validate_row(
    row_value: Any,
    artifact_dir: Path,
    ordinal: int,
    family: str,
) -> tuple[dict[str, Any], dict[str, Any], Path]:
    row = _object(row_value, "sustained CUDA request")
    _exact(
        row,
        {"ordinal", "family", "statement", "receipt", "proof",
         "oracle_hook", "timing_ns", "residency", "device"},
        "sustained CUDA request",
    )
    if row["ordinal"] != ordinal or row["family"] != family:
        raise BenchmarkError("sustained CUDA publication order changed")
    if row["statement"] != _expected_statement(family):
        raise BenchmarkError("sustained CUDA request statement changed")

    receipt = _object(row["receipt"], "sustained CUDA receipt")
    _exact(
        receipt,
        {
            "ticket", "runtime_generation", "queue_depth_at_admission",
            "queue_wait_ns", "service_ns", "service_cold", "shape_cache_hit",
            "shape_retained_after", "shape_key_sha256",
            "predicted_device_bytes", "retained_input_bytes_upper_bound",
        },
        "sustained CUDA receipt",
    )
    if (
        receipt["ticket"] != ordinal + 1
        or receipt["runtime_generation"] != 1
        or receipt["queue_depth_at_admission"] != ordinal + 1
        or receipt["service_cold"] is not (ordinal == 0)
        or receipt["shape_cache_hit"] is not True
        or receipt["shape_retained_after"] is not True
    ):
        raise BenchmarkError("sustained CUDA receipt lifecycle is invalid")
    _digest(receipt["shape_key_sha256"], "sustained CUDA shape key")
    _integer(receipt["queue_wait_ns"], "sustained CUDA receipt queue_wait_ns")
    for key in (
        "service_ns",
        "predicted_device_bytes",
        "retained_input_bytes_upper_bound",
    ):
        _integer(receipt[key], f"sustained CUDA receipt {key}", 1)

    proof = _object(row["proof"], "sustained CUDA proof")
    _exact(
        proof,
        {
            "artifact_path", "format", "canonical_bytes", "canonical_sha256",
            "artifact_sha256", "zig_verified",
            "exact_for_repeated_family_input",
        },
        "sustained CUDA proof",
    )
    expected_path = artifact_dir / f"{ordinal:03d}-{family}.proof.json"
    if Path(proof["artifact_path"]) != expected_path:
        raise BenchmarkError("sustained CUDA proof path changed")
    try:
        artifact = validate_artifact(expected_path, SHAPES[family])
    except DiagnosticError as error:
        raise BenchmarkError(str(error)) from error
    if (
        proof["format"] != EXCHANGE_MODE
        or proof["canonical_bytes"] != artifact["canonical_bytes"]
        or proof["canonical_sha256"] != artifact["canonical_sha256"]
        or proof["artifact_sha256"] != artifact["artifact_sha256"]
        or proof["zig_verified"] is not True
        or proof["exact_for_repeated_family_input"] is not True
    ):
        raise BenchmarkError("sustained CUDA proof evidence is invalid")

    hook = _object(row["oracle_hook"], "sustained CUDA oracle hook")
    _exact(
        hook,
        {
            "required", "authority", "upstream_commit", "artifact_path",
            "artifact_sha256", "receipt",
        },
        "sustained CUDA oracle hook",
    )
    if hook != {
        "required": True,
        "authority": "pinned-rust-stwo",
        "upstream_commit": UPSTREAM_COMMIT,
        "artifact_path": str(expected_path),
        "artifact_sha256": artifact["artifact_sha256"],
        "receipt": None,
    }:
        raise BenchmarkError("sustained CUDA oracle hook is invalid")

    timing = _object(row["timing_ns"], "sustained CUDA request timing")
    timing_keys = {
        "resident_prove", "terminal_decode", "independent_verification",
        "verified_request", "device_critical_path",
    }
    _exact(timing, timing_keys, "sustained CUDA request timing")
    for key in timing_keys:
        _integer(timing[key], f"sustained CUDA request timing {key}", 1)
    if timing["verified_request"] < (
        timing["resident_prove"]
        + timing["terminal_decode"]
        + timing["independent_verification"]
    ):
        raise BenchmarkError("sustained CUDA verified timing is not enclosing")

    residency = _object(row["residency"], "sustained CUDA residency")
    _exact(
        residency,
        {
            "resident", "strict_aot", "runtime_proof_index",
            "cpu_fallback_attempts", "cpu_fallbacks_completed",
            "terminal_d2h_operations", "terminal_d2h_bytes",
            "kernel_launches", "graph_launches", "sync_calls",
            "peak_live_bytes",
        },
        "sustained CUDA residency",
    )
    if (
        residency["resident"] is not True
        or residency["strict_aot"] is not True
        or residency["runtime_proof_index"] != ordinal + 1
        or residency["cpu_fallback_attempts"] != 0
        or residency["cpu_fallbacks_completed"] != 0
        or residency["terminal_d2h_operations"] != 1
    ):
        raise BenchmarkError("sustained CUDA residency contract failed")
    for key in (
        "terminal_d2h_bytes",
        "kernel_launches",
        "sync_calls",
        "peak_live_bytes",
    ):
        _integer(residency[key], f"sustained CUDA residency {key}", 1)
    _integer(residency["graph_launches"], "sustained CUDA graph launches")

    device = _object(row["device"], "sustained CUDA device")
    _exact(
        device,
        {
            "uuid", "sm", "ordinal", "total_global_memory",
            "multiprocessors", "driver_version", "runtime_version",
            "toolkit_version",
        },
        "sustained CUDA device",
    )
    _digest(device["uuid"], "sustained CUDA UUID", 32)
    for key in set(device) - {"uuid"}:
        _integer(device[key], f"sustained CUDA device {key}", 0)
    if device["sm"] < 1 or device["total_global_memory"] < 1:
        raise BenchmarkError("sustained CUDA device identity is incomplete")
    return row, artifact, expected_path


def validate_report(
    report_value: Any,
    artifact_dir: Path,
    cycles: int,
) -> dict[str, Any]:
    cycles = validate_invocation_cycles(cycles)
    report = _object(report_value, "sustained CUDA report")
    _exact(report, TOP_KEYS, "sustained CUDA report")
    expected_scalars = {
        "schema": SCHEMA,
        "schema_version": 1,
        "product": "stwo-native-cuda",
        "backend": "cuda",
        "execution_mode": "graphs",
    }
    for key, value in expected_scalars.items():
        if report[key] != value:
            raise BenchmarkError(f"sustained CUDA report has invalid {key}")

    count = cycles * len(FAMILIES)
    workload = _object(report["workload"], "sustained CUDA workload")
    expected_workload = {
        "id": WORKLOAD_ID,
        "structural_class": "sustained",
        "deterministic": True,
        "cycles": cycles,
        "request_count": count,
        "cycle_order": list(FAMILIES),
        "queue_sha256": queue_digest(cycles),
    }
    if workload != expected_workload:
        raise BenchmarkError("sustained CUDA workload identity is invalid")
    identity = _validate_identity(report["product_identity"])
    if report["promotion"] != {
        "registry_enabled": False,
        "headline_eligible": False,
        "evidence_class": "diagnostic_unjudged",
        "blockers": BLOCKERS,
    }:
        raise BenchmarkError("sustained CUDA promotion policy opened")
    if report["proof_contract"] != {
        "all_zig_verified": True,
        "all_repeated_family_proofs_exact": True,
        "ordered_publication": True,
        "oracle_receipts_present": False,
    }:
        raise BenchmarkError("sustained CUDA proof contract failed")
    if report["runtime_contract"] != {
        "process_count": 1,
        "runtime_generation_count": 1,
        "execution_lane_count": 1,
        "sequential_proof_indices": True,
        "cpu_fallbacks_allowed": False,
    }:
        raise BenchmarkError("sustained CUDA runtime contract failed")
    service = _validate_service(report["service"], count)

    rows_value = report["requests"]
    if not isinstance(rows_value, list) or len(rows_value) != count:
        raise BenchmarkError("sustained CUDA request catalog is incomplete")
    rows = []
    artifacts = []
    paths = []
    devices = set()
    family_proofs: dict[str, set[tuple[str, int, str, int]]] = {
        family: set() for family in FAMILIES
    }
    for ordinal, row_value in enumerate(rows_value):
        family = FAMILIES[ordinal % len(FAMILIES)]
        row, artifact, path = _validate_row(
            row_value,
            artifact_dir,
            ordinal,
            family,
        )
        rows.append(row)
        artifacts.append(artifact)
        paths.append(path)
        devices.add(json.dumps(row["device"], sort_keys=True))
        family_proofs[family].add(
            (
                artifact["canonical_sha256"],
                artifact["canonical_bytes"],
                artifact["artifact_sha256"],
                artifact["artifact_bytes"],
            )
        )
    if len(devices) != 1 or any(
        len(proofs) != 1 for proofs in family_proofs.values()
    ):
        raise BenchmarkError("sustained CUDA device or proof catalog changed")

    aggregate = _object(report["aggregate"], "sustained CUDA aggregate")
    _exact(
        aggregate,
        {
            "trace_rows", "committed_trace_cells", "service_wall_ns",
            "device_critical_path_ns", "verified_trace_row_mhz",
            "verified_committed_mcells_per_second",
        },
        "sustained CUDA aggregate",
    )
    total_rows = sum(row["statement"]["trace_rows"] for row in rows)
    total_cells = sum(row["statement"]["trace_cells"] for row in rows)
    total_device = sum(row["timing_ns"]["device_critical_path"] for row in rows)
    if (
        aggregate["trace_rows"] != total_rows
        or aggregate["committed_trace_cells"] != total_cells
        or aggregate["device_critical_path_ns"] != total_device
    ):
        raise BenchmarkError("sustained CUDA aggregate totals are inconsistent")

    timing = _object(report["timing_ns"], "sustained CUDA lifecycle timing")
    _exact(
        timing,
        {
            "runtime_init", "shape_preparation", "service_wall",
            "runtime_teardown", "total_before_report_publication",
        },
        "sustained CUDA lifecycle timing",
    )
    for key in timing:
        _integer(timing[key], f"sustained CUDA lifecycle {key}", 1)
    if (
        timing["runtime_init"] != service["runtime_init_ns"]
        or timing["service_wall"] != aggregate["service_wall_ns"]
        or timing["total_before_report_publication"]
        < timing["runtime_init"]
        + timing["shape_preparation"]
        + timing["service_wall"]
        + timing["runtime_teardown"]
    ):
        raise BenchmarkError("sustained CUDA lifecycle timing is inconsistent")
    seconds = timing["service_wall"] / 1e9
    expected_rates = (
        total_rows / seconds / 1e6,
        total_cells / seconds / 1e6,
    )
    actual_rates = (
        aggregate["verified_trace_row_mhz"],
        aggregate["verified_committed_mcells_per_second"],
    )
    if any(
        not isinstance(actual, (int, float))
        or not math.isclose(actual, expected, rel_tol=1e-12)
        for actual, expected in zip(actual_rates, expected_rates, strict=True)
    ):
        raise BenchmarkError("sustained CUDA aggregate rates are inconsistent")
    return {
        "schema_version": report["schema_version"],
        "product_identity": identity,
        "service": service,
        "timing_ns": timing,
        "aggregate": aggregate,
        "requests": rows,
        "artifacts": artifacts,
        "proof_paths": paths,
        "device": json.loads(next(iter(devices))),
        "proof_catalog": {
            family: {
                "canonical_sha256": next(iter(proofs))[0],
                "canonical_bytes": next(iter(proofs))[1],
                "artifact_sha256": next(iter(proofs))[2],
                "artifact_bytes": next(iter(proofs))[3],
            }
            for family, proofs in family_proofs.items()
        },
    }


def steady_metrics(validated: dict[str, Any]) -> dict[str, Any]:
    rows = validated["requests"]
    steady_cycles = [
        rows[offset : offset + len(FAMILIES)]
        for offset in range(len(FAMILIES), len(rows), len(FAMILIES))
    ]
    if not steady_cycles:
        raise BenchmarkError("sustained CUDA report has no steady cycle")

    def cycle_values(key: str) -> list[int]:
        return [
            sum(row["timing_ns"][key] for row in cycle)
            for cycle in steady_cycles
        ]

    verified = cycle_values("verified_request")
    resident = cycle_values("resident_prove")
    device = cycle_values("device_critical_path")
    decode = cycle_values("terminal_decode")
    verification = cycle_values("independent_verification")
    cycle_rows = sum(row["statement"]["trace_rows"] for row in steady_cycles[0])
    cycle_cells = sum(
        row["statement"]["trace_cells"] for row in steady_cycles[0]
    )
    verified_median = statistics.median(verified)
    resident_median = statistics.median(resident)
    device_median = statistics.median(device)
    first = rows[: len(FAMILIES)]
    return {
        "first_request": {
            "cycle_verified_ms": (
                sum(row["timing_ns"]["verified_request"] for row in first)
                / 1_000_000.0
            ),
            "cycle_service_ms": (
                sum(row["receipt"]["service_ns"] for row in first)
                / 1_000_000.0
            ),
        },
        "steady": {
            "verified_ms": _summary([value / 1e6 for value in verified]),
            "resident_ms": _summary([value / 1e6 for value in resident]),
            "device_critical_path_ms": _summary(
                [value / 1e6 for value in device]
            ),
            "terminal_decode_ms": _summary([value / 1e6 for value in decode]),
            "independent_verification_ms": _summary(
                [value / 1e6 for value in verification]
            ),
            "verified_row_mhz": cycle_rows * 1000.0 / verified_median,
            "resident_row_mhz": cycle_rows * 1000.0 / resident_median,
            "device_row_mhz": cycle_rows * 1000.0 / device_median,
            "verified_committed_mcells_per_second": (
                cycle_cells * 1000.0 / verified_median
            ),
            "resident_committed_mcells_per_second": (
                cycle_cells * 1000.0 / resident_median
            ),
            "device_committed_mcells_per_second": (
                cycle_cells * 1000.0 / device_median
            ),
        },
        "mechanism": {
            "persistent_process_runtime": True,
            "runtime_generation_count": 1,
            "execution_lane_count": 1,
            "ordered_publication": True,
            "cpu_fallbacks": 0,
            "shape_cache_hits": validated["service"]["shape_hits"],
        },
        "raw_service": validated["service"],
        "proof_catalog": validated["proof_catalog"],
    }


def proof_identity(
    cold: dict[str, list[dict[str, Any]]],
    sessions: list[dict[str, Any]],
) -> dict[str, Any]:
    samples = [
        sample for arm in cold.values() for sample in arm
    ] + [session["raw"] for session in sessions]
    catalogs = {
        json.dumps(sample["proof_catalog"], sort_keys=True)
        for sample in samples
    }
    devices = {json.dumps(sample["device"], sort_keys=True) for sample in samples}
    if len(catalogs) != 1 or len(devices) != 1:
        raise BenchmarkError("sustained CUDA proof catalog or device changed")
    for arm in {sample["arm"] for sample in samples}:
        identities = {
            json.dumps(sample["product_identity"], sort_keys=True)
            for sample in samples
            if sample["arm"] == arm
        }
        if len(identities) != 1:
            raise BenchmarkError("sustained CUDA product identity changed within arm")
    return {
        "all_arms_byte_identical": True,
        "proof_catalog": json.loads(next(iter(catalogs))),
        "device": json.loads(next(iter(devices))),
        "ordered_family_sequence": list(FAMILIES),
    }
