"""Fail-closed validation for one Native CUDA product invocation."""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path
from typing import Any

from .model import (
    APPLICATION,
    BACKEND,
    EXCHANGE_MODE,
    MAX_PROOF_ARTIFACT_BYTES,
    PRODUCT,
    PROTOCOL,
    UPSTREAM_COMMIT,
    BlakeShape,
    DiagnosticError,
    Shape,
    PlonkShape,
    XorShape,
)


REPORT_KEYS = {
    "schema_version",
    "product",
    "backend",
    "application",
    "protocol",
    "execution_mode",
    "product_identity",
    "statement",
    "plan",
    "proof",
    "timing_ns",
    "process_repetition",
    "residency",
    "device_stage_timing_ns",
    "aot",
    "device",
}
REPORT_KEYS_V4 = REPORT_KEYS - {"execution_mode"}
PRODUCT_IDENTITY_KEYS = {
    "schema_version",
    "name",
    "frontend",
    "backend",
    "role",
    "protocol_features",
    "protocol_manifest_sha256",
    "identity_sha256",
    "implementation_repository",
    "implementation_commit",
    "implementation_tree",
    "implementation_dirty",
    "dirty_content_sha256",
    "zig_version",
    "target_arch",
    "target_os",
    "target_abi",
    "cpu_model",
    "cpu_features_sha256",
    "optimize",
    "runtime_manifest",
    "sdk_manifest",
    "aot_manifest",
}
PLAN_KEYS = {
    "program_sha256",
    "semantic_sha256",
    "cache_key_sha256",
    "schedule_version",
    "compiled_once",
    "reuse_count",
    "node_count",
    "request_bytes",
    "persistent_bytes",
    "predicted_minimum_launches",
    "transcript_barriers",
}
PLAN_KEYS_V4_V5 = PLAN_KEYS - {"semantic_sha256"}
PROOF_KEYS = {
    "path",
    "format",
    "canonical_bytes",
    "canonical_sha256",
    "upstream_commit",
    "zig_verified",
}
TIMING_KEYS = {
    "runtime_init",
    "shape_prepare",
    "resident_prove",
    "terminal_decode",
    "independent_verification",
    "verified_request",
    "runtime_teardown",
    "total_before_publication",
}
PROCESS_REPETITION_KEYS = {
    "count",
    "persistent_session",
    "all_canonical_bytes_identical",
    "stable_launch_topology",
    "request_allocations_released",
    "bounded_persistent_pool_usage",
    "graph_cache_hits_total",
    "graph_cache_misses_total",
    "resident_prove_ns",
    "terminal_decode_ns",
    "independent_verification_ns",
    "verified_request_ns",
    "device_elapsed_ns",
    "runtime_proof_indices",
}
PROCESS_REPETITION_KEYS_V4 = {
    "count",
    "persistent_session",
    "all_canonical_bytes_identical",
    "stable_launch_topology",
    "zero_final_pool_usage",
    "resident_prove_ns",
    "terminal_decode_ns",
    "independent_verification_ns",
    "verified_request_ns",
    "device_elapsed_ns",
    "runtime_proof_indices",
}
RESIDENCY_KEYS = {
    "resident",
    "strict_aot",
    "all_stages_complete_once",
    "terminal_d2h_operations",
    "terminal_d2h_bytes",
    "h2d_bytes",
    "d2d_bytes",
    "cpu_fallback_attempts",
    "cpu_fallbacks_completed",
    "kernel_launches",
    "graph_launches",
    "graph_cache_hits",
    "graph_cache_misses",
    "sync_calls",
    "device_timing_intervals",
    "device_elapsed_ns",
    "peak_live_bytes",
    "persistent_bytes",
    "pool_used_bytes",
    "pool_reserved_bytes",
}
RESIDENCY_KEYS_V4 = {
    "resident",
    "strict_aot",
    "all_stages_complete_once",
    "terminal_d2h_operations",
    "terminal_d2h_bytes",
    "h2d_bytes",
    "d2d_bytes",
    "cpu_fallback_attempts",
    "cpu_fallbacks_completed",
    "kernel_launches",
    "graph_launches",
    "sync_calls",
    "device_timing_intervals",
    "device_elapsed_ns",
    "peak_live_bytes",
    "pool_used_bytes",
    "pool_reserved_bytes",
}
DEVICE_STAGE_TIMING_KEYS = {
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
    "total",
}
AOT_KEYS = {
    "entries",
    "loads",
    "cache_hits",
    "misses",
    "launches",
    "launch_failures",
    "build_identity_sha256",
}
DEVICE_KEYS = {
    "ordinal",
    "sm_major",
    "sm_minor",
    "uuid",
    "driver_version",
    "runtime_version",
    "toolkit_version",
    "global_memory_bytes",
    "multiprocessors",
}
ARTIFACT_KEYS = {
    "schema_version",
    "upstream_commit",
    "exchange_mode",
    "generator",
    "example",
    "prove_mode",
    "pcs_config",
    "blake_statement",
    "plonk_statement",
    "poseidon_statement",
    "state_machine_statement",
    "wide_fibonacci_statement",
    "xor_statement",
    "proof_bytes_hex",
}

EXPECTED_PCS = {
    "pow_bits": 10,
    "fri_config": {
        "log_blowup_factor": 1,
        "log_last_layer_degree_bound": 0,
        "n_queries": 3,
        "fold_step": 1,
    },
    "lifting_log_size": None,
}


def _object(value: Any, context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise DiagnosticError(f"{context} must be an object")
    return value


def _exact_keys(value: dict[str, Any], expected: set[str], context: str) -> None:
    if set(value) != expected:
        missing = sorted(expected - set(value))
        extra = sorted(set(value) - expected)
        raise DiagnosticError(
            f"{context} has wrong fields; missing={missing}, extra={extra}"
        )


def _integer(
    value: Any,
    context: str,
    *,
    minimum: int = 0,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise DiagnosticError(f"{context} must be an integer >= {minimum}")
    return value


def _digest(value: Any, context: str, length: int = 64) -> str:
    if (
        not isinstance(value, str)
        or len(value) != length
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise DiagnosticError(
            f"{context} must be {length} lowercase hexadecimal characters"
        )
    return value


def _read_json(path: Path, maximum: int, context: str) -> tuple[dict[str, Any], bytes]:
    try:
        with path.open("rb") as source:
            raw = source.read(maximum + 1)
    except FileNotFoundError as error:
        raise DiagnosticError(f"{context} was not produced: {path}") from error
    if len(raw) > maximum:
        raise DiagnosticError(f"{context} exceeds {maximum} bytes")
    try:
        decoded = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DiagnosticError(f"{context} is not one valid JSON object") from error
    return _object(decoded, context), raw


def validate_artifact(
    path: Path,
    shape: Shape | XorShape | PlonkShape | BlakeShape,
) -> dict[str, Any]:
    document, raw = _read_json(
        path,
        MAX_PROOF_ARTIFACT_BYTES,
        "CUDA proof artifact",
    )
    _exact_keys(document, ARTIFACT_KEYS, "CUDA proof artifact")
    expected_scalars = {
        "schema_version": 1,
        "upstream_commit": UPSTREAM_COMMIT,
        "exchange_mode": EXCHANGE_MODE,
        "generator": "zig",
        "example": shape.application,
        "prove_mode": "prove",
    }
    for key, expected in expected_scalars.items():
        if document[key] != expected:
            raise DiagnosticError(f"CUDA proof artifact has invalid {key}")
    if document["pcs_config"] != EXPECTED_PCS:
        raise DiagnosticError("CUDA proof artifact has invalid PCS parameters")
    statement_key = shape.artifact_statement_key
    if document[statement_key] != shape.artifact_statement():
        raise DiagnosticError("CUDA proof artifact statement does not match request")
    for key in ARTIFACT_KEYS:
        if (
            key.endswith("_statement")
            and key != statement_key
            and document[key] is not None
        ):
            raise DiagnosticError(f"CUDA proof artifact has unexpected {key}")

    proof_hex = document["proof_bytes_hex"]
    if (
        not isinstance(proof_hex, str)
        or len(proof_hex) == 0
        or len(proof_hex) % 2 != 0
        or any(character not in "0123456789abcdef" for character in proof_hex)
    ):
        raise DiagnosticError("CUDA proof artifact has noncanonical proof bytes")
    proof_bytes = bytes.fromhex(proof_hex)
    try:
        proof_wire = json.loads(proof_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DiagnosticError("CUDA canonical proof bytes are not JSON wire data") from error
    if not isinstance(proof_wire, dict):
        raise DiagnosticError("CUDA canonical proof wire root must be an object")
    return {
        "example": shape.application,
        "statement": shape.artifact_statement(),
        "artifact_bytes": len(raw),
        "artifact_sha256": hashlib.sha256(raw).hexdigest(),
        "canonical_bytes": len(proof_bytes),
        "canonical_sha256": hashlib.sha256(proof_bytes).hexdigest(),
    }


def validate_report(
    report: dict[str, Any],
    shape: Shape | XorShape | PlonkShape | BlakeShape,
    proof_path: Path,
    artifact: dict[str, Any],
    *,
    expected_repetitions: int = 1,
    expected_execution_mode: str = "graphs",
    allow_historical_baseline: bool = False,
) -> dict[str, Any]:
    schema_version = report.get("schema_version")
    historical_v4 = schema_version == 4 and allow_historical_baseline
    historical_v5 = schema_version == 5 and allow_historical_baseline
    historical = historical_v4 or historical_v5
    if historical and not isinstance(shape, Shape):
        raise DiagnosticError("historical CUDA reports are wide-Fibonacci only")
    if schema_version != 6 and not historical:
        raise DiagnosticError("CUDA report has invalid schema_version")
    _exact_keys(
        report,
        REPORT_KEYS_V4 if historical_v4 else REPORT_KEYS,
        "CUDA report",
    )
    execution_mode = "direct" if historical_v4 else expected_execution_mode
    expected_scalars = {
        "schema_version": schema_version,
        "product": PRODUCT,
        "backend": BACKEND,
        "application": shape.application,
        "protocol": shape.protocol,
    }
    if not historical_v4:
        expected_scalars["execution_mode"] = expected_execution_mode
    for key, expected in expected_scalars.items():
        if report[key] != expected:
            raise DiagnosticError(f"CUDA report has invalid {key}")

    identity = _object(report["product_identity"], "CUDA product identity")
    _exact_keys(
        identity,
        PRODUCT_IDENTITY_KEYS,
        "CUDA product identity",
    )
    expected_identity = {
        "schema_version": 2,
        "name": PRODUCT,
        "frontend": "native-examples",
        "backend": BACKEND,
        "role": "cli",
        "implementation_repository": (
            "https://github.com/teddyjfpender/stwo-zig"
        ),
        "runtime_manifest": "cuda-process-runtime-v1",
        "sdk_manifest": "cuda-explicit-toolchain-v1",
        "aot_manifest": "cuda-authenticated-native-pack-v1",
    }
    for key, expected in expected_identity.items():
        if identity[key] != expected:
            raise DiagnosticError(f"CUDA product identity has invalid {key}")
    current_protocol_features = (
        "native-examples-v1+cuda-resident-proof-v1+explicit-toolchain-v1"
    )
    historical_protocol_features = (
        "native-wide-fibonacci-v1+cuda-resident-proof-v1+"
        "explicit-toolchain-v1"
    )
    accepted_protocol_features = (
        {current_protocol_features, historical_protocol_features}
        if historical
        else {current_protocol_features}
    )
    if identity["protocol_features"] not in accepted_protocol_features:
        raise DiagnosticError(
            "CUDA product identity has invalid protocol_features"
        )
    for key in (
        "zig_version",
        "target_arch",
        "target_os",
        "target_abi",
        "cpu_model",
        "optimize",
    ):
        if not isinstance(identity[key], str) or not identity[key]:
            raise DiagnosticError(f"CUDA product identity has empty {key}")
    protocol_sha256 = hashlib.sha256(
        identity["protocol_features"].encode()
    ).hexdigest()
    if (
        _digest(
            identity["protocol_manifest_sha256"],
            "CUDA protocol-manifest digest",
        )
        != protocol_sha256
    ):
        raise DiagnosticError("CUDA protocol-manifest digest is inconsistent")
    _digest(identity["identity_sha256"], "CUDA product-identity digest")
    _digest(
        identity["cpu_features_sha256"],
        "CUDA CPU-feature digest",
    )
    _digest(
        identity["implementation_commit"],
        "CUDA implementation commit",
        length=40,
    )
    implementation_tree = identity["implementation_tree"]
    if implementation_tree is None:
        raise DiagnosticError("CUDA product identity has no implementation tree")
    _digest(implementation_tree, "CUDA implementation tree", length=40)
    if not isinstance(identity["implementation_dirty"], bool):
        raise DiagnosticError("CUDA implementation dirty state is not boolean")
    dirty_digest = identity["dirty_content_sha256"]
    if identity["implementation_dirty"] != (dirty_digest is not None):
        raise DiagnosticError("CUDA product dirty identity is inconsistent")
    if dirty_digest is not None:
        _digest(dirty_digest, "CUDA dirty-content digest")

    statement = _object(report["statement"], "CUDA report statement")
    _exact_keys(statement, set(shape.statement()), "CUDA report statement")
    if statement != shape.statement():
        raise DiagnosticError("CUDA report statement does not match request")

    plan = _object(report["plan"], "CUDA report plan")
    _exact_keys(
        plan,
        PLAN_KEYS_V4_V5 if historical else PLAN_KEYS,
        "CUDA report plan",
    )
    _digest(plan["program_sha256"], "CUDA proof-program digest")
    semantic_sha256 = None
    if not historical:
        semantic_sha256 = _digest(
            plan["semantic_sha256"],
            "CUDA semantic-program digest",
        )
    _digest(plan["cache_key_sha256"], "CUDA plan cache key")
    if plan["compiled_once"] is not True:
        raise DiagnosticError("CUDA shape plan was not compiled exactly once")
    if _integer(plan["reuse_count"], "CUDA plan reuse count", minimum=1) != (
        expected_repetitions
    ):
        raise DiagnosticError("CUDA plan reuse count disagrees with repetitions")
    for key in (
        "schedule_version",
        "node_count",
        "request_bytes",
        "predicted_minimum_launches",
        "transcript_barriers",
    ):
        _integer(plan[key], f"CUDA plan {key}", minimum=1)
    _integer(
        plan["persistent_bytes"],
        "CUDA plan persistent_bytes",
        minimum=0 if historical_v4 else 1,
    )

    proof = _object(report["proof"], "CUDA report proof")
    _exact_keys(proof, PROOF_KEYS, "CUDA report proof")
    if proof["path"] != str(proof_path):
        raise DiagnosticError("CUDA report proof path does not match request")
    if proof["format"] != EXCHANGE_MODE or proof["upstream_commit"] != UPSTREAM_COMMIT:
        raise DiagnosticError("CUDA report proof protocol identity is invalid")
    if proof["zig_verified"] is not True:
        raise DiagnosticError("CUDA proof was not independently Zig-verified")
    if proof["canonical_bytes"] != artifact["canonical_bytes"]:
        raise DiagnosticError("CUDA report proof byte count disagrees with artifact")
    if _digest(
        proof["canonical_sha256"], "CUDA report proof digest"
    ) != artifact["canonical_sha256"]:
        raise DiagnosticError("CUDA report proof digest disagrees with artifact")

    timing = _object(report["timing_ns"], "CUDA report timing")
    _exact_keys(timing, TIMING_KEYS, "CUDA report timing")
    resident_ns = _integer(
        timing["resident_prove"],
        "CUDA resident proof time",
        minimum=1,
    )
    decode_ns = _integer(
        timing["terminal_decode"],
        "CUDA terminal decode time",
        minimum=1,
    )
    total_ns = _integer(
        timing["total_before_publication"],
        "CUDA total-before-publication time",
        minimum=1,
    )
    runtime_init_ns = _integer(
        timing["runtime_init"],
        "CUDA runtime initialization time",
        minimum=1,
    )
    shape_prepare_ns = _integer(
        timing["shape_prepare"],
        "CUDA shape preparation time",
        minimum=1,
    )
    verification_ns = _integer(
        timing["independent_verification"],
        "CUDA independent verification time",
        minimum=1,
    )
    verified_request_ns = _integer(
        timing["verified_request"],
        "CUDA verified request time",
        minimum=1,
    )
    runtime_teardown_ns = _integer(
        timing["runtime_teardown"],
        "CUDA runtime teardown time",
        minimum=1,
    )
    if verified_request_ns < resident_ns + decode_ns + verification_ns:
        raise DiagnosticError(
            "CUDA verified request does not enclose prove, decode, and verification"
        )
    if total_ns < (
        runtime_init_ns
        + shape_prepare_ns
        + verified_request_ns
        + runtime_teardown_ns
    ):
        raise DiagnosticError("CUDA total time does not enclose its lifecycle stages")

    repetition = _object(
        report["process_repetition"],
        "CUDA process repetition",
    )
    _exact_keys(
        repetition,
        (
            PROCESS_REPETITION_KEYS_V4
            if historical_v4
            else PROCESS_REPETITION_KEYS
        ),
        "CUDA process repetition",
    )
    if (
        repetition["count"] != expected_repetitions
        or repetition["persistent_session"] is not True
    ):
        raise DiagnosticError(
            "CUDA product repetition count disagrees with the process contract"
        )
    invariant_keys = (
        (
            "all_canonical_bytes_identical",
            "stable_launch_topology",
            "zero_final_pool_usage",
        )
        if historical_v4
        else (
            "all_canonical_bytes_identical",
            "stable_launch_topology",
            "request_allocations_released",
            "bounded_persistent_pool_usage",
        )
    )
    for key in invariant_keys:
        if repetition[key] is not True:
            raise DiagnosticError(f"CUDA repetition invariant failed: {key}")
    sequences = {}
    graph_hits_total = 0
    graph_misses_total = 0
    if not historical_v4:
        graph_hits_total = _integer(
            repetition["graph_cache_hits_total"],
            "CUDA cumulative graph-cache hits",
        )
        graph_misses_total = _integer(
            repetition["graph_cache_misses_total"],
            "CUDA cumulative graph-cache misses",
        )
    for key in (
        "resident_prove_ns",
        "terminal_decode_ns",
        "independent_verification_ns",
        "verified_request_ns",
        "device_elapsed_ns",
        "runtime_proof_indices",
    ):
        value = repetition[key]
        if not isinstance(value, list) or len(value) != expected_repetitions:
            raise DiagnosticError(f"CUDA repetition {key} has the wrong length")
        sequences[key] = [
            _integer(item, f"CUDA repetition {key}", minimum=1)
            for item in value
        ]
    if sequences["resident_prove_ns"][0] != resident_ns:
        raise DiagnosticError("CUDA repetition resident timing disagrees with sample")
    if sequences["terminal_decode_ns"][0] != decode_ns:
        raise DiagnosticError("CUDA repetition decode timing disagrees with sample")
    if sequences["independent_verification_ns"][0] != verification_ns:
        raise DiagnosticError("CUDA repetition verification timing disagrees")
    if sequences["verified_request_ns"][0] != verified_request_ns:
        raise DiagnosticError("CUDA repetition request timing disagrees")
    if sequences["runtime_proof_indices"] != list(
        range(1, expected_repetitions + 1)
    ):
        raise DiagnosticError("CUDA runtime proof sequence is not contiguous")
    for resident, decode, verification, verified in zip(
        sequences["resident_prove_ns"],
        sequences["terminal_decode_ns"],
        sequences["independent_verification_ns"],
        sequences["verified_request_ns"],
        strict=True,
    ):
        if verified < resident + decode + verification:
            raise DiagnosticError(
                "CUDA repeated verified request does not enclose all work"
            )

    residency = _object(report["residency"], "CUDA residency")
    _exact_keys(
        residency,
        RESIDENCY_KEYS_V4 if historical_v4 else RESIDENCY_KEYS,
        "CUDA residency",
    )
    for key in ("resident", "strict_aot", "all_stages_complete_once"):
        if residency[key] is not True:
            raise DiagnosticError(f"CUDA residency invariant failed: {key}")
    for key in ("cpu_fallback_attempts", "cpu_fallbacks_completed"):
        if _integer(residency[key], f"CUDA residency {key}") != 0:
            raise DiagnosticError(f"CUDA residency observed {key}")
    if _integer(
        residency["device_timing_intervals"],
        "CUDA device timing interval count",
    ) != len(DEVICE_STAGE_TIMING_KEYS) - 1:
        raise DiagnosticError("CUDA device timing does not cover every proof stage")
    device_elapsed_ns = _integer(
        residency["device_elapsed_ns"],
        "CUDA total device elapsed time",
        minimum=1,
    )
    if _integer(
        residency["terminal_d2h_operations"],
        "CUDA terminal D2H operations",
    ) != 1:
        raise DiagnosticError("CUDA proof must perform exactly one terminal D2H")
    for key in (
        "terminal_d2h_bytes",
        "h2d_bytes",
        "d2d_bytes",
        "kernel_launches",
        "sync_calls",
        "peak_live_bytes",
    ):
        _integer(residency[key], f"CUDA residency {key}", minimum=1)
    for key in ("graph_launches", "pool_used_bytes", "pool_reserved_bytes"):
        _integer(residency[key], f"CUDA residency {key}")
    graph_launches = residency["graph_launches"]
    if historical_v4:
        if graph_launches != 0:
            raise DiagnosticError(
                "historical schema-v4 CUDA baseline reported graph activity"
            )
        if residency["pool_used_bytes"] != 0:
            raise DiagnosticError(
                "historical schema-v4 CUDA baseline retained pool allocations"
            )
    else:
        for key in (
            "graph_cache_hits",
            "graph_cache_misses",
            "persistent_bytes",
        ):
            _integer(residency[key], f"CUDA residency {key}")
    if not historical_v4 and execution_mode == "graphs":
        if graph_launches == 0:
            raise DiagnosticError("CUDA graph execution has no graph launches")
        if (
            residency["graph_cache_hits"] + residency["graph_cache_misses"]
            != graph_launches
        ):
            raise DiagnosticError("CUDA graph launches lack cache provenance")
        if graph_misses_total != graph_launches:
            raise DiagnosticError("CUDA graph cache did not capture each stage once")
        if graph_hits_total != graph_launches * (expected_repetitions - 1):
            raise DiagnosticError("CUDA graph cache reuse count is inconsistent")
    elif not historical_v4 and execution_mode == "direct":
        if any(
            value != 0
            for value in (
                graph_launches,
                residency["graph_cache_hits"],
                residency["graph_cache_misses"],
                graph_hits_total,
                graph_misses_total,
            )
        ):
            raise DiagnosticError("CUDA direct execution reported graph activity")
    elif not historical_v4:
        raise DiagnosticError("unsupported expected CUDA execution mode")
    if (
        not historical_v4
        and residency["pool_used_bytes"] < residency["persistent_bytes"]
    ):
        raise DiagnosticError("CUDA persistent arena is absent from its pool")
    if residency["pool_reserved_bytes"] < residency["pool_used_bytes"]:
        raise DiagnosticError("CUDA pool reserved bytes are below used bytes")
    if residency["peak_live_bytes"] > residency["pool_reserved_bytes"]:
        raise DiagnosticError("CUDA peak live bytes exceed the reserved pool")

    stage_timing = _object(
        report["device_stage_timing_ns"],
        "CUDA device stage timing",
    )
    _exact_keys(
        stage_timing,
        DEVICE_STAGE_TIMING_KEYS,
        "CUDA device stage timing",
    )
    stage_total = sum(
        _integer(stage_timing[key], f"CUDA device stage timing {key}")
        for key in DEVICE_STAGE_TIMING_KEYS
        if key != "total"
    )
    if stage_timing["total"] != stage_total or stage_total != device_elapsed_ns:
        raise DiagnosticError("CUDA device stage timings do not sum to the total")
    if device_elapsed_ns > resident_ns:
        raise DiagnosticError("CUDA device time exceeds resident proof wall time")
    if sequences["device_elapsed_ns"][-1] != device_elapsed_ns:
        raise DiagnosticError("CUDA repetition device timing disagrees with sample")

    aot = _object(report["aot"], "CUDA AOT telemetry")
    _exact_keys(aot, AOT_KEYS, "CUDA AOT telemetry")
    aot_entries = _integer(aot["entries"], "CUDA AOT entries", minimum=1)
    aot_loads = _integer(aot["loads"], "CUDA AOT loads", minimum=1)
    _integer(aot["launches"], "CUDA AOT launches", minimum=1)
    for key in ("cache_hits", "misses", "launch_failures"):
        _integer(aot[key], f"CUDA AOT {key}")
    if aot_loads > aot_entries:
        raise DiagnosticError("CUDA AOT loads exceed packaged entries")
    if aot["misses"] != 0 or aot["launch_failures"] != 0:
        raise DiagnosticError("CUDA strict-AOT sample reported misses or failures")
    expected_aot_launches = (
        aot_loads
        if execution_mode == "graphs"
        else aot_loads * expected_repetitions
    )
    expected_aot_hits = (
        0
        if execution_mode == "graphs"
        else aot_loads * (expected_repetitions - 1)
    )
    if aot["launches"] != expected_aot_launches:
        raise DiagnosticError("CUDA AOT lifecycle disagrees with repetitions")
    if aot["cache_hits"] != expected_aot_hits:
        raise DiagnosticError("CUDA AOT cache-hit count disagrees with reuse")
    _digest(aot["build_identity_sha256"], "CUDA AOT build identity")

    device = _object(report["device"], "CUDA device")
    _exact_keys(device, DEVICE_KEYS, "CUDA device")
    for key in (
        "ordinal",
        "sm_major",
        "sm_minor",
        "driver_version",
        "runtime_version",
        "toolkit_version",
        "global_memory_bytes",
        "multiprocessors",
    ):
        _integer(device[key], f"CUDA device {key}")
    if device["ordinal"] != 0:
        raise DiagnosticError(
            "CUDA product did not select ordinal zero inside the masked device set"
        )
    if device["sm_major"] * 10 + device["sm_minor"] not in (86, 89, 90):
        raise DiagnosticError("CUDA device SM is outside the product contract")
    _digest(device["uuid"], "CUDA device UUID", length=32)
    if device["global_memory_bytes"] <= 0 or device["multiprocessors"] <= 0:
        raise DiagnosticError("CUDA device capacity telemetry is invalid")

    return {
        "schema_version": schema_version,
        "execution_mode": execution_mode,
        "semantic_sha256": semantic_sha256,
        "statement": statement,
        "protocol": report["protocol"],
        "product_identity": identity,
        "proof": proof,
        "plan": plan,
        "timing_ns": timing,
        "process_repetition": repetition,
        "residency": residency,
        "device_stage_timing_ns": stage_timing,
        "aot": aot,
        "device": device,
        "resident_trace_row_mhz": shape.trace_rows * 1000.0 / resident_ns,
        "resident_committed_mcells_per_second": (
            shape.trace_cells * 1000.0 / resident_ns
        ),
    }


def require_finite_positive(value: float, context: str) -> float:
    if not math.isfinite(value) or value <= 0:
        raise DiagnosticError(f"{context} must be finite and positive")
    return value
