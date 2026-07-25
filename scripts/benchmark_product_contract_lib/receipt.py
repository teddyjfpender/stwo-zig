"""Bounded, product-scoped benchmark and profiler receipts."""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any

from .identity import ProductEvidenceError, validate_product_identity


RECEIPT_PROTOCOL = "focused_product_measurement_receipt_v1"
MIN_PROMOTION_WARMUPS = 10
MIN_PROMOTION_VERIFIED_SAMPLES = 10
MAX_TRACE_LOG_ROWS = 22
RECEIPT_KEYS = {
    "schema_version",
    "protocol",
    "evidence_kind",
    "promotion_eligible",
    "product_identity",
    "executable_sha256",
    "measurement_policy",
    "host_device",
    "measurements",
    "receipt_sha256",
}
MEASUREMENT_KEYS = {
    "workload",
    "numerator",
    "security_profile",
    "timing_scope",
    "cold_warm_state",
    "proof_status",
    "eligibility_status",
}
BENCHMARK_POLICY = {
    "execution": "sequential_alternating_lane_order",
    "final_correctness_oracle": "pinned Rust Stwo",
    "minimum_excluded_warmups": MIN_PROMOTION_WARMUPS,
    "minimum_verified_samples": MIN_PROMOTION_VERIFIED_SAMPLES,
}
BENCHMARK_POLICY_KEYS = {
    *BENCHMARK_POLICY,
    "proof_protocol",
    "formal",
    "profiled",
    "every_measured_proof_locally_verified",
    "cross_backend_canonical_proof_equality",
}
PROFILE_POLICY = {
    "execution": "bounded_sequential_cpu_then_metal",
    "profiled_diagnostic": True,
    "headline_eligible": False,
    "final_correctness_oracle_checked": False,
}
PROFILE_POLICY_KEYS = {
    *PROFILE_POLICY,
    "proof_protocol",
    "every_measured_proof_locally_verified",
    "cross_backend_canonical_proof_equality",
}
SECURITY_PROFILES = {
    "smoke": {
        "name": "smoke",
        "pow_bits": 0,
        "log_blowup_factor": 1,
        "log_last_layer_degree_bound": 0,
        "n_queries": 3,
        "fold_step": 1,
    },
    "functional": {
        "name": "functional",
        "pow_bits": 10,
        "log_blowup_factor": 1,
        "log_last_layer_degree_bound": 0,
        "n_queries": 3,
        "fold_step": 1,
    },
}
WORKLOAD_KEYS = {
    "name",
    "parameters",
    "trace_log_rows",
    "trace_rows",
    "committed_trees",
    "committed_columns",
    "committed_trace_cells",
    "native_unit",
    "native_units",
    "descriptor_sha256",
}
WORKLOAD_PARAMETERS = {
    "wide_fibonacci": ("log_n_rows", "sequence_len"),
    "xor": ("log_size", "log_step", "offset"),
    "plonk": ("log_n_rows",),
    "state_machine": ("log_n_rows", "initial_x", "initial_y"),
    "blake": ("log_n_rows", "n_rounds"),
    "poseidon": ("log_n_instances",),
}
NATIVE_UNITS = {
    "wide_fibonacci": "trace_rows",
    "xor": "xor_rows",
    "plonk": "plonk_rows",
    "state_machine": "state_transitions",
    "blake": "blake_round_instances",
    "poseidon": "poseidon_instances",
}
AIR_PROTOCOLS = {
    "xor": "raw-stwo-xor-lookup-v2",
    "poseidon": "raw-stwo-poseidon-logup-split2-v1",
    "state_machine": "raw-stwo-state-machine-v2",
}


def _canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _digest(value: Any) -> str:
    return hashlib.sha256(_canonical_bytes(value)).hexdigest()


def _require_digest(value: Any, context: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ProductEvidenceError(f"{context} must be a lowercase SHA-256 digest")
    return value


def _require_int(value: Any, context: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise ProductEvidenceError(f"{context} must be an integer >= {minimum}")
    return value


def _require_safe_json(value: Any, context: str) -> None:
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ProductEvidenceError(f"{context} contains a non-finite number")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _require_safe_json(item, f"{context}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str) or not key:
                raise ProductEvidenceError(f"{context} contains an invalid object key")
            _require_safe_json(item, f"{context}.{key}")
        return
    raise ProductEvidenceError(f"{context} contains a non-JSON value")


def _require_exact(value: Any, keys: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise ProductEvidenceError(f"{context} has an unsupported schema")
    return value


def _validate_policy(value: Any, evidence_kind: str, lane: str) -> dict[str, Any]:
    context = f"{lane} receipt measurement policy"
    if evidence_kind == "benchmark":
        policy = _require_exact(value, BENCHMARK_POLICY_KEYS, context)
        for field, expected in BENCHMARK_POLICY.items():
            if policy[field] != expected:
                raise ProductEvidenceError(f"{context}.{field} is unsupported")
        if policy["proof_protocol"] not in SECURITY_PROFILES:
            raise ProductEvidenceError(f"{context}.proof_protocol is unsupported")
        for field in (
            "formal",
            "profiled",
            "every_measured_proof_locally_verified",
            "cross_backend_canonical_proof_equality",
        ):
            if not isinstance(policy[field], bool):
                raise ProductEvidenceError(f"{context}.{field} must be boolean")
        return policy
    if evidence_kind == "profile":
        policy = _require_exact(value, PROFILE_POLICY_KEYS, context)
        for field, expected in PROFILE_POLICY.items():
            if policy[field] != expected:
                raise ProductEvidenceError(f"{context}.{field} is unsupported")
        if policy["proof_protocol"] not in SECURITY_PROFILES:
            raise ProductEvidenceError(f"{context}.proof_protocol is unsupported")
        for field in (
            "every_measured_proof_locally_verified",
            "cross_backend_canonical_proof_equality",
        ):
            if not isinstance(policy[field], bool):
                raise ProductEvidenceError(f"{context}.{field} must be boolean")
        return policy
    raise ProductEvidenceError(f"{lane} receipt evidence kind is unsupported")


def _validate_workload(value: Any, context: str) -> dict[str, Any]:
    workload = _require_exact(value, WORKLOAD_KEYS, context)
    name = workload["name"]
    if name not in WORKLOAD_PARAMETERS:
        raise ProductEvidenceError(f"{context}.name is unsupported")
    parameters = workload["parameters"]
    expected_parameters = set(WORKLOAD_PARAMETERS[name])
    if not isinstance(parameters, dict) or set(parameters) != expected_parameters:
        raise ProductEvidenceError(f"{context}.parameters has an unsupported schema")
    for field, item in parameters.items():
        _require_int(item, f"{context}.parameters.{field}")
    log_rows = _require_int(workload["trace_log_rows"], f"{context}.trace_log_rows", minimum=1)
    if log_rows > MAX_TRACE_LOG_ROWS:
        raise ProductEvidenceError(f"{context}.trace_log_rows exceeds the product limit")
    expected_log_rows = (
        parameters["log_size"]
        if name == "xor"
        else parameters["log_n_instances"] - 3
        if name == "poseidon"
        else parameters["log_n_rows"]
    )
    if log_rows != expected_log_rows:
        raise ProductEvidenceError(f"{context}.trace_log_rows disagrees with parameters")
    if name == "xor" and log_rows < 2:
        raise ProductEvidenceError(f"{context}.trace_log_rows is unsupported for exact XOR")
    if name == "state_machine" and log_rows < 5:
        raise ProductEvidenceError(
            f"{context}.trace_log_rows is unsupported for exact State Machine"
        )
    trace_rows = _require_int(workload["trace_rows"], f"{context}.trace_rows", minimum=1)
    if trace_rows != 1 << log_rows:
        raise ProductEvidenceError(f"{context}.trace_rows is inconsistent")
    expected_trees = 3 if name in {"xor", "state_machine", "poseidon"} else 2
    if workload["committed_trees"] != expected_trees:
        raise ProductEvidenceError(f"{context}.committed_trees is unsupported")
    columns = _require_int(
        workload["committed_columns"], f"{context}.committed_columns", minimum=1
    )
    expected_columns = (
        parameters["sequence_len"]
        if name == "wide_fibonacci"
        else parameters["n_rounds"] * 96
        if name == "blake"
        else 1296
        if name == "poseidon"
        else 15
        if name == "xor"
        else 12
        if name == "state_machine"
        else 8
    )
    if columns != expected_columns:
        raise ProductEvidenceError(f"{context}.committed_columns disagrees with parameters")
    cells = _require_int(
        workload["committed_trace_cells"],
        f"{context}.committed_trace_cells",
        minimum=1,
    )
    expected_cells = trace_rows * 9 if name == "state_machine" else trace_rows * columns
    if cells != expected_cells:
        raise ProductEvidenceError(f"{context}.committed_trace_cells is inconsistent")
    if workload["native_unit"] != NATIVE_UNITS[name]:
        raise ProductEvidenceError(f"{context}.native_unit is unsupported")
    native_units = _require_int(
        workload["native_units"], f"{context}.native_units", minimum=1
    )
    expected_native_units = (
        trace_rows * parameters["n_rounds"]
        if name == "blake"
        else 1 << parameters["log_n_instances"]
        if name == "poseidon"
        else trace_rows + trace_rows // 2
        if name == "state_machine"
        else trace_rows
    )
    if native_units != expected_native_units:
        raise ProductEvidenceError(f"{context}.native_units disagrees with parameters")
    _require_digest(workload["descriptor_sha256"], f"{context}.descriptor_sha256")
    return workload


def _validate_measurement(
    value: Any,
    *,
    lane: str,
    evidence_kind: str,
    policy: dict[str, Any],
    index: int,
) -> dict[str, Any]:
    context = f"{lane}.measurements[{index}]"
    measurement = _require_exact(value, MEASUREMENT_KEYS, context)
    workload = _validate_workload(measurement["workload"], f"{context}.workload")

    numerator = _require_exact(
        measurement["numerator"], {"unit", "units"}, f"{context}.numerator"
    )
    if numerator != {"unit": workload["native_unit"], "units": workload["native_units"]}:
        raise ProductEvidenceError(f"{context}.numerator disagrees with the workload")

    security = measurement["security_profile"]
    if security != SECURITY_PROFILES[policy["proof_protocol"]]:
        raise ProductEvidenceError(f"{context}.security_profile is unsupported")
    descriptor_fields = ["native-proof-workload-v3", f"example={workload['name']}"]
    descriptor_fields.extend(
        f"{field}={workload['parameters'][field]}"
        for field in WORKLOAD_PARAMETERS[workload["name"]]
    )
    if air_protocol := AIR_PROTOCOLS.get(workload["name"]):
        descriptor_fields.append(f"air_protocol={air_protocol}")
    descriptor_fields.extend(
        (
            f"protocol={security['name']}",
            f"pow_bits={security['pow_bits']}",
            f"log_blowup_factor={security['log_blowup_factor']}",
            f"log_last_layer_degree_bound={security['log_last_layer_degree_bound']}",
            f"n_queries={security['n_queries']}",
            f"fold_step={security['fold_step']}",
        )
    )
    expected_descriptor = hashlib.sha256("|".join(descriptor_fields).encode("ascii")).hexdigest()
    if workload["descriptor_sha256"] != expected_descriptor:
        raise ProductEvidenceError(f"{context}.workload descriptor is inconsistent")

    if evidence_kind == "benchmark":
        timing = _require_exact(
            measurement["timing_scope"],
            {"headline", "total", "included", "backend_init"},
            f"{context}.timing_scope",
        )
        if timing != {
            "headline": "prove_seconds",
            "total": "request_seconds",
            "included": [
                "input_seconds",
                "prove_seconds",
                "proof_encode_seconds",
                "verify_seconds",
            ],
            "backend_init": "reported_separately",
        }:
            raise ProductEvidenceError(f"{context}.timing_scope is unsupported")
    else:
        timing = _require_exact(
            measurement["timing_scope"],
            {"headline", "diagnostic", "host_timers", "gpu_timers"},
            f"{context}.timing_scope",
        )
        if timing["headline"] is not None or timing["diagnostic"] != "instrumented_verified_request":
            raise ProductEvidenceError(f"{context}.timing_scope is not diagnostic")
        _require_safe_json(timing["host_timers"], f"{context}.timing_scope.host_timers")
        _require_safe_json(timing["gpu_timers"], f"{context}.timing_scope.gpu_timers")

    cold = _require_exact(
        measurement["cold_warm_state"],
        {
            "backend_initialization",
            "warmups_excluded",
            "measured_samples",
            "sample_state",
            "metal_runtime",
        },
        f"{context}.cold_warm_state",
    )
    if cold["backend_initialization"] != "once_before_warmups":
        raise ProductEvidenceError(f"{context}.cold_warm_state initialization is unsupported")
    _require_int(cold["warmups_excluded"], f"{context}.warmups_excluded")
    measured_samples = _require_int(
        cold["measured_samples"], f"{context}.measured_samples", minimum=1
    )
    expected_state = (
        "post_warmup" if evidence_kind == "benchmark" else "profiled_post_warmup_diagnostic"
    )
    if cold["sample_state"] != expected_state:
        raise ProductEvidenceError(f"{context}.cold_warm_state sample state is unsupported")
    expected_runtime = "not_applicable" if lane == "cpu" else None
    if expected_runtime is not None and cold["metal_runtime"] != expected_runtime:
        raise ProductEvidenceError(f"{context}.cold_warm_state Metal runtime is inconsistent")
    if lane == "metal" and cold["metal_runtime"] not in {"source-jit", "authenticated-aot"}:
        raise ProductEvidenceError(f"{context}.cold_warm_state Metal runtime is unsupported")

    proof = _require_exact(
        measurement["proof_status"],
        {
            "local_verification",
            "verified_samples",
            "byte_identical_samples",
            "cross_backend_canonical_equality",
            "pinned_rust_stwo_verified",
            "proof_sha256",
        },
        f"{context}.proof_status",
    )
    for field in (
        "local_verification",
        "byte_identical_samples",
        "cross_backend_canonical_equality",
        "pinned_rust_stwo_verified",
    ):
        if not isinstance(proof[field], bool):
            raise ProductEvidenceError(f"{context}.proof_status.{field} must be boolean")
    if proof["local_verification"] is not True:
        raise ProductEvidenceError(f"{context} is not bound to a locally verified proof")
    verified_samples = _require_int(
        proof["verified_samples"], f"{context}.verified_samples", minimum=1
    )
    if verified_samples != measured_samples:
        raise ProductEvidenceError(f"{context} verified samples differ from measured samples")
    _require_digest(proof["proof_sha256"], f"{context}.proof_sha256")

    eligibility = _require_exact(
        measurement["eligibility_status"],
        {"headline_eligible", "stability_satisfied", "evidence_class", "profiled"},
        f"{context}.eligibility_status",
    )
    for field in ("headline_eligible", "stability_satisfied", "profiled"):
        if not isinstance(eligibility[field], bool):
            raise ProductEvidenceError(f"{context}.eligibility_status.{field} must be boolean")
    expected_class = "profiled_diagnostic" if evidence_kind == "profile" else None
    if expected_class is not None and (
        eligibility["evidence_class"] != expected_class
        or eligibility["profiled"] is not True
        or eligibility["headline_eligible"] is not False
        or eligibility["stability_satisfied"] is not False
    ):
        raise ProductEvidenceError(f"{context}.eligibility_status is not profiled diagnostic")
    if evidence_kind == "benchmark" and eligibility["evidence_class"] not in {
        "correctness_only",
        "verified_unprofiled",
    }:
        raise ProductEvidenceError(f"{context}.eligibility_status evidence class is unsupported")
    return measurement


def derive_promotion_eligibility(
    *,
    evidence_kind: str,
    product_identity: dict[str, Any],
    measurement_policy: dict[str, Any],
    measurements: list[dict[str, Any]],
) -> bool:
    """Derive promotion state solely from validated receipt evidence."""

    if evidence_kind != "benchmark":
        return False
    if not (
        measurement_policy["formal"] is True
        and measurement_policy["profiled"] is False
        and measurement_policy["proof_protocol"] == "functional"
        and measurement_policy["every_measured_proof_locally_verified"] is True
        and measurement_policy["cross_backend_canonical_proof_equality"] is True
        and product_identity["implementation_dirty"] is False
        and product_identity["optimize"] == "ReleaseFast"
    ):
        return False
    return bool(measurements) and all(
        measurement["cold_warm_state"]["warmups_excluded"] >= MIN_PROMOTION_WARMUPS
        and measurement["cold_warm_state"]["measured_samples"]
        >= MIN_PROMOTION_VERIFIED_SAMPLES
        and measurement["proof_status"]["verified_samples"]
        == measurement["cold_warm_state"]["measured_samples"]
        and measurement["proof_status"]["byte_identical_samples"] is True
        and measurement["proof_status"]["cross_backend_canonical_equality"] is True
        and measurement["proof_status"]["pinned_rust_stwo_verified"] is True
        and measurement["eligibility_status"]
        == {
            "headline_eligible": True,
            "stability_satisfied": True,
            "evidence_class": "verified_unprofiled",
            "profiled": False,
        }
        for measurement in measurements
    )


def build_receipt(
    *,
    lane: str,
    evidence_kind: str,
    product_identity: dict[str, Any],
    executable_sha256: str,
    measurement_policy: dict[str, Any],
    host_device: dict[str, Any],
    measurements: list[dict[str, Any]],
    promotion_eligible: bool,
) -> dict[str, Any]:
    payload = {
        "schema_version": 1,
        "protocol": RECEIPT_PROTOCOL,
        "evidence_kind": evidence_kind,
        "promotion_eligible": promotion_eligible,
        "product_identity": product_identity,
        "executable_sha256": executable_sha256,
        "measurement_policy": measurement_policy,
        "host_device": host_device,
        "measurements": measurements,
    }
    receipt = {**payload, "receipt_sha256": _digest(payload)}
    validate_receipt(
        receipt,
        lane=lane,
        evidence_kind=evidence_kind,
        expected_host_device=host_device,
    )
    return receipt


def validate_receipt(
    value: Any,
    *,
    lane: str,
    evidence_kind: str,
    expected_identity: dict[str, Any] | None = None,
    expected_executable_sha256: str | None = None,
    expected_host_device: dict[str, Any] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != RECEIPT_KEYS:
        raise ProductEvidenceError(f"{lane} measurement receipt has an unsupported schema")
    _require_safe_json(value, f"{lane} measurement receipt")
    if value["schema_version"] != 1 or value["protocol"] != RECEIPT_PROTOCOL:
        raise ProductEvidenceError(f"{lane} measurement receipt protocol is unsupported")
    if value["evidence_kind"] != evidence_kind:
        raise ProductEvidenceError(f"{lane} measurement receipt has the wrong evidence kind")
    if not isinstance(value["promotion_eligible"], bool):
        raise ProductEvidenceError(f"{lane} receipt promotion_eligible must be boolean")
    identity = validate_product_identity(value["product_identity"], lane)
    if expected_identity is not None and identity != expected_identity:
        raise ProductEvidenceError(f"{lane} receipt product identity changed")
    executable = _require_digest(value["executable_sha256"], f"{lane}.executable_sha256")
    if expected_executable_sha256 is not None and executable != expected_executable_sha256:
        raise ProductEvidenceError(f"{lane} receipt executable digest changed")
    policy = _validate_policy(value["measurement_policy"], evidence_kind, lane)
    measurements_value = value["measurements"]
    if not isinstance(measurements_value, list) or not measurements_value:
        raise ProductEvidenceError(f"{lane} receipt has no measurements")
    measurements = [
        _validate_measurement(
            measurement,
            lane=lane,
            evidence_kind=evidence_kind,
            policy=policy,
            index=index,
        )
        for index, measurement in enumerate(measurements_value)
    ]
    if not isinstance(value["host_device"], dict) or not value["host_device"]:
        raise ProductEvidenceError(f"{lane} receipt has no host/device identity")
    if expected_host_device is not None and value["host_device"] != expected_host_device:
        raise ProductEvidenceError(f"{lane} receipt host/device identity changed")
    expected_promotion = derive_promotion_eligibility(
        evidence_kind=evidence_kind,
        product_identity=identity,
        measurement_policy=policy,
        measurements=measurements,
    )
    if value["promotion_eligible"] is not expected_promotion:
        raise ProductEvidenceError(
            f"{lane} receipt promotion eligibility disagrees with measurement evidence"
        )
    claimed = _require_digest(value["receipt_sha256"], f"{lane}.receipt_sha256")
    payload = {key: item for key, item in value.items() if key != "receipt_sha256"}
    if claimed != _digest(payload):
        raise ProductEvidenceError(f"{lane} measurement receipt digest is invalid")
    return value
