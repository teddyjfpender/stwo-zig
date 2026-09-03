"""Topology, security, and admitted parent-worker plan authority.

The selected recursive leaf is the full Ethereum Poseidon2-M31 product. Its
native base roster is verifier-derived; only the 14 extension components are
fixed by this profile.
The older Blake2s SegmentV3 product may be disclosed diagnostically, but is
never interpreted as recursive ingress.
"""

from __future__ import annotations

import re
from typing import Any


PARENT_EXECUTION_SCHEMA = "stwo.ethereum.block-proof-parent-execution.v1"
SECURITY_SCHEMA = "stwo.ethereum.block-proof-security.v2"
VERIFICATION_SECURITY_SCHEMA = "stwo.ethereum.block-proof-verification-security.v2"
ARTIFACT_SECURITY_SCHEMA = "stwo.ethereum.block-proof-artifact-security.v2"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
M31_MODULUS = (1 << 31) - 1
PCS_FIELDS = {
    "field", "commitment_hash", "transcript_hash", "pow_bits", "n_queries",
    "log_blowup_factor", "fold_step", "log_last_layer_degree_bound",
    "lifting_log_size",
}
RECURSIVE_PCS = {
    "field": "M31", "commitment_hash": "Poseidon2-M31",
    "transcript_hash": "Poseidon2-M31", "pow_bits": 16, "n_queries": 193,
    "log_blowup_factor": 1, "fold_step": 4,
    "log_last_layer_degree_bound": 0, "lifting_log_size": None,
}
RECURSIVE_NODE_AUTHORITY = {
    **RECURSIVE_PCS, "interaction_pow_bits": 10,
    "configured_pcs_bits": 209, "conjectured_security_bits": 120,
}
RECURSIVE_PROFILE_NAME = "stwo.ethereum-segment-v3-recursive-poseidon2-m31-v1"
RECURSIVE_SECURITY_IDENTITY = (
    "bc339bc9bcf2d57ed49caccff618e944ddd03b401d528e7b3cb0d2f514306b04"
)
RECURSIVE_NODE_SECURITY_IDENTITY = (
    "675ff4fd58923d26ae7f4573b19a53a268bcf27bf9ad96cb18a04bd845169e63"
)
RECURSIVE_LEAF_PROFILE_FIELDS = {
    "air_program_id_m31_le", "configured_pcs_bits",
    "conjectured_security_bits", "extension_component_count", "hash_suite",
    "interaction_pow_bits",
    "child_air_manifest_sha256", "leaf_verification_key_id_m31_le",
    "profile_id_m31_le", "profile_name", "proof_kind", "recursive_ingress",
    "security_identity_sha256",
}
SECURITY_PARAMETER_FIELDS = {
    "schema", "native_blake_leaf", "recursive_ethereum_leaf", "recursive_node",
    "conservative_end_to_end_target_bits", "independent_verifier",
}


class PlanAuthorityError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise PlanAuthorityError(message)


def node_counts(segment_count: int, arity: int) -> list[int]:
    _require(type(segment_count) is int and segment_count >= 2,
             "proof plan requires at least two segments")
    _require(arity == 2, "proof plan arity must be binary")
    result = [1 << (segment_count - 1).bit_length()]
    while result[-1] > 1:
        result.append(result[-1] // arity)
    return result


def _sha(value: Any, where: str) -> str:
    _require(type(value) is str and SHA256.fullmatch(value) is not None,
             f"{where} differs")
    return value


def _m31(value: Any, where: str) -> str:
    _require(type(value) is str and len(value) == 64, f"{where} differs")
    try:
        raw = bytes.fromhex(value)
    except ValueError as error:
        raise PlanAuthorityError(f"{where} differs") from error
    _require(value == raw.hex() and any(raw), f"{where} differs")
    _require(all(int.from_bytes(raw[offset:offset + 4], "little") < M31_MODULUS
                 for offset in range(0, 32, 4)),
             f"{where} contains a non-canonical M31 limb")
    return value


def _pcs(value: Any, where: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == PCS_FIELDS,
             f"{where} keys differ")
    _require(value == RECURSIVE_PCS, f"{where} differs")
    return value


def validate_recursive_leaf_profile(value: Any, where: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == RECURSIVE_LEAF_PROFILE_FIELDS,
             f"{where} keys differ")
    for field in ("air_program_id_m31_le", "leaf_verification_key_id_m31_le",
                  "profile_id_m31_le"):
        _m31(value[field], f"{where}.{field}")
    for field in ("child_air_manifest_sha256", "security_identity_sha256"):
        _sha(value[field], f"{where}.{field}")
    _require(
        value["extension_component_count"] == 14
        and value["configured_pcs_bits"] == 209
        and value["conjectured_security_bits"] == 120
        and value["hash_suite"] == "Poseidon2-M31"
        and value["interaction_pow_bits"] == 10
        and value["profile_name"] == RECURSIVE_PROFILE_NAME
        and value["proof_kind"] == "ethereum_segment_v3_poseidon2"
        and value["recursive_ingress"] == "ethereum_segment_v3_full"
        and value["security_identity_sha256"] == RECURSIVE_SECURITY_IDENTITY,
        f"{where} differs",
    )
    return value


def recursive_leaf_from_source(pcs: Any, profile: Any) -> dict[str, Any]:
    return {
        "pcs": _pcs(pcs, "recursive Ethereum leaf PCS"),
        "proof_profile": validate_recursive_leaf_profile(
            profile, "recursive Ethereum leaf profile",
        ),
    }


def validate_recursive_node(value: Any, where: str) -> dict[str, Any]:
    keys = set(RECURSIVE_NODE_AUTHORITY) | {"security_identity_sha256"}
    _require(type(value) is dict and set(value) == keys, f"{where} keys differ")
    _require(value["security_identity_sha256"] == RECURSIVE_NODE_SECURITY_IDENTITY,
             f"{where}.security_identity_sha256 differs")
    _require(all(value[field] == expected
                 for field, expected in RECURSIVE_NODE_AUTHORITY.items()),
             f"{where} differs")
    return value


def validate_security(value: Any, where: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == SECURITY_PARAMETER_FIELDS,
             f"{where} keys differ")
    _require(value["schema"] == SECURITY_SCHEMA and value["native_blake_leaf"] is None,
             f"{where} selected profile differs")
    leaf = value["recursive_ethereum_leaf"]
    _require(type(leaf) is dict and set(leaf) == {"pcs", "proof_profile"},
             f"{where}.recursive_ethereum_leaf keys differ")
    recursive_leaf_from_source(leaf["pcs"], leaf["proof_profile"])
    validate_recursive_node(value["recursive_node"], f"{where}.recursive_node")
    _require(value["conservative_end_to_end_target_bits"] == 120,
             f"{where} conservative target differs")
    _require(type(value["independent_verifier"]) is bool,
             f"{where}.independent_verifier differs")
    return value


def require_production_security(value: Any, where: str) -> dict[str, Any]:
    # Per-level ProfilePlan production admission is an additional mandatory
    # gate in plan validation; this checks the selected leaf/root suites only.
    value = validate_security(value, where)
    _require(value["independent_verifier"] is True,
             f"{where} lacks an independent verifier")
    return value


def pcs_from_profile(value: dict[str, Any]) -> dict[str, Any]:
    return {field: value[field] for field in PCS_FIELDS}


def receipt_security(value: dict[str, Any], *, leaf: bool) -> dict[str, Any]:
    validate_security(value, "receipt security authority")
    if leaf:
        selected = value["recursive_ethereum_leaf"]
        return {
            "schema": VERIFICATION_SECURITY_SCHEMA,
            "profile_kind": "recursive_ethereum_leaf",
            "pcs": selected["pcs"],
            "proof_profile": selected["proof_profile"],
        }
    return {
        "schema": VERIFICATION_SECURITY_SCHEMA,
        "profile_kind": "recursive_node",
        "recursive_node": value["recursive_node"],
    }


def artifact_security(
    value: dict[str, Any], *, leaf: bool, proof_bytes: int,
) -> dict[str, Any]:
    validate_security(value, "artifact security authority")
    _require(type(proof_bytes) is int and proof_bytes > 0,
             "artifact proof bytes differ")
    return {
        "schema": ARTIFACT_SECURITY_SCHEMA,
        "proof_profile": "recursive_ethereum_leaf" if leaf else "recursive_node",
        "native_blake_leaf": None,
        "recursive_ethereum_leaf": value["recursive_ethereum_leaf"],
        "recursive_node": value["recursive_node"],
        "conservative_end_to_end_target_bits": 120,
        "proof_bytes": proof_bytes,
        "fresh_verification": True,
        "independent_verifier": value["independent_verifier"],
    }


def validate_parent_execution(value: Any, where: str) -> dict[str, Any]:
    keys = {
        "schema", "policy", "max_workers", "admitted_host_logical_cores",
        "admitted_host_memory_bytes", "per_worker_memory_budget_bytes",
        "total_worker_memory_budget_bytes",
    }
    _require(type(value) is dict and set(value) == keys, f"{where} keys differ")
    _require(value["schema"] == PARENT_EXECUTION_SCHEMA
             and value["policy"] == "bounded-level-node-pool-v1",
             f"{where} authority differs")
    for field in keys - {"schema", "policy"}:
        _require(type(value[field]) is int and value[field] > 0,
                 f"{where}.{field} must be positive")
    _require(value["max_workers"] <= value["admitted_host_logical_cores"]
             and value["total_worker_memory_budget_bytes"]
             == value["max_workers"] * value["per_worker_memory_budget_bytes"]
             and value["total_worker_memory_budget_bytes"]
             <= value["admitted_host_memory_bytes"],
             f"{where} resource envelope differs")
    return value
