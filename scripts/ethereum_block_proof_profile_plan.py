"""Admission for the Zig-emitted temporal recursion profile plan.

The entry and whole-plan digests are opaque Zig authorities.  This module
validates the canonical transport, production policy, ordering, and exact
cross-level edges; it deliberately never recreates the native digest or
profile hashing domains in Python.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from scripts import ethereum_block_proof_protocol as protocol
from scripts import ethereum_block_proof_store as store


TRANSPORT_SCHEMA = "stwo.recursion.temporal-profile-plan.v2"
BINDING_SCHEMA = "stwo.ethereum.block-proof-profile-policy-template-binding.v1"
ENTRY_KINDS = ("real_h1", "empty_h1") + ("upper",) * 7
SECURITY_FIELDS = {
    "configured_pcs_bits", "conjectured_security_bits", "field_id",
    "format_version", "fri_fold_step", "fri_log_blowup_factor",
    "fri_log_last_layer_degree_bound", "fri_query_count", "hash_suite",
    "identity_sha256", "interaction_pow_bits", "kind", "pcs_lifting_mode",
    "pcs_pow_bits", "proof_present", "recursive_ingress", "schema_version",
}
ENTRY_FIELDS = {
    "admitted_child_security", "air_profile_sha256", "air_program_sha256",
    "child_composition_manifest_sha256", "entry_kind", "entry_sha256",
    "next_parent_vk_sha256", "node_profile_sha256", "ordinal",
    "parent_height", "parent_outer_manifest_sha256", "parent_proof_security", "transcript",
    "verification_key_sha256",
}
TRANSCRIPT_FIELDS = {
    "cohort_format_version", "cohort_schema_version", "component_count",
    "domain", "format_version", "identity_sha256", "kind", "schema_version",
}
M31_FIELD_ID = 0x4D33_3101
LEAF_SECURITY_IDENTITY = (
    "bc339bc9bcf2d57ed49caccff618e944ddd03b401d528e7b3cb0d2f514306b04"
)
PARENT_SECURITY_IDENTITY = (
    "675ff4fd58923d26ae7f4573b19a53a268bcf27bf9ad96cb18a04bd845169e63"
)
EMPTY_SECURITY_IDENTITY = (
    "fb9e07f89cfbd9beadff4386839f6e2d253d0d70433ce810d6dc6672f3f2e5ed"
)


def _nonzero_sha(value: Any, where: str) -> str:
    protocol._sha(value, where)
    protocol.require(value != "00" * 32, f"{where} is zero")
    return value


def _security(
    value: Any, where: str, *, kind: str, hash_suite: str,
    ingress: str, proof_present: bool, interaction_pow_bits: int,
    pcs_pow_bits: int, query_count: int, fold_step: int,
    configured_bits: int, conjectured_bits: int, identity: str | None,
) -> dict[str, Any]:
    value = protocol.exact(value, SECURITY_FIELDS, where)
    expected = {
        "format_version": 1, "schema_version": 1, "kind": kind,
        "hash_suite": hash_suite, "recursive_ingress": ingress,
        "proof_present": proof_present, "field_id": M31_FIELD_ID,
        "interaction_pow_bits": interaction_pow_bits,
        "pcs_pow_bits": pcs_pow_bits, "fri_log_blowup_factor": 1,
        "fri_query_count": query_count, "fri_fold_step": fold_step,
        "fri_log_last_layer_degree_bound": 0, "pcs_lifting_mode": 0,
        "configured_pcs_bits": configured_bits,
        "conjectured_security_bits": conjectured_bits,
    }
    protocol.require(all(value[field] == expected_value
                         for field, expected_value in expected.items()),
                     f"{where} differs")
    _nonzero_sha(value["identity_sha256"], f"{where}.identity_sha256")
    if identity is not None:
        protocol.require(value["identity_sha256"] == identity,
                         f"{where}.identity_sha256 differs")
    return value


def _leaf_security(value: Any, where: str) -> dict[str, Any]:
    return _security(
        value, where, kind="ethereum_segment_v3_poseidon2",
        hash_suite="poseidon2_m31", ingress="ethereum_segment_v3_full",
        proof_present=True, interaction_pow_bits=10, pcs_pow_bits=16,
        query_count=193, fold_step=4, configured_bits=209,
        conjectured_bits=120, identity=LEAF_SECURITY_IDENTITY,
    )


def _empty_security(value: Any, where: str) -> dict[str, Any]:
    return _security(
        value, where, kind="proofless_empty", hash_suite="none",
        ingress="no_proof", proof_present=False, interaction_pow_bits=0,
        pcs_pow_bits=0, query_count=0, fold_step=0, configured_bits=0,
        conjectured_bits=0, identity=EMPTY_SECURITY_IDENTITY,
    )


def _parent_security(value: Any, where: str) -> dict[str, Any]:
    return _security(
        value, where, kind="recursive_parent_secure",
        hash_suite="poseidon2_m31", ingress="recursive_parent",
        proof_present=True, interaction_pow_bits=10, pcs_pow_bits=16,
        query_count=193, fold_step=4, configured_bits=209,
        conjectured_bits=120, identity=PARENT_SECURITY_IDENTITY,
    )


def _transcript(value: Any, where: str, ordinal: int) -> dict[str, Any]:
    value = protocol.exact(value, TRANSCRIPT_FIELDS, where)
    if ordinal == 0:
        expected = ("temporal_parent_v3", 0x5450_4333, 3)
    elif ordinal == 1:
        expected = ("empty_parent_v1", 0x4550_4331, 1)
    else:
        expected = ("recursive_node_v1", 0x4C32_4331, 1)
    protocol.require(
        value["kind"] == expected[0] and value["domain"] == expected[1]
        and value["cohort_format_version"] == expected[2]
        and value["cohort_schema_version"] == 1
        and value["component_count"] == 36
        and value["format_version"] == 1 and value["schema_version"] == 1,
        f"{where} differs",
    )
    _nonzero_sha(value["identity_sha256"], f"{where}.identity_sha256")
    return value


def validate_projection(value: Any) -> dict[str, Any]:
    """Validate a production-secure nine-entry transport projection."""
    value = protocol.exact(value, {
        "entries", "format_version", "profile_plan_sha256", "schema",
        "schema_version",
    }, "temporal profile plan")
    protocol.require(value["schema"] == TRANSPORT_SCHEMA
                     and value["format_version"] == 1
                     and value["schema_version"] == 2,
                     "temporal profile plan schema differs")
    _nonzero_sha(value["profile_plan_sha256"],
                 "temporal profile plan identity")
    entries = value["entries"]
    protocol.require(type(entries) is list and len(entries) == 9,
                     "temporal profile plan entry count differs")
    for ordinal, entry in enumerate(entries):
        entry = protocol.exact(
            entry, ENTRY_FIELDS, f"temporal profile plan entry {ordinal}",
        )
        protocol.require(
            type(entry["ordinal"]) is int and entry["ordinal"] == ordinal
            and type(entry["parent_height"]) is int
            and entry["parent_height"] == (1 if ordinal < 2 else ordinal)
            and entry["entry_kind"] == ENTRY_KINDS[ordinal],
            f"temporal profile plan entry {ordinal} topology differs",
        )
        for field in (
            "air_profile_sha256", "air_program_sha256", "entry_sha256",
            "child_composition_manifest_sha256", "next_parent_vk_sha256",
            "node_profile_sha256", "verification_key_sha256",
            "parent_outer_manifest_sha256",
        ):
            _nonzero_sha(entry[field],
                         f"temporal profile plan entry {ordinal}.{field}")
        _transcript(entry["transcript"],
                    f"temporal profile plan entry {ordinal}.transcript", ordinal)
        if ordinal == 0:
            _leaf_security(entry["admitted_child_security"],
                           "real-h1 admitted child security")
        elif ordinal == 1:
            _empty_security(entry["admitted_child_security"],
                            "empty-h1 admitted child security")
        else:
            _parent_security(entry["admitted_child_security"],
                             f"h{ordinal} admitted child security")
        _parent_security(entry["parent_proof_security"],
                         f"entry {ordinal} parent proof security")
    protocol.require(
        entries[0]["next_parent_vk_sha256"]
        == entries[2]["verification_key_sha256"]
        and entries[1]["next_parent_vk_sha256"]
        == entries[2]["verification_key_sha256"]
        and entries[0]["parent_proof_security"]
        == entries[2]["admitted_child_security"]
        and entries[1]["parent_proof_security"]
        == entries[2]["admitted_child_security"],
        "height-one profile edge differs",
    )
    for current, following in zip(entries[2:-1], entries[3:], strict=True):
        protocol.require(
            current["next_parent_vk_sha256"]
            == following["verification_key_sha256"]
            and current["parent_proof_security"]
            == following["admitted_child_security"],
            "upper profile edge differs",
        )
    protocol.require(len({entry["entry_sha256"] for entry in entries}) == 9,
                     "temporal profile plan entry identities are not unique")
    return value


def read(path: Path) -> dict[str, Any]:
    """Reopen the retained canonical transport and return its exact custody."""
    projection = validate_projection(
        store.read_canonical_json(path, "temporal profile plan"),
    )
    return {
        "projection": projection,
        "identity": {
            "schema": TRANSPORT_SCHEMA, "path": str(path),
            **store.file_identity(path, "temporal profile plan"),
        },
    }


def binding(path: Path) -> dict[str, Any]:
    admitted = read(path)
    return {
        "schema": BINDING_SCHEMA,
        "artifact": admitted["identity"],
        "projection": admitted["projection"],
    }


def validate_binding(value: Any) -> dict[str, Any]:
    value = protocol.exact(
        value, {"schema", "artifact", "projection"},
        "temporal profile policy template binding",
    )
    protocol.require(value["schema"] == BINDING_SCHEMA,
                     "temporal profile policy template binding schema differs")
    artifact = protocol.exact(
        value["artifact"], {"schema", "path", "bytes", "sha256"},
        "temporal profile policy template artifact",
    )
    protocol.require(artifact["schema"] == TRANSPORT_SCHEMA
                     and type(artifact["path"]) is str and artifact["path"],
                     "temporal profile policy template artifact authority differs")
    protocol._positive(
        artifact["bytes"], "temporal profile policy template artifact bytes",
    )
    _nonzero_sha(
        artifact["sha256"], "temporal profile policy template artifact SHA-256",
    )
    validate_projection(value["projection"])
    return value


def reopen_binding(value: Any, owner: Path) -> dict[str, Any]:
    """Reopen the bound file and require exact byte and semantic equality."""
    value = validate_binding(value)
    raw_path = Path(value["artifact"]["path"])
    path = raw_path if raw_path.is_absolute() else owner / raw_path
    admitted = read(path)
    protocol.require(
        {key: admitted["identity"][key] for key in ("schema", "bytes", "sha256")}
        == {key: value["artifact"][key] for key in ("schema", "bytes", "sha256")}
        and admitted["projection"] == value["projection"],
        "temporal profile policy template differs from retained artifact",
    )
    return admitted["projection"]


def parent_entry(
    value: dict[str, Any], *, parent_height: int, child_kind: str,
) -> dict[str, Any]:
    """Select the exact Zig-planned parent profile; never infer its contents."""
    value = validate_binding(value)
    protocol.require(type(parent_height) is int and 1 <= parent_height <= 8,
                     "parent profile height differs")
    if parent_height == 1:
        protocol.require(child_kind in ("real", "empty"),
                         "height-one parent child kind differs")
        ordinal = 0 if child_kind == "real" else 1
    else:
        protocol.require(child_kind in ("real", "empty", "mixed"),
                         "upper parent child kind differs")
        ordinal = parent_height
    return value["projection"]["entries"][ordinal]
