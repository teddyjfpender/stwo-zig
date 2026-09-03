"""Sealed authority for one resumable Ethereum leaf-producer session."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from scripts import ethereum_block_proof_process as process
from scripts import ethereum_block_proof_protocol as protocol
from scripts import ethereum_block_proof_store as store


REQUEST_SCHEMA = "stwo.ethereum.block-proof-leaf-stream-request.v1"
PROGRESS_RECORD_SCHEMA = "stwo.ethereum.block-proof-leaf-progress-record.v1"
SOURCE_SCHEMA_V1 = "stwo.ethereum.block-proof-leaf-stream-source.v1"
SOURCE_SCHEMA_V2 = "stwo.ethereum.block-proof-leaf-stream-source.v2"
SOURCE_SCHEMA = SOURCE_SCHEMA_V2
PROFILE_NAME = "rv32im-zkvm-ethereum-v1"
PROFILE_DIGEST = "fbe8833de35b29ab155afed58f593d44d2a7257ad4491d953742d394da66cfc2"
NATIVE_BLAKE_PCS = {
    "commitment_hash": "Blake2s", "field": "M31", "fold_step": 1,
    "lifting_log_size": None, "log_blowup_factor": 1,
    "log_last_layer_degree_bound": 0, "n_queries": 70, "pow_bits": 26,
    "transcript_hash": "Blake2s",
}
SECURE_PCS = NATIVE_BLAKE_PCS
RECURSIVE_POSEIDON_PCS = {
    "commitment_hash": "Poseidon2-M31", "field": "M31", "fold_step": 4,
    "lifting_log_size": None, "log_blowup_factor": 1,
    "log_last_layer_degree_bound": 0, "n_queries": 193, "pow_bits": 16,
    "transcript_hash": "Poseidon2-M31",
}
RECURSIVE_PROFILE_NAME = "stwo.ethereum-segment-v3-recursive-poseidon2-m31-v1"
RECURSIVE_SECURITY_IDENTITY = (
    "bc339bc9bcf2d57ed49caccff618e944ddd03b401d528e7b3cb0d2f514306b04"
)
PROOF_PROFILE_KEYS = {
    "air_program_id_m31_le", "configured_pcs_bits",
    "conjectured_security_bits", "extension_component_count", "hash_suite",
    "interaction_pow_bits",
    "child_air_manifest_sha256", "leaf_verification_key_id_m31_le",
    "profile_id_m31_le", "profile_name", "proof_kind", "recursive_ingress",
    "security_identity_sha256",
}
M31_MODULUS = (1 << 31) - 1


def _m31(value: Any, where: str) -> str:
    protocol.require(type(value) is str and len(value) == 64, f"{where} differs")
    try:
        raw = bytes.fromhex(value)
    except ValueError as error:
        raise protocol.ProofProtocolError(f"{where} differs") from error
    protocol.require(value == raw.hex() and any(raw), f"{where} differs")
    protocol.require(all(
        int.from_bytes(raw[offset:offset + 4], "little") < M31_MODULUS
        for offset in range(0, 32, 4)
    ), f"{where} contains a non-canonical M31 limb")
    return value


def validate_recursive_profile(value: Any) -> dict[str, Any]:
    value = protocol.exact(value, PROOF_PROFILE_KEYS,
                           "recursive Ethereum leaf proof profile")
    for field in (
        "air_program_id_m31_le", "leaf_verification_key_id_m31_le",
        "profile_id_m31_le",
    ):
        _m31(value[field], f"recursive Ethereum leaf proof profile.{field}")
    for field in ("child_air_manifest_sha256", "security_identity_sha256"):
        protocol._sha(value[field], f"recursive Ethereum leaf proof profile.{field}")
    protocol.require(
        value["extension_component_count"] == 14
        and value["configured_pcs_bits"] == 209
        and value["conjectured_security_bits"] == 120
        and value["hash_suite"] == "Poseidon2-M31"
        and value["interaction_pow_bits"] == 10
        and value["profile_name"] == RECURSIVE_PROFILE_NAME
        and value["proof_kind"] == "ethereum_segment_v3_poseidon2"
        and value["recursive_ingress"] == "ethereum_segment_v3_full"
        and value["security_identity_sha256"] == RECURSIVE_SECURITY_IDENTITY,
        "recursive Ethereum leaf proof profile differs",
    )
    return value


def _source_identity(
    value: Any, source_path: Path, where: str,
) -> dict[str, Any]:
    value = protocol.exact(value, {"path", "bytes", "sha256"}, where)
    protocol.require(type(value["path"]) is str and value["path"]
                     and type(value["bytes"]) is int and value["bytes"] > 0,
                     f"{where} differs")
    protocol._sha(value["sha256"], f"{where}.sha256")
    path = Path(value["path"])
    if not path.is_absolute():
        path = source_path.parent / path
    store.validate_file_identity(
        path, process.identity_without_path(value), where,
    )
    return value


def validate_source_file(
    path: Path, *, require_recursive: bool = False,
) -> dict[str, Any]:
    """Reopen an append-only V1-native or V2-recursive SourceRequest."""
    value = store.read_canonical_json(path, "leaf stream source")
    schema = value.get("schema")
    keys = {
        "clock_frame", "elf", "execution_journal", "execution_profile",
        "expected_output", "input", "pcs", "profile_abi_version",
        "profile_semantic_digest", "profile_wire_id", "schema",
        "segment_authority_magic", "segment_authority_version", "segment_count",
        "segment_step_budget", "strict_completion",
    }
    if schema == SOURCE_SCHEMA_V2:
        keys.add("proof_profile")
    value = protocol.exact(value, keys, "leaf stream source")
    expected_pcs = (RECURSIVE_POSEIDON_PCS if schema == SOURCE_SCHEMA_V2
                    else NATIVE_BLAKE_PCS)
    protocol.require(
        schema in (SOURCE_SCHEMA_V1, SOURCE_SCHEMA_V2)
        and (not require_recursive or schema == SOURCE_SCHEMA_V2)
        and value["clock_frame"] == "leaf_local"
        and value["execution_profile"] == PROFILE_NAME
        and value["profile_wire_id"] == 3
        and value["profile_abi_version"] == 1
        and value["profile_semantic_digest"] == PROFILE_DIGEST
        and value["segment_authority_magic"] == "STWESG31"
        and value["segment_authority_version"] == 1
        and type(value["segment_count"]) is int and value["segment_count"] >= 2
        and type(value["segment_step_budget"]) is int
        and value["segment_step_budget"] > 0
        and value["strict_completion"] is True
        and value["pcs"] == expected_pcs,
        "leaf stream source authority differs",
    )
    if schema == SOURCE_SCHEMA_V2:
        validate_recursive_profile(value["proof_profile"])
    for field in ("elf", "input", "expected_output", "execution_journal"):
        _source_identity(value[field], path, f"leaf stream source {field}")
    return value


def build(
    plan: dict[str, Any], context: dict[str, Any], committed: list[dict[str, Any]],
    stream_session_sha256: str, session_index: int, progress_path: Path,
) -> dict[str, Any]:
    """Bind exact sources and an already-verified committed prefix."""
    segment_paths = context["segment_authority_paths"]
    protocol.require(len(segment_paths) == plan["real_segment_count"],
                     "leaf stream segment authority count differs")
    committed_by_index = {record["node_index"]: record for record in committed}
    committed_inputs = {
        item["node_index"]: item for item in context["committed_leaf_inputs"]
    }
    segments = []
    for index, (segment, source_path) in enumerate(
        zip(plan["segments"], segment_paths, strict=True)
    ):
        expected = process.identity_without_path(segment["source"])
        store.validate_file_identity(
            source_path, expected, f"leaf stream segment {index} authority",
        )
        committed_record = committed_by_index.get(index)
        committed_projection = None
        if committed_record is not None:
            artifact = committed_record["proof_artifact"]
            retained = committed_inputs[index]
            protocol.require(retained["kind"] == "verified_real_leaf",
                             "leaf stream committed input kind differs")
            store.validate_file_identity(
                retained["proof_path"], artifact["proof"],
                f"committed leaf {index} proof",
            )
            receipt_identity = process.identity_without_path(
                committed_record["files"]["verification_receipt"],
            )
            store.validate_file_identity(
                retained["verification_receipt_path"], receipt_identity,
                f"committed leaf {index} verifier receipt",
            )
            committed_projection = {
                "record_sha256": committed_record["content_sha256"],
                "statement_sha256": artifact["statement_sha256"],
                "root_sha256": artifact["root_sha256"],
                "proof": {"path": str(retained["proof_path"]), **artifact["proof"]},
                "verification_receipt": {
                    "path": str(retained["verification_receipt_path"]),
                    **receipt_identity,
                },
            }
        segments.append({
            "segment_index": index,
            "expected_statement_sha256": plan["segments"][index][
                "source_public_statement_sha256"
            ],
            "recursive_statement_sha256": plan["segments"][index][
                "recursive_statement_sha256"
            ],
            "expected_authority": {"path": str(source_path), **expected},
            "committed": committed_projection,
        })
    source = plan["leaf_stream_request"]
    stream_source_path = Path(context["leaf_stream_request_path"])
    store.validate_file_identity(
        stream_source_path, process.identity_without_path(source),
        "leaf stream source request",
    )
    return protocol.seal({
        "schema": REQUEST_SCHEMA,
        "plan_sha256": plan["content_sha256"],
        "session_id": plan["session_id"],
        "stream_session_sha256": stream_session_sha256,
        "source_request": {
            "schema": source["schema"],
            "path": str(stream_source_path),
            **process.identity_without_path(source),
        },
        "producer_sha256": plan["prover"]["sha256"],
        "verifier_sha256": plan["verifier"]["sha256"],
        "real_segment_count": plan["real_segment_count"],
        "first_uncommitted_segment": len(committed),
        "durable_progress": {
            "schema": PROGRESS_RECORD_SCHEMA,
            "path": str(progress_path),
            "publication_prefix": f"sessions/session-{session_index:06d}/proofs",
        },
        "segments": segments,
    })
