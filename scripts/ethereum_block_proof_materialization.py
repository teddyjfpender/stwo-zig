"""Admission for Zig-emitted Ethereum leaf-source materialization evidence.

The native M31/Poseidon identifiers are retained as opaque custody.  They are
never interpreted as, or substituted for, the independently emitted SHA-256
statement authorities consumed by the proof plan.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from scripts import ethereum_block_proof_process as process
from scripts import ethereum_block_proof_protocol as protocol
from scripts import ethereum_block_proof_store as store
from scripts import ethereum_block_proof_stream_request as stream_request


MATERIALIZATION_SCHEMA = (
    "stwo.ethereum.block-proof-source-materialization-result.v1"
)
NATIVE_M31_ID_FIELDS = (
    "metadata_id_m31_le", "statement_id_m31_le",
)
M31_MODULUS = (1 << 31) - 1


def _resolve(owner: Path, raw: Any, where: str) -> Path:
    protocol.require(type(raw) is str and raw, f"{where}.path differs")
    path = Path(raw)
    return path if path.is_absolute() else owner.parent / path


def _file(
    value: Any, owner: Path, where: str, *, schema: str | tuple[str, ...] | None = None,
) -> tuple[dict[str, Any], Path]:
    keys = {"path", "bytes", "sha256"} | ({"schema"} if schema else set())
    value = protocol.exact(value, keys, where)
    if schema is not None:
        admitted = (schema,) if type(schema) is str else schema
        protocol.require(value["schema"] in admitted, f"{where}.schema differs")
    protocol.require(type(value["bytes"]) is int and value["bytes"] > 0,
                     f"{where}.bytes differs")
    protocol._sha(value["sha256"], f"{where}.sha256")
    path = _resolve(owner, value["path"], where)
    store.validate_file_identity(
        path, process.identity_without_path(value), where,
    )
    return value, path


def _m31_digest(value: Any, where: str) -> str:
    """Validate eight canonical little-endian M31 limbs, without relabeling."""
    protocol.require(type(value) is str and len(value) == 64,
                     f"{where} differs")
    try:
        raw = bytes.fromhex(value)
    except ValueError as error:
        raise protocol.ProofProtocolError(f"{where} differs") from error
    protocol.require(value == raw.hex(), f"{where} differs")
    for offset in range(0, 32, 4):
        protocol.require(int.from_bytes(raw[offset:offset + 4], "little") < M31_MODULUS,
                         f"{where} contains a non-canonical M31 limb")
    return value


def validate(path: Path) -> dict[str, Any]:
    """Reopen a canonical materialization manifest and all named authorities."""
    value = protocol.exact(
        store.read_canonical_json(path, "Ethereum source materialization"),
        {
            "execution_journal", "execution_profile", "expected_output", "input",
            "job", "leaf_sources", "pcs", "schema", "segment_authority_magic",
            "segment_authority_version", "segment_count", "source_request", "status",
            "total_cycles", "content_sha256",
        },
        "Ethereum source materialization",
    )
    protocol.require(
        value["schema"] == MATERIALIZATION_SCHEMA
        and value["status"] == "materialized"
        and value["execution_profile"] == stream_request.PROFILE_NAME
        and value["segment_authority_magic"] == "STWESG31"
        and value["segment_authority_version"] == 1
        and type(value["segment_count"]) is int and value["segment_count"] >= 2
        and type(value["total_cycles"]) is int and value["total_cycles"] > 0
        and value["content_sha256"] == protocol.content_sha256(value),
        "Ethereum source materialization authority differs",
    )

    job = protocol.exact(value["job"], {
        "final_state_sha256", "initial_state_sha256", "job_sha256",
        "program_m31_le", "public_input_m31_le", "public_output_m31_le",
    }, "Ethereum source materialization job")
    for field in ("final_state_sha256", "initial_state_sha256", "job_sha256"):
        protocol._sha(job[field], f"Ethereum source materialization job.{field}")
    for field in ("program_m31_le", "public_input_m31_le", "public_output_m31_le"):
        _m31_digest(job[field], f"Ethereum source materialization job.{field}")

    source_identity, source_path = _file(
        value["source_request"], path, "Ethereum leaf source request",
        schema=(stream_request.SOURCE_SCHEMA_V1, stream_request.SOURCE_SCHEMA_V2),
    )
    source = stream_request.validate_source_file(source_path)
    protocol.require(
        value["execution_profile"] == source["execution_profile"]
        and value["segment_count"] == source["segment_count"]
        and value["segment_authority_magic"] == source["segment_authority_magic"]
        and value["segment_authority_version"]
        == source["segment_authority_version"]
        and value["pcs"] == source["pcs"],
        "materialization and SourceRequest authority differ",
    )
    for field in ("execution_journal", "input", "expected_output"):
        identity, _ = _file(
            value[field], path, f"Ethereum source materialization {field}",
        )
        protocol.require(identity == source[field],
                         f"materialization {field} differs from SourceRequest")

    leaves = value["leaf_sources"]
    protocol.require(type(leaves) is list
                     and len(leaves) == value["segment_count"],
                     "materialized leaf count differs")
    authority_paths = []
    statement_sha256 = []
    for index, leaf in enumerate(leaves):
        leaf = protocol.exact(leaf, {
            "authority", "metadata_id_m31_le", "segment_index",
            "statement_id_m31_le", "statement_sha256",
        }, f"materialized leaf {index}")
        protocol.require(leaf["segment_index"] == index,
                         "materialized leaf order differs")
        for field in NATIVE_M31_ID_FIELDS:
            _m31_digest(leaf[field], f"materialized leaf {index}.{field}")
        protocol._sha(
            leaf["statement_sha256"],
            f"materialized leaf {index}.statement_sha256",
        )
        _, authority_path = _file(
            leaf["authority"], path, f"materialized leaf {index} authority",
        )
        authority_paths.append(authority_path)
        statement_sha256.append(leaf["statement_sha256"])

    return {
        "manifest": value,
        "manifest_path": path,
        "source_request": source,
        "source_request_identity": source_identity,
        "source_request_path": source_path,
        "segment_authority_paths": authority_paths,
        "leaf_statement_sha256": statement_sha256,
    }
