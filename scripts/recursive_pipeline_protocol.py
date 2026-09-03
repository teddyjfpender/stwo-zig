"""Canonical schemas for the resumable recursive-proof control plane.

Production key manifests are minted by typed Zig commands.  The constructors in
this module are deliberately restricted to the test-only mock backend; normal
orchestration only parses and validates already-sealed key manifests.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import struct
from typing import Any, Iterable


PIPELINE_MANIFEST_SCHEMA = "stwo.recursive-pipeline-manifest.v1"
SEMANTIC_KEY_SCHEMA = "stwo.recursive-pipeline-semantic-key.v1"
EXECUTION_KEY_SCHEMA = "stwo.recursive-pipeline-execution-key.v1"
STAGE_RESULT_SCHEMA = "stwo.recursive-pipeline-stage-result.v1"
VALIDATION_RECEIPT_SCHEMA = "stwo.recursive-pipeline-validation-receipt.v1"
PROFILE_RECEIPT_SCHEMA = "stwo.recursive-pipeline-profile-receipt.v1"
CACHE_RECORD_SCHEMA = "stwo.recursive-pipeline-cache-record.v1"

SHA256 = re.compile(r"^[0-9a-f]{64}$")
NODE_ID = re.compile(r"^[a-z0-9][a-z0-9_/-]*$")
ROLE = re.compile(r"^[a-z][a-z0-9_.-]*$")

SEMANTIC_KEY_DOMAIN = b"stwo-zig/artifact-store/semantic-key/v1\x00"
EXECUTION_KEY_DOMAIN = b"stwo-zig/artifact-store/execution-key/v1\x00"
STAGE_MANIFEST_DOMAIN = b"stwo-zig/artifact-store/stage-manifest/v1\x00"


class PipelineError(ValueError):
    """Fail-closed pipeline admission error."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise PipelineError(message)


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8") + b"\n"


def sha256_bytes(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def content_sha256(value: dict[str, Any]) -> str:
    unsigned = copy.deepcopy(value)
    unsigned.pop("content_sha256", None)
    return sha256_bytes(canonical_bytes(unsigned))


def seal(value: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(value)
    result.pop("content_sha256", None)
    result["content_sha256"] = content_sha256(result)
    return result


def exact(value: Any, keys: Iterable[str], where: str) -> dict[str, Any]:
    expected = set(keys)
    require(type(value) is dict and set(value) == expected, f"{where} fields differ")
    return value


def digest(value: Any, where: str) -> str:
    require(type(value) is str and SHA256.fullmatch(value) is not None,
            f"{where} digest differs")
    return value


def nonzero_digest(value: Any, where: str) -> str:
    result = digest(value, where)
    require(result != "00" * 32, f"{where} digest is zero")
    return result


def canonical_digest(value: Any) -> str:
    return sha256_bytes(canonical_bytes(value))


def validate_seal(value: dict[str, Any], where: str) -> dict[str, Any]:
    digest(value.get("content_sha256"), f"{where}.content_sha256")
    require(value["content_sha256"] == content_sha256(value),
            f"{where} content seal differs")
    return value


def blob_ref(
    *, kind: int, format_version: int = 1, schema_version: int,
    byte_count: int, sha256: str,
) -> dict[str, Any]:
    value = {
        "kind": kind,
        "format_version": format_version,
        "schema_version": schema_version,
        "byte_count": byte_count,
        "sha256": sha256,
    }
    return validate_blob_ref(value, "blob reference")


def validate_blob_ref(value: Any, where: str) -> dict[str, Any]:
    value = exact(
        value,
        {"kind", "format_version", "schema_version", "byte_count", "sha256"},
        where,
    )
    require(type(value["kind"]) is int and 0 < value["kind"] <= 0xFFFFFFFF,
            f"{where}.kind differs")
    require(type(value["schema_version"]) is int
            and 0 < value["schema_version"] <= 0xFFFF,
            f"{where}.schema_version differs")
    require(type(value["format_version"]) is int
            and value["format_version"] == 1,
            f"{where}.format_version differs")
    require(type(value["byte_count"]) is int
            and 0 <= value["byte_count"] <= 0xFFFFFFFFFFFFFFFF,
            f"{where}.byte_count differs")
    nonzero_digest(value["sha256"], f"{where}.sha256")
    return value


def blob_ref_bytes(value: dict[str, Any]) -> bytes:
    """Return the frozen 48-byte Zig BlobRefV1 wire."""
    validate_blob_ref(value, "blob reference wire")
    return struct.pack(
        "<IHHQ", value["kind"], value["format_version"],
        value["schema_version"], value["byte_count"],
    ) + bytes.fromhex(value["sha256"])


def mock_stage_manifest_bytes(
    *, node: dict[str, Any], semantic: dict[str, Any],
    execution: dict[str, Any], ordered_inputs: list[dict[str, Any]],
    output_ref: dict[str, Any],
    dependency_stage_manifest_refs: list[dict[str, Any]],
) -> bytes:
    """Test-only encoder matching Zig StageManifestV1 canonical bytes.

    Production StageManifest creation and publication is exclusively owned by
    the persistent Zig worker.  The mock needs exact wire-shaped custody so the
    Python scheduler exercises the same typed-reference graph.
    """
    validate_node(node, "mock stage manifest node")
    validate_semantic_key(semantic)
    validate_execution_key(execution, semantic)
    validate_blob_ref(output_ref, "mock stage manifest output")
    for index, item in enumerate(dependency_stage_manifest_refs):
        validate_blob_ref(item, f"mock stage manifest dependency {index}")
        require(item["kind"] == 4 and item["schema_version"] == 1,
                "mock dependency stage manifest codec differs")
    result = bytearray(STAGE_MANIFEST_DOMAIN)
    result.extend(struct.pack(
        "<HIHH", 1, node["stage_kind"],
        node["stage_schema_version"], 4,
    ))
    result.extend(struct.pack("<H", 1))
    result.extend(bytes.fromhex(node["local_task_identity_sha256"]))
    result.extend(bytes.fromhex(semantic["identity_sha256"]))
    result.extend(bytes.fromhex(execution["identity_sha256"]))
    result.extend(struct.pack("<I", len(dependency_stage_manifest_refs)))
    for item in dependency_stage_manifest_refs:
        result.extend(bytes.fromhex(item["sha256"]))
    result.extend(struct.pack("<I", len(ordered_inputs)))
    for index, item in enumerate(ordered_inputs):
        _validate_role_ref(item, f"mock stage manifest input {index}")
        result.extend(struct.pack("<II", item["role"], item["ordinal"]))
        result.extend(blob_ref_bytes(item["blob"]))
    result.extend(struct.pack("<I", 1))
    result.extend(blob_ref_bytes(output_ref))
    result.extend(struct.pack("<II", 0, 0))
    return bytes(result)


def _validate_role_ref(value: Any, where: str) -> dict[str, Any]:
    value = exact(value, {"role", "ordinal", "blob"}, where)
    require(type(value["role"]) is int and 0 < value["role"] <= 0xFFFFFFFF,
            f"{where}.role differs")
    require(type(value["ordinal"]) is int
            and 0 <= value["ordinal"] <= 0xFFFFFFFF,
            f"{where}.ordinal differs")
    validate_blob_ref(value["blob"], f"{where}.blob")
    return value


KEY_AUTHORITY_FIELDS = (
    "protocol_identity_sha256",
    "program_identity_sha256",
    "profile_identity_sha256",
    "pcs_identity_sha256",
    "security_identity_sha256",
    "statement_identity_sha256",
    "provider_identity_sha256",
    "layout_identity_sha256",
    "registry_identity_sha256",
)


def validate_semantic_key(value: Any) -> dict[str, Any]:
    where = "semantic key"
    value = exact(value, {
        "schema", "format_version", "campaign_namespace_sha256", "stage_kind",
        "stage_schema_version", "local_task_identity_sha256",
        *KEY_AUTHORITY_FIELDS, "ordered_inputs",
        "semantic_options_identity_sha256", "identity_sha256",
    }, where)
    require(value["schema"] == SEMANTIC_KEY_SCHEMA,
            "semantic key schema differs")
    require(value["format_version"] == 1,
            "semantic key format version differs")
    nonzero_digest(value["campaign_namespace_sha256"],
                   "semantic key campaign")
    require(type(value["stage_kind"]) is int and value["stage_kind"] > 0,
            "semantic key stage kind differs")
    require(type(value["stage_schema_version"]) is int
            and 0 < value["stage_schema_version"] <= 0xFFFF,
            "semantic key stage schema differs")
    nonzero_digest(value["local_task_identity_sha256"],
                   "semantic key task identity")
    for field in KEY_AUTHORITY_FIELDS:
        digest(value[field], f"semantic key {field}")
    require(type(value["ordered_inputs"]) is list,
            "semantic key inputs differ")
    roles = []
    for index, item in enumerate(value["ordered_inputs"]):
        _validate_role_ref(item, f"semantic key input {index}")
        roles.append((item["role"], item["ordinal"]))
    require(len(roles) == len(set(roles)), "semantic key input roles differ")
    digest(value["semantic_options_identity_sha256"], "semantic key options")
    digest(value["identity_sha256"], "semantic key identity")
    require(value["identity_sha256"] == sha256_bytes(semantic_key_bytes(value)),
            "semantic key identity differs")
    return value


EXECUTION_AUTHORITY_FIELDS = (
    "producer_identity_sha256",
    "verifier_identity_sha256",
    "source_identity_sha256",
    "build_identity_sha256",
    "executable_identity_sha256",
    "toolchain_identity_sha256",
    "backend_identity_sha256",
    "optimization_identity_sha256",
    "worker_policy_identity_sha256",
    "memory_policy_identity_sha256",
    "retention_policy_identity_sha256",
    "timeout_policy_identity_sha256",
)


def validate_execution_key(value: Any, semantic: dict[str, Any] | None = None) -> dict[str, Any]:
    where = "execution key"
    value = exact(value, {
        "schema", "format_version", "semantic_key_identity_sha256",
        *EXECUTION_AUTHORITY_FIELDS, "identity_sha256",
    }, where)
    require(value["schema"] == EXECUTION_KEY_SCHEMA,
            "execution key schema differs")
    require(value["format_version"] == 1,
            "execution key format version differs")
    nonzero_digest(value["semantic_key_identity_sha256"],
                   "execution key semantic identity")
    for field in EXECUTION_AUTHORITY_FIELDS:
        nonzero_digest(value[field], f"execution key {field}")
    if semantic is not None:
        validate_semantic_key(semantic)
        require(value["semantic_key_identity_sha256"] == semantic["identity_sha256"],
                "execution key semantic identity differs")
    digest(value["identity_sha256"], "execution key identity")
    require(value["identity_sha256"] == sha256_bytes(execution_key_bytes(value)),
            "execution key identity differs")
    return value


def mock_semantic_key(
    *, campaign_namespace: str, node: dict[str, Any],
    ordered_inputs: list[dict[str, Any]],
) -> dict[str, Any]:
    """Test-only key derivation. Production must consume a Zig-minted key."""
    authorities = node["semantic_authorities"]
    result = {
        "schema": SEMANTIC_KEY_SCHEMA,
        "format_version": 1,
        "campaign_namespace_sha256": campaign_namespace,
        "stage_kind": node["stage_kind"],
        "stage_schema_version": node["stage_schema_version"],
        "local_task_identity_sha256": node["local_task_identity_sha256"],
        **{field: authorities[field] for field in KEY_AUTHORITY_FIELDS},
        "ordered_inputs": ordered_inputs,
        "semantic_options_identity_sha256": canonical_digest(node["semantic_options"]),
    }
    result["identity_sha256"] = sha256_bytes(semantic_key_bytes(result))
    return validate_semantic_key(result)


def mock_execution_key(
    semantic: dict[str, Any], execution_authorities: dict[str, str],
) -> dict[str, Any]:
    """Test-only execution key derivation."""
    result = {
        "schema": EXECUTION_KEY_SCHEMA,
        "format_version": 1,
        "semantic_key_identity_sha256": semantic["identity_sha256"],
        **{field: execution_authorities[field]
           for field in EXECUTION_AUTHORITY_FIELDS},
    }
    result["identity_sha256"] = sha256_bytes(execution_key_bytes(result))
    return validate_execution_key(result, semantic)


def blob_ref_bytes(value: dict[str, Any]) -> bytes:
    validate_blob_ref(value, "canonical blob reference")
    return (
        struct.pack(
            "<IHHQ", value["kind"], value["format_version"],
            value["schema_version"], value["byte_count"],
        )
        + bytes.fromhex(value["sha256"])
    )


def semantic_key_bytes(value: dict[str, Any]) -> bytes:
    fields = [
        value["campaign_namespace_sha256"],
        value["local_task_identity_sha256"],
        *(value[field] for field in KEY_AUTHORITY_FIELDS),
        value["semantic_options_identity_sha256"],
    ]
    inputs = value["ordered_inputs"]
    result = bytearray(SEMANTIC_KEY_DOMAIN)
    result.extend(struct.pack(
        "<HIH", value["format_version"], value["stage_kind"],
        value["stage_schema_version"],
    ))
    for field in fields:
        result.extend(bytes.fromhex(field))
    result.extend(struct.pack("<I", len(inputs)))
    for item in inputs:
        result.extend(struct.pack("<II", item["role"], item["ordinal"]))
        result.extend(blob_ref_bytes(item["blob"]))
    return bytes(result)


def execution_key_bytes(value: dict[str, Any]) -> bytes:
    result = bytearray(EXECUTION_KEY_DOMAIN)
    result.extend(struct.pack("<H", value["format_version"]))
    result.extend(bytes.fromhex(value["semantic_key_identity_sha256"]))
    for field in EXECUTION_AUTHORITY_FIELDS:
        result.extend(bytes.fromhex(value[field]))
    return bytes(result)


def decode_semantic_key(raw: bytes) -> dict[str, Any]:
    minimum = len(SEMANTIC_KEY_DOMAIN) + 2 + 4 + 2 + 12 * 32 + 4
    require(len(raw) >= minimum and raw.startswith(SEMANTIC_KEY_DOMAIN),
            "semantic key wire framing differs")
    offset = len(SEMANTIC_KEY_DOMAIN)
    format_version, stage_kind, stage_schema_version = struct.unpack_from(
        "<HIH", raw, offset,
    )
    offset += 8

    def read_digest() -> str:
        nonlocal offset
        require(offset + 32 <= len(raw), "semantic key wire is truncated")
        result = raw[offset:offset + 32].hex()
        offset += 32
        return result

    campaign = read_digest()
    local_task = read_digest()
    authorities = {field: read_digest() for field in KEY_AUTHORITY_FIELDS}
    options = read_digest()
    require(offset + 4 <= len(raw), "semantic key wire is truncated")
    count = struct.unpack_from("<I", raw, offset)[0]
    offset += 4
    inputs = []
    for _ in range(count):
        require(offset + 56 <= len(raw), "semantic key input is truncated")
        role, ordinal = struct.unpack_from("<II", raw, offset)
        offset += 8
        kind, blob_format, schema_version, byte_count = struct.unpack_from(
            "<IHHQ", raw, offset,
        )
        offset += 16
        sha256 = raw[offset:offset + 32].hex()
        offset += 32
        inputs.append({
            "role": role,
            "ordinal": ordinal,
            "blob": blob_ref(
                kind=kind, format_version=blob_format,
                schema_version=schema_version, byte_count=byte_count,
                sha256=sha256,
            ),
        })
    require(offset == len(raw), "semantic key wire has trailing bytes")
    value = {
        "schema": SEMANTIC_KEY_SCHEMA,
        "format_version": format_version,
        "campaign_namespace_sha256": campaign,
        "stage_kind": stage_kind,
        "stage_schema_version": stage_schema_version,
        "local_task_identity_sha256": local_task,
        **authorities,
        "ordered_inputs": inputs,
        "semantic_options_identity_sha256": options,
        "identity_sha256": sha256_bytes(raw),
    }
    return validate_semantic_key(value)


def decode_execution_key(raw: bytes) -> dict[str, Any]:
    expected = len(EXECUTION_KEY_DOMAIN) + 2 + (1 + len(EXECUTION_AUTHORITY_FIELDS)) * 32
    require(len(raw) == expected and raw.startswith(EXECUTION_KEY_DOMAIN),
            "execution key wire framing differs")
    offset = len(EXECUTION_KEY_DOMAIN)
    format_version = struct.unpack_from("<H", raw, offset)[0]
    offset += 2
    semantic = raw[offset:offset + 32].hex()
    offset += 32
    authorities = {}
    for field in EXECUTION_AUTHORITY_FIELDS:
        authorities[field] = raw[offset:offset + 32].hex()
        offset += 32
    value = {
        "schema": EXECUTION_KEY_SCHEMA,
        "format_version": format_version,
        "semantic_key_identity_sha256": semantic,
        **authorities,
        "identity_sha256": sha256_bytes(raw),
    }
    return validate_execution_key(value)


def validate_node(value: Any, where: str) -> dict[str, Any]:
    value = exact(value, {
        "node_id", "stage_kind", "stage_schema_version", "adapter",
        "dependencies", "external_inputs", "local_task_identity_sha256",
        "semantic_authorities", "semantic_options", "cpu_tokens",
        "rss_tokens", "output_kind", "output_schema_version",
    }, where)
    require(type(value["node_id"]) is str
            and NODE_ID.fullmatch(value["node_id"]) is not None
            and "@" not in value["node_id"], f"{where}.node_id differs")
    require(type(value["stage_kind"]) is int and value["stage_kind"] > 0,
            f"{where}.stage_kind differs")
    require(type(value["stage_schema_version"]) is int
            and value["stage_schema_version"] > 0,
            f"{where}.stage_schema_version differs")
    require(type(value["adapter"]) is str and value["adapter"],
            f"{where}.adapter differs")
    require(type(value["dependencies"]) is list
            and all(type(item) is dict for item in value["dependencies"]),
            f"{where}.dependencies differ")
    dependency_ids = []
    dependency_roles = []
    for index, item in enumerate(value["dependencies"]):
        item = exact(item, {"node_id", "role", "ordinal"},
                     f"{where}.dependencies[{index}]")
        require(type(item["node_id"]) is str and NODE_ID.fullmatch(item["node_id"]),
                f"{where}.dependency node differs")
        require(type(item["role"]) is int and 0 < item["role"] <= 0xFFFFFFFF,
                f"{where}.dependency role differs")
        require(type(item["ordinal"]) is int
                and 0 <= item["ordinal"] <= 0xFFFFFFFF,
                f"{where}.dependency ordinal differs")
        dependency_ids.append(item["node_id"])
        dependency_roles.append((item["role"], item["ordinal"]))
    require(len(dependency_ids) == len(set(dependency_ids))
            and len(dependency_roles) == len(set(dependency_roles)),
            f"{where}.dependencies differ")
    require(type(value["external_inputs"]) is list,
            f"{where}.external_inputs differs")
    for index, item in enumerate(value["external_inputs"]):
        _validate_role_ref(item, f"{where}.external_inputs[{index}]")
    digest(value["local_task_identity_sha256"], f"{where}.task identity")
    authorities = exact(
        value["semantic_authorities"], KEY_AUTHORITY_FIELDS,
        f"{where}.semantic_authorities",
    )
    for field in KEY_AUTHORITY_FIELDS:
        digest(authorities[field], f"{where}.{field}")
    require(type(value["semantic_options"]) is dict,
            f"{where}.semantic_options differs")
    for field in ("cpu_tokens", "rss_tokens", "output_kind",
                  "output_schema_version"):
        require(type(value[field]) is int and value[field] > 0,
                f"{where}.{field} differs")
    return value


def validate_pipeline_manifest(value: Any) -> dict[str, Any]:
    where = "pipeline manifest"
    value = exact(value, {
        "schema", "campaign_namespace_sha256", "goal", "test_only", "nodes",
        "content_sha256",
    }, where)
    require(value["schema"] == PIPELINE_MANIFEST_SCHEMA,
            "pipeline manifest schema differs")
    nonzero_digest(value["campaign_namespace_sha256"], "pipeline campaign")
    require(type(value["goal"]) is str and NODE_ID.fullmatch(value["goal"]),
            "pipeline goal differs")
    require(type(value["test_only"]) is bool, "pipeline test flag differs")
    require(type(value["nodes"]) is list and value["nodes"],
            "pipeline nodes differ")
    seen: set[str] = set()
    for index, node in enumerate(value["nodes"]):
        validate_node(node, f"pipeline node {index}")
        require(node["node_id"] not in seen, "pipeline node ids differ")
        require({item["node_id"] for item in node["dependencies"]} <= seen,
                f"pipeline node {node['node_id']} is not topologically ordered")
        seen.add(node["node_id"])
    require(value["goal"] in seen, "pipeline goal is absent")
    return validate_seal(value, where)


def parse_canonical(raw: bytes, validator: Any, where: str) -> dict[str, Any]:
    require(raw.endswith(b"\n") and raw.count(b"\n") == 1,
            f"{where} framing differs")
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PipelineError(f"{where} is not canonical JSON") from error
    require(canonical_bytes(value) == raw, f"{where} is not canonical JSON")
    return validator(value)
