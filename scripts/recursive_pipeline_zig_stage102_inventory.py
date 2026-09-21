"""Strict parser for Zig's immutable campaign Stage102 inventory receipt.

The receipt is emitted only after Zig revalidates the complete process-local
Session.  It contains durable controller projections, never admission
pointers, proof captures, or live lease selectors.  Python checks the exact
canonical document and forwards its rows without minting keys or topology.
"""

from __future__ import annotations

import copy
from typing import Any

from scripts import recursive_pipeline_protocol as protocol


FORMAT = "stwo.recursive-pipeline.campaign-stage102-immutable-inventory.v4"
FORMAT_VERSION = 4
SCHEMA_VERSION = 1
MAX_DESCRIPTION_BYTES = 64 * 1024 * 1024

STAGE_KIND = 2
STAGE_SCHEMA_VERSION = 102
ADAPTER = "campaign_ethereum_incremental_leaf_wrapper_v4"
SEMANTIC_OPTIONS_SCHEMA = (
    "stwo.recursive-campaign-real-leaf-wrapper-options.v4"
)
PROOF_INPUT_ROLE = 8
RECURSION_NODE_KIND = 10
RECURSION_NODE_SCHEMA_VERSION = 2
RECURSION_NODE_BYTE_COUNT = 2380
STAGE_MANIFEST_KIND = 4
STAGE_MANIFEST_SCHEMA_VERSION = 1

DESCRIPTION_FIELDS = {
    "authority_identity_sha256",
    "campaign_inventory_identity_sha256",
    "campaign_namespace_sha256",
    "campaign_shape_identity_sha256",
    "content_sha256",
    "cpu_tokens_per_node",
    "empty_leaf_count",
    "final_remint_binding_identity_sha256",
    "fold_count",
    "format",
    "format_version",
    "host_execution_identity_sha256",
    "maximum_parallel_nodes",
    "memory_policy_identity_sha256",
    "padded_leaf_count",
    "production",
    "proof_worker_count",
    "real_leaf_count",
    "registry_identity_sha256",
    "root_height",
    "rows",
    "rss_bytes_per_node",
    "schema_version",
    "total_cpu_tokens",
    "total_rss_bytes",
    "worker_policy_identity_sha256",
}
ROW_FIELDS = {
    "coordinate",
    "dependency_stage_manifest_refs",
    "execution_key",
    "node",
    "ordered_inputs",
    "output_ref",
    "semantic_key",
    "stage_manifest_ref",
}


def _positive_integer(value: Any, where: str, maximum: int) -> int:
    protocol.require(
        type(value) is int and 0 < value <= maximum,
        f"{where} differs",
    )
    return value


def _count(value: Any, where: str, maximum: int) -> int:
    protocol.require(
        type(value) is int and 0 <= value <= maximum,
        f"{where} differs",
    )
    return value


def _input_ref(value: Any, where: str) -> dict[str, Any]:
    value = protocol.exact(value, {"blob", "ordinal", "role"}, where)
    _positive_integer(value["role"], f"{where}.role", 0xFFFFFFFF)
    _count(value["ordinal"], f"{where}.ordinal", 0xFFFFFFFF)
    protocol.validate_blob_ref(value["blob"], f"{where}.blob")
    return value


def _manifest_ref(value: Any, where: str) -> dict[str, Any]:
    value = protocol.validate_blob_ref(value, where)
    protocol.require(
        value["kind"] == STAGE_MANIFEST_KIND
        and value["schema_version"] == STAGE_MANIFEST_SCHEMA_VERSION
        and value["byte_count"] > 0,
        f"{where} codec differs",
    )
    return value


def _validate_row(
    value: Any,
    *,
    expected_index: int,
    namespace: str,
    registry: str,
    cpu_tokens: int,
    rss_tokens: int,
    worker_policy: str,
    memory_policy: str,
) -> dict[str, Any]:
    where = f"Zig Stage102 inventory row {expected_index}"
    value = protocol.exact(value, ROW_FIELDS, where)
    coordinate = protocol.exact(
        value["coordinate"], {"height", "index"}, f"{where}.coordinate"
    )
    protocol.require(
        coordinate == {"height": 0, "index": expected_index},
        f"{where}.coordinate differs",
    )

    node = protocol.validate_node(value["node"], f"{where}.node")
    inputs = value["ordered_inputs"]
    protocol.require(
        type(inputs) is list and len(inputs) == 1,
        f"{where}.ordered_inputs differ",
    )
    _input_ref(inputs[0], f"{where}.ordered_inputs[0]")
    protocol.require(
        node["stage_kind"] == STAGE_KIND
        and node["stage_schema_version"] == STAGE_SCHEMA_VERSION
        and node["adapter"] == ADAPTER
        and len(node["dependencies"]) == 1
        and node["external_inputs"] == []
        and node["dependencies"][0]["role"] == PROOF_INPUT_ROLE
        and node["dependencies"][0]["ordinal"] == 0
        and (inputs[0]["role"], inputs[0]["ordinal"])
        == (PROOF_INPUT_ROLE, 0)
        and inputs[0]["blob"]["kind"] == 8
        and inputs[0]["blob"]["schema_version"] == 1
        and inputs[0]["blob"]["byte_count"] > 0
        and node["cpu_tokens"] == cpu_tokens
        and node["rss_tokens"] == rss_tokens
        and node["output_kind"] == RECURSION_NODE_KIND
        and node["output_schema_version"] == RECURSION_NODE_SCHEMA_VERSION,
        f"{where}.node contract differs",
    )
    options = protocol.exact(
        node["semantic_options"],
        {"schema", "campaign_semantic_inputs_identity_sha256"},
        f"{where}.semantic_options",
    )
    protocol.require(
        options["schema"] == SEMANTIC_OPTIONS_SCHEMA,
        f"{where}.semantic_options schema differs",
    )
    protocol.nonzero_digest(
        options["campaign_semantic_inputs_identity_sha256"],
        f"{where}.campaign semantic identity",
    )

    semantic = protocol.validate_semantic_key(value["semantic_key"])
    execution = protocol.validate_execution_key(
        value["execution_key"], semantic
    )
    protocol.require(
        semantic["campaign_namespace_sha256"] == namespace
        and semantic["stage_kind"] == node["stage_kind"]
        and semantic["stage_schema_version"] == node["stage_schema_version"]
        and semantic["local_task_identity_sha256"]
        == node["local_task_identity_sha256"]
        and semantic["ordered_inputs"] == inputs
        and semantic["semantic_options_identity_sha256"]
        == protocol.canonical_digest(node["semantic_options"])
        and semantic["registry_identity_sha256"] == registry
        and execution["worker_policy_identity_sha256"] == worker_policy
        and execution["memory_policy_identity_sha256"] == memory_policy,
        f"{where}.key projection differs",
    )
    for field in protocol.KEY_AUTHORITY_FIELDS:
        protocol.require(
            semantic[field] == node["semantic_authorities"][field],
            f"{where}.{field} differs",
        )

    output_ref = protocol.validate_blob_ref(
        value["output_ref"], f"{where}.output_ref"
    )
    protocol.require(
        output_ref["kind"] == RECURSION_NODE_KIND
        and output_ref["schema_version"] == RECURSION_NODE_SCHEMA_VERSION
        and output_ref["byte_count"] == RECURSION_NODE_BYTE_COUNT,
        f"{where}.output_ref codec differs",
    )
    _manifest_ref(value["stage_manifest_ref"], f"{where}.stage_manifest_ref")
    dependencies = value["dependency_stage_manifest_refs"]
    protocol.require(
        type(dependencies) is list and len(dependencies) == 1,
        f"{where}.dependency manifests differ",
    )
    _manifest_ref(dependencies[0], f"{where}.dependency manifest")
    return value


def validate_description(value: Any) -> dict[str, Any]:
    value = protocol.exact(
        value, DESCRIPTION_FIELDS, "Zig immutable Stage102 inventory"
    )
    protocol.validate_seal(value, "Zig immutable Stage102 inventory")
    protocol.require(
        value["format"] == FORMAT
        and value["format_version"] == FORMAT_VERSION
        and value["schema_version"] == SCHEMA_VERSION
        and value["production"] is False,
        "Zig immutable Stage102 inventory schema differs",
    )
    for field in (
        "authority_identity_sha256",
        "campaign_inventory_identity_sha256",
        "campaign_namespace_sha256",
        "campaign_shape_identity_sha256",
        "final_remint_binding_identity_sha256",
        "host_execution_identity_sha256",
        "memory_policy_identity_sha256",
        "registry_identity_sha256",
        "worker_policy_identity_sha256",
    ):
        protocol.nonzero_digest(value[field], f"Zig Stage102 {field}")

    real_count = _positive_integer(
        value["real_leaf_count"], "Zig Stage102 real count", 0xFFFFFFFF
    )
    for field in ("padded_leaf_count", "empty_leaf_count", "fold_count"):
        _count(value[field], f"Zig Stage102 {field}", 0xFFFFFFFF)
    _count(value["root_height"], "Zig Stage102 root height", 0xFF)
    for field in (
        "total_cpu_tokens",
        "cpu_tokens_per_node",
        "proof_worker_count",
        "maximum_parallel_nodes",
    ):
        _positive_integer(value[field], f"Zig Stage102 {field}", 0xFFFF)
    for field in ("total_rss_bytes", "rss_bytes_per_node"):
        _positive_integer(value[field], f"Zig Stage102 {field}", 0xFFFFFFFFFFFFFFFF)

    rows = value["rows"]
    protocol.require(
        type(rows) is list and len(rows) == real_count,
        "Zig Stage102 row count differs",
    )
    node_ids: set[str] = set()
    dependency_ids: set[str] = set()
    output_ids: set[tuple[int, int, str]] = set()
    manifest_ids: set[tuple[int, int, str]] = set()
    for index, row in enumerate(rows):
        row = _validate_row(
            row,
            expected_index=index,
            namespace=value["campaign_namespace_sha256"],
            registry=value["registry_identity_sha256"],
            cpu_tokens=value["cpu_tokens_per_node"],
            rss_tokens=value["rss_bytes_per_node"],
            worker_policy=value["worker_policy_identity_sha256"],
            memory_policy=value["memory_policy_identity_sha256"],
        )
        node_id = row["node"]["node_id"]
        dependency_id = row["node"]["dependencies"][0]["node_id"]
        output = row["output_ref"]
        manifest = row["stage_manifest_ref"]
        output_id = (output["kind"], output["schema_version"], output["sha256"])
        manifest_id = (
            manifest["kind"], manifest["schema_version"], manifest["sha256"]
        )
        protocol.require(
            node_id not in node_ids
            and dependency_id not in dependency_ids
            and output_id not in output_ids
            and manifest_id not in manifest_ids,
            "Zig Stage102 inventory rows are not unique",
        )
        node_ids.add(node_id)
        dependency_ids.add(dependency_id)
        output_ids.add(output_id)
        manifest_ids.add(manifest_id)

    authority_projection = copy.deepcopy(value)
    authority_projection.pop("content_sha256")
    observed_authority = authority_projection.pop("authority_identity_sha256")
    protocol.require(
        observed_authority == protocol.canonical_digest(authority_projection),
        "Zig Stage102 authority identity differs",
    )
    return value


def parse_description(raw: bytes) -> dict[str, Any]:
    protocol.require(
        0 < len(raw) <= MAX_DESCRIPTION_BYTES,
        "Zig immutable Stage102 inventory size differs",
    )
    return protocol.parse_canonical(
        raw,
        validate_description,
        "Zig immutable Stage102 inventory",
    )


def rows(value: dict[str, Any]) -> list[dict[str, Any]]:
    """Return durable row projections only; no live capability can appear."""
    value = validate_description(value)
    return copy.deepcopy(value["rows"])
