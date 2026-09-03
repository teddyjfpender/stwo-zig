"""Strict controller forwarder for Zig-owned campaign Stage103/104 plans.

The Zig description already binds runtime topology, campaign semantics, and
execution policy.  Python validates its canonical envelope and stage/CAS
shape, then forwards the exact node and ordered inputs to the persistent Zig
worker.  It never derives campaign semantics, predicts parent outputs, or
serializes a live verifier lease.
"""

from __future__ import annotations

import copy
import re
from typing import Any

from scripts import recursive_pipeline_protocol as protocol


FORMAT = "stwo.recursive-pipeline.campaign-final-stage-description.v2"
FORMAT_VERSION = 2
SCHEMA_VERSION = 1

STAGE103_KIND = 2
STAGE103_SCHEMA_VERSION = 103
STAGE103_ADAPTER = "campaign_canonical_empty_v2"
STAGE103_SOURCE_KIND = 14
STAGE103_SOURCE_SCHEMA_VERSION = 2
STAGE103_SOURCE_BYTE_COUNT = 1892

STAGE104_KIND = 4
STAGE104_SCHEMA_VERSION = 104
STAGE104_ADAPTER = "campaign_common_fold_v2"

RECURSION_NODE_KIND = 10
RECURSION_NODE_SCHEMA_VERSION = 2
RECURSION_NODE_BYTE_COUNT = 2380
STAGE_MANIFEST_KIND = 4
STAGE_MANIFEST_SCHEMA_VERSION = 1

EMPTY_NODE_ID = re.compile(r"^empty/[0-9]+$")
FOLD_NODE_ID = re.compile(r"^fold/[0-9]+/[0-9]+$")

DESCRIPTION_FIELDS = {
    "campaign_namespace_sha256",
    "campaign_shape_identity_sha256",
    "content_sha256",
    "dependency_stage_manifest_refs",
    "description_identity_sha256",
    "execution_key_identity_sha256",
    "final_remint_binding_identity_sha256",
    "format",
    "format_version",
    "node",
    "ordered_inputs",
    "planned_semantic_identity_sha256",
    "production",
    "registry_identity_sha256",
    "schema_version",
    "semantic_key_identity_sha256",
    "serializable_fresh_capability",
}


def _input_ref(value: Any, where: str) -> dict[str, Any]:
    value = protocol.exact(value, {"blob", "ordinal", "role"}, where)
    protocol.require(
        type(value["role"]) is int and 0 < value["role"] <= 0xFFFFFFFF,
        f"{where}.role differs",
    )
    protocol.require(
        type(value["ordinal"]) is int
        and 0 <= value["ordinal"] <= 0xFFFFFFFF,
        f"{where}.ordinal differs",
    )
    protocol.validate_blob_ref(value["blob"], f"{where}.blob")
    return value


def _manifest_ref(value: Any, where: str) -> dict[str, Any]:
    result = protocol.validate_blob_ref(value, where)
    protocol.require(
        result["kind"] == STAGE_MANIFEST_KIND
        and result["schema_version"] == STAGE_MANIFEST_SCHEMA_VERSION
        and result["byte_count"] > 0,
        f"{where} codec differs",
    )
    return result


def _validate_stage103(
    node: dict[str, Any], ordered_inputs: list[dict[str, Any]],
    manifests: list[dict[str, Any]],
) -> None:
    protocol.require(
        node["stage_kind"] == STAGE103_KIND
        and node["stage_schema_version"] == STAGE103_SCHEMA_VERSION
        and node["adapter"] == STAGE103_ADAPTER
        and EMPTY_NODE_ID.fullmatch(node["node_id"]) is not None
        and node["dependencies"] == []
        and len(node["external_inputs"]) == 1
        and node["external_inputs"] == ordered_inputs
        and len(ordered_inputs) == 1
        and manifests == [],
        "Zig Stage103 description topology differs",
    )
    source = ordered_inputs[0]
    protocol.require(
        (source["role"], source["ordinal"]) == (1, 0)
        and source["blob"]["kind"] == STAGE103_SOURCE_KIND
        and source["blob"]["schema_version"]
        == STAGE103_SOURCE_SCHEMA_VERSION
        and source["blob"]["byte_count"] == STAGE103_SOURCE_BYTE_COUNT,
        "Zig Stage103 source codec differs",
    )


def _validate_stage104(
    node: dict[str, Any], ordered_inputs: list[dict[str, Any]],
    manifests: list[dict[str, Any]],
) -> None:
    protocol.require(
        node["stage_kind"] == STAGE104_KIND
        and node["stage_schema_version"] == STAGE104_SCHEMA_VERSION
        and node["adapter"] == STAGE104_ADAPTER
        and FOLD_NODE_ID.fullmatch(node["node_id"]) is not None
        and node["external_inputs"] == []
        and len(node["dependencies"]) == 2
        and len(ordered_inputs) == 2
        and len(manifests) == 2,
        "Zig Stage104 description topology differs",
    )
    expected = ((6, 0), (7, 0))
    for index, (dependency, item, coordinate) in enumerate(
        zip(node["dependencies"], ordered_inputs, expected, strict=True)
    ):
        protocol.require(
            (dependency["role"], dependency["ordinal"]) == coordinate
            and (item["role"], item["ordinal"]) == coordinate
            and item["blob"]["kind"] == RECURSION_NODE_KIND
            and item["blob"]["schema_version"]
            == RECURSION_NODE_SCHEMA_VERSION
            and item["blob"]["byte_count"] == RECURSION_NODE_BYTE_COUNT,
            f"Zig Stage104 child {index} differs",
        )
    for index, manifest in enumerate(manifests):
        _manifest_ref(manifest, f"Zig Stage104 manifest {index}")


def validate_description(value: Any) -> dict[str, Any]:
    value = protocol.exact(
        value, DESCRIPTION_FIELDS, "Zig campaign final stage description",
    )
    protocol.validate_seal(value, "Zig campaign final stage description")
    protocol.require(
        value["format"] == FORMAT
        and value["format_version"] == FORMAT_VERSION
        and value["schema_version"] == SCHEMA_VERSION
        and value["production"] is False
        and value["serializable_fresh_capability"] is False,
        "Zig campaign final stage description schema differs",
    )
    for field in (
        "campaign_namespace_sha256",
        "campaign_shape_identity_sha256",
        "final_remint_binding_identity_sha256",
        "registry_identity_sha256",
        "planned_semantic_identity_sha256",
        "semantic_key_identity_sha256",
        "execution_key_identity_sha256",
        "description_identity_sha256",
    ):
        protocol.nonzero_digest(value[field], f"Zig final description {field}")
    node = protocol.validate_node(value["node"], "Zig final description node")
    protocol.require(
        node["output_kind"] == RECURSION_NODE_KIND
        and node["output_schema_version"] == RECURSION_NODE_SCHEMA_VERSION
        and node["semantic_authorities"]["registry_identity_sha256"]
        == value["registry_identity_sha256"],
        "Zig final description node authority differs",
    )
    options = protocol.exact(
        node["semantic_options"],
        {"schema", "campaign_semantic_inputs_identity_sha256"},
        "Zig final description semantic options",
    )
    protocol.require(
        options["schema"] == "stwo.recursive-campaign-node-options.v2"
        and options["campaign_semantic_inputs_identity_sha256"]
        == value["planned_semantic_identity_sha256"],
        "Zig final description semantic projection differs",
    )
    ordered_inputs = value["ordered_inputs"]
    protocol.require(
        type(ordered_inputs) is list,
        "Zig final description ordered inputs differ",
    )
    roles: list[tuple[int, int]] = []
    for index, item in enumerate(ordered_inputs):
        item = _input_ref(item, f"Zig final description input {index}")
        roles.append((item["role"], item["ordinal"]))
    protocol.require(
        len(roles) == len(set(roles)),
        "Zig final description input roles differ",
    )
    manifests = value["dependency_stage_manifest_refs"]
    protocol.require(
        type(manifests) is list,
        "Zig final description manifests differ",
    )
    if node["stage_schema_version"] == STAGE103_SCHEMA_VERSION:
        _validate_stage103(node, ordered_inputs, manifests)
    elif node["stage_schema_version"] == STAGE104_SCHEMA_VERSION:
        _validate_stage104(node, ordered_inputs, manifests)
    else:
        raise protocol.PipelineError(
            "Zig final description stage is not Stage103 or Stage104"
        )
    return value


def parse_description(raw: bytes) -> dict[str, Any]:
    return protocol.parse_canonical(
        raw,
        validate_description,
        "Zig campaign final stage description",
    )


def forward_worker_inputs(
    value: dict[str, Any],
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Return an exact copy suitable for the persistent Zig worker.

    The copy contains no lease selector.  The scheduler obtains live child
    leases from successful `coldOpen` responses and passes those separately.
    """
    value = validate_description(value)
    return copy.deepcopy(value["node"]), copy.deepcopy(value["ordered_inputs"])


def dependency_stage_manifest_refs(
    value: dict[str, Any],
) -> list[dict[str, Any]]:
    value = validate_description(value)
    return copy.deepcopy(value["dependency_stage_manifest_refs"])


def validate_worker_derivation(
    value: dict[str, Any], semantic: dict[str, Any],
    execution: dict[str, Any],
) -> None:
    """Match independently Zig-derived worker keys to the Zig plan."""
    value = validate_description(value)
    semantic = protocol.validate_semantic_key(semantic)
    execution = protocol.validate_execution_key(execution, semantic)
    node = value["node"]
    protocol.require(
        semantic["identity_sha256"] == value["semantic_key_identity_sha256"]
        and execution["identity_sha256"]
        == value["execution_key_identity_sha256"]
        and semantic["campaign_namespace_sha256"]
        == value["campaign_namespace_sha256"]
        and semantic["stage_kind"] == node["stage_kind"]
        and semantic["stage_schema_version"] == node["stage_schema_version"]
        and semantic["local_task_identity_sha256"]
        == node["local_task_identity_sha256"]
        and semantic["ordered_inputs"] == value["ordered_inputs"],
        "worker derivation differs from Zig final description",
    )
    for field in protocol.KEY_AUTHORITY_FIELDS:
        protocol.require(
            semantic[field] == node["semantic_authorities"][field],
            f"worker derivation {field} differs from Zig final description",
        )


def require_complete_recursive_campaign(_: list[dict[str, Any]]) -> None:
    """Remain fail-closed until Zig also supplies the Stage102 inventory."""
    raise protocol.PipelineError(
        "complete recursive campaign still requires Zig Stage102 inventory"
    )
