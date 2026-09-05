"""Read the Zig-authenticated Stage101 campaign frontier.

The input to this module is controller metadata emitted only after the Zig
campaign cold-describe command has rehashed the CAS and transitively validated
the STWCIT04 table.  Python validates canonical framing and the frozen worker
contract, but deliberately does not recompute the Zig validation receipt or
derive recursive topology.

This boundary emits native-leaf nodes only.  Empty leaves, wrappers, and folds
must come from their own Zig-owned descriptions before a complete production
manifest can be assembled.
"""

from __future__ import annotations

import copy
import math
from pathlib import Path
import subprocess
import tempfile
from typing import Any

from scripts import recursive_pipeline_protocol as protocol
from scripts import recursive_pipeline_zig_final_description as final_description
from scripts import recursive_pipeline_zig_stage102_inventory as stage102_inventory


FORMAT = "stwo.recursive-pipeline.incremental-campaign-worker-description.v4"
SCHEMA_VERSION = 4
CONTROLLER_VIEW_FORMAT = "stwo.recursive-pipeline.stage101-frontier-view.v1"
CONTROLLER_VIEW_SCHEMA_VERSION = 1
COMPLETE_VIEW_FORMAT = "stwo.recursive-pipeline.zig-campaign-controller-view.v2"
COMPLETE_VIEW_SCHEMA_VERSION = 2
MAX_DESCRIPTION_BYTES = 64 * 1024 * 1024
MAX_DIAGNOSTIC_BYTES = 4096

ADAPTER = "ethereum_incremental_native_leaf_v4"
STAGE_KIND = 2  # Artifact Store StageKindV1.prove.
STAGE_SCHEMA_VERSION = 101
OUTPUT_KIND = 8  # ArtifactKindV1.proof_artifact.
OUTPUT_SCHEMA_VERSION = 1

TABLE_KIND = 9
TABLE_SCHEMA_VERSION = 0x0410
RECIPE_KIND = 9
RECIPE_SCHEMA_VERSION = 1

STAGE_INPUT_COORDINATES = (
    (2, 0),
    (3, 0),
    (4, 0),
    (5, 0),
    (9, 0),
    (9, 1),
    (10, 0),
)
STAGE_INPUT_CODECS = (
    (12, 1),
    (13, 1),
    (9, RECIPE_SCHEMA_VERSION),
    (9, 1),
    (9, 4),
    (9, 0x0402),
    (11, 1),
)

DESCRIPTION_FIELDS = {
    "authenticated_segment_count",
    "campaign_namespace_sha256",
    "custody_validation_receipt_identity_sha256",
    "format",
    "import_receipt_identity_sha256",
    "rows",
    "schema_version",
    "table_ref",
    "topology",
    "validation_receipt_identity_sha256",
}
ROW_FIELDS = {
    "campaign_namespace_sha256",
    "local_task_identity_sha256",
    "recipe_ref",
    "segment_index",
    "semantic_authorities",
    "stage_inputs",
}
TOPOLOGY_FIELDS = {
    "empty_leaf_count",
    "fold_count",
    "leaf_count",
    "padded_leaf_count",
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


def _topology(value: Any, authenticated_count: int) -> dict[str, int]:
    value = protocol.exact(value, TOPOLOGY_FIELDS, "Zig campaign topology")
    for field in TOPOLOGY_FIELDS:
        protocol.require(
            type(value[field]) is int and 0 <= value[field] <= 0xFFFFFFFF,
            f"Zig campaign topology {field} differs",
        )
    protocol.require(
        value["leaf_count"] == authenticated_count
        and value["padded_leaf_count"] >= authenticated_count,
        "Zig campaign topology custody differs",
    )
    # Do not derive a power of two or fold count here.  Those values are
    # authenticated by Zig and are intentionally forwarded verbatim.
    return value


def validate_description(value: Any) -> dict[str, Any]:
    value = protocol.exact(value, DESCRIPTION_FIELDS, "Zig Stage101 description")
    protocol.require(
        value["format"] == FORMAT and value["schema_version"] == SCHEMA_VERSION,
        "Zig Stage101 description schema differs",
    )
    count = value["authenticated_segment_count"]
    protocol.require(
        type(count) is int and 0 < count <= 0xFFFFFFFF,
        "Zig Stage101 authenticated count differs",
    )
    namespace = protocol.nonzero_digest(
        value["campaign_namespace_sha256"], "Zig Stage101 campaign namespace"
    )
    for field in (
        "custody_validation_receipt_identity_sha256",
        "import_receipt_identity_sha256",
        "validation_receipt_identity_sha256",
    ):
        protocol.nonzero_digest(value[field], f"Zig Stage101 {field}")

    table_ref = protocol.validate_blob_ref(
        value["table_ref"], "Zig Stage101 campaign table"
    )
    protocol.require(
        table_ref["kind"] == TABLE_KIND
        and table_ref["schema_version"] == TABLE_SCHEMA_VERSION
        and table_ref["byte_count"] > 0,
        "Zig Stage101 campaign table codec differs",
    )
    _topology(value["topology"], count)

    rows = value["rows"]
    protocol.require(
        type(rows) is list and len(rows) == count,
        "Zig Stage101 row count differs",
    )
    for expected_index, row in enumerate(rows):
        where = f"Zig Stage101 row {expected_index}"
        row = protocol.exact(row, ROW_FIELDS, where)
        protocol.require(
            row["segment_index"] == expected_index,
            f"{where}.segment_index differs",
        )
        protocol.require(
            row["campaign_namespace_sha256"] == namespace,
            f"{where}.campaign namespace differs",
        )
        protocol.nonzero_digest(
            row["local_task_identity_sha256"], f"{where}.task identity"
        )
        authorities = protocol.exact(
            row["semantic_authorities"],
            protocol.KEY_AUTHORITY_FIELDS,
            f"{where}.semantic authorities",
        )
        for field in protocol.KEY_AUTHORITY_FIELDS:
            protocol.digest(authorities[field], f"{where}.{field}")

        recipe = protocol.validate_blob_ref(row["recipe_ref"], f"{where}.recipe")
        protocol.require(
            recipe["kind"] == RECIPE_KIND
            and recipe["schema_version"] == RECIPE_SCHEMA_VERSION
            and recipe["byte_count"] > 0,
            f"{where}.recipe codec differs",
        )
        inputs = row["stage_inputs"]
        protocol.require(
            type(inputs) is list and len(inputs) == len(STAGE_INPUT_COORDINATES),
            f"{where}.stage inputs differ",
        )
        for ordinal, (item, coordinate, codec) in enumerate(
            zip(inputs, STAGE_INPUT_COORDINATES, STAGE_INPUT_CODECS, strict=True)
        ):
            item = _input_ref(item, f"{where}.stage_inputs[{ordinal}]")
            protocol.require(
                (item["role"], item["ordinal"]) == coordinate
                and (item["blob"]["kind"], item["blob"]["schema_version"])
                == codec,
                f"{where}.stage input {ordinal} contract differs",
            )
        protocol.require(
            inputs[2]["blob"] == recipe,
            f"{where}.recipe reference differs",
        )
    return value


def parse_description(raw: bytes) -> dict[str, Any]:
    protocol.require(
        0 < len(raw) <= MAX_DESCRIPTION_BYTES,
        "Zig Stage101 description size differs",
    )
    return protocol.parse_canonical(
        raw, validate_description, "Zig Stage101 description"
    )


def _resolve_path(
    value: str | Path, *, regular_file: bool, where: str,
) -> Path:
    try:
        result = Path(value).resolve(strict=True)
    except OSError as error:
        raise protocol.PipelineError(f"{where} is unavailable") from error
    protocol.require(
        result.is_file() if regular_file else result.is_dir(),
        f"{where} type differs",
    )
    return result


def run_cold_describe(
    executable: str | Path,
    campaign_import_receipt: str | Path,
    artifact_store_root: str | Path,
    *,
    timeout_seconds: float = 3600.0,
) -> dict[str, Any]:
    """Run the Zig custody boundary and parse its canonical description.

    The subprocess receives only the STWCIR04 receipt and Zig CAS root.  It is
    the Zig command—not this Python wrapper—that rehashes the CAS and performs
    transitive typed admission.  Temporary files keep command output out of
    Python memory until its size has been bounded.
    """
    protocol.require(
        type(timeout_seconds) in (int, float)
        and math.isfinite(timeout_seconds)
        and timeout_seconds > 0,
        "Zig cold-describe timeout differs",
    )
    binary = _resolve_path(
        executable, regular_file=True, where="Zig cold-describe executable"
    )
    receipt = _resolve_path(
        campaign_import_receipt,
        regular_file=True,
        where="campaign import receipt",
    )
    store = _resolve_path(
        artifact_store_root, regular_file=False, where="Zig artifact store"
    )
    command = [
        str(binary),
        "--campaign-import-receipt",
        str(receipt),
        "--artifact-store-root",
        str(store),
    ]
    try:
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            completed = subprocess.run(
                command,
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=stdout,
                stderr=stderr,
                timeout=timeout_seconds,
                close_fds=True,
            )
            if completed.returncode != 0:
                stderr.seek(0)
                diagnostic = stderr.read(MAX_DIAGNOSTIC_BYTES).decode(
                    "utf-8", errors="replace"
                ).strip()
                suffix = f": {diagnostic}" if diagnostic else ""
                raise protocol.PipelineError(
                    f"Zig cold-describe failed with exit {completed.returncode}{suffix}"
                )
            size = stdout.tell()
            protocol.require(
                0 < size <= MAX_DESCRIPTION_BYTES,
                "Zig Stage101 description size differs",
            )
            stdout.seek(0)
            raw = stdout.read(size)
    except subprocess.TimeoutExpired as error:
        raise protocol.PipelineError("Zig cold-describe timed out") from error
    except OSError as error:
        raise protocol.PipelineError("Zig cold-describe could not execute") from error
    return parse_description(raw)


def stage101_frontier_from_cold_receipt(
    executable: str | Path,
    campaign_import_receipt: str | Path,
    artifact_store_root: str | Path,
    *,
    timeout_seconds: float = 3600.0,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    description = run_cold_describe(
        executable,
        campaign_import_receipt,
        artifact_store_root,
        timeout_seconds=timeout_seconds,
    )
    return description, stage101_frontier(description)


def stage101_frontier(value: dict[str, Any]) -> list[dict[str, Any]]:
    """Return only worker-described native-leaf nodes in authenticated order."""
    validate_description(value)
    nodes: list[dict[str, Any]] = []
    for row in value["rows"]:
        index = row["segment_index"]
        node = {
            "node_id": f"native/{index}",
            "stage_kind": STAGE_KIND,
            "stage_schema_version": STAGE_SCHEMA_VERSION,
            "adapter": ADAPTER,
            "dependencies": [],
            "external_inputs": copy.deepcopy(row["stage_inputs"]),
            "local_task_identity_sha256": row["local_task_identity_sha256"],
            "semantic_authorities": copy.deepcopy(row["semantic_authorities"]),
            "semantic_options": {},
            "cpu_tokens": 1,
            "rss_tokens": 1,
            "output_kind": OUTPUT_KIND,
            "output_schema_version": OUTPUT_SCHEMA_VERSION,
        }
        nodes.append(protocol.validate_node(node, f"Zig Stage101 node {index}"))
    return nodes


def controller_view(value: dict[str, Any]) -> dict[str, Any]:
    """Return a path-free, explicitly incomplete controller handoff.

    The authenticated Zig description is retained verbatim.  This envelope is
    intentionally unsealed: it is a convenience view, never an admission
    receipt or a complete recursive pipeline manifest.
    """
    validate_description(value)
    return {
        "complete_recursive_campaign": False,
        "description": copy.deepcopy(value),
        "format": CONTROLLER_VIEW_FORMAT,
        "nodes": stage101_frontier(value),
        "schema_version": CONTROLLER_VIEW_SCHEMA_VERSION,
    }


def validate_controller_view(value: Any) -> dict[str, Any]:
    value = protocol.exact(value, {
        "complete_recursive_campaign",
        "description",
        "format",
        "nodes",
        "schema_version",
    }, "Zig Stage101 controller view")
    protocol.require(
        value["format"] == CONTROLLER_VIEW_FORMAT
        and value["schema_version"] == CONTROLLER_VIEW_SCHEMA_VERSION
        and value["complete_recursive_campaign"] is False,
        "Zig Stage101 controller view schema differs",
    )
    expected = stage101_frontier(validate_description(value["description"]))
    protocol.require(
        value["nodes"] == expected,
        "Zig Stage101 controller view nodes differ",
    )
    return value


def _complete_controller_view(
    stage101: dict[str, Any],
    stage102: dict[str, Any],
    final_stages: list[dict[str, Any]],
) -> dict[str, Any]:
    stage101 = validate_description(stage101)
    stage102 = stage102_inventory.validate_description(stage102)
    final_stages = [
        final_description.validate_description(value) for value in final_stages
    ]
    topology = stage101["topology"]
    protocol.require(
        stage102["campaign_namespace_sha256"]
        == stage101["campaign_namespace_sha256"]
        and stage102["campaign_inventory_identity_sha256"]
        == stage101["table_ref"]["sha256"]
        and stage102["real_leaf_count"]
        == stage101["authenticated_segment_count"]
        and stage102["real_leaf_count"] == topology["leaf_count"]
        and stage102["padded_leaf_count"] == topology["padded_leaf_count"]
        and stage102["empty_leaf_count"] == topology["empty_leaf_count"]
        and stage102["fold_count"] == topology["fold_count"],
        "Zig campaign controller Stage101/102 authority differs",
    )

    stage103_count = 0
    stage104_count = 0
    descriptions: set[str] = set()
    recursive_nodes: dict[str, dict[str, Any]] = {}
    durable_outputs: dict[str, dict[str, Any]] = {}
    durable_manifests: dict[str, dict[str, Any]] = {}
    dependencies_seen: set[str] = set()
    stage102_rows = stage102["rows"]
    native_nodes = stage101_frontier(stage101)
    for index, (native, row) in enumerate(
        zip(native_nodes, stage102_rows, strict=True)
    ):
        dependency = row["node"]["dependencies"][0]
        protocol.require(
            dependency["node_id"] not in dependencies_seen,
            f"Zig Stage102 dependency {index} is duplicated",
        )
        dependencies_seen.add(dependency["node_id"])
        # Stage101's description does not carry controller node IDs.  The
        # immutable Zig Stage102 row does, so the join forwards that exact ID
        # instead of manufacturing a naming convention in Python.
        native["node_id"] = dependency["node_id"]
        protocol.validate_node(native, f"joined Zig Stage101 node {index}")
        wrapper_id = row["node"]["node_id"]
        protocol.require(
            wrapper_id not in recursive_nodes
            and wrapper_id not in dependencies_seen,
            f"Zig Stage102 node {index} aliases its frontier",
        )
        recursive_nodes[wrapper_id] = row["node"]
        durable_outputs[wrapper_id] = row["output_ref"]
        durable_manifests[wrapper_id] = row["stage_manifest_ref"]

    for index, description in enumerate(final_stages):
        protocol.require(
            description["campaign_namespace_sha256"]
            == stage102["campaign_namespace_sha256"]
            and description["campaign_shape_identity_sha256"]
            == stage102["campaign_shape_identity_sha256"]
            and description["final_remint_binding_identity_sha256"]
            == stage102["final_remint_binding_identity_sha256"]
            and description["registry_identity_sha256"]
            == stage102["registry_identity_sha256"]
            and description["node"]["cpu_tokens"]
            == stage102["cpu_tokens_per_node"]
            and description["node"]["rss_tokens"]
            == stage102["rss_bytes_per_node"],
            f"Zig final stage description {index} authority differs",
        )
        identity = description["description_identity_sha256"]
        node = description["node"]
        node_id = node["node_id"]
        protocol.require(
            identity not in descriptions and node_id not in recursive_nodes,
            f"Zig final stage description {index} is duplicated",
        )
        descriptions.add(identity)
        if node["stage_schema_version"] == (
            final_description.STAGE103_SCHEMA_VERSION
        ):
            stage103_count += 1
        else:
            stage104_count += 1
            for dependency, item, manifest in zip(
                node["dependencies"],
                description["ordered_inputs"],
                description["dependency_stage_manifest_refs"],
                strict=True,
            ):
                child_id = dependency["node_id"]
                protocol.require(
                    child_id in recursive_nodes,
                    f"Zig Stage104 description {index} precedes its child",
                )
                if child_id in durable_outputs:
                    protocol.require(
                        item["blob"] == durable_outputs[child_id]
                        and manifest == durable_manifests[child_id],
                        f"Zig Stage104 description {index} child custody differs",
                    )
                else:
                    # Parent input and dependency-manifest positions expose
                    # the child's already-published durable refs.  Python
                    # records those exact values; it never predicts them.
                    durable_outputs[child_id] = item["blob"]
                    durable_manifests[child_id] = manifest
        recursive_nodes[node_id] = node

    protocol.require(
        stage103_count == stage102["empty_leaf_count"]
        and stage104_count == stage102["fold_count"],
        "Zig final stage description inventory is incomplete",
    )
    consumer_counts = {node_id: 0 for node_id in recursive_nodes}
    for description in final_stages:
        if description["node"]["stage_schema_version"] != (
            final_description.STAGE104_SCHEMA_VERSION
        ):
            continue
        for dependency in description["node"]["dependencies"]:
            child = dependency["node_id"]
            consumer_counts[child] += 1
            protocol.require(
                consumer_counts[child] == 1,
                "Zig final stage child is consumed more than once",
            )
    roots = [node_id for node_id, count in consumer_counts.items() if count == 0]
    protocol.require(
        len(roots) == 1
        and all(
            count == 1 for node_id, count in consumer_counts.items()
            if node_id != roots[0]
        ),
        "Zig final stage descriptions do not form one complete tree",
    )
    nodes = [*native_nodes]
    nodes.extend(copy.deepcopy(row["node"]) for row in stage102_rows)
    nodes.extend(copy.deepcopy(value["node"]) for value in final_stages)
    protocol.require(
        len({node["node_id"] for node in nodes}) == len(nodes),
        "joined Zig campaign node IDs differ",
    )
    return {
        "complete_recursive_campaign": True,
        "description": copy.deepcopy(stage101),
        "final_stage_descriptions": copy.deepcopy(final_stages),
        "format": COMPLETE_VIEW_FORMAT,
        "goal_node_id": roots[0],
        "nodes": nodes,
        "schema_version": COMPLETE_VIEW_SCHEMA_VERSION,
        "stage102_inventory": copy.deepcopy(stage102),
    }


def complete_controller_view(
    stage101: dict[str, Any],
    stage102_inventory_raw: bytes,
    final_description_raws: list[bytes],
) -> dict[str, Any]:
    """Join only independently canonical Zig documents.

    The returned value is still non-admitting controller metadata.  It does
    not derive Semantic/Execution keys, predict output refs, or serialize a
    live verifier capability.
    """
    protocol.require(
        type(stage102_inventory_raw) is bytes
        and type(final_description_raws) is list
        and all(type(value) is bytes for value in final_description_raws),
        "complete Zig campaign inputs are not canonical byte documents",
    )
    stage102 = stage102_inventory.parse_description(stage102_inventory_raw)
    final_stages = [
        final_description.parse_description(raw)
        for raw in final_description_raws
    ]
    return _complete_controller_view(stage101, stage102, final_stages)


def validate_complete_controller_view(value: Any) -> dict[str, Any]:
    value = protocol.exact(value, {
        "complete_recursive_campaign",
        "description",
        "final_stage_descriptions",
        "format",
        "goal_node_id",
        "nodes",
        "schema_version",
        "stage102_inventory",
    }, "complete Zig campaign controller view")
    protocol.require(
        value["format"] == COMPLETE_VIEW_FORMAT
        and value["schema_version"] == COMPLETE_VIEW_SCHEMA_VERSION
        and value["complete_recursive_campaign"] is True,
        "complete Zig campaign controller view schema differs",
    )
    expected = _complete_controller_view(
        value["description"],
        value["stage102_inventory"],
        value["final_stage_descriptions"],
    )
    protocol.require(
        value == expected,
        "complete Zig campaign controller view differs",
    )
    return value


def require_complete_recursive_description(
    value: dict[str, Any],
    *,
    stage102_inventory_raw: bytes | None = None,
    final_description_raws: list[bytes] | None = None,
) -> dict[str, Any]:
    """Require every canonical Zig campaign description or fail closed."""
    if stage102_inventory_raw is None or final_description_raws is None:
        raise protocol.PipelineError(
            "complete recursive campaign requires Zig wrapper, empty, and "
            "fold descriptions plus immutable Stage102 inventory"
        )
    return complete_controller_view(
        value,
        stage102_inventory_raw,
        final_description_raws,
    )
