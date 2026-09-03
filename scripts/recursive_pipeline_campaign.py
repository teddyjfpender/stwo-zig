"""Sealed, inventory-shaped production recursive campaign planner.

This module owns topology and custody only.  It never derives production keys,
opens proof bytes, or mints proof/verifier admission.  Every executable node is
an opaque typed stage dispatched to the persistent Zig worker.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any

from scripts import recursive_pipeline_protocol as protocol


INVENTORY_SCHEMA = "stwo.recursive-production-campaign-inventory.v2"
AUTHORITY_SCHEMA = "stwo.recursive-production-campaign-authority.v2"
LEAF_AUTHORITY_KIND = "compact-execution-role-aware-incremental-memory-v2"
ETHEREUM_V4_REAL_LEAF_COUNT = 210
# The publication transport currently admits at most 210 segments, but a
# campaign may contain any authenticated count within that protocol capacity.
# In particular, 210 is not a recursive-tree shape constant.
MAX_REAL_LEAF_COUNT = 210
RECURSIVE_NODE_SCHEMA_VERSION = 2
RECURSIVE_NODE_BYTE_COUNT = 2380


@dataclass(frozen=True)
class CampaignShape:
    real_leaf_count: int
    padded_leaf_count: int
    empty_leaf_count: int
    fold_count: int
    root_level: int

    @property
    def logical_node_count(self) -> int:
        return self.padded_leaf_count + self.fold_count


def derive_shape(real_leaf_count: int) -> CampaignShape:
    """Derive the complete binary tree from authenticated real inventory size."""
    protocol.require(
        type(real_leaf_count) is int
        and 0 < real_leaf_count <= MAX_REAL_LEAF_COUNT,
        "campaign real leaf count differs",
    )
    padded = 1 << (real_leaf_count - 1).bit_length()
    return CampaignShape(
        real_leaf_count=real_leaf_count,
        padded_leaf_count=padded,
        empty_leaf_count=padded - real_leaf_count,
        fold_count=padded - 1,
        root_level=padded.bit_length() - 1,
    )


# Compatibility names identify the current Ethereum V4 admission profile.
# Planner logic below never reads them; all topology comes from inventory.
ETHEREUM_V4_SHAPE = derive_shape(ETHEREUM_V4_REAL_LEAF_COUNT)
REAL_LEAF_COUNT = ETHEREUM_V4_SHAPE.real_leaf_count
EMPTY_LEAF_COUNT = ETHEREUM_V4_SHAPE.empty_leaf_count
LEAF_COUNT = ETHEREUM_V4_SHAPE.padded_leaf_count
FOLD_COUNT = ETHEREUM_V4_SHAPE.fold_count
ROOT_LEVEL = ETHEREUM_V4_SHAPE.root_level

STAGE_NAMES = (
    "compact_native", "recursive_wrapper", "canonical_empty", "common_fold",
    "import_native", "import_wrapper", "import_fold",
)
# The two capture inputs deliberately share role 9 and differ by ordinal:
# ordinal 0 is STWIMT04 and ordinal 1 is STWIPR04.  STWIPR04 transitively
# authenticates the separately stored canonical PublicDataV2 wire bytes.
COMPACT_INPUT_COORDINATES = (
    (2, 0), (3, 0), (4, 0), (5, 0), (9, 0), (9, 1), (10, 0),
)
PUBLIC_WIRE_REFERENCE_SCHEMA_VERSION = 0x0402
PUBLIC_WIRE_MANIFEST_SCHEMA_VERSION = 0x0403
COMPACT_INPUT_CODECS = {
    (2, 0): (12, 1),
    (3, 0): (13, 1),
    (4, 0): (9, 1),
    (5, 0): (9, 1),
    (9, 0): (9, 4),
    (9, 1): (9, PUBLIC_WIRE_REFERENCE_SCHEMA_VERSION),
    (10, 0): (11, 1),
}


def _nullable_blob(value: Any, where: str) -> dict[str, Any] | None:
    if value is None:
        return None
    return protocol.validate_blob_ref(value, where)


def _manifest_ref(value: Any, where: str) -> dict[str, Any]:
    result = protocol.validate_blob_ref(value, where)
    protocol.require(result["kind"] == 4 and result["schema_version"] == 1,
                     f"{where} codec differs")
    return result


def _validate_stage_spec(value: Any, where: str) -> dict[str, Any]:
    value = protocol.exact(value, {
        "adapter", "stage_kind", "stage_schema_version", "output_kind",
        "output_schema_version", "cpu_tokens", "rss_tokens",
    }, where)
    protocol.require(type(value["adapter"]) is str and value["adapter"],
                     f"{where}.adapter differs")
    for field in (
        "stage_kind", "stage_schema_version", "output_kind",
        "output_schema_version", "cpu_tokens", "rss_tokens",
    ):
        protocol.require(type(value[field]) is int and value[field] > 0,
                         f"{where}.{field} differs")
    return value


def _validate_task(value: Any, where: str) -> dict[str, Any]:
    value = protocol.exact(value, {
        "local_task_identity_sha256", "semantic_authorities",
        "semantic_options",
    }, where)
    protocol.nonzero_digest(value["local_task_identity_sha256"],
                            f"{where}.local_task_identity")
    authorities = protocol.exact(
        value["semantic_authorities"], protocol.KEY_AUTHORITY_FIELDS,
        f"{where}.semantic_authorities",
    )
    for field in protocol.KEY_AUTHORITY_FIELDS:
        protocol.digest(authorities[field], f"{where}.{field}")
    protocol.require(type(value["semantic_options"]) is dict,
                     f"{where}.semantic_options differs")
    return value


def _validate_inputs(value: Any, where: str) -> list[dict[str, Any]]:
    protocol.require(type(value) is list, f"{where} differs")
    roles: list[tuple[int, int]] = []
    for index, item in enumerate(value):
        protocol._validate_role_ref(item, f"{where}[{index}]")
        roles.append((item["role"], item["ordinal"]))
    protocol.require(len(roles) == len(set(roles)), f"{where} roles differ")
    return value


def _validate_real_leaf(value: Any, index: int) -> dict[str, Any]:
    where = f"campaign real leaf {index}"
    value = protocol.exact(value, {
        "ordinal", "boundary_kind", "compact_inputs", "boundary_artifact",
        "boundary_stage_manifest", "native_task", "wrapper_task",
    }, where)
    protocol.require(value["ordinal"] == index, f"{where}.ordinal differs")
    protocol.require(value["boundary_kind"] in ("source", "native", "wrapper"),
                     f"{where}.boundary_kind differs")
    inputs = _validate_inputs(value["compact_inputs"], f"{where}.compact_inputs")
    artifact = _nullable_blob(value["boundary_artifact"],
                              f"{where}.boundary_artifact")
    manifest = _nullable_blob(value["boundary_stage_manifest"],
                              f"{where}.boundary_stage_manifest")
    if value["boundary_kind"] == "source":
        protocol.require(artifact is None and manifest is None,
                         f"{where} source boundary carries an artifact")
        protocol.require(
            [(item["role"], item["ordinal"]) for item in inputs]
            == list(COMPACT_INPUT_COORDINATES),
            f"{where} compact input roles differ",
        )
        for item, coordinate in zip(
            inputs, COMPACT_INPUT_COORDINATES, strict=True,
        ):
            expected_kind, expected_schema = COMPACT_INPUT_CODECS[coordinate]
            protocol.require(
                item["blob"]["kind"] == expected_kind
                and item["blob"]["schema_version"] == expected_schema,
                f"{where} input {coordinate} codec differs",
            )
    else:
        protocol.require(inputs == [] and artifact is not None and manifest is not None,
                         f"{where} imported boundary custody differs")
        _manifest_ref(manifest, f"{where}.boundary_stage_manifest")
        expected_kind = 8 if value["boundary_kind"] == "native" else 10
        protocol.require(artifact["kind"] == expected_kind,
                         f"{where} boundary artifact kind differs")
        if value["boundary_kind"] == "wrapper":
            protocol.require(
                artifact["schema_version"] == RECURSIVE_NODE_SCHEMA_VERSION
                and artifact["byte_count"] == RECURSIVE_NODE_BYTE_COUNT,
                f"{where} wrapper artifact codec differs",
            )
    _validate_task(value["native_task"], f"{where}.native_task")
    _validate_task(value["wrapper_task"], f"{where}.wrapper_task")
    return value


def _validate_empty_leaf(
    value: Any, index: int, real_leaf_count: int,
) -> dict[str, Any]:
    where = f"campaign empty leaf {index}"
    value = protocol.exact(value, {"ordinal", "task"}, where)
    protocol.require(value["ordinal"] == real_leaf_count + index,
                     f"{where}.ordinal differs")
    _validate_task(value["task"], f"{where}.task")
    return value


def _fold_coordinates(shape: CampaignShape) -> list[tuple[int, int]]:
    return [
        (level, ordinal)
        for level in range(1, shape.root_level + 1)
        for ordinal in range(shape.padded_leaf_count >> level)
    ]


def _validate_fold(value: Any, coordinate: tuple[int, int]) -> dict[str, Any]:
    level, ordinal = coordinate
    where = f"campaign fold {level}/{ordinal}"
    value = protocol.exact(value, {
        "level", "ordinal", "task", "boundary_artifact",
        "boundary_stage_manifest",
    }, where)
    protocol.require((value["level"], value["ordinal"]) == coordinate,
                     f"{where} coordinate differs")
    _validate_task(value["task"], f"{where}.task")
    artifact = _nullable_blob(value["boundary_artifact"],
                              f"{where}.boundary_artifact")
    manifest = _nullable_blob(value["boundary_stage_manifest"],
                              f"{where}.boundary_stage_manifest")
    protocol.require((artifact is None) == (manifest is None),
                     f"{where} boundary custody differs")
    if artifact is not None:
        protocol.require(artifact["kind"] == 10
                         and artifact["schema_version"]
                         == RECURSIVE_NODE_SCHEMA_VERSION
                         and artifact["byte_count"]
                         == RECURSIVE_NODE_BYTE_COUNT,
                         f"{where} artifact kind differs")
        _manifest_ref(manifest, f"{where}.boundary_stage_manifest")
    return value


def validate_inventory(value: Any) -> dict[str, Any]:
    value = protocol.exact(value, {
        "schema", "format_version", "campaign_namespace_sha256",
        "leaf_authority_kind", "stages", "real_leaves", "empty_leaves",
        "canonical_empty_input", "capture_publications", "folds",
        "legacy_differential_imports", "content_sha256",
    }, "production campaign inventory")
    protocol.require(value["schema"] == INVENTORY_SCHEMA
                     and value["format_version"] == 1,
                     "production campaign inventory schema differs")
    protocol.nonzero_digest(value["campaign_namespace_sha256"],
                            "production campaign namespace")
    protocol.require(value["leaf_authority_kind"] == LEAF_AUTHORITY_KIND,
                     "production campaign leaf authority differs")
    stages = protocol.exact(value["stages"], STAGE_NAMES, "campaign stages")
    adapters = set()
    for name in STAGE_NAMES:
        adapters.add(_validate_stage_spec(stages[name], f"campaign stage {name}")[
            "adapter"
        ])
    protocol.require(len(adapters) == 1,
                     "production campaign must use one generic worker adapter")
    for name in (
        "recursive_wrapper", "canonical_empty", "common_fold",
        "import_wrapper", "import_fold",
    ):
        stage = stages[name]
        protocol.require(
            stage["output_kind"] == 10
            and stage["output_schema_version"]
            == RECURSIVE_NODE_SCHEMA_VERSION,
            f"campaign stage {name} must emit field-native recursive nodes",
        )
    protocol.require(type(value["real_leaves"]) is list,
                     "production campaign real leaves differ")
    shape = derive_shape(len(value["real_leaves"]))
    for index, leaf in enumerate(value["real_leaves"]):
        _validate_real_leaf(leaf, index)
    protocol.require(type(value["empty_leaves"]) is list
                     and len(value["empty_leaves"]) == shape.empty_leaf_count,
                     "production campaign empty leaf count differs")
    for index, leaf in enumerate(value["empty_leaves"]):
        _validate_empty_leaf(leaf, index, shape.real_leaf_count)
    empty = protocol.validate_blob_ref(
        value["canonical_empty_input"], "canonical empty input",
    )
    protocol.require(empty["kind"] == 9,
                     "canonical empty input must be capture transport")
    publications = protocol.exact(value["capture_publications"], {
        "incremental_boundary_v4", "public_wire_v4",
    }, "campaign capture publications")
    boundary_manifest = protocol.validate_blob_ref(
        publications["incremental_boundary_v4"],
        "campaign incremental boundary publication",
    )
    public_wire_manifest = protocol.validate_blob_ref(
        publications["public_wire_v4"],
        "campaign public wire publication",
    )
    protocol.require(
        boundary_manifest["kind"] == 9
        and public_wire_manifest["kind"] == 9
        and public_wire_manifest["schema_version"]
        == PUBLIC_WIRE_MANIFEST_SCHEMA_VERSION
        and boundary_manifest != public_wire_manifest,
        "campaign capture publication codecs differ",
    )
    coordinates = _fold_coordinates(shape)
    protocol.require(type(value["folds"]) is list
                     and len(value["folds"]) == shape.fold_count,
                     "production campaign fold count differs")
    for fold, coordinate in zip(value["folds"], coordinates, strict=True):
        _validate_fold(fold, coordinate)
    legacy = value["legacy_differential_imports"]
    protocol.require(type(legacy) is list, "legacy differential imports differ")
    seen: set[int] = set()
    for index, item in enumerate(legacy):
        item = protocol.exact(item, {
            "leaf_ordinal", "artifact", "stage_manifest",
        }, f"legacy differential import {index}")
        ordinal = item["leaf_ordinal"]
        protocol.require(type(ordinal) is int
                         and 0 <= ordinal < shape.real_leaf_count
                         and ordinal not in seen,
                         "legacy differential import ordinal differs")
        seen.add(ordinal)
        protocol.validate_blob_ref(item["artifact"],
                                   "legacy differential artifact")
        _manifest_ref(item["stage_manifest"],
                      "legacy differential stage manifest")
    return protocol.validate_seal(value, "production campaign inventory")


def _task_node(
    node_id: str, task: dict[str, Any], stage: dict[str, Any], *,
    dependencies: list[dict[str, Any]], external_inputs: list[dict[str, Any]],
    generated_options: dict[str, Any],
) -> dict[str, Any]:
    options = copy.deepcopy(task["semantic_options"])
    for key, item in generated_options.items():
        protocol.require(key not in options,
                         f"campaign generated semantic option collides: {key}")
        options[key] = item
    return protocol.validate_node({
        "node_id": node_id,
        "stage_kind": stage["stage_kind"],
        "stage_schema_version": stage["stage_schema_version"],
        "adapter": stage["adapter"],
        "dependencies": dependencies,
        "external_inputs": external_inputs,
        "local_task_identity_sha256": task["local_task_identity_sha256"],
        "semantic_authorities": copy.deepcopy(task["semantic_authorities"]),
        "semantic_options": options,
        "cpu_tokens": stage["cpu_tokens"],
        "rss_tokens": stage["rss_tokens"],
        "output_kind": stage["output_kind"],
        "output_schema_version": stage["output_schema_version"],
    }, f"campaign node {node_id}")


def _import_inputs(artifact: dict[str, Any], manifest: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {"role": 1, "ordinal": 0, "blob": manifest},
        {"role": 8, "ordinal": 0, "blob": artifact},
    ]


def _logical_id(level: int, ordinal: int) -> str:
    return f"leaf/{ordinal:03d}" if level == 0 else f"fold/{level:02d}/{ordinal:03d}"


def _needed_logical_nodes(
    boundaries: set[tuple[int, int]], root_level: int,
) -> set[tuple[int, int]]:
    needed: set[tuple[int, int]] = set()
    encountered: set[tuple[int, int]] = set()

    def visit(level: int, ordinal: int) -> None:
        coordinate = (level, ordinal)
        needed.add(coordinate)
        if coordinate in boundaries:
            encountered.add(coordinate)
            return
        if level == 0:
            return
        visit(level - 1, ordinal * 2)
        visit(level - 1, ordinal * 2 + 1)

    visit(root_level, 0)
    protocol.require(encountered == boundaries,
                     "campaign fold boundaries overlap or are unreachable")
    return needed


def plan(inventory: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build the executable manifest and a sealed structural authority."""
    validate_inventory(inventory)
    shape = derive_shape(len(inventory["real_leaves"]))
    stages = inventory["stages"]
    fold_map = {
        (item["level"], item["ordinal"]): item for item in inventory["folds"]
    }
    boundaries = {
        coordinate for coordinate, item in fold_map.items()
        if item["boundary_artifact"] is not None
    }
    needed = _needed_logical_nodes(boundaries, shape.root_level)
    nodes: list[dict[str, Any]] = []

    for ordinal in range(shape.padded_leaf_count):
        if (0, ordinal) not in needed:
            continue
        leaf_id = _logical_id(0, ordinal)
        if ordinal < shape.real_leaf_count:
            leaf = inventory["real_leaves"][ordinal]
            boundary = leaf["boundary_kind"]
            common = {
                "tree_level": 0, "leaf_ordinal": ordinal,
                "leaf_authority_kind": LEAF_AUTHORITY_KIND,
            }
            if boundary in ("source", "native"):
                native_id = f"native/{ordinal:03d}"
                if boundary == "source":
                    native_stage = stages["compact_native"]
                    native_inputs = copy.deepcopy(leaf["compact_inputs"])
                    operation = "build-compact-native"
                else:
                    native_stage = stages["import_native"]
                    native_inputs = _import_inputs(
                        leaf["boundary_artifact"],
                        leaf["boundary_stage_manifest"],
                    )
                    operation = "cold-import-native"
                nodes.append(_task_node(
                    native_id, leaf["native_task"], native_stage,
                    dependencies=[], external_inputs=native_inputs,
                    generated_options={**common, "pipeline_stage": "compact-native",
                                       "operation": operation},
                ))
                nodes.append(_task_node(
                    leaf_id, leaf["wrapper_task"], stages["recursive_wrapper"],
                    dependencies=[{"node_id": native_id, "role": 8, "ordinal": 0}],
                    external_inputs=[], generated_options={
                        **common, "pipeline_stage": "wrapper",
                        "operation": "build-wrapper",
                    },
                ))
            else:
                nodes.append(_task_node(
                    leaf_id, leaf["wrapper_task"], stages["import_wrapper"],
                    dependencies=[], external_inputs=_import_inputs(
                        leaf["boundary_artifact"],
                        leaf["boundary_stage_manifest"],
                    ), generated_options={
                        **common, "pipeline_stage": "wrapper",
                        "operation": "cold-import-wrapper",
                    },
                ))
        else:
            empty = inventory["empty_leaves"][ordinal - shape.real_leaf_count]
            nodes.append(_task_node(
                leaf_id, empty["task"], stages["canonical_empty"],
                dependencies=[], external_inputs=[{
                    "role": 1, "ordinal": 0,
                    "blob": inventory["canonical_empty_input"],
                }], generated_options={
                    "tree_level": 0, "leaf_ordinal": ordinal,
                    "pipeline_stage": "empty", "operation": "build-empty",
                },
            ))

    for level in range(1, shape.root_level + 1):
        for ordinal in range(shape.padded_leaf_count >> level):
            coordinate = (level, ordinal)
            if coordinate not in needed:
                continue
            fold = fold_map[coordinate]
            node_id = _logical_id(level, ordinal)
            options = {
                "tree_level": level, "fold_ordinal": ordinal,
                "pipeline_stage": f"fold-{level}",
            }
            if fold["boundary_artifact"] is not None:
                stage = stages["import_fold"]
                dependencies: list[dict[str, Any]] = []
                inputs = _import_inputs(
                    fold["boundary_artifact"], fold["boundary_stage_manifest"],
                )
                options["operation"] = "cold-import-fold"
            else:
                stage = stages["common_fold"]
                dependencies = [
                    {"node_id": _logical_id(level - 1, ordinal * 2),
                     "role": 6, "ordinal": 0},
                    {"node_id": _logical_id(level - 1, ordinal * 2 + 1),
                     "role": 7, "ordinal": 0},
                ]
                inputs = []
                options["operation"] = "build-common-fold"
            nodes.append(_task_node(
                node_id, fold["task"], stage, dependencies=dependencies,
                external_inputs=inputs, generated_options=options,
            ))

    manifest = protocol.seal({
        "schema": protocol.PIPELINE_MANIFEST_SCHEMA,
        "campaign_namespace_sha256": inventory["campaign_namespace_sha256"],
        "goal": _logical_id(shape.root_level, 0),
        "test_only": False,
        "nodes": nodes,
    })
    protocol.validate_pipeline_manifest(manifest)
    authority = protocol.seal({
        "schema": AUTHORITY_SCHEMA,
        "format_version": 1,
        "campaign_namespace_sha256": inventory["campaign_namespace_sha256"],
        "input_inventory_sha256": inventory["content_sha256"],
        "pipeline_manifest_sha256": manifest["content_sha256"],
        "leaf_authority_kind": LEAF_AUTHORITY_KIND,
        "real_leaf_count": shape.real_leaf_count,
        "empty_leaf_count": shape.empty_leaf_count,
        "common_fold_count": shape.fold_count,
        "logical_node_count": shape.logical_node_count,
        "executable_node_count": len(nodes),
        "goal_node_id": manifest["goal"],
        "incremental_boundary_manifest_sha256": inventory[
            "capture_publications"
        ]["incremental_boundary_v4"]["sha256"],
        "public_wire_manifest_sha256": inventory["capture_publications"][
            "public_wire_v4"
        ]["sha256"],
        "legacy_differential_import_count": len(
            inventory["legacy_differential_imports"]
        ),
    })
    validate_authority(authority, inventory, manifest)
    return manifest, authority


def validate_authority(
    value: Any, inventory: dict[str, Any] | None = None,
    manifest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    value = protocol.exact(value, {
        "schema", "format_version", "campaign_namespace_sha256",
        "input_inventory_sha256", "pipeline_manifest_sha256",
        "leaf_authority_kind", "real_leaf_count", "empty_leaf_count",
        "common_fold_count", "logical_node_count", "executable_node_count",
        "goal_node_id", "incremental_boundary_manifest_sha256",
        "public_wire_manifest_sha256", "legacy_differential_import_count",
        "content_sha256",
    }, "production campaign authority")
    protocol.require(value["schema"] == AUTHORITY_SCHEMA
                     and value["format_version"] == 1
                     and value["leaf_authority_kind"] == LEAF_AUTHORITY_KIND,
                     "production campaign authority schema differs")
    for field in (
        "campaign_namespace_sha256", "input_inventory_sha256",
        "pipeline_manifest_sha256", "incremental_boundary_manifest_sha256",
        "public_wire_manifest_sha256",
    ):
        protocol.nonzero_digest(value[field], f"campaign authority {field}")
    shape = derive_shape(value["real_leaf_count"])
    protocol.require(
        value["empty_leaf_count"] == shape.empty_leaf_count
        and value["common_fold_count"] == shape.fold_count
        and value["logical_node_count"] == shape.logical_node_count
        and type(value["executable_node_count"]) is int
        and 0 < value["executable_node_count"] <= shape.logical_node_count
        + shape.real_leaf_count,
        "production campaign authority counts differ",
    )
    protocol.require(value["goal_node_id"] == _logical_id(shape.root_level, 0),
                     "production campaign authority goal differs")
    protocol.require(type(value["legacy_differential_import_count"]) is int
                     and value["legacy_differential_import_count"] >= 0,
                     "legacy differential import count differs")
    protocol.validate_seal(value, "production campaign authority")
    if inventory is not None:
        validate_inventory(inventory)
        inventory_shape = derive_shape(len(inventory["real_leaves"]))
        protocol.require(
            value["campaign_namespace_sha256"]
            == inventory["campaign_namespace_sha256"]
            and value["input_inventory_sha256"] == inventory["content_sha256"]
            and value["incremental_boundary_manifest_sha256"]
            == inventory["capture_publications"][
                "incremental_boundary_v4"
            ]["sha256"]
            and value["public_wire_manifest_sha256"]
            == inventory["capture_publications"]["public_wire_v4"]["sha256"]
            and value["legacy_differential_import_count"]
            == len(inventory["legacy_differential_imports"]),
            "production campaign authority inventory differs",
        )
        protocol.require(shape == inventory_shape,
                         "production campaign authority shape differs")
    if manifest is not None:
        protocol.validate_pipeline_manifest(manifest)
        protocol.require(
            value["pipeline_manifest_sha256"] == manifest["content_sha256"]
            and value["campaign_namespace_sha256"]
            == manifest["campaign_namespace_sha256"]
            and value["executable_node_count"] == len(manifest["nodes"])
            and value["goal_node_id"] == manifest["goal"],
            "production campaign authority manifest differs",
        )
    return value


def referenced_blobs(inventory: dict[str, Any]) -> list[dict[str, Any]]:
    """Return every path-independent input ref in deterministic wire order."""
    validate_inventory(inventory)
    # Campaign-wide manifests establish completeness/provenance, but are not
    # direct stage inputs.  Leaf semantic keys therefore remain local and a
    # one-leaf mutation does not invalidate every native proof.
    result: list[dict[str, Any]] = [
        inventory["capture_publications"]["incremental_boundary_v4"],
        inventory["capture_publications"]["public_wire_v4"],
    ]
    for leaf in inventory["real_leaves"]:
        result.extend(item["blob"] for item in leaf["compact_inputs"])
        if leaf["boundary_artifact"] is not None:
            result.extend((leaf["boundary_stage_manifest"],
                           leaf["boundary_artifact"]))
    result.append(inventory["canonical_empty_input"])
    for fold in inventory["folds"]:
        if fold["boundary_artifact"] is not None:
            result.extend((fold["boundary_stage_manifest"],
                           fold["boundary_artifact"]))
    for item in inventory["legacy_differential_imports"]:
        result.extend((item["stage_manifest"], item["artifact"]))
    return result
