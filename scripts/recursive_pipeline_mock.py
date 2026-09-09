"""Fast, exact-shape mock campaign for control-plane tests and demos."""

from __future__ import annotations

from typing import Any

from scripts import recursive_pipeline_campaign as campaign
from scripts import recursive_pipeline_protocol as protocol
from scripts import recursive_pipeline_store as store_mod


REAL_LEAF_COUNT = campaign.ETHEREUM_V4_REAL_LEAF_COUNT
DEFAULT_SHAPE = campaign.derive_shape(REAL_LEAF_COUNT)
EMPTY_LEAF_COUNT = DEFAULT_SHAPE.empty_leaf_count
LEAF_COUNT = DEFAULT_SHAPE.padded_leaf_count
FOLD_COUNT = DEFAULT_SHAPE.fold_count
MOCK_LEAF_STAGE_KIND = 2
MOCK_FOLD_STAGE_KIND = 4
MOCK_INPUT_KIND = 1
MOCK_PROOF_KIND = 10
MOCK_SCHEMA_VERSION = 1
MOCK_ADAPTER = "mock"


def _digest(label: str) -> str:
    return protocol.sha256_bytes(label.encode("ascii"))


def campaign_namespace(real_leaf_count: int) -> str:
    shape = campaign.derive_shape(real_leaf_count)
    return _digest(
        f"stwo.recursive-{shape.real_leaf_count}-to-"
        f"{shape.padded_leaf_count}.mock.v2"
    )


CAMPAIGN_NAMESPACE = campaign_namespace(REAL_LEAF_COUNT)


def execution_authorities(*, resource_policy: str = "mock-resource-v1") -> dict[str, str]:
    return {
        field: _digest(
            f"{field}:{resource_policy if field.endswith('_policy_identity_sha256') else 'v1'}"
        )
        for field in protocol.EXECUTION_AUTHORITY_FIELDS
    }


def build_manifest(
    workspace: store_mod.Workspace, *, mutate_leaf: int | None = None,
    real_leaf_count: int = REAL_LEAF_COUNT,
) -> dict[str, Any]:
    """Create an immutable, inventory-shaped mock DAG.

    A mutation changes only one leaf's direct BlobRef.  The campaign namespace
    and every unrelated node remain byte-identical, so cache invalidation is
    limited to that leaf and its derived root path.
    """
    shape = campaign.derive_shape(real_leaf_count)
    protocol.require(
        mutate_leaf is None or 0 <= mutate_leaf < shape.padded_leaf_count,
        "mock mutation leaf differs",
    )
    authorities = {
        field: _digest(f"mock-semantic:{field}:v1")
        for field in protocol.KEY_AUTHORITY_FIELDS
    }
    nodes: list[dict[str, Any]] = []
    prior: list[str] = []
    for index in range(shape.padded_leaf_count):
        real = index < shape.real_leaf_count
        payload = protocol.canonical_bytes({
            "schema": "stwo.recursive-pipeline-mock-leaf-input.v1",
            "ordinal": index,
            "kind": "real" if real else "empty",
            "mutation": 1 if index == mutate_leaf else 0,
        })
        input_ref = workspace.put_blob(
            payload, kind=MOCK_INPUT_KIND, schema_version=MOCK_SCHEMA_VERSION,
        )
        node_id = f"leaf/{index:03d}"
        nodes.append({
            "node_id": node_id,
            "stage_kind": MOCK_LEAF_STAGE_KIND,
            "stage_schema_version": MOCK_SCHEMA_VERSION,
            "adapter": MOCK_ADAPTER,
            "dependencies": [],
            "external_inputs": [{"role": 1, "ordinal": 0, "blob": input_ref}],
            "local_task_identity_sha256": _digest(f"mock-leaf-task:{index}"),
            "semantic_authorities": dict(authorities),
            "semantic_options": {
                "pipeline_stage": "leaf",
                "tree_level": 0,
                "leaf_ordinal": index,
                "leaf_kind": "real" if real else "empty",
            },
            "cpu_tokens": 1,
            "rss_tokens": 1,
            "output_kind": MOCK_PROOF_KIND,
            "output_schema_version": MOCK_SCHEMA_VERSION,
        })
        prior.append(node_id)

    level = 1
    while len(prior) > 1:
        current: list[str] = []
        for index in range(0, len(prior), 2):
            ordinal = index // 2
            node_id = f"fold/{level:02d}/{ordinal:03d}"
            nodes.append({
                "node_id": node_id,
                "stage_kind": MOCK_FOLD_STAGE_KIND,
                "stage_schema_version": MOCK_SCHEMA_VERSION,
                "adapter": MOCK_ADAPTER,
                "dependencies": [
                    {"node_id": prior[index], "role": 6, "ordinal": 0},
                    {"node_id": prior[index + 1], "role": 7, "ordinal": 0},
                ],
                "external_inputs": [],
                "local_task_identity_sha256": _digest(
                    f"mock-fold-task:{level}:{ordinal}"
                ),
                "semantic_authorities": dict(authorities),
                "semantic_options": {
                    "pipeline_stage": f"fold-{level}",
                    "tree_level": level,
                    "fold_ordinal": ordinal,
                },
                "cpu_tokens": 1,
                "rss_tokens": 1,
                "output_kind": MOCK_PROOF_KIND,
                "output_schema_version": MOCK_SCHEMA_VERSION,
            })
            current.append(node_id)
        prior = current
        level += 1

    protocol.require(len(nodes) == shape.logical_node_count,
                     "mock recursive DAG shape differs")
    manifest = protocol.seal({
        "schema": protocol.PIPELINE_MANIFEST_SCHEMA,
        "campaign_namespace_sha256": campaign_namespace(shape.real_leaf_count),
        "goal": prior[0],
        "test_only": True,
        "nodes": nodes,
    })
    return protocol.validate_pipeline_manifest(manifest)
