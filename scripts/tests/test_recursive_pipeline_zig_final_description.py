from __future__ import annotations

import copy
import unittest

from scripts import recursive_pipeline_protocol as protocol
from scripts import recursive_pipeline_zig_final_description as final_description
from scripts import recursive_pipeline_zig_stage101_frontier as stage101_frontier
from scripts import recursive_pipeline_zig_stage102_inventory as stage102_inventory
from scripts.tests import test_recursive_pipeline_zig_stage101_frontier as stage101_fixture


def digest(value: int) -> str:
    return f"{value:064x}"


def blob(kind: int, schema: int, seed: int, byte_count: int) -> dict:
    return {
        "byte_count": byte_count,
        "format_version": 1,
        "kind": kind,
        "schema_version": schema,
        "sha256": digest(seed),
    }


def authorities(seed: int) -> dict:
    result = {
        field: digest(seed + index)
        for index, field in enumerate(protocol.KEY_AUTHORITY_FIELDS)
    }
    result["provider_identity_sha256"] = "00" * 32
    return result


def node(
    stage104: bool = False,
    *,
    node_id: str | None = None,
    dependency_ids: tuple[str, str] | None = None,
    seed: int = 0,
) -> dict:
    if stage104:
        dependency_ids = dependency_ids or ("empty/14", "empty/15")
        dependencies = [
            {"node_id": dependency_ids[0], "role": 6, "ordinal": 0},
            {"node_id": dependency_ids[1], "role": 7, "ordinal": 0},
        ]
        external_inputs: list[dict] = []
        node_id = node_id or "fold/1/7"
        stage_kind = 4
        stage_schema = 104
        adapter = "campaign_common_fold_v2"
    else:
        dependencies = []
        external_inputs = [{
            "role": 1,
            "ordinal": 0,
            "blob": blob(14, 2, 31 + seed, 1892),
        }]
        node_id = node_id or "empty/13"
        stage_kind = 2
        stage_schema = 103
        adapter = "campaign_canonical_empty_v2"
    return {
        "node_id": node_id,
        "stage_kind": stage_kind,
        "stage_schema_version": stage_schema,
        "adapter": adapter,
        "dependencies": dependencies,
        "external_inputs": external_inputs,
        "local_task_identity_sha256": digest(10 + seed),
        "semantic_authorities": authorities(40),
        "semantic_options": {
            "schema": "stwo.recursive-campaign-node-options.v2",
            "campaign_semantic_inputs_identity_sha256": digest(11 + seed),
        },
        "cpu_tokens": 4,
        "rss_tokens": 40_000,
        "output_kind": 10,
        "output_schema_version": 2,
    }


def description(
    stage104: bool = False,
    *,
    node_id: str | None = None,
    dependency_ids: tuple[str, str] | None = None,
    input_blobs: tuple[dict, dict] | None = None,
    manifest_blobs: tuple[dict, dict] | None = None,
    campaign_namespace: str | None = None,
    seed: int = 0,
) -> dict:
    worker_node = node(
        stage104,
        node_id=node_id,
        dependency_ids=dependency_ids,
        seed=seed,
    )
    if stage104:
        input_blobs = input_blobs or (
            blob(10, 2, 60 + seed * 2, 2380),
            blob(10, 2, 61 + seed * 2, 2380),
        )
        inputs = [
            {"role": 6, "ordinal": 0, "blob": input_blobs[0]},
            {"role": 7, "ordinal": 0, "blob": input_blobs[1]},
        ]
        manifest_blobs = manifest_blobs or (
            blob(4, 1, 70 + seed * 2, 512),
            blob(4, 1, 71 + seed * 2, 512),
        )
        manifests = list(manifest_blobs)
    else:
        inputs = copy.deepcopy(worker_node["external_inputs"])
        manifests = []
    campaign_namespace = campaign_namespace or digest(1)
    semantic = protocol.mock_semantic_key(
        campaign_namespace=campaign_namespace,
        node=worker_node,
        ordered_inputs=inputs,
    )
    execution = protocol.mock_execution_key(
        semantic,
        {
            field: digest(100 + index)
            for index, field in enumerate(protocol.EXECUTION_AUTHORITY_FIELDS)
        },
    )
    return protocol.seal({
        "campaign_namespace_sha256": campaign_namespace,
        "campaign_shape_identity_sha256": digest(2),
        "dependency_stage_manifest_refs": manifests,
        "description_identity_sha256": digest(3 + seed),
        "execution_key_identity_sha256": execution["identity_sha256"],
        "final_remint_binding_identity_sha256": digest(4),
        "format": final_description.FORMAT,
        "format_version": final_description.FORMAT_VERSION,
        "node": worker_node,
        "ordered_inputs": inputs,
        "planned_semantic_identity_sha256": digest(11 + seed),
        "production": False,
        "registry_identity_sha256": worker_node[
            "semantic_authorities"
        ]["registry_identity_sha256"],
        "schema_version": final_description.SCHEMA_VERSION,
        "semantic_key_identity_sha256": semantic["identity_sha256"],
        "serializable_fresh_capability": False,
    })


def immutable_stage102(stage101: dict) -> dict:
    worker_policy = digest(120)
    memory_policy = digest(121)
    rows = []
    for index in range(stage101["authenticated_segment_count"]):
        proof_ref = blob(8, 1, 200 + index, 4096 + index)
        ordered_inputs = [{"role": 8, "ordinal": 0, "blob": proof_ref}]
        stage_node = {
            "node_id": f"real/{index}",
            "stage_kind": 2,
            "stage_schema_version": 102,
            "adapter": stage102_inventory.ADAPTER,
            "dependencies": [{
                "node_id": f"native/{index}",
                "role": 8,
                "ordinal": 0,
            }],
            "external_inputs": [],
            "local_task_identity_sha256": digest(300 + index),
            "semantic_authorities": authorities(40),
            "semantic_options": {
                "schema": stage102_inventory.SEMANTIC_OPTIONS_SCHEMA,
                "campaign_semantic_inputs_identity_sha256": digest(400 + index),
            },
            "cpu_tokens": 4,
            "rss_tokens": 40_000,
            "output_kind": 10,
            "output_schema_version": 2,
        }
        semantic = protocol.mock_semantic_key(
            campaign_namespace=stage101["campaign_namespace_sha256"],
            node=stage_node,
            ordered_inputs=ordered_inputs,
        )
        execution_authorities = {
            field: digest(500 + index * 32 + ordinal)
            for ordinal, field in enumerate(protocol.EXECUTION_AUTHORITY_FIELDS)
        }
        execution_authorities["worker_policy_identity_sha256"] = worker_policy
        execution_authorities["memory_policy_identity_sha256"] = memory_policy
        execution = protocol.mock_execution_key(
            semantic,
            execution_authorities,
        )
        rows.append({
            "coordinate": {"height": 0, "index": index},
            "dependency_stage_manifest_refs": [
                blob(4, 1, 700 + index, 512),
            ],
            "execution_key": execution,
            "node": stage_node,
            "ordered_inputs": ordered_inputs,
            "output_ref": blob(10, 2, 600 + index, 2380),
            "semantic_key": semantic,
            "stage_manifest_ref": blob(4, 1, 800 + index, 512),
        })
    topology = stage101["topology"]
    result = {
        "campaign_inventory_identity_sha256": stage101["table_ref"]["sha256"],
        "campaign_namespace_sha256": stage101["campaign_namespace_sha256"],
        "campaign_shape_identity_sha256": digest(2),
        "cpu_tokens_per_node": 4,
        "empty_leaf_count": topology["empty_leaf_count"],
        "final_remint_binding_identity_sha256": digest(4),
        "fold_count": topology["fold_count"],
        "format": stage102_inventory.FORMAT,
        "format_version": stage102_inventory.FORMAT_VERSION,
        "host_execution_identity_sha256": digest(122),
        "maximum_parallel_nodes": 4,
        "memory_policy_identity_sha256": memory_policy,
        "padded_leaf_count": topology["padded_leaf_count"],
        "production": False,
        "proof_worker_count": 4,
        "real_leaf_count": topology["leaf_count"],
        "registry_identity_sha256": authorities(40)[
            "registry_identity_sha256"
        ],
        "root_height": topology["padded_leaf_count"].bit_length() - 1,
        "rows": rows,
        "rss_bytes_per_node": 40_000,
        "schema_version": stage102_inventory.SCHEMA_VERSION,
        "total_cpu_tokens": 8,
        "total_rss_bytes": 160_000,
        "worker_policy_identity_sha256": worker_policy,
    }
    result["authority_identity_sha256"] = protocol.canonical_digest(result)
    return protocol.seal(result)


class ZigFinalDescriptionTests(unittest.TestCase):
    def test_stage103_forwards_exact_zig_node_without_lease(self) -> None:
        source = description()
        parsed = final_description.parse_description(
            protocol.canonical_bytes(source)
        )
        worker_node, inputs = final_description.forward_worker_inputs(parsed)
        self.assertEqual(worker_node, source["node"])
        self.assertEqual(inputs, source["ordered_inputs"])
        self.assertNotIn("lease_id", parsed)
        self.assertNotIn("live_lease_selector", parsed)

    def test_stage104_forwards_exact_children_and_manifests(self) -> None:
        source = description(True)
        parsed = final_description.parse_description(
            protocol.canonical_bytes(source)
        )
        worker_node, inputs = final_description.forward_worker_inputs(parsed)
        self.assertEqual(worker_node["node_id"], "fold/1/7")
        self.assertEqual([item["role"] for item in inputs], [6, 7])
        self.assertEqual(
            final_description.dependency_stage_manifest_refs(parsed),
            source["dependency_stage_manifest_refs"],
        )

    def test_worker_derivation_must_match_zig_advertised_identities(self) -> None:
        source = description(True)
        semantic = protocol.mock_semantic_key(
            campaign_namespace=source["campaign_namespace_sha256"],
            node=source["node"],
            ordered_inputs=source["ordered_inputs"],
        )
        execution = protocol.mock_execution_key(
            semantic,
            {
                field: digest(100 + index)
                for index, field in enumerate(
                    protocol.EXECUTION_AUTHORITY_FIELDS
                )
            },
        )
        final_description.validate_worker_derivation(
            source, semantic, execution,
        )
        hostile = copy.deepcopy(source)
        hostile["semantic_key_identity_sha256"] = digest(999)
        hostile = protocol.seal(hostile)
        with self.assertRaises(protocol.PipelineError):
            final_description.validate_worker_derivation(
                hostile, semantic, execution,
            )

    def test_stage_codec_semantics_and_capability_mutations_fail(self) -> None:
        mutations = []
        changed = description()
        changed["node"]["external_inputs"][0]["blob"]["byte_count"] += 1
        changed["ordered_inputs"][0]["blob"]["byte_count"] += 1
        mutations.append(protocol.seal(changed))
        changed = description(True)
        changed["node"]["dependencies"].reverse()
        mutations.append(protocol.seal(changed))
        changed = description(True)
        changed["dependency_stage_manifest_refs"][0]["kind"] = 8
        mutations.append(protocol.seal(changed))
        changed = description()
        changed["lease_id"] = "serialized-capability"
        mutations.append(protocol.seal(changed))
        changed = description()
        changed["serializable_fresh_capability"] = True
        mutations.append(protocol.seal(changed))
        for value in mutations:
            with self.subTest(value=value):
                with self.assertRaises(protocol.PipelineError):
                    final_description.parse_description(
                        protocol.canonical_bytes(value)
                    )

    def test_complete_campaign_stays_closed_without_stage102_inventory(self) -> None:
        with self.assertRaisesRegex(protocol.PipelineError, "Stage102"):
            final_description.require_complete_recursive_campaign([
                description(), description(True),
            ])

    def test_stage102_inventory_is_exact_canonical_and_capability_free(self) -> None:
        stage101 = stage101_fixture.description(3)
        source = immutable_stage102(stage101)
        parsed = stage102_inventory.parse_description(
            protocol.canonical_bytes(source)
        )
        self.assertEqual(len(stage102_inventory.rows(parsed)), 3)
        self.assertEqual(parsed["rows"][2]["coordinate"], {
            "height": 0,
            "index": 2,
        })
        self.assertNotIn("lease_id", parsed)
        self.assertNotIn("admission", parsed)

        changed = copy.deepcopy(source)
        changed["live_lease_selector"] = "host-capability"
        changed = protocol.seal(changed)
        with self.assertRaises(protocol.PipelineError):
            stage102_inventory.parse_description(protocol.canonical_bytes(changed))

        with self.assertRaises(protocol.PipelineError):
            stage102_inventory.parse_description(
                protocol.canonical_bytes(source)[:-1]
            )

        changed = copy.deepcopy(source)
        changed["rows"][0]["node"]["cpu_tokens"] += 1
        changed.pop("content_sha256")
        changed.pop("authority_identity_sha256")
        changed["authority_identity_sha256"] = protocol.canonical_digest(changed)
        changed = protocol.seal(changed)
        with self.assertRaises(protocol.PipelineError):
            stage102_inventory.parse_description(protocol.canonical_bytes(changed))

    def test_complete_controller_joins_only_zig_supplied_tree(self) -> None:
        stage101 = stage101_fixture.description(3)
        stage102 = immutable_stage102(stage101)
        rows = stage102["rows"]
        namespace = stage101["campaign_namespace_sha256"]
        empty = description(
            node_id="empty/3",
            campaign_namespace=namespace,
            seed=10,
        )
        left = description(
            True,
            node_id="fold/1/0",
            dependency_ids=("real/0", "real/1"),
            input_blobs=(rows[0]["output_ref"], rows[1]["output_ref"]),
            manifest_blobs=(
                rows[0]["stage_manifest_ref"],
                rows[1]["stage_manifest_ref"],
            ),
            campaign_namespace=namespace,
            seed=20,
        )
        right = description(
            True,
            node_id="fold/1/1",
            dependency_ids=("real/2", "empty/3"),
            input_blobs=(rows[2]["output_ref"], blob(10, 2, 901, 2380)),
            manifest_blobs=(
                rows[2]["stage_manifest_ref"],
                blob(4, 1, 902, 512),
            ),
            campaign_namespace=namespace,
            seed=21,
        )
        root = description(
            True,
            node_id="fold/2/0",
            dependency_ids=("fold/1/0", "fold/1/1"),
            input_blobs=(blob(10, 2, 903, 2380), blob(10, 2, 904, 2380)),
            manifest_blobs=(blob(4, 1, 905, 512), blob(4, 1, 906, 512)),
            campaign_namespace=namespace,
            seed=30,
        )
        final_raws = [
            protocol.canonical_bytes(value)
            for value in (empty, left, right, root)
        ]
        view = stage101_frontier.require_complete_recursive_description(
            stage101,
            stage102_inventory_raw=protocol.canonical_bytes(stage102),
            final_description_raws=final_raws,
        )
        stage101_frontier.validate_complete_controller_view(view)
        self.assertTrue(view["complete_recursive_campaign"])
        self.assertEqual(view["goal_node_id"], "fold/2/0")
        self.assertEqual(len(view["nodes"]), 10)
        self.assertEqual(
            [node["node_id"] for node in view["nodes"][:3]],
            ["native/0", "native/1", "native/2"],
        )

        with self.assertRaises(protocol.PipelineError):
            stage101_frontier.complete_controller_view(
                stage101,
                protocol.canonical_bytes(stage102),
                final_raws[:-1],
            )
        changed = copy.deepcopy(left)
        changed["ordered_inputs"][0]["blob"] = blob(10, 2, 999, 2380)
        changed["semantic_key_identity_sha256"] = digest(999)
        changed = protocol.seal(changed)
        with self.assertRaises(protocol.PipelineError):
            stage101_frontier.complete_controller_view(
                stage101,
                protocol.canonical_bytes(stage102),
                [
                    protocol.canonical_bytes(empty),
                    protocol.canonical_bytes(changed),
                    protocol.canonical_bytes(right),
                    protocol.canonical_bytes(root),
                ],
            )

        changed_inventory = copy.deepcopy(stage102)
        changed_inventory["campaign_inventory_identity_sha256"] = digest(998)
        changed_inventory.pop("content_sha256")
        changed_inventory.pop("authority_identity_sha256")
        changed_inventory["authority_identity_sha256"] = (
            protocol.canonical_digest(changed_inventory)
        )
        changed_inventory = protocol.seal(changed_inventory)
        with self.assertRaises(protocol.PipelineError):
            stage101_frontier.complete_controller_view(
                stage101,
                protocol.canonical_bytes(changed_inventory),
                final_raws,
            )

        changed_root = copy.deepcopy(root)
        changed_root["final_remint_binding_identity_sha256"] = digest(997)
        changed_root = protocol.seal(changed_root)
        with self.assertRaises(protocol.PipelineError):
            stage101_frontier.complete_controller_view(
                stage101,
                protocol.canonical_bytes(stage102),
                [
                    *final_raws[:-1],
                    protocol.canonical_bytes(changed_root),
                ],
            )


if __name__ == "__main__":
    unittest.main()
