from __future__ import annotations

import json
import os
import copy
from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest

from scripts import recursive_pipeline_campaign as campaign
from scripts import recursive_pipeline_mock as mock
from scripts import recursive_pipeline_protocol as protocol
from scripts import recursive_pipeline_registry as registry_mod
from scripts import recursive_pipeline_runner as runner_mod
from scripts import recursive_pipeline_store as store_mod


def digest(label: str) -> str:
    return protocol.sha256_bytes(label.encode("ascii"))


def task(label: str) -> dict:
    return {
        "local_task_identity_sha256": digest(f"task:{label}"),
        "semantic_authorities": {
            field: digest(f"semantic:{field}:v1")
            for field in protocol.KEY_AUTHORITY_FIELDS
        },
        "semantic_options": {"task_contract": label},
    }


def stage(
    stage_kind: int, schema: int, output_kind: int, *, adapter: str = "zig-worker-v1",
) -> dict:
    return {
        "adapter": adapter,
        "stage_kind": stage_kind,
        "stage_schema_version": schema,
        "output_kind": output_kind,
        "output_schema_version": (
            campaign.RECURSIVE_NODE_SCHEMA_VERSION
            if output_kind == 10 else 1
        ),
        "cpu_tokens": 1,
        "rss_tokens": 1,
    }


def fixture_inventory(
    workspace: store_mod.Workspace, *, mutate_leaf: int | None = None,
    leaf_boundary: tuple[int, str] | None = None,
    fold_boundary: tuple[int, int] | None = None,
    legacy_differential: bool = False,
    real_leaf_count: int = campaign.REAL_LEAF_COUNT,
) -> dict:
    shape = campaign.derive_shape(real_leaf_count)
    shared_inputs = {
        coordinate: workspace.put_blob(
            ("compact-input-role-%d-ordinal-%d\n" % coordinate).encode(),
            kind=campaign.COMPACT_INPUT_CODECS[coordinate][0],
            schema_version=campaign.COMPACT_INPUT_CODECS[coordinate][1],
        )
        for coordinate in campaign.COMPACT_INPUT_COORDINATES
    }
    boundary_manifest = workspace.put_blob(
        b"test-stage-manifest\n", kind=4, schema_version=1,
    )
    native_artifact = workspace.put_blob(
        b"test-native-proof\n", kind=8, schema_version=1,
    )
    wrapper_artifact = workspace.put_blob(
        b"W" * campaign.RECURSIVE_NODE_BYTE_COUNT,
        kind=10,
        schema_version=campaign.RECURSIVE_NODE_SCHEMA_VERSION,
    )
    real_leaves = []
    for ordinal in range(shape.real_leaf_count):
        boundary = (leaf_boundary[1]
                    if leaf_boundary is not None and leaf_boundary[0] == ordinal
                    else "source")
        if boundary == "source":
            inputs = [
                {"role": coordinate[0], "ordinal": coordinate[1], "blob": (
                    workspace.put_blob(
                        b"mutated-public-wire-reference\n",
                        kind=9,
                        schema_version=(
                            campaign.PUBLIC_WIRE_REFERENCE_SCHEMA_VERSION
                        ),
                    ) if ordinal == mutate_leaf and coordinate == (9, 1)
                    else ref
                )}
                for coordinate, ref in shared_inputs.items()
            ]
            artifact = None
            manifest = None
        else:
            inputs = []
            artifact = native_artifact if boundary == "native" else wrapper_artifact
            manifest = boundary_manifest
        real_leaves.append({
            "ordinal": ordinal,
            "boundary_kind": boundary,
            "compact_inputs": inputs,
            "boundary_artifact": artifact,
            "boundary_stage_manifest": manifest,
            "native_task": task(f"native:{ordinal}"),
            "wrapper_task": task(f"wrapper:{ordinal}"),
        })
    folds = []
    for level in range(1, shape.root_level + 1):
        for ordinal in range(shape.padded_leaf_count >> level):
            imported = fold_boundary == (level, ordinal)
            folds.append({
                "level": level,
                "ordinal": ordinal,
                "task": task(f"fold:{level}:{ordinal}"),
                "boundary_artifact": wrapper_artifact if imported else None,
                "boundary_stage_manifest": boundary_manifest if imported else None,
            })
    inventory = protocol.seal({
        "schema": campaign.INVENTORY_SCHEMA,
        "format_version": 1,
        "campaign_namespace_sha256": digest("production-campaign-namespace-v1"),
        "leaf_authority_kind": campaign.LEAF_AUTHORITY_KIND,
        "stages": {
            "compact_native": stage(2, 101, 8),
            "recursive_wrapper": stage(2, 102, 10),
            "canonical_empty": stage(2, 103, 10),
            "common_fold": stage(4, 104, 10),
            "import_native": stage(3, 105, 8),
            "import_wrapper": stage(3, 106, 10),
            "import_fold": stage(3, 107, 10),
        },
        "real_leaves": real_leaves,
        "empty_leaves": [
            {"ordinal": shape.real_leaf_count + index,
             "task": task(f"empty:{index}")}
            for index in range(shape.empty_leaf_count)
        ],
        "canonical_empty_input": workspace.put_blob(
            b"canonical-empty-capture\n", kind=9, schema_version=1,
        ),
        "capture_publications": {
            "incremental_boundary_v4": workspace.put_blob(
                b"incremental-boundary-v4-manifest\n",
                kind=9,
                schema_version=4,
            ),
            "public_wire_v4": workspace.put_blob(
                b"incremental-public-wire-v4-manifest\n",
                kind=9,
                schema_version=campaign.PUBLIC_WIRE_MANIFEST_SCHEMA_VERSION,
            ),
        },
        "folds": folds,
        "legacy_differential_imports": ([{
            "leaf_ordinal": 0,
            "artifact": native_artifact,
            "stage_manifest": boundary_manifest,
        }] if legacy_differential else []),
    })
    return campaign.validate_inventory(inventory)


def mock_registry(authorities: dict[str, str]) -> tuple[
    registry_mod.StageRegistry, registry_mod.MockStageAdapter,
]:
    adapter = registry_mod.MockStageAdapter(authorities)
    registry = registry_mod.StageRegistry(allow_mock=True)
    registry.register("zig-worker-v1", adapter)
    return registry, adapter


FAKE_WORKER = r'''#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

from scripts import recursive_pipeline_protocol as protocol

REQUEST = "stwo.recursive-pipeline-worker-request.v1"
RESPONSE = "stwo.recursive-pipeline-worker-response.v1"
CANDIDATE = "stwo.recursive-pipeline-worker-candidate-ref.v1"
live = set()
next_lease = 0

def publish(path, raw, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        if path.read_bytes() != raw or stat.S_IMODE(path.stat().st_mode) != mode:
            raise RuntimeError("ExistingArtifactMismatch")
        return
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(raw)
    os.chmod(temporary, mode)
    os.link(temporary, path)
    temporary.unlink()

def object_root(payload):
    paths = payload.get("input_object_paths", [])
    if paths:
        return Path(paths[0]).parents[1]
    return Path(payload["output_path"]).parents[5] / "objects" / "sha256"

def put(root, raw, kind, schema):
    sha = hashlib.sha256(raw).hexdigest()
    publish(root / sha[:2] / (sha + ".blob"), raw, 0o400)
    return protocol.blob_ref(
        kind=kind, schema_version=schema, byte_count=len(raw), sha256=sha,
    )

def handle(action, payload):
    global next_lease
    if action == "describe":
        node_kind = payload["stage_kind"]
        schema = payload["stage_schema_version"]
        output_kind = 8 if schema in (101, 105) else 10
        return {"description": protocol.seal({
            "schema": "stwo.recursive-pipeline-stage-description.v1",
            "stage_kind": node_kind, "stage_schema_version": schema,
            "output_kind": output_kind,
            "output_schema_version": (
                2 if output_kind == 10 else 1
            ),
            "minimum_cpu_tokens": 1, "minimum_rss_tokens": 1,
            "root_cold_open_transitive": True,
        })}
    if action == "derive":
        semantic = protocol.mock_semantic_key(
            campaign_namespace=payload["campaign_namespace_sha256"],
            node=payload["node"], ordered_inputs=payload["ordered_inputs"],
        )
        execution = protocol.mock_execution_key(
            semantic, payload["execution_authorities"],
        )
        semantic_raw = protocol.semantic_key_bytes(semantic)
        execution_raw = protocol.execution_key_bytes(execution)
        return {
            "semantic_key_hex": semantic_raw.hex(),
            "execution_key_hex": execution_raw.hex(),
            "semantic_projection": semantic,
            "execution_projection": execution,
        }
    if action == "build":
        for lease in payload["dependency_lease_ids"]:
            if lease not in live:
                raise RuntimeError("MissingDependencyLease")
        node = payload["node"]
        output = protocol.canonical_bytes({
            "schema": "stwo.recursive-pipeline-fake-worker-output.v1",
            "node_id": node["node_id"],
            "semantic_key_sha256": payload["semantic_key"]["identity_sha256"],
            "ordered_input_sha256": [
                item["blob"]["sha256"] for item in payload["ordered_inputs"]
            ],
        })
        root = object_root(payload)
        output_ref = put(
            root, output, node["output_kind"], node["output_schema_version"],
        )
        publish(payload["output_path"], output)
        profile = protocol.seal({
            "schema": "stwo.recursive-pipeline-fake-worker-profile.v1",
            "node_id": node["node_id"], "wall_ns": 1,
        })
        publish(payload["profile_receipt_path"], protocol.canonical_bytes(profile))
        candidate = protocol.seal({
            "schema": CANDIDATE, "output_ref": output_ref,
        })
        publish(payload["candidate_ref_path"], protocol.canonical_bytes(candidate))
        for lease in payload["dependency_lease_ids"]:
            live.remove(lease)
        return {
            "output_path": payload["output_path"], "output_ref": output_ref,
            "profile_receipt_path": payload["profile_receipt_path"],
            "candidate_ref_path": payload["candidate_ref_path"],
            "consumed_lease_ids": payload["dependency_lease_ids"],
        }
    if action == "coldOpen":
        output_ref = payload["output_ref"]
        raw = Path(payload["output_path"]).read_bytes()
        if len(raw) != output_ref["byte_count"] or hashlib.sha256(raw).hexdigest() != output_ref["sha256"]:
            raise RuntimeError("InvalidOutputRef")
        manifest_ref = payload["stage_manifest_ref"]
        if manifest_ref is None:
            manifest_raw = protocol.mock_stage_manifest_bytes(
                node=payload["node"], semantic=payload["semantic_key"],
                execution=payload["execution_key"],
                ordered_inputs=payload["ordered_inputs"], output_ref=output_ref,
                dependency_stage_manifest_refs=payload[
                    "dependency_stage_manifest_refs"
                ],
            )
            root = Path(payload["output_path"]).parents[1]
            manifest_ref = put(root, manifest_raw, 4, 1)
        token = "fake-lease-%08d" % next_lease
        next_lease += 1
        live.add(token)
        return {
            "validation_receipt": protocol.seal({
                "schema": "stwo.recursive-pipeline-fake-worker-validation.v1",
                "node_id": payload["node"]["node_id"],
                "output_sha256": output_ref["sha256"],
                "validator_version": payload["validator_version"],
                "mode": payload["mode"],
            }),
            "lease_id": token, "stage_manifest_ref": manifest_ref,
        }
    if action == "closeLease":
        live.remove(payload["lease_id"])
        return {}
    if action == "shutdown":
        if live:
            raise RuntimeError("LeakedLease")
        return {}
    raise RuntimeError("UnsupportedAction")

for raw in sys.stdin.buffer:
    request = json.loads(raw)
    action = request["action"]
    try:
        if request["schema"] != REQUEST:
            raise RuntimeError("InvalidRequest")
        payload = handle(action, request["payload"])
        status = "ok"
    except Exception as error:
        payload = {"error": type(error).__name__, "consumed_lease_ids": []}
        status = "error"
    response = protocol.seal({
        "schema": RESPONSE, "sequence": request["sequence"],
        "action": action, "status": status, "payload": payload,
    })
    sys.stdout.buffer.write(protocol.canonical_bytes(response))
    sys.stdout.buffer.flush()
    if action == "shutdown" and status == "ok":
        break
'''


class RecursivePipelineCampaignTests(unittest.TestCase):
    def test_campaign_shape_is_inventory_derived_for_arbitrary_blocks(self) -> None:
        expected = {
            1: (1, 0, 0, 0),
            2: (2, 0, 1, 1),
            3: (4, 1, 3, 2),
            5: (8, 3, 7, 3),
            13: (16, 3, 15, 4),
            210: (256, 46, 255, 8),
        }
        for real_count, values in expected.items():
            with self.subTest(real_count=real_count):
                shape = campaign.derive_shape(real_count)
                self.assertEqual(
                    (
                        shape.padded_leaf_count,
                        shape.empty_leaf_count,
                        shape.fold_count,
                        shape.root_level,
                    ),
                    values,
                )
        with self.assertRaises(protocol.PipelineError):
            campaign.derive_shape(0)
        with self.assertRaises(protocol.PipelineError):
            campaign.derive_shape(campaign.MAX_REAL_LEAF_COUNT + 1)

        with tempfile.TemporaryDirectory() as raw:
            workspace = store_mod.Workspace(Path(raw) / "workspace", create=True)
            inventory = fixture_inventory(workspace, real_leaf_count=13)
            manifest, authority = campaign.plan(inventory)
            self.assertEqual(authority["real_leaf_count"], 13)
            self.assertEqual(authority["empty_leaf_count"], 3)
            self.assertEqual(authority["common_fold_count"], 15)
            self.assertEqual(authority["logical_node_count"], 31)
            self.assertEqual(authority["goal_node_id"], "fold/04/000")
            self.assertEqual(len(manifest["nodes"]), 44)
            mocked = mock.build_manifest(workspace, real_leaf_count=5)
            self.assertEqual(len(mocked["nodes"]), 15)
            self.assertEqual(mocked["goal"], "fold/03/000")

    def test_inventory_order_roles_and_boundary_custody_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            workspace = store_mod.Workspace(Path(raw) / "workspace", create=True)
            inventory = fixture_inventory(workspace)
            for mutate in (
                lambda value: value["real_leaves"].__setitem__(
                    slice(None), value["real_leaves"][:-1],
                ),
                lambda value: value["real_leaves"][0]["compact_inputs"].reverse(),
                lambda value: value["folds"][0].__setitem__("ordinal", 1),
                lambda value: value["capture_publications"]["public_wire_v4"]
                .__setitem__("schema_version", 4),
            ):
                with self.subTest(mutation=mutate):
                    changed = copy.deepcopy(inventory)
                    changed.pop("content_sha256")
                    mutate(changed)
                    changed = protocol.seal(changed)
                    with self.assertRaises(protocol.PipelineError):
                        campaign.validate_inventory(changed)

            imported = fixture_inventory(
                workspace, leaf_boundary=(0, "wrapper"),
            )
            for field, wrong in (
                ("schema_version", 1),
                ("byte_count", campaign.RECURSIVE_NODE_BYTE_COUNT - 1),
            ):
                changed = copy.deepcopy(imported)
                changed.pop("content_sha256")
                changed["real_leaves"][0]["boundary_artifact"][field] = wrong
                changed = protocol.seal(changed)
                with self.subTest(field=field), self.assertRaises(
                    protocol.PipelineError,
                ):
                    campaign.validate_inventory(changed)
            changed = copy.deepcopy(inventory)
            changed.pop("content_sha256")
            changed["stages"]["common_fold"]["output_schema_version"] = 1
            changed = protocol.seal(changed)
            with self.assertRaises(protocol.PipelineError):
                campaign.validate_inventory(changed)

            overlap = copy.deepcopy(inventory)
            overlap.pop("content_sha256")
            artifact = workspace.put_blob(
                b"O" * campaign.RECURSIVE_NODE_BYTE_COUNT,
                kind=10,
                schema_version=campaign.RECURSIVE_NODE_SCHEMA_VERSION,
            )
            manifest_ref = workspace.put_blob(
                b"overlap-manifest\n", kind=4, schema_version=1,
            )
            for coordinate in ((1, 0), (8, 0)):
                item = next(
                    fold for fold in overlap["folds"]
                    if (fold["level"], fold["ordinal"]) == coordinate
                )
                item["boundary_artifact"] = artifact
                item["boundary_stage_manifest"] = manifest_ref
            overlap = protocol.seal(overlap)
            campaign.validate_inventory(overlap)
            with self.assertRaises(protocol.PipelineError):
                campaign.plan(overlap)

    def test_exact_topology_and_source_native_wrapper_fold_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            workspace = store_mod.Workspace(Path(raw) / "workspace", create=True)
            source = fixture_inventory(workspace, legacy_differential=True)
            manifest, authority = campaign.plan(source)
            self.assertEqual(len(manifest["nodes"]), 721)
            self.assertEqual(authority["logical_node_count"], 511)
            self.assertEqual(authority["real_leaf_count"], 210)
            self.assertEqual(authority["empty_leaf_count"], 46)
            self.assertEqual(authority["common_fold_count"], 255)
            self.assertEqual(authority["legacy_differential_import_count"], 1)
            referenced = campaign.referenced_blobs(source)
            self.assertEqual(referenced[0], source["capture_publications"][
                "incremental_boundary_v4"
            ])
            self.assertEqual(referenced[1], source["capture_publications"][
                "public_wire_v4"
            ])
            self.assertFalse(any(
                "legacy" in json.dumps(node) for node in manifest["nodes"]
            ))
            self.assertFalse(any(
                source["capture_publications"]["public_wire_v4"]["sha256"]
                in json.dumps(node) for node in manifest["nodes"]
            ))

            native, _ = campaign.plan(fixture_inventory(
                workspace, leaf_boundary=(0, "native"),
            ))
            imported_native = next(
                node for node in native["nodes"] if node["node_id"] == "native/000"
            )
            self.assertEqual(imported_native["semantic_options"]["operation"],
                             "cold-import-native")
            wrapper, _ = campaign.plan(fixture_inventory(
                workspace, leaf_boundary=(0, "wrapper"),
            ))
            self.assertFalse(any(
                node["node_id"] == "native/000" for node in wrapper["nodes"]
            ))
            imported_wrapper = next(
                node for node in wrapper["nodes"] if node["node_id"] == "leaf/000"
            )
            self.assertEqual(imported_wrapper["semantic_options"]["operation"],
                             "cold-import-wrapper")
            folded, fold_authority = campaign.plan(fixture_inventory(
                workspace, fold_boundary=(8, 0),
            ))
            self.assertEqual(len(folded["nodes"]), 1)
            self.assertEqual(fold_authority["logical_node_count"], 511)
            self.assertEqual(folded["nodes"][0]["semantic_options"]["operation"],
                             "cold-import-fold")

            authorities = mock.execution_authorities()
            for run_id, selected, through, expected in (
                ("from-source", manifest, "leaf/000", 2),
                ("from-native", native, "leaf/000", 2),
                ("from-wrapper", wrapper, "leaf/000", 1),
                ("from-fold", folded, None, 1),
            ):
                with self.subTest(boundary=run_id):
                    selected_registry, _ = mock_registry(authorities)
                    summary = runner_mod.Runner(
                        workspace, selected, run_id, selected_registry,
                        authorities, cpu_tokens=1, rss_tokens=1,
                    ).run(through=through)
                    self.assertEqual(summary.committed, expected)

    def test_one_compact_leaf_change_invalidates_only_its_physical_path(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            workspace = store_mod.Workspace(Path(raw) / "workspace", create=True)
            authorities = mock.execution_authorities()
            first, _ = campaign.plan(fixture_inventory(workspace))
            first_registry, _ = mock_registry(authorities)
            first_summary = runner_mod.Runner(
                workspace, first, "first", first_registry, authorities,
                cpu_tokens=4, rss_tokens=4, lease_frontier_limit=16,
            ).run()
            self.assertEqual(first_summary.executed, 721)

            second, _ = campaign.plan(fixture_inventory(
                workspace, mutate_leaf=17,
            ))
            second_registry, second_adapter = mock_registry(authorities)
            second_summary = runner_mod.Runner(
                workspace, second, "second", second_registry, authorities,
                cpu_tokens=4, rss_tokens=4, lease_frontier_limit=16,
            ).run()
            self.assertEqual(second_summary.executed, 10)
            self.assertEqual(second_summary.cache_hits, 711)
            self.assertEqual(second_adapter.build_count, 10)
            explanation = runner_mod.explain_run_difference(
                workspace, "first", "second", second,
            )
            self.assertEqual(explanation["first_difference"], "native/017")
            self.assertEqual(explanation["invalidated_nodes"], [
                "native/017", "leaf/017", "fold/01/008", "fold/02/004",
                "fold/03/002", "fold/04/001", "fold/05/000",
                "fold/06/000", "fold/07/000", "fold/08/000",
            ])

    def test_import_plan_and_missing_adapter_fail_before_build(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            workspace_path = root / "workspace"
            workspace = store_mod.Workspace(workspace_path, create=True)
            inventory = fixture_inventory(workspace)
            inventory_path = root / "inventory.json"
            inventory_path.write_bytes(protocol.canonical_bytes(inventory))
            command = [sys.executable, "-m", "scripts.recursive_pipeline_cli"]
            imported = subprocess.run([
                *command, "import", "--workspace", str(workspace_path),
                "--inventory", str(inventory_path),
            ], check=True, capture_output=True)
            imported_value = protocol.parse_canonical(
                imported.stdout, lambda item: item, "campaign import output",
            )
            planned = subprocess.run([
                *command, "plan", "--workspace", str(workspace_path),
                "--campaign-inventory", imported_value["inventory_sha256"],
            ], check=True, capture_output=True)
            planned_value = protocol.parse_canonical(
                planned.stdout, lambda item: item, "campaign plan output",
            )
            self.assertEqual(planned_value["node_count"], 721)
            self.assertIsNotNone(planned_value["campaign_authority_sha256"])
            unpublished = root / "root-publication.json"
            rejected = subprocess.run([
                *command, "publish-root", "--workspace", str(workspace_path),
                "--manifest", planned_value["manifest_sha256"],
                "--run-id", "absent", "--result", str(unpublished),
            ], capture_output=True)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertFalse(unpublished.exists())

            manifest, _ = campaign.plan(inventory)
            authorities = mock.execution_authorities()
            empty_registry = registry_mod.StageRegistry()
            control = runner_mod.Runner(
                workspace, manifest, "missing-adapter", empty_registry,
                authorities, cpu_tokens=1, rss_tokens=1,
            )
            with self.assertRaises(protocol.PipelineError):
                control.run(through="leaf/000")

    def test_injected_cross_process_worker_acceptance(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            workspace_path = root / "workspace"
            workspace = store_mod.Workspace(workspace_path, create=True)
            inventory = fixture_inventory(workspace)
            inventory_path = root / "inventory.json"
            inventory_path.write_bytes(protocol.canonical_bytes(inventory))
            worker = root / "fake-worker.py"
            worker.write_text(textwrap.dedent(FAKE_WORKER))
            authorities = protocol.seal({
                "schema": "stwo.recursive-pipeline-execution-authority-set.v1",
                "authorities": mock.execution_authorities(),
            })
            authorities_path = root / "execution-authorities.json"
            authorities_path.write_bytes(protocol.canonical_bytes(authorities))
            completed = subprocess.run([
                sys.executable, "-m",
                "scripts.recursive_pipeline_worker_acceptance",
                "--workspace", str(workspace_path),
                "--inventory", str(inventory_path),
                "--execution-authorities", str(authorities_path),
                "--worker", sys.executable,
                "--worker-arg", str(worker),
                "--worker-cwd", str(Path.cwd()),
                "--through", "leaf/000",
            ], capture_output=True, timeout=30, env={
                **os.environ, "PYTHONPATH": str(Path.cwd()),
            })
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())
            result = protocol.parse_canonical(
                completed.stdout, lambda item: item,
                "cross-process worker acceptance output",
            )
            self.assertEqual(result["committed"], 2)
            self.assertEqual(result["executed"], 2)
            manifest, _ = campaign.plan(inventory)
            selected = workspace.read_run_ref(
                "worker-acceptance", "leaf/000",
            )
            self.assertEqual(selected["stage_manifest"]["kind"], 4)
            self.assertEqual(selected["stage_manifest"]["schema_version"], 1)
            self.assertNotIn(
                str(workspace.root),
                protocol.canonical_bytes(inventory).decode("ascii"),
            )
            self.assertEqual(manifest["goal"], "fold/08/000")

            root_inventory = fixture_inventory(
                workspace, fold_boundary=(8, 0),
            )
            root_inventory_path = root / "root-inventory.json"
            root_inventory_path.write_bytes(
                protocol.canonical_bytes(root_inventory),
            )
            acceptance = [
                sys.executable, "-m",
                "scripts.recursive_pipeline_worker_acceptance",
                "--workspace", str(workspace_path),
                "--inventory", str(root_inventory_path),
                "--execution-authorities", str(authorities_path),
                "--worker", sys.executable,
                "--worker-arg", str(worker),
                "--worker-cwd", str(Path.cwd()),
                "--run-id", "root-boundary",
            ]
            root_run = subprocess.run(
                acceptance, capture_output=True, timeout=30,
                env={**os.environ, "PYTHONPATH": str(Path.cwd())},
            )
            self.assertEqual(root_run.returncode, 0, root_run.stderr.decode())
            root_manifest, _ = campaign.plan(root_inventory)
            backend = [
                "--workspace", str(workspace_path),
                "--manifest", root_manifest["content_sha256"],
                "--run-id", "root-boundary",
                "--worker", sys.executable,
                "--worker-arg", str(worker),
                "--worker-cwd", str(Path.cwd()),
                "--execution-authorities", str(authorities_path),
                "--cpu-tokens", "1", "--rss-tokens", "1",
            ]
            cli = [sys.executable, "-m", "scripts.recursive_pipeline_cli"]
            environment = {**os.environ, "PYTHONPATH": str(Path.cwd())}
            resumed = subprocess.run(
                [*cli, "resume", *backend], capture_output=True, timeout=30,
                env=environment,
            )
            self.assertEqual(resumed.returncode, 0, resumed.stderr.decode())
            subprocess.run([
                *cli, "status", "--workspace", str(workspace_path),
                "--manifest", root_manifest["content_sha256"],
                "--run-id", "root-boundary",
            ], check=True, capture_output=True, env=environment)
            verified = subprocess.run(
                [*cli, "verify", *backend, "--mode", "root"],
                capture_output=True, timeout=30, env=environment,
            )
            self.assertEqual(verified.returncode, 0, verified.stderr.decode())
            publication = root / "root-publication.json"
            published = subprocess.run(
                [*cli, "publish-root", *backend,
                 "--result", str(publication)],
                capture_output=True, timeout=30, env=environment,
            )
            self.assertEqual(published.returncode, 0, published.stderr.decode())
            self.assertTrue(publication.is_file())


if __name__ == "__main__":
    unittest.main()
