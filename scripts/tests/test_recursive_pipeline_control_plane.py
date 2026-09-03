from __future__ import annotations

import copy
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

from scripts import recursive_pipeline_mock as mock
from scripts import recursive_pipeline_protocol as protocol
from scripts import recursive_pipeline_registry as registry_mod
from scripts import recursive_pipeline_runner as runner_mod
from scripts import recursive_pipeline_store as store_mod


def tiny_manifest(workspace: store_mod.Workspace) -> dict:
    full = mock.build_manifest(workspace)
    wanted = {"leaf/000", "leaf/001", "fold/01/000"}
    return protocol.validate_pipeline_manifest(protocol.seal({
        "schema": protocol.PIPELINE_MANIFEST_SCHEMA,
        "campaign_namespace_sha256": full["campaign_namespace_sha256"],
        "goal": "fold/01/000",
        "test_only": True,
        "nodes": [node for node in full["nodes"] if node["node_id"] in wanted],
    }))


def registry(
    authorities: dict[str, str], *, validator_version: int = 1,
) -> tuple[registry_mod.StageRegistry, registry_mod.MockStageAdapter]:
    adapter = registry_mod.MockStageAdapter(
        authorities, validator_version=validator_version,
    )
    result = registry_mod.StageRegistry(allow_mock=True)
    result.register(mock.MOCK_ADAPTER, adapter)
    return result, adapter


def runner(
    workspace: store_mod.Workspace, manifest: dict, run_id: str,
    registry_value: registry_mod.StageRegistry,
    authorities: dict[str, str], *, crash_hook=None,
) -> runner_mod.Runner:
    return runner_mod.Runner(
        workspace, manifest, run_id, registry_value, authorities,
        cpu_tokens=1, rss_tokens=1, crash_hook=crash_hook,
    )


def overwrite_cas_for_test(path: Path, raw: bytes) -> None:
    """Deliberately mutate one CAS blob, then restore immutable custody."""
    os.chmod(path, 0o600)
    try:
        path.write_bytes(raw)
    finally:
        os.chmod(path, 0o400)


class RecursivePipelineControlPlaneTests(unittest.TestCase):
    def test_shared_cas_is_immutable_before_publish_and_rejects_mode_drift(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            workspace = store_mod.Workspace(Path(raw) / "workspace", create=True)
            payload = b"immutable shared CAS object"
            ref = workspace.put_blob(payload, kind=1, schema_version=9)
            path = workspace.object_path(ref["sha256"])
            metadata = path.lstat()
            self.assertTrue(stat.S_ISREG(metadata.st_mode))
            self.assertFalse(stat.S_ISLNK(metadata.st_mode))
            self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o400)
            self.assertEqual(workspace.read_blob(ref), payload)
            self.assertEqual(workspace.put_blob(
                payload, kind=1, schema_version=9,
            ), ref)

            source = Path(raw) / "streamed-input.bin"
            source.write_bytes(b"streamed immutable CAS object")
            streamed = workspace.put_file(source, kind=8, schema_version=1)
            streamed_path = workspace.object_path(streamed["sha256"])
            self.assertEqual(stat.S_IMODE(streamed_path.lstat().st_mode), 0o400)
            self.assertEqual(workspace.read_blob(streamed), source.read_bytes())

            os.chmod(path, 0o600)
            for operation in (
                lambda: workspace.read_blob(ref),
                lambda: workspace.validate_blob(ref),
                lambda: workspace.stat_blob(ref),
                lambda: workspace.put_blob(payload, kind=1, schema_version=9),
            ):
                with self.assertRaises(protocol.PipelineError):
                    operation()

    def test_mock_key_wire_matches_frozen_zig_golden_vectors(self) -> None:
        digest = lambda byte: (bytes([byte]) * 32).hex()
        inputs = [
            {"role": 2, "ordinal": 0, "blob": protocol.blob_ref(
                kind=12, schema_version=3, byte_count=5, sha256=digest(0x11),
            )},
            {"role": 6, "ordinal": 0, "blob": protocol.blob_ref(
                kind=10, schema_version=2, byte_count=9, sha256=digest(0x22),
            )},
        ]
        semantic = {
            "schema": protocol.SEMANTIC_KEY_SCHEMA,
            "format_version": 1,
            "stage_kind": 2,
            "stage_schema_version": 7,
            "campaign_namespace_sha256": digest(1),
            "local_task_identity_sha256": digest(2),
            **dict(zip(protocol.KEY_AUTHORITY_FIELDS,
                       (digest(value) for value in range(3, 12)))),
            "semantic_options_identity_sha256": digest(12),
            "ordered_inputs": inputs,
        }
        semantic["identity_sha256"] = protocol.sha256_bytes(
            protocol.semantic_key_bytes(semantic),
        )
        self.assertEqual(len(protocol.semantic_key_bytes(semantic)), 548)
        self.assertEqual(
            semantic["identity_sha256"],
            "abe55472520e39062de460217ce896bb63c2b690ec7478368d09b89a2ae8a1c4",
        )
        execution = {
            "schema": protocol.EXECUTION_KEY_SCHEMA,
            "format_version": 1,
            "semantic_key_identity_sha256": semantic["identity_sha256"],
            **dict(zip(protocol.EXECUTION_AUTHORITY_FIELDS,
                       (digest(value) for value in range(21, 33)))),
        }
        execution["identity_sha256"] = protocol.sha256_bytes(
            protocol.execution_key_bytes(execution),
        )
        self.assertEqual(len(protocol.execution_key_bytes(execution)), 459)
        self.assertEqual(
            execution["identity_sha256"],
            "17b1e66e314d5cfe7356d78e8861c6d1019f6123640fa4d1190a033508bf5731",
        )
        self.assertEqual(protocol.decode_semantic_key(
            protocol.semantic_key_bytes(semantic)), semantic)
        self.assertEqual(protocol.decode_execution_key(
            protocol.execution_key_bytes(execution)), execution)

    def test_shared_cas_blob_wire_accepts_empty_logs_but_mock_proof_rejects_empty(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            workspace = store_mod.Workspace(Path(raw) / "workspace", create=True)
            empty = workspace.put_blob(b"", kind=1, schema_version=1)
            self.assertEqual(empty, {
                "kind": 1,
                "format_version": 1,
                "schema_version": 1,
                "byte_count": 0,
                "sha256": protocol.sha256_bytes(b""),
            })
            self.assertEqual(workspace.read_blob(empty), b"")
            manifest = tiny_manifest(workspace)
            authorities = mock.execution_authorities()
            registry_value, adapter = registry(authorities)
            node = manifest["nodes"][0]
            keys = adapter.derive(
                manifest["campaign_namespace_sha256"], node,
                node["external_inputs"],
                authorities,
            )
            proof_ref = protocol.blob_ref(
                kind=10, schema_version=1, byte_count=0,
                sha256=protocol.sha256_bytes(b""),
            )
            with self.assertRaises(protocol.PipelineError):
                adapter.cold_open(
                    node, node["external_inputs"], keys.semantic,
                    keys.execution, proof_ref, b"",
                    output_path=workspace.object_path(proof_ref["sha256"]),
                    dependency_stage_manifest_refs=[], stage_manifest_ref=None,
                    mode="cold",
                )

    def test_current_ethereum_profile_mock_dag_and_leaf_local_invalidation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            workspace = store_mod.Workspace(Path(raw) / "workspace", create=True)
            authorities = mock.execution_authorities()
            first = mock.build_manifest(workspace)
            self.assertEqual(len(first["nodes"]), 511)
            self.assertEqual(
                sum(node["semantic_options"].get("leaf_kind") == "real"
                    for node in first["nodes"]), 210,
            )
            self.assertEqual(
                sum(node["semantic_options"].get("leaf_kind") == "empty"
                    for node in first["nodes"]), 46,
            )
            first_registry, first_adapter = registry(authorities)
            first_summary = runner(
                workspace, first, "first", first_registry, authorities,
            ).run()
            self.assertEqual(first_summary.executed, 511)
            self.assertLessEqual(first_summary.max_live_leases, 10)

            second = mock.build_manifest(workspace, mutate_leaf=17)
            second_registry, second_adapter = registry(authorities)
            second_summary = runner(
                workspace, second, "second", second_registry, authorities,
            ).run()
            self.assertEqual(second_summary.executed, 9)
            self.assertEqual(second_summary.cache_hits, 502)
            self.assertEqual(second_adapter.build_count, 9)
            explanation = runner_mod.explain_run_difference(
                workspace, "first", "second", second,
            )
            self.assertEqual(explanation["first_difference"], "leaf/017")
            self.assertEqual(explanation["first_field"], "ordered_inputs")
            self.assertEqual(explanation["invalidated_count"], 9)
            self.assertEqual(explanation["invalidated_nodes"], [
                "leaf/017", "fold/01/008", "fold/02/004", "fold/03/002",
                "fold/04/001", "fold/05/000", "fold/06/000",
                "fold/07/000", "fold/08/000",
            ])

    def test_inventory_shaped_mock_invalidation_has_no_fixed_tree_depth(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            workspace = store_mod.Workspace(Path(raw) / "workspace", create=True)
            authorities = mock.execution_authorities()
            first = mock.build_manifest(workspace, real_leaf_count=13)
            first_registry, _ = registry(authorities)
            first_summary = runner(
                workspace, first, "generic-first", first_registry, authorities,
            ).run()
            self.assertEqual(first_summary.executed, 31)

            second = mock.build_manifest(
                workspace, real_leaf_count=13, mutate_leaf=12,
            )
            second_registry, second_adapter = registry(authorities)
            second_summary = runner(
                workspace, second, "generic-second", second_registry, authorities,
            ).run()
            self.assertEqual(second_summary.executed, 5)
            self.assertEqual(second_summary.cache_hits, 26)
            self.assertEqual(second_adapter.build_count, 5)
            explanation = runner_mod.explain_run_difference(
                workspace, "generic-first", "generic-second", second,
            )
            self.assertEqual(explanation["invalidated_nodes"], [
                "leaf/012", "fold/01/006", "fold/02/003", "fold/03/001",
                "fold/04/000",
            ])

    def test_parent_first_scheduler_runs_concurrently_within_both_token_caps(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            workspace = store_mod.Workspace(Path(raw) / "workspace", create=True)
            manifest = mock.build_manifest(workspace)
            authorities = mock.execution_authorities()
            adapter = registry_mod.MockStageAdapter(
                authorities, build_delay_seconds=0.01, max_parallelism=8,
            )
            registry_value = registry_mod.StageRegistry(allow_mock=True)
            registry_value.register(mock.MOCK_ADAPTER, adapter)
            control = runner_mod.Runner(
                workspace, manifest, "parallel", registry_value, authorities,
                cpu_tokens=4, rss_tokens=2, lease_frontier_limit=2,
            )
            summary = control.run(through="fold/02/000")
            self.assertEqual(summary.committed, 7)
            self.assertEqual(summary.max_parallel_tasks, 2)
            self.assertEqual(summary.peak_cpu_tokens, 2)
            self.assertEqual(summary.peak_rss_tokens, 2)
            self.assertEqual(adapter.max_active_builds, 2)
            self.assertLessEqual(summary.max_live_leases, 2)
            self.assertGreaterEqual(adapter.release_count, 1)
            self.assertEqual(adapter._live, set())

    def test_failed_parent_build_retains_then_runner_closes_child_leases(self) -> None:
        class RejectingParent(registry_mod.MockStageAdapter):
            def build(self, node, ordered_inputs, semantic, execution,
                      dependency_leases, attempt_directory):
                if dependency_leases:
                    raise protocol.PipelineError("injected parent rejection")
                return super().build(
                    node, ordered_inputs, semantic, execution,
                    dependency_leases, attempt_directory,
                )

        with tempfile.TemporaryDirectory() as raw:
            workspace = store_mod.Workspace(Path(raw) / "workspace", create=True)
            manifest = tiny_manifest(workspace)
            authorities = mock.execution_authorities()
            adapter = RejectingParent(authorities)
            registry_value = registry_mod.StageRegistry(allow_mock=True)
            registry_value.register(mock.MOCK_ADAPTER, adapter)
            with self.assertRaises(protocol.PipelineError):
                runner(workspace, manifest, "failed", registry_value,
                       authorities).run()
            self.assertEqual(adapter._live, set())
            self.assertEqual(adapter.release_count, 2)

    def test_crash_recovery_adopts_complete_outputs_at_every_phase(self) -> None:
        phases = (
            "intent", "running", "candidate_written", "outputs_published",
            "validated", "committed",
        )
        for phase in phases:
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as raw:
                workspace = store_mod.Workspace(Path(raw) / "workspace", create=True)
                manifest = tiny_manifest(workspace)
                authorities = mock.execution_authorities()
                first_registry, _ = registry(authorities)
                crashed = False

                def inject(actual: str, node_id: str) -> None:
                    nonlocal crashed
                    if not crashed and node_id == "leaf/000" and actual == phase:
                        crashed = True
                        raise runner_mod.InjectedCrash(phase)

                with self.assertRaises(runner_mod.InjectedCrash):
                    runner(
                        workspace, manifest, "resume", first_registry,
                        authorities, crash_hook=inject,
                    ).run()
                self.assertTrue(crashed)
                resumed_registry, resumed_adapter = registry(authorities)
                summary = runner(
                    workspace, manifest, "resume", resumed_registry, authorities,
                ).run()
                self.assertEqual(summary.committed, 3)
                if phase in ("intent", "running"):
                    self.assertEqual(resumed_adapter.build_count, 3)
                else:
                    self.assertEqual(resumed_adapter.build_count, 2)
                    self.assertGreaterEqual(summary.recovered, 1)
                self.assertIsNotNone(
                    workspace.maybe_run_ref("resume", manifest["goal"]),
                )

    def test_execution_change_and_validator_upgrade_revalidate_without_reprove(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            workspace = store_mod.Workspace(Path(raw) / "workspace", create=True)
            manifest = tiny_manifest(workspace)
            first_authorities = mock.execution_authorities(resource_policy="a")
            first_registry, _ = registry(first_authorities, validator_version=1)
            runner(
                workspace, manifest, "first", first_registry, first_authorities,
            ).run()

            second_authorities = mock.execution_authorities(resource_policy="b")
            second_registry, second_adapter = registry(
                second_authorities, validator_version=2,
            )
            summary = runner(
                workspace, manifest, "second", second_registry, second_authorities,
            ).run()
            self.assertEqual(summary.cache_hits, 3)
            self.assertEqual(second_adapter.build_count, 0)
            self.assertEqual(second_adapter.validate_count, 3)
            self.assertEqual(second_adapter.release_count, 3)
            versions = {
                record["validator_version"]
                for record in workspace.cache_records(
                    workspace.read_run_ref("second", "leaf/000")[
                        "semantic_key_sha256"
                    ],
                )
            }
            self.assertIn(2, versions)

    def test_reprofile_is_append_only_and_explicit_promotion_invalidates_parent(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            workspace = store_mod.Workspace(Path(raw) / "workspace", create=True)
            manifest = tiny_manifest(workspace)
            authorities = mock.execution_authorities()
            registry_value, adapter = registry(authorities)
            control = runner(
                workspace, manifest, "candidate", registry_value, authorities,
            )
            control.run()
            selected_before = workspace.read_run_ref("candidate", "leaf/000")
            summary = control.run(reprofile=("leaf/000",))
            selected_after = workspace.read_run_ref("candidate", "leaf/000")
            self.assertEqual(summary.reprofiled, 1)
            self.assertEqual(selected_before, selected_after)
            candidates = list(workspace.cache_records(
                selected_before["semantic_key_sha256"],
            ))
            self.assertGreaterEqual(len(candidates), 2)
            promoted = next(
                item for item in candidates
                if item["output_artifact"] != selected_before["output_artifact"]
            )
            promoted_summary = control.run(promote={
                "leaf/000": promoted["content_sha256"],
            })
            selected_promoted = workspace.read_run_ref("candidate", "leaf/000")
            self.assertEqual(selected_promoted["generation"], 1)
            self.assertEqual(selected_promoted["output_artifact"],
                             promoted["output_artifact"])
            self.assertEqual(promoted_summary.executed, 1)

    def test_crashed_reprofile_is_adopted_without_implicit_selection(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            workspace = store_mod.Workspace(Path(raw) / "workspace", create=True)
            manifest = tiny_manifest(workspace)
            authorities = mock.execution_authorities()
            first_registry, _ = registry(authorities)
            runner(workspace, manifest, "selected", first_registry, authorities).run()
            before = workspace.read_run_ref("selected", "leaf/000")
            crashed_registry, _ = registry(authorities)

            def crash(phase: str, node_id: str) -> None:
                if phase == "outputs_published" and node_id == "leaf/000":
                    raise runner_mod.InjectedCrash(phase)

            with self.assertRaises(runner_mod.InjectedCrash):
                runner(
                    workspace, manifest, "selected", crashed_registry,
                    authorities, crash_hook=crash,
                ).run(reprofile=("leaf/000",))
            resumed_registry, _ = registry(authorities)
            runner(workspace, manifest, "selected", resumed_registry,
                   authorities).run()
            after = workspace.read_run_ref("selected", "leaf/000")
            self.assertEqual(after, before)

    def test_rejected_promotion_does_not_advance_selected_generation(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            workspace = store_mod.Workspace(Path(raw) / "workspace", create=True)
            manifest = tiny_manifest(workspace)
            authorities = mock.execution_authorities()
            registry_value, _ = registry(authorities)
            control = runner(workspace, manifest, "promote", registry_value, authorities)
            control.run()
            control.run(reprofile=("leaf/000",))
            before = workspace.read_run_ref("promote", "leaf/000")
            candidate = next(
                item for item in workspace.cache_records(before["semantic_key_sha256"])
                if item["output_artifact"] != before["output_artifact"]
            )
            overwrite_cas_for_test(
                workspace.object_path(candidate["output_artifact"]["sha256"]),
                b"rejected",
            )
            with self.assertRaises(Exception):
                control.run(promote={"leaf/000": candidate["content_sha256"]})
            self.assertEqual(workspace.read_run_ref("promote", "leaf/000"), before)

    def test_run_lock_blocks_a_second_mutating_runner(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            workspace = store_mod.Workspace(Path(raw) / "workspace", create=True)
            manifest = tiny_manifest(workspace)
            workspace.prepare_run("locked", manifest)
            authorities = mock.execution_authorities()
            registry_value, _ = registry(authorities)
            second = runner_mod.Runner(
                workspace, manifest, "locked", registry_value, authorities,
                cpu_tokens=1, rss_tokens=1, prepare_run=False,
            )
            with workspace.run_lock("locked", exclusive=True):
                with self.assertRaises(protocol.PipelineError):
                    second.run()

    def test_long_lived_worker_stderr_is_drained_without_pipe_deadlock(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            workspace = store_mod.Workspace(root / "workspace", create=True)
            worker = root / "fake-worker.py"
            worker.write_text("""#!/usr/bin/env python3
import hashlib, json, sys
def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(\",\", \":\")) + \"\\n\").encode()
def seal(value):
    result = dict(value)
    result[\"content_sha256\"] = hashlib.sha256(canonical(result)).hexdigest()
    return result
for line in sys.stdin.buffer:
    request = json.loads(line)
    sys.stderr.write(\"diagnostic-x\" * 20000)
    sys.stderr.flush()
    action = request[\"action\"]
    if action == \"describe\":
        description = seal({
            \"schema\": \"stwo.recursive-pipeline-stage-description.v1\",
            \"stage_kind\": request[\"payload\"][\"stage_kind\"],
            \"stage_schema_version\": request[\"payload\"][\"stage_schema_version\"],
            \"output_kind\": 10, \"output_schema_version\": 1,
            \"minimum_cpu_tokens\": 1, \"minimum_rss_tokens\": 1,
            \"root_cold_open_transitive\": True,
        })
        payload = {\"description\": description}
    elif action == \"shutdown\": payload = {}
    else: payload = {\"error\": \"Unsupported\", \"consumed_lease_ids\": []}
    response = seal({
        \"schema\": \"stwo.recursive-pipeline-worker-response.v1\",
        \"sequence\": request[\"sequence\"], \"action\": action,
        \"status\": \"ok\" if action in (\"describe\", \"shutdown\") else \"error\",
        \"payload\": payload,
    })
    sys.stdout.buffer.write(canonical(response)); sys.stdout.buffer.flush()
""")
            worker.chmod(0o700)
            adapter = registry_mod.ZigWorkerAdapter(
                [sys.executable, str(worker)], cwd=root, validator_version=1,
                object_root=workspace.sha_objects,
            )
            manifest = tiny_manifest(workspace)
            description = adapter.describe(manifest["nodes"][0])
            self.assertTrue(description["root_cold_open_transitive"])
            self.assertGreater(adapter.stderr_path.stat().st_size, 64 * 1024)
            adapter.close()

    def test_codec_substitution_and_manifest_selector_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            workspace = store_mod.Workspace(Path(raw) / "workspace", create=True)
            manifest = tiny_manifest(workspace)
            path = workspace.publish_manifest(manifest)
            wrong_identity = "11" * 32
            (workspace.manifests / f"{wrong_identity}.json").write_bytes(path.read_bytes())
            with self.assertRaises(protocol.PipelineError):
                workspace.read_manifest(wrong_identity)
            authorities = mock.execution_authorities()
            registry_value, _ = registry(authorities)
            runner(workspace, manifest, "codec", registry_value, authorities).run()
            selected = workspace.read_run_ref("codec", "leaf/000")
            record = workspace.cache_record_by_identity(
                selected["semantic_key_sha256"], selected["cache_record_sha256"],
            )
            mutation = copy.deepcopy(record)
            mutation["stage_result"] = record["profile_receipt"]
            mutation = protocol.seal({
                key: value for key, value in mutation.items()
                if key != "content_sha256"
            })
            with self.assertRaises(protocol.PipelineError):
                store_mod.validate_cache_record(mutation)

    def test_corrupt_selected_blob_fails_deep_and_root_cold_verification(self) -> None:
        for mode in ("deep", "root"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as raw:
                workspace = store_mod.Workspace(Path(raw) / "workspace", create=True)
                manifest = tiny_manifest(workspace)
                authorities = mock.execution_authorities()
                registry_value, _ = registry(authorities)
                control = runner(
                    workspace, manifest, "corrupt", registry_value, authorities,
                )
                control.run()
                root_ref = workspace.read_run_ref("corrupt", manifest["goal"])
                overwrite_cas_for_test(
                    workspace.object_path(root_ref["output_artifact"]["sha256"]),
                    b"corrupt",
                )
                verify_registry, _ = registry(authorities)
                with self.assertRaises(Exception):
                    runner(
                        workspace, manifest, "corrupt", verify_registry, authorities,
                    ).verify(mode=mode)

    def test_cli_plan_run_resume_status_verify_and_explain_cache(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            workspace = Path(raw) / "workspace"
            base = [sys.executable, "-m", "scripts.recursive_pipeline_cli"]
            plan = subprocess.run(
                [
                    *base, "plan", "--workspace", str(workspace),
                    "--mock-real-leaves", "13",
                ],
                check=True, capture_output=True,
            )
            manifest = protocol.parse_canonical(
                plan.stdout,
                lambda value: value,
                "CLI plan output",
            )["manifest_sha256"]
            common = [
                "--workspace", str(workspace), "--manifest", manifest,
                "--run-id", "cli", "--mock", "--cpu-tokens", "1",
                "--rss-tokens", "1",
            ]
            completed = subprocess.run(
                [*base, "run", *common, "--through", "leaf/001"],
                check=True, capture_output=True,
            )
            self.assertEqual(protocol.parse_canonical(
                completed.stdout, lambda value: value, "CLI run output",
            )["committed"], 1)
            resumed = subprocess.run(
                [*base, "resume", *common], check=True, capture_output=True,
            )
            self.assertEqual(protocol.parse_canonical(
                resumed.stdout, lambda value: value, "CLI resume output",
            )["committed"], 31)
            for arguments in (
                ["status", "--workspace", str(workspace), "--manifest", manifest,
                 "--run-id", "cli"],
                ["verify", *common, "--mode", "root"],
                ["explain-cache", "--workspace", str(workspace),
                 "--manifest", manifest, "--left-run", "cli",
                 "--right-run", "cli"],
            ):
                subprocess.run([*base, *arguments], check=True, capture_output=True)
            publication = Path(raw) / "root-publication.json"
            subprocess.run([
                *base, "publish-root", *common, "--result", str(publication),
            ], check=True, capture_output=True)
            published = protocol.parse_canonical(
                publication.read_bytes(),
                lambda value: protocol.validate_seal(value, "root publication"),
                "root publication",
            )
            self.assertEqual(published["status"], "cold_verified")

            missing = Path(raw) / "missing-workspace"
            subprocess.run([
                *base, "plan", "--workspace", str(missing),
                "--mock-real-leaves", "5",
            ], check=True, capture_output=True)
            missing_manifest = next((missing / "manifests").glob("*.json")).stem
            failed = subprocess.run([
                *base, "status", "--workspace", str(missing),
                "--manifest", missing_manifest, "--run-id", "absent",
            ], capture_output=True)
            self.assertNotEqual(failed.returncode, 0)
            self.assertFalse((missing / "runs" / "absent").exists())


if __name__ == "__main__":
    unittest.main()
