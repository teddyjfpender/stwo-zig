from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import unittest

from scripts import ethereum_block_proof_controller as controller
from scripts import ethereum_block_proof_protocol as protocol
from scripts.tests.ethereum_block_proof_fixture import build_plan, digest


class FakeChild:
    def __init__(self, prover: dict, verifier: dict) -> None:
        self.prover = prover
        self.verifier = verifier
        self.calls: list[str] = []
        self.mutate_receipt = False
        self.leaf_stream_sessions = 0
        self._leaf_stream_started = False
        self._segment_count = 0

    def __call__(self, request: dict, context: dict) -> dict:
        if request["task_kind"] == "real_leaf_proof" and not self._leaf_stream_started:
            self._leaf_stream_started = True
            self.leaf_stream_sessions += 1
        self.calls.append(request["task_id"])
        self.assert_context(request, context)
        proof = b"proof:" + request["content_sha256"].encode("ascii")
        proof_identity = {
            "bytes": len(proof), "sha256": hashlib.sha256(proof).hexdigest(),
        }
        root = digest(f"root-{request['content_sha256']}")
        receipt = protocol.expected_receipt(
            request, proof_identity, root, self.verifier,
            context["plan"]["security_parameters"],
        )
        if self.mutate_receipt:
            receipt["statement_sha256"] = digest("wrong-statement")
        prove_timing = {"wall_ns": 10, "user_ns": 9, "system_ns": 1}
        verify_timing = {"wall_ns": 2, "user_ns": 2, "system_ns": 0}
        producer = self.process_receipt(
            "proof_producer", self.prover, request["task_id"], prove_timing,
        )
        if request["task_kind"] == "real_leaf_proof":
            producer = {
                "schema": protocol.LEAF_PRODUCER_OBSERVATION_SCHEMA,
                "role": "leaf_stream_producer",
                "executable": self.prover,
                "argv": ["leaf_stream_producer", "fake-session"],
                "stream_session_sha256": digest("fake-leaf-stream-session"),
                "segment_index": request["node_index"],
                "progress_record_sha256": digest(
                    f"fake-progress-{request['node_index']}"
                ),
                "prove_timing": prove_timing,
            }
        return {
            "schema": protocol.CHILD_RESULT_SCHEMA,
            "statement_sha256": request["expected_statement_sha256"],
            "root_sha256": root,
            "proof_bytes": proof,
            "verification_receipt": receipt,
            "prove_timing": prove_timing,
            "fresh_verify_timing": verify_timing,
            "producer_process": producer,
            "verifier_process": self.process_receipt(
                "fresh_verifier", self.verifier, request["task_id"], verify_timing,
            ),
        }

    @staticmethod
    def process_receipt(
        role: str, executable: dict, task_id: str, timing: dict,
    ) -> dict:
        return {
            "schema": protocol.PROCESS_RECEIPT_SCHEMA,
            "role": role,
            "executable": executable,
            "argv": [role, task_id],
            "exit_code": 0,
            "stdout_bytes": 0,
            "stderr_bytes": 0,
            "timing": timing,
        }

    def assert_context(self, request: dict, context: dict) -> None:
        assert context["prover_path"].is_file()
        assert context["verifier_path"].is_file()
        assert context["leaf_stream_request_path"].is_file()
        assert all(path.is_file() for path in context["segment_authority_paths"])
        if request["scope"] == "leaf":
            assert request["task_kind"] == "real_leaf_proof"
            assert request["covered_segments"] == [request["node_index"]]
            assert context["source_path"].is_file()
            assert len(context["committed_leaf_records"]) == request["node_index"]
            assert context["child_inputs"] == []
        else:
            assert request["task_kind"] == "recursive_parent_proof"
            assert context["source_path"] is None
            assert len(context["child_inputs"]) == 2
            for child in context["child_inputs"]:
                paths = (child["proof_path"], child["authority_path"])
                assert sum(path is not None for path in paths) == 1
                assert next(path for path in paths if path is not None).is_file()

    def finish_leaf_stream(self, context: dict) -> None:
        self._segment_count = len(context["segment_authority_paths"])

    def session_publications(self) -> list[dict]:
        receipt = protocol.seal({
            "schema": "stwo.ethereum.block-proof-leaf-session-receipt.v1",
            "classification": "complete",
            "session_index": 0,
            "stream_session_sha256": digest("fake-leaf-stream-session"),
            "executable": self.prover,
            "argv": ["leaf_stream_producer", "fake-session"],
            "request": {"path": "stream-request.json", "bytes": 1,
                        "sha256": digest("fake-stream-request")},
            "first_segment_index": 0,
            "published_segment_indices": list(range(self._segment_count)),
            "exit_code": 0,
            "stdout_bytes": 0,
            "stderr_bytes": 0,
            "timing": {"wall_ns": 10, "user_ns": None, "system_ns": None},
            "stream_result": {"path": "stream-result.json", "bytes": 1,
                              "sha256": digest("fake-stream-result")},
        })
        raw = protocol.canonical_bytes(receipt)
        return [{
            "receipt": receipt,
            "file": {"path": "leaf-stream/session-receipt.json",
                     "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()},
        }]


class ConcurrentParentChild(FakeChild):
    def __init__(self, prover: dict, verifier: dict) -> None:
        super().__init__(prover, verifier)
        self.lock = threading.Lock()
        self.active_parents = 0
        self.max_active_parents = 0

    def __call__(self, request: dict, context: dict) -> dict:
        if request["level"] == 0:
            return super().__call__(request, context)
        with self.lock:
            self.active_parents += 1
            self.max_active_parents = max(
                self.max_active_parents, self.active_parents,
            )
        try:
            time.sleep(0.02)
            return super().__call__(request, context)
        finally:
            with self.lock:
                self.active_parents -= 1


class SimulatedCrash(RuntimeError):
    pass


class CrashOnce:
    def __init__(self, event: str) -> None:
        self.event = event
        self.fired = False

    def __call__(self, event: str, _: dict) -> None:
        if not self.fired and event == self.event:
            self.fired = True
            raise SimulatedCrash(event)


class CrashTaskOnce:
    def __init__(self, event: str, task_id: str) -> None:
        self.event = event
        self.task_id = task_id
        self.fired = False

    def __call__(self, event: str, context: dict) -> None:
        if (not self.fired and event == self.event
                and context.get("task_id") == self.task_id):
            self.fired = True
            raise SimulatedCrash(event)


def execute(plan: dict, paths: dict, child: FakeChild, fault=None) -> dict:
    return controller.run_for_test(
        plan,
        paths["run_root"],
        paths["segment_root"],
        prover_path=paths["prover"],
        verifier_path=paths["verifier"],
        child=child,
        fault=fault,
    )


class EthereumBlockProofControllerTests(unittest.TestCase):
    def test_production_run_and_replay_fail_before_launch_without_descriptors(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            plan, paths = build_plan(Path(raw))
            for operation in (controller.run, controller.replay):
                with self.subTest(operation=operation.__name__), self.assertRaises(
                    protocol.VerifierMintedDescriptorPlanUnavailable,
                ):
                    operation(
                        plan, paths["run_root"], paths["segment_root"],
                        prover_path=paths["prover"], verifier_path=paths["verifier"],
                    )
            self.assertFalse(paths["run_root"].exists())

    def test_parent_levels_use_the_authenticated_bounded_worker_pool(self) -> None:
        available = os.cpu_count() or 1
        if available < 2:
            self.skipTest("parallel parent test requires two logical cores")
        with tempfile.TemporaryDirectory() as raw:
            plan, paths = build_plan(Path(raw), segment_count=8)
            plan["parent_execution"].update({
                "max_workers": 2,
                "admitted_host_logical_cores": 2,
                "total_worker_memory_budget_bytes": 1024 * 1024 * 1024,
            })
            plan = protocol.seal({
                key: value for key, value in plan.items() if key != "content_sha256"
            })
            child = ConcurrentParentChild(plan["prover"], plan["verifier"])
            result = execute(plan, paths, child)
            self.assertGreaterEqual(child.max_active_parents, 2)
            parents = [record for record in result["records"] if record["level"] > 0]
            self.assertEqual(
                [(record["level"], record["node_index"]) for record in parents],
                sorted((record["level"], record["node_index"]) for record in parents),
            )

    def test_210_real_segments_materialize_exact_binary_temporal_topology(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            plan, paths = build_plan(Path(raw), segment_count=210)
            self.assertEqual(plan["node_counts"], [256, 128, 64, 32, 16, 8, 4, 2, 1])
            self.assertEqual(plan["real_segment_count"], 210)
            self.assertEqual(plan["padded_leaf_count"], 256)
            self.assertEqual(plan["empty_leaf_count"], 46)
            child = FakeChild(plan["prover"], plan["verifier"])
            summary = execute(plan, paths, child)
            self.assertEqual(len(summary["records"]), 511)
            self.assertEqual(len(summary["checkpoints"]), 9)
            self.assertEqual(len(child.calls), 210 + 255)
            self.assertEqual(child.leaf_stream_sessions, 1)
            self.assertEqual(sum(call.startswith("segment-") for call in child.calls), 210)
            self.assertEqual(sum(call.startswith("level-") for call in child.calls), 255)
            self.assertFalse(any(call.startswith("empty-leaf-") for call in child.calls))
            self.assertEqual(summary["records"][-1]["scope"], "final_root")
            self.assertEqual(
                summary["result"]["systems"]["stwo"]["proof_custody"]["proof_counts"],
                {
                    "real_leaf_proofs": 210,
                    "proofless_empty_authorities": 46,
                    "recursive_parent_proofs": 254,
                    "total_proofs": 464,
                },
            )

    def test_normal_run_is_breadth_first_and_resume_never_reruns_committed_work(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            plan, paths = build_plan(Path(raw))
            child = FakeChild(plan["prover"], plan["verifier"])
            first = execute(plan, paths, child)
            self.assertEqual(child.calls, [
                "segment-000000", "segment-000001", "segment-000002",
                "segment-000003", "segment-000004", "segment-000005",
                "level-0001-node-000000", "level-0001-node-000001",
                "level-0001-node-000002", "level-0001-node-000003",
                "level-0002-node-000000", "level-0002-node-000001",
                "level-0003-node-000000",
            ])
            self.assertEqual(len(first["records"]), 15)
            self.assertEqual(len(first["checkpoints"]), 4)
            result = first["result"]
            stwo = result["systems"]["stwo"]
            self.assertEqual(stwo["status"], "incomplete")
            self.assertEqual(stwo["proof_custody"]["scope"], "parent")
            self.assertIsNone(stwo["proof_custody"]["final_root"])
            self.assertTrue(all(value is None for value in stwo["security"].values()))
            self.assertEqual(stwo["proof_custody"]["covered_segments"], list(range(6)))
            self.assertEqual(stwo["proof_custody"]["topology"]["node_counts"], [8, 4, 2, 1])
            self.assertEqual(stwo["proof_custody"]["topology"]["padded_leaf_count"], 8)
            self.assertEqual(stwo["proof_custody"]["topology"]["empty_leaf_count"], 2)
            self.assertEqual(stwo["proof_custody"]["proof_counts"], {
                "real_leaf_proofs": 6,
                "proofless_empty_authorities": 2,
                "recursive_parent_proofs": 6,
                "total_proofs": 12,
            })
            self.assertEqual(first["records"][6]["covered_segments"], [])
            self.assertNotIn("proof_artifact", first["records"][6])
            self.assertFalse(result["comparison_ready"])
            self.assertFalse(first["manifest"]["production_admissible"])
            self.assertFalse(first["manifest"]["proof_complete"])
            self.assertFalse(first["manifest"]["security_complete"])
            self.assertNotIn("root_proof", first["manifest"])
            manifest_bytes = (paths["run_root"] / "topology-test.json").read_bytes()
            (paths["run_root"] / ".staging/orphaned-link-source.tmp").write_bytes(
                b"non-authoritative-staging-residue",
            )
            second = execute(plan, paths, child)
            self.assertEqual(len(child.calls), 13)
            self.assertEqual(second["manifest"], first["manifest"])
            self.assertEqual((paths["run_root"] / "topology-test.json").read_bytes(),
                             manifest_bytes)
            journals = sorted(paths["run_root"].glob("**/publication.ndjson"))
            self.assertEqual(len(journals), 15)
            self.assertTrue(all(len(path.read_text().splitlines()) == 4 for path in journals))

    def test_recovered_pending_proof_intent_is_sealed_and_retried_in_new_attempt(self) -> None:
        for event, expected_calls in (
            ("after_intent", 0),
            ("after_child", 1),
            ("after_proof", 1),
            ("after_receipt", 1),
        ):
            with self.subTest(event=event), tempfile.TemporaryDirectory() as raw:
                plan, paths = build_plan(Path(raw))
                child = FakeChild(plan["prover"], plan["verifier"])
                with self.assertRaises(SimulatedCrash):
                    execute(plan, paths, child, CrashOnce(event))
                self.assertEqual(len(child.calls), expected_calls)
                summary = execute(plan, paths, child)
                self.assertEqual(len(child.calls), expected_calls + 13)
                attempts = summary["records"][0]["proof_artifact"]["attempts"]
                self.assertEqual(attempts["total_attempt_count"], 2)
                self.assertEqual(attempts["successful_attempt_index"], 1)
                self.assertEqual(attempts["indeterminate_attempt_count"], 1)
                self.assertFalse(attempts["performance_claim_eligible"])
                stwo = summary["result"]["systems"]["stwo"]
                self.assertIsNone(stwo["timings"]["proving"])
                self.assertIsNone(stwo["timings"]["verification"])

    def test_proofless_empty_intent_and_prepared_cuts_resume_without_child_launch(
        self,
    ) -> None:
        for event in ("after_intent", "after_authority", "after_prepared", "after_committed"):
            with self.subTest(event=event), tempfile.TemporaryDirectory() as raw:
                plan, paths = build_plan(Path(raw))
                child = FakeChild(plan["prover"], plan["verifier"])
                fault = CrashTaskOnce(event, "empty-leaf-000006")
                with self.assertRaises(SimulatedCrash):
                    execute(plan, paths, child, fault)
                self.assertEqual(child.calls, [
                    "segment-000000", "segment-000001", "segment-000002",
                    "segment-000003", "segment-000004", "segment-000005",
                ])
                summary = execute(plan, paths, child)
                self.assertEqual(len(child.calls), 13)
                empty = summary["records"][6]
                self.assertEqual(empty["record_kind"], "canonical_empty")
                self.assertFalse(empty["empty_authority"]["proof_present"])
                self.assertEqual(set(empty["files"]), {"authority"})
                journal = (
                    paths["run_root"]
                    / "leaves/empty-leaf-000006/publication.ndjson"
                )
                self.assertEqual(len(journal.read_text().splitlines()), 4)

    def test_prepared_and_committed_crash_cuts_resume_without_duplicate_child(self) -> None:
        for event in ("after_prepared", "after_committed"):
            with self.subTest(event=event), tempfile.TemporaryDirectory() as raw:
                plan, paths = build_plan(Path(raw))
                child = FakeChild(plan["prover"], plan["verifier"])
                with self.assertRaises(SimulatedCrash):
                    execute(plan, paths, child, CrashOnce(event))
                self.assertEqual(child.calls, ["segment-000000"])
                summary = execute(plan, paths, child)
                self.assertEqual(len(child.calls), 13)
                self.assertEqual(summary["manifest"]["result_schema"],
                                 protocol.benchmark.RESULT_SCHEMA)

    def test_level_and_finalization_crash_cuts_are_byte_idempotent(self) -> None:
        for event, first_calls in (
            ("after_checkpoint", 6),
            ("after_result", 13),
            ("after_final_manifest", 13),
        ):
            with self.subTest(event=event), tempfile.TemporaryDirectory() as raw:
                plan, paths = build_plan(Path(raw))
                child = FakeChild(plan["prover"], plan["verifier"])
                with self.assertRaises(SimulatedCrash):
                    execute(plan, paths, child, CrashOnce(event))
                self.assertEqual(len(child.calls), first_calls)
                summary = execute(plan, paths, child)
                self.assertEqual(len(child.calls), 13)
                self.assertEqual(summary["manifest"]["comparison_ready"], False)

    def test_near_root_launch_crash_preserves_prefix_and_retries_only_root(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            plan, paths = build_plan(Path(raw))
            child = FakeChild(plan["prover"], plan["verifier"])
            fault = CrashTaskOnce("after_child", "level-0003-node-000000")
            with self.assertRaises(SimulatedCrash):
                execute(plan, paths, child, fault)
            self.assertEqual(child.calls[-1], "level-0003-node-000000")
            preserved_paths = sorted(
                path for path in paths["run_root"].glob("**/*")
                if path.is_file() and "level-0003" not in path.as_posix()
            )
            preserved = {path: path.read_bytes() for path in preserved_paths}
            summary = execute(plan, paths, child)
            self.assertEqual(child.calls[-2:], [
                "level-0003-node-000000", "level-0003-node-000000",
            ])
            self.assertEqual(len(child.calls), 14)
            for path, raw_bytes in preserved.items():
                self.assertEqual(path.read_bytes(), raw_bytes)
            root_attempts = summary["records"][-1]["proof_artifact"]["attempts"]
            self.assertEqual(root_attempts["total_attempt_count"], 2)
            self.assertEqual(root_attempts["indeterminate_attempt_count"], 1)
            self.assertFalse(root_attempts["performance_claim_eligible"])

    def test_retained_artifact_checkpoint_source_and_plan_mutations_reject(self) -> None:
        mutators = (
            ("proof", lambda paths, plan: (
                paths["run_root"]
                / "leaves/segment-000000/attempts/attempt-000000/proof.bin"
            ).write_bytes(b"mutated-proof")),
            ("receipt symlink", self._replace_receipt_with_symlink),
            ("journal symlink", self._replace_journal_with_symlink),
            ("empty authority", lambda paths, plan: (
                paths["run_root"] / "leaves/empty-leaf-000006/empty-authority.json"
            ).write_bytes(b"{}\n")),
            ("empty authority symlink", self._replace_empty_authority_with_symlink),
            ("checkpoint", lambda paths, plan: (
                paths["run_root"] / "checkpoints/level-0000.json"
            ).write_bytes(b"{}\n")),
            ("final result", lambda paths, plan: (
                paths["run_root"] / "final-result.json"
            ).write_bytes(b"{}\n")),
            ("final manifest", lambda paths, plan: (
                paths["run_root"] / "topology-test.json"
            ).write_bytes(b"{}\n")),
            ("source", lambda paths, plan: (
                paths["segment_root"] / "segment-000000.bin"
            ).write_bytes(b"mutated-source")),
            ("leaf stream source", lambda paths, plan: (
                paths["segment_root"] / "leaf-stream-request.json"
            ).write_bytes(b"{}\n")),
        )
        for name, mutate in mutators:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as raw:
                plan, paths = build_plan(Path(raw))
                child = FakeChild(plan["prover"], plan["verifier"])
                execute(plan, paths, child)
                mutate(paths, plan)
                with self.assertRaises(protocol.ProofProtocolError):
                    execute(plan, paths, child)
                self.assertEqual(len(child.calls), 13)

        with tempfile.TemporaryDirectory() as raw:
            plan, paths = build_plan(Path(raw))
            child = FakeChild(plan["prover"], plan["verifier"])
            execute(plan, paths, child)
            changed = copy.deepcopy(plan)
            changed["expected_statements"][0]["recursive_statement_sha256"] = digest(
                "changed"
            )
            changed = protocol.seal({key: value for key, value in changed.items()
                                     if key != "content_sha256"})
            with self.assertRaises(protocol.ProofProtocolError):
                execute(changed, paths, child)
            self.assertEqual(len(child.calls), 13)

    def test_resealed_prepared_record_mutations_still_reject_exact_authorities(self) -> None:
        mutations = (
            lambda record: record.update({"covered_segments": [1]}),
            lambda record: record["proof_artifact"].update(
                {"statement_sha256": digest("wrong-statement")},
            ),
            lambda record: record["proof_artifact"]["verifier"].update(
                {"sha256": digest("wrong-verifier")},
            ),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate), tempfile.TemporaryDirectory() as raw:
                plan, paths = build_plan(Path(raw))
                child = FakeChild(plan["prover"], plan["verifier"])
                with self.assertRaises(SimulatedCrash):
                    execute(plan, paths, child, CrashOnce("after_prepared"))
                journal = paths["run_root"] / "leaves/segment-000000/publication.ndjson"
                records = [json.loads(line) for line in journal.read_text().splitlines()]
                prepared = records[2]
                mutate(prepared["task_record"])
                prepared["task_record"]["content_sha256"] = protocol.content_sha256(
                    prepared["task_record"],
                )
                prepared["task_record_sha256"] = prepared["task_record"]["content_sha256"]
                prepared["content_sha256"] = protocol.content_sha256(prepared)
                journal.write_bytes(
                    b"".join(protocol.canonical_bytes(record) for record in records),
                )
                with self.assertRaises(protocol.ProofProtocolError):
                    execute(plan, paths, child)
                self.assertEqual(child.calls, ["segment-000000"])

    def test_resealed_child_kind_and_authority_path_mutations_reject(self) -> None:
        cases = (
            (
                "child kind",
                "levels/level-0001/node-000003/publication.ndjson",
                lambda record: record["children"][1].update(
                    {"kind": "verified_real_leaf"},
                ),
            ),
            (
                "empty authority path",
                "leaves/empty-leaf-000006/publication.ndjson",
                lambda record: record["files"]["authority"].update(
                    {"path": "different-authority.json"},
                ),
            ),
        )
        for name, relative, mutate in cases:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as raw:
                plan, paths = build_plan(Path(raw))
                child = FakeChild(plan["prover"], plan["verifier"])
                execute(plan, paths, child)
                journal = paths["run_root"] / relative
                records = [json.loads(line) for line in journal.read_text().splitlines()]
                mutate(records[2]["task_record"])
                self._reseal_prepared_journal(records)
                journal.write_bytes(
                    b"".join(protocol.canonical_bytes(record) for record in records),
                )
                with self.assertRaises(protocol.ProofProtocolError):
                    execute(plan, paths, child)
                self.assertEqual(len(child.calls), 13)

    def test_plan_segment_index_and_executable_identities_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            plan, paths = build_plan(Path(raw))
            changed = copy.deepcopy(plan)
            changed["segments"][0]["segment_index"] = 1
            changed = protocol.seal({key: value for key, value in changed.items()
                                     if key != "content_sha256"})
            with self.assertRaisesRegex(protocol.ProofProtocolError, "segment order"):
                protocol.validate_plan(changed)

            child = FakeChild(plan["prover"], plan["verifier"])
            paths["verifier"].write_bytes(b"different-verifier")
            with self.assertRaisesRegex(protocol.ProofProtocolError, "identity differs"):
                execute(plan, paths, child)
            self.assertEqual(child.calls, [])

    def test_binary_padding_rejects_ragged_parents_holes_and_nontrailing_empty_leaves(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            plan, paths = build_plan(Path(raw))
            self.assertEqual(plan["real_segment_count"], 6)
            self.assertEqual(plan["slot_capacity"], 8)
            self.assertEqual(plan["padded_leaf_count"], 8)
            self.assertEqual(plan["empty_leaf_count"], 2)
            self.assertEqual(plan["node_counts"], [8, 4, 2, 1])
            padding = protocol.task_request(plan, 0, 6, [])
            self.assertEqual(padding["task_id"], "empty-leaf-000006")
            self.assertEqual(padding["task_kind"], "canonical_empty_authority")
            self.assertEqual(padding["covered_segments"], [])
            self.assertIsNone(padding["source_segment"])

            child = FakeChild(plan["prover"], plan["verifier"])
            summary = execute(plan, paths, child)
            with self.assertRaisesRegex(protocol.ProofProtocolError, "children differ"):
                protocol.task_request(plan, 1, 3, [summary["records"][6]])

            ragged = copy.deepcopy(plan)
            ragged["node_counts"] = [7, 4, 2, 1]
            ragged["slot_capacity"] = 7
            ragged["padded_leaf_count"] = 7
            ragged["empty_leaf_count"] = 1
            ragged = protocol.seal({
                key: value for key, value in ragged.items() if key != "content_sha256"
            })
            with self.assertRaisesRegex(protocol.ProofProtocolError, "node counts"):
                protocol.validate_plan(ragged)

            hole = copy.deepcopy(plan)
            hole["segments"][1]["segment_index"] = 2
            hole = protocol.seal({
                key: value for key, value in hole.items() if key != "content_sha256"
            })
            with self.assertRaisesRegex(protocol.ProofProtocolError, "segment order"):
                protocol.validate_plan(hole)

            empty_before_real = copy.deepcopy(plan)
            empty_before_real["segments"][1]["source"] = None
            empty_before_real = protocol.seal({
                key: value for key, value in empty_before_real.items()
                if key != "content_sha256"
            })
            with self.assertRaises(protocol.ProofProtocolError):
                protocol.validate_plan(empty_before_real)

            forged_empty = protocol.empty_authority(plan, padding)
            forged_empty["node_index"] = 5
            with self.assertRaisesRegex(protocol.ProofProtocolError, "authority differs"):
                protocol.validate_empty_authority(forged_empty, plan, padding)

    def test_invalid_child_receipt_fails_before_artifact_publication(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            plan, paths = build_plan(Path(raw))
            child = FakeChild(plan["prover"], plan["verifier"])
            child.mutate_receipt = True
            with self.assertRaisesRegex(protocol.ProofProtocolError,
                                        "verifier receipt differs"):
                execute(plan, paths, child)
            task = paths["run_root"] / "leaves/segment-000000"
            attempt = task / "attempts/attempt-000000"
            self.assertFalse((attempt / "proof.bin").exists())
            self.assertFalse((attempt / "verify-receipt.json").exists())
            child.mutate_receipt = False
            summary = execute(plan, paths, child)
            self.assertEqual(len(child.calls), 14)
            self.assertEqual(
                summary["records"][0]["proof_artifact"]["attempts"][
                    "failed_attempt_count"
                ],
                1,
            )
            self.assertEqual(
                summary["records"][0]["proof_artifact"]["attempts"][
                    "indeterminate_attempt_count"
                ],
                0,
            )

    @staticmethod
    def _replace_receipt_with_symlink(paths: dict, _: dict) -> None:
        receipt = (
            paths["run_root"]
            / "leaves/segment-000000/attempts/attempt-000000/verify-receipt.json"
        )
        target = paths["run_root"] / "final-result.json"
        receipt.unlink()
        receipt.symlink_to(target)

    @staticmethod
    def _reseal_prepared_journal(records: list[dict]) -> None:
        task_record = records[2]["task_record"]
        task_record["content_sha256"] = protocol.content_sha256(task_record)
        records[2]["task_record_sha256"] = task_record["content_sha256"]
        records[2]["content_sha256"] = protocol.content_sha256(records[2])
        records[3]["task_record_sha256"] = task_record["content_sha256"]
        records[3]["content_sha256"] = protocol.content_sha256(records[3])

    @staticmethod
    def _replace_journal_with_symlink(paths: dict, _: dict) -> None:
        journal = paths["run_root"] / "leaves/segment-000000/publication.ndjson"
        target = paths["run_root"] / "final-result.json"
        journal.unlink()
        journal.symlink_to(target)

    @staticmethod
    def _replace_empty_authority_with_symlink(paths: dict, _: dict) -> None:
        authority = (
            paths["run_root"] / "leaves/empty-leaf-000006/empty-authority.json"
        )
        target = paths["run_root"] / "final-result.json"
        authority.unlink()
        authority.symlink_to(target)


if __name__ == "__main__":
    unittest.main()
