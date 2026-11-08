from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path

from scripts.bench.performance_epoch_gate_lib import EvidenceError, validate_receipt
from scripts.bench.performance_epoch_gate_lib.capture import ExecutionResult, HostCaptureController
from scripts.bench.performance_epoch_gate_lib.builds import build_budget_pass
from scripts.bench.performance_epoch_gate_lib.codec import atomic_write, canonical_bytes, content_digest, sha256_bytes
from scripts.bench.performance_epoch_gate_lib.model import DEFAULT_PROTOCOL, ROOT
from scripts.bench.performance_epoch_gate_lib.plan import build_plan, validate_plan
from scripts.bench.performance_epoch_gate_lib.performance import performance_budget_pass
from scripts.bench.performance_epoch_gate_lib.policy import load_protocol
from scripts.tests.performance_epoch_fixture import Fixture


class FakeExecutor:
    def run(self, command, artifact_path, timeout_seconds):
        return ExecutionResult(0, b"out", b"", 0.1, 100)


class PerformanceEpochPlanAndCaptureTests(unittest.TestCase):
    def setUp(self):
        self.protocol, self.digest = load_protocol(ROOT, DEFAULT_PROTOCOL)

    def test_protocol_keeps_frozen_statistical_authority(self):
        self.assertEqual(4000, self.protocol["statistics"]["bootstrap_iterations"])
        self.assertEqual(0.97, self.protocol["budgets"]["minimum_throughput_ci_lower"])
        self.assertEqual("stwo-native-cpu", self.protocol["build_comparisons"][0]["candidate_step"])

    def test_numeric_and_semantic_budgets_are_exact(self):
        self.assertTrue(performance_budget_pass(self.protocol, 0.97, 1.05))
        self.assertFalse(performance_budget_pass(self.protocol, 0.969999, 1.0))
        self.assertFalse(performance_budget_pass(self.protocol, 1.0, 1.050001))
        spec = next(item for item in self.protocol["build_comparisons"] if item["id"] == "linux-riscv-cpu-static")
        self.assertTrue(build_budget_pass(
            self.protocol, spec, baseline_cold_seconds=60.0,
            candidate_cold_seconds=60.0, candidate_warm_seconds=2.0,
            candidate_link_entries=[],
        ))
        self.assertFalse(build_budget_pass(
            self.protocol, spec, baseline_cold_seconds=60.0,
            candidate_cold_seconds=60.001, candidate_warm_seconds=2.0,
            candidate_link_entries=[],
        ))
        self.assertFalse(build_budget_pass(
            self.protocol, spec, baseline_cold_seconds=60.0,
            candidate_cold_seconds=60.0, candidate_warm_seconds=2.0,
            candidate_link_entries=["PT_INTERP"],
        ))

    def test_plan_is_repository_derived_and_arm_roles_are_fixed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {key: str(root / key) for key in (
                "baseline_root", "candidate_root", "bundle_root", "baseline_local_cache",
                "baseline_global_cache", "candidate_local_cache", "candidate_global_cache",
            )}
            plan = build_plan(
                protocol=self.protocol, protocol_sha256=self.digest, host_role="linux",
                session_nonce="1" * 64, candidate_commit="a" * 40,
                candidate_tree="b" * 40, paths=paths,
            )
            validate_plan(plan, self.protocol, self.digest)
            changed = copy.deepcopy(plan)
            changed["sources"]["baseline"], changed["sources"]["candidate"] = (
                changed["sources"]["candidate"], changed["sources"]["baseline"],
            )
            changed["content_sha256"] = content_digest(changed)
            with self.assertRaises(EvidenceError):
                validate_plan(changed, self.protocol, self.digest)

    def test_capture_controller_appends_chain_and_seals_raw_ledger(self):
        with tempfile.TemporaryDirectory() as directory:
            fixture = Fixture(Path(directory), self.protocol, self.digest)
            plan = fixture.plans["linux"]
            staging = Path(directory) / "capture"
            controller = HostCaptureController(
                plan=plan, plan_sha256=fixture.plan_digests["linux"],
                staging_root=staging, executor=FakeExecutor(), timeout_seconds=1,
            )
            command = plan["commands"][0]
            controller.run_attempt({
                "command_id": command["id"], "stage": command["phase"],
                "workload_id": None, "round_index": None, "order_position": None,
            })
            captured = controller.seal()
            self.assertEqual(1, captured.attempt_count)
            self.assertEqual(
                captured.attempts[0]["attempt_sha256"], captured.terminal_attempt_sha256,
            )
            journal = next(item for item in captured.artifacts if item["id"] == captured.attempt_journal_artifact)
            self.assertEqual(canonical_bytes(captured.attempts[0]), (staging / journal["path"]).read_bytes())


class PerformanceEpochReceiptTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        protocol, digest = load_protocol(ROOT, DEFAULT_PROTOCOL)
        self.fixture = Fixture(self.root, protocol, digest)
        self.receipt, self.path = self.fixture.build()

    def tearDown(self):
        self.temporary.cleanup()

    def validate(self, receipt=None, trusted=None):
        value = self.receipt if receipt is None else receipt
        path = self.path
        if receipt is not None:
            path = self.root / "mutated.json"
            atomic_write(path, value, replace=True)
        return validate_receipt(
            value, receipt_path=path, root=ROOT, protocol=self.fixture.protocol,
            protocol_sha256=self.fixture.protocol_sha256, plans=self.fixture.plans,
            plan_digests=self.fixture.plan_digests, raw_root=self.fixture.raw,
            trusted_attestations=trusted or self.fixture.trusted,
        )

    def mutate(self, update):
        value = copy.deepcopy(self.receipt)
        update(value)
        value["content_sha256"] = content_digest(value)
        return value

    def test_valid_receipt_exports_architecture_binding(self):
        result = self.validate()
        self.assertEqual("PASS", result.verdict)
        self.assertEqual(self.fixture.candidate_commit, result.architecture_binding()["candidate_commit"])

    def test_source_commit_and_tree_substitution_fail(self):
        for arm in ("baseline", "candidate"):
            for field in ("commit", "tree"):
                with self.subTest(arm=arm, field=field):
                    changed = self.mutate(
                        lambda value, selected_arm=arm, selected_field=field:
                        value["sources"][selected_arm].__setitem__(selected_field, "d" * 40)
                    )
                    with self.assertRaises(EvidenceError):
                        self.validate(changed)

    def test_swapping_arms_after_results_fails(self):
        def update(value):
            paired = value["performance_rows"][0]["rounds"][0]
            paired["baseline"], paired["candidate"] = paired["candidate"], paired["baseline"]
        with self.assertRaises(EvidenceError):
            self.validate(self.mutate(update))

    def test_deleted_or_reordered_round_fails(self):
        for update in (
            lambda value: value["performance_rows"][0]["rounds"].pop(),
            lambda value: value["performance_rows"][0]["rounds"].reverse(),
        ):
            with self.assertRaises(EvidenceError):
                self.validate(self.mutate(update))

    def test_workload_or_numerator_mutation_fails(self):
        for update in (
            lambda value: value["performance_rows"][0]["workload"]["parameters"].__setitem__("log_n_rows", 9),
            lambda value: value["performance_rows"][0]["numerator"].__setitem__("units", 1),
        ):
            with self.assertRaises(EvidenceError):
                self.validate(self.mutate(update))

    def test_raw_proof_verifier_executable_and_timing_digest_mutations_fail(self):
        kinds = ("proof", "verifier", "executable", "timing")
        for kind in kinds:
            with self.subTest(kind=kind):
                def update(value, selected=kind):
                    artifact = next(item for item in value["raw_bundle"]["artifacts"] if item["kind"] == selected)
                    artifact["sha256"] = "e" * 64
                    value["raw_bundle"]["content_sha256"] = content_digest(value["raw_bundle"])
                with self.assertRaises(EvidenceError):
                    self.validate(self.mutate(update))

    def test_host_sdk_metal_runtime_and_trusted_bundle_substitution_fail(self):
        updates = (
            lambda value: value["sessions"]["macos"]["host"].__setitem__("runner_id", "forged"),
            lambda value: value["sessions"]["macos"]["host"].__setitem__("sdk", "forged"),
            lambda value: value["sessions"]["macos"]["host"].__setitem__("metal_runtime", "forged"),
            lambda value: value["riscv_challenge"]["trusted_bundle_identity"].__setitem__("commit", "e" * 40),
        )
        for update in updates:
            with self.assertRaises(EvidenceError):
                self.validate(self.mutate(update))

    def test_cpu_fallback_cannot_be_relabelled_as_metal_dispatch(self):
        def update(value):
            sample = value["performance_rows"][6]["rounds"][0]["baseline"][0]
            sample["metal_fallback_count"] = 0
            sample["metal_device_dispatches"] += 1
        with self.assertRaises(EvidenceError):
            self.validate(self.mutate(update))

    def test_comparator_source_and_policy_mutations_fail(self):
        for update in (
            lambda value: value["authority"].__setitem__("stats_sha256", "e" * 64),
            lambda value: value.__setitem__("protocol_sha256", "e" * 64),
        ):
            with self.assertRaises(EvidenceError):
                self.validate(self.mutate(update))

    def test_failed_attempt_omission_fails_external_terminal_binding(self):
        # Delete the retained terminal infrastructure failure and recompute every
        # unkeyed receipt, bundle, ledger, journal, chain, and embedded-attestation digest.
        changed = copy.deepcopy(self.receipt)
        removed = changed["attempts"]["linux"].pop()
        self.assertEqual("infrastructure_failure", removed["status"])
        session = changed["sessions"]["linux"]
        remaining = changed["attempts"]["linux"]
        for field, kind, content in (
            ("attempt_ledger_artifact", "attempt-ledger", canonical_bytes({
                "schema": "build-monorepo-performance-attempt-ledger-v1", "attempts": remaining,
            })),
            ("attempt_journal_artifact", "attempt-journal", b"".join(canonical_bytes(item) for item in remaining)),
        ):
            identifier = session[field]
            artifact = next(item for item in changed["raw_bundle"]["artifacts"] if item["id"] == identifier)
            path = self.fixture.raw / artifact["path"]
            path.write_bytes(content)
            artifact["sha256"] = sha256_bytes(content)
            artifact["bytes"] = len(content)
        attestation = changed["sessions"]["linux"]["producer_attestation"]
        attestation["attempt_count"] = len(remaining)
        attestation["terminal_attempt_sha256"] = remaining[-1]["attempt_sha256"]
        changed["raw_bundle"]["content_sha256"] = content_digest(changed["raw_bundle"])
        for role in ("linux", "macos"):
            role_attestation = changed["sessions"][role]["producer_attestation"]
            role_attestation["raw_bundle_sha256"] = changed["raw_bundle"]["content_sha256"]
            role_attestation["attestation_sha256"] = sha256_bytes(canonical_bytes({
                key: item for key, item in role_attestation.items() if key != "attestation_sha256"
            }))
        changed["content_sha256"] = content_digest(changed)
        with self.assertRaises(EvidenceError):
            self.validate(changed)

    def test_nonfinite_and_duplicate_json_fail_closed(self):
        raw = self.path.read_text()
        duplicate = self.root / "duplicate.json"
        duplicate.write_text(raw.replace('{"aot_checks"', '{"schema":"duplicate","aot_checks"', 1))
        nonfinite = self.root / "nonfinite.json"
        nonfinite.write_text(raw.replace('"created_at_unix":1800000000', '"created_at_unix":NaN'))
        from scripts.bench.performance_epoch_gate_lib.codec import strict_json
        with self.assertRaises(EvidenceError):
            strict_json(duplicate, 20_000_000)
        with self.assertRaises(EvidenceError):
            strict_json(nonfinite, 20_000_000)


if __name__ == "__main__":
    unittest.main()
