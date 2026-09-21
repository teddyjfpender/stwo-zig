"""Controller custody tests; actual proof acceptance uses the retained bundle gate."""
from __future__ import annotations

import hashlib
from contextlib import nullcontext
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts import ethereum_full_leaf_bundle_producer as subject
from scripts import ethereum_block_proof_protocol as protocol


class SerialBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for name in ("prover", "verifier", "materialization"):
            (self.root / name).write_bytes(name.encode())
        (self.root / "publication").mkdir()
        self.options = dict(prover=self.root / "prover", verifier=self.root / "verifier",
                            materialization_path=self.root / "materialization",
                            publication_root=self.root / "publication", output=self.root / "output",
                            workers=1, host_byte_budget=1024, host_byte_limit=2048)
        self.calls = []
        self.lock = patch.object(subject, "build_lock", side_effect=lambda **_: nullcontext())
        self.lock.start()
        self.addCleanup(self.lock.stop)
        self.fail_leaf = None
        self.wrong_receipt = False
        self.change_binary = False
        self.change_aot = False
        self.fail_verification = None
        self.wrong_leaf_receipt = False
        self.admission = patch.object(subject.materialization, "validate_recursive", return_value={"manifest": {"segment_count": 2}})
        self.admission.start()
        self.addCleanup(self.admission.stop)
        self.process = patch.object(subject.subprocess, "run", side_effect=self.child)
        self.process.start()
        self.addCleanup(self.process.stop)

    def child(self, argv, *, stdout, stderr, timeout, check):
        self.calls.append(argv)
        if argv[0] == str(self.options["prover"].resolve()):
            offset = 1 if self.options.get("backend") == "metal" else 2
            options = dict(zip(argv[offset::2], argv[offset + 1::2], strict=True))
            index = int(options["--segment-index"])
            if index == self.fail_leaf:
                return subprocess.CompletedProcess(argv, 1)
            proof = f"mock-worker-artifact-{index}".encode()
            Path(options["--output"]).write_bytes(proof)
            leaf = {"metadata": {"segment_index": index}, "proof_bytes": len(proof),
                    "proof_sha256": list(hashlib.sha256(proof).digest())}
            Path(options["--global-metadata-output"]).write_text(json.dumps(leaf))
            if self.change_binary:
                Path(argv[0]).write_bytes(b"changed executable")
            if self.change_aot:
                (self.options["aot_bundle"] / "stwo_zig_core.metallib").write_bytes(b"changed library")
        elif argv[1] in ("verify-leaf", "verify-leaf-fixed-program-v5"):
            self.assertEqual(len(argv), 8)
            proof = Path(argv[2]).read_bytes()
            metadata = Path(argv[3]).read_bytes()
            leaf = json.loads(metadata)
            index = leaf["metadata"]["segment_index"]
            if index == self.fail_verification:
                return subprocess.CompletedProcess(argv, 1)
            receipt = {"endpoint": "verified_native_selected_leaf", "segment_index": index,
                       "segment_count": 2, "worker_count": int(argv[7]),
                       "proof_bytes": len(proof), "proof_sha256": list(hashlib.sha256(proof).digest()),
                       "metadata_file_sha256": list(hashlib.sha256(metadata).digest()),
                       "materialization_sha256": [0] * 32 if self.wrong_leaf_receipt else list(bytes.fromhex(argv[5])),
                       "retained_admission_destroyed_before_proof": True}
            if argv[1] == "verify-leaf-fixed-program-v5":
                receipt = {"endpoint": "verified_native_selected_leaf_fixed_program_v5", "verification": receipt}
            stdout.write(json.dumps(receipt).encode())
        else:
            if argv[1] == "verify-bundle-fixed-program-v5":
                argv = [argv[0], *argv[2:]]
            self.assertEqual(len(argv), 7)
            self.assertEqual(argv[5:], ["--workers", str(self.options["workers"])])
            self.assertEqual(argv[3], str(self.options["materialization_path"].resolve()))
            self.assertEqual(argv[4], hashlib.sha256(b"materialization").hexdigest())
            receipt = {"endpoint": "verified_native_full_leaf_bundle", "leaf_count": 2, "worker_count": self.options["workers"],
                       "manifest_sha256": list(bytes.fromhex(argv[2])),
                       "materialization_sha256": [0] * 32 if self.wrong_receipt else list(bytes.fromhex(argv[4]))}
            stdout.write(json.dumps(receipt).encode())
        return subprocess.CompletedProcess(argv, 0)

    def worker_calls(self):
        return [call for call in self.calls if call[0] == str(self.options["prover"].resolve())]

    def test_shared_leaf_receipt_check_rejects_campaign_binding_mutations(self):
        self.options["claim_admission"] = "fixed_program_narrow_v5"
        subject.run(**self.options)
        output = self.options["output"]
        plan = json.loads((output / "plan.json").read_bytes())
        attempt = next((output / "attempts").glob("verify-leaf-000000-*"))
        metadata_path = Path(json.loads((attempt / "request.json").read_bytes())["argv"][3])
        leaf = json.loads(metadata_path.read_bytes())
        receipt = json.loads((attempt / "stdout.json").read_bytes())
        subject.validate_leaf_receipt(receipt, 0, leaf, metadata_path, plan)
        for changed in ({**leaf, "unverified": True},
                        {**leaf, "metadata": {"segment_index": False}},
                        {**leaf, "metadata": {"segment_index": 0.0}}):
            with self.subTest(leaf=changed):
                with self.assertRaisesRegex(ValueError, "published leaf differs"):
                    subject.validate_leaf_receipt(receipt, 0, changed, metadata_path, plan)
        mutations = {
            "endpoint": "wrong", "segment_index": 1, "segment_count": 3,
            "worker_count": 2, "proof_bytes": leaf["proof_bytes"] + 1,
            "proof_sha256": [0] * 32, "metadata_file_sha256": [0] * 32,
            "materialization_sha256": [0] * 32,
            "retained_admission_destroyed_before_proof": False,
        }
        for field, value in mutations.items():
            with self.subTest(field=field):
                changed = {**receipt, "verification": {**receipt["verification"], field: value}}
                with self.assertRaisesRegex(ValueError, "receipt differs"):
                    subject.validate_leaf_receipt(changed, 0, leaf, metadata_path, plan)
        with self.assertRaisesRegex(ValueError, "wrong profile endpoint"):
            subject.validate_leaf_receipt({**receipt, "endpoint": "wrong"}, 0, leaf, metadata_path, plan)

    def test_opt_in_bounds_only_leaf_verification_and_preserves_campaign_plan(self):
        self.options["claim_admission"] = "fixed_program_narrow_v5"
        subject.run(**self.options)
        plan_before = (self.options["output"] / "plan.json").read_bytes()
        self.calls.clear()
        self.options["verification_policy"] = self.root / "schedule.json"
        self.options["verification_policy_sha256"] = "a" * 64
        policy = {"verifier": {"path": str(self.options["verifier"].resolve())},
                  "materialization": {"path": str(self.options["materialization_path"].resolve())}}

        def bounded(argv, policy, *, stdout, stderr, timeout, observation):
            self.assertEqual(argv[1], "verify-leaf-fixed-program-v5")
            observation["resource_envelope_passed"] = True
            return self.child(argv, stdout=stdout, stderr=stderr, timeout=timeout, check=False)

        with patch.object(subject.bounded_verifier, "load_policy", return_value=policy), \
                patch.object(subject.bounded_verifier, "run", side_effect=bounded) as lane:
            subject.run(**self.options)
        self.assertEqual(lane.call_count, 2)
        self.assertEqual(len(self.worker_calls()), 0)
        self.assertEqual(plan_before, (self.options["output"] / "plan.json").read_bytes())
        self.assertEqual(self.calls[-1][1], "verify-bundle-fixed-program-v5")
        observations = list((self.options["output"] / "attempts").glob("verify-leaf-*/scheduling.json"))
        self.assertEqual(len(observations), 2)
        self.assertTrue(all(json.loads(path.read_text())["resource_envelope_passed"] for path in observations))

    def test_opt_in_new_leaves_use_bounded_lane_but_bundle_and_producers_keep_lock(self):
        self.options.update(claim_admission="fixed_program_narrow_v5", verification_policy=self.root / "schedule.json",
                            verification_policy_sha256="a" * 64)
        policy = {"verifier": {"path": str(self.options["verifier"].resolve())},
                  "materialization": {"path": str(self.options["materialization_path"].resolve())}}

        def bounded(argv, policy, *, stdout, stderr, timeout, observation):
            observation["resource_envelope_passed"] = True
            return self.child(argv, stdout=stdout, stderr=stderr, timeout=timeout, check=False)

        with patch.object(subject.bounded_verifier, "load_policy", return_value=policy), \
                patch.object(subject.bounded_verifier, "run", side_effect=bounded) as lane, \
                patch.object(subject, "build_lock", side_effect=lambda **_: nullcontext()) as heavy:
            subject.run(**self.options)
        self.assertEqual(lane.call_count, 2)
        self.assertEqual([call.kwargs["label"] for call in heavy.call_args_list],
                         ["ethereum leaf 0", "ethereum leaf 1", "ethereum verify bundle"])

    def test_proof_changed_after_verifier_execution_is_rejected(self):
        original = self.child

        def changed(argv, **kwargs):
            result = original(argv, **kwargs)
            if argv[1] == "verify-leaf":
                Path(argv[2]).write_bytes(b"changed after verification")
            return result

        with patch.object(subject.subprocess, "run", side_effect=changed), self.assertRaises(protocol.ProofProtocolError):
            subject.run(**self.options)
        self.assertFalse((self.options["output"] / "leaf-000000.json").exists())

    def test_bounded_resource_rejection_retains_candidate_for_resume(self):
        self.options.update(claim_admission="fixed_program_narrow_v5", verification_policy=self.root / "schedule.json",
                            verification_policy_sha256="a" * 64)
        policy = {"verifier": {"path": str(self.options["verifier"].resolve())},
                  "materialization": {"path": str(self.options["materialization_path"].resolve())}}
        with patch.object(subject.bounded_verifier, "load_policy", return_value=policy), \
                patch.object(subject.bounded_verifier, "run", side_effect=ValueError("insufficient headroom")):
            with self.assertRaisesRegex(ValueError, "headroom"):
                subject.run(**self.options)
        self.assertTrue((self.options["output"] / "attempts/leaf-000000-0000/proof.bin").exists())
        self.assertFalse((self.options["output"] / "leaf-000000.json").exists())
        del self.options["verification_policy"]
        del self.options["verification_policy_sha256"]
        subject.run(**self.options)
        self.assertEqual(len(self.worker_calls()), 2)

    def test_bounded_lane_needs_policy_pin_profile_and_one_worker(self):
        for changes in ({"verification_policy": self.root / "policy.json"},
                        {"verification_policy_sha256": "a" * 64},
                        {"verification_policy": self.root / "policy.json", "verification_policy_sha256": "a" * 64},
                        {"verification_policy": self.root / "policy.json", "verification_policy_sha256": "a" * 64,
                         "claim_admission": "fixed_program_narrow_v5", "workers": 2}):
            with self.subTest(changes=changes), self.assertRaises(protocol.ProofProtocolError):
                subject.run(**{**self.options, **changes})
        self.assertEqual(self.calls, [])

    def test_resume_skips_production_but_freshly_verifies_every_time(self):
        first = subject.run(**self.options)
        second = subject.run(**self.options)
        self.assertEqual(len(self.worker_calls()), 2)
        self.assertEqual(len(self.calls), 8)
        self.assertEqual(first["receipt"], second["receipt"])
        self.assertEqual(first["leaves_in_flight"], 1)

    def test_failed_leaf_retains_completed_prefix_and_uses_new_attempt(self):
        self.fail_leaf = 1
        with self.assertRaises(protocol.ProofProtocolError):
            subject.run(**self.options)
        self.assertTrue((self.options["output"] / "leaf-000000.json").exists())
        self.assertFalse((self.options["output"] / "leaf-000001.json").exists())
        self.fail_leaf = None
        subject.run(**self.options)
        self.assertEqual(len(self.worker_calls()), 3)
        self.assertIn("leaf-000001-0001", " ".join(self.worker_calls()[-1]))

    def test_selected_leaf_admissions_are_per_index_and_stable_across_retry(self):
        self.options["selected_leaf_admission_root"] = self.root / "selected"
        self.options["pcs_retained_byte_budget"] = 1536
        self.fail_leaf = 1
        with self.assertRaises(protocol.ProofProtocolError):
            subject.run(**self.options)
        self.fail_leaf = None
        subject.run(**self.options)
        self.assertTrue(all(call[call.index("--pcs-retained-byte-budget") + 1] == "1536" for call in self.worker_calls()))
        roots = [call[call.index("--selected-leaf-admission-root") + 1]
                 for call in self.worker_calls()]
        self.assertEqual(roots, [str((self.root / "selected" / "leaf-000000").resolve()),
                                 str((self.root / "selected" / "leaf-000001").resolve()),
                                 str((self.root / "selected" / "leaf-000001").resolve())])
        self.calls.clear()
        self.options["selected_leaf_admission_root"] = self.root / "different"
        with self.assertRaises(protocol.ProofProtocolError):
            subject.run(**self.options)
        self.assertEqual(self.calls, [])

    def test_sealed_campaign_default_does_not_select_leaf_admission(self):
        subject.run(**self.options)
        self.assertTrue(all("--selected-leaf-admission-root" not in call
                            for call in self.worker_calls()))
        plan = json.loads((self.options["output"] / "plan.json").read_text())
        self.assertNotIn("selected_leaf_admission", plan)

    def test_changed_worker_cannot_publish_a_completed_leaf(self):
        self.change_binary = True
        with self.assertRaises(protocol.ProofProtocolError):
            subject.run(**self.options)
        self.assertFalse((self.options["output"] / "leaf-000000.json").exists())

    def test_corrupt_resumed_proof_fails_before_more_production(self):
        self.fail_leaf = 1
        with self.assertRaises(protocol.ProofProtocolError):
            subject.run(**self.options)
        proof = next(self.options["output"].glob("*.bin"))
        proof.write_bytes(b"changed retained bytes")
        self.calls.clear()
        self.fail_leaf = None
        with self.assertRaises(protocol.ProofProtocolError):
            subject.run(**self.options)
        self.assertEqual(self.calls, [])

    def test_verifier_receipt_must_bind_original_materialization(self):
        self.wrong_receipt = True
        with self.assertRaises(protocol.ProofProtocolError):
            subject.run(**self.options)
        self.assertFalse(list((self.options["output"] / "attempts").glob("verify-*/result.json")))

    def test_fixed_program_profile_routes_all_commands_and_cannot_change_on_resume(self):
        self.options["claim_admission"] = "fixed_program_narrow_v5"
        subject.run(**self.options)
        self.assertTrue(all(call[call.index("--claim-admission") + 1] == "fixed_program_narrow_v5"
                            for call in self.worker_calls()))
        self.assertEqual([call[1] for call in self.calls], [
            "ethereum-incremental-full-leaf-replay-prepared-cpu-v1", "verify-leaf-fixed-program-v5",
            "ethereum-incremental-full-leaf-replay-prepared-cpu-v1", "verify-leaf-fixed-program-v5",
            "verify-bundle-fixed-program-v5"])
        self.calls.clear()
        self.options["claim_admission"] = "field_authority_v4"
        with self.assertRaises(protocol.ProofProtocolError):
            subject.run(**self.options)
        self.assertEqual(self.calls, [])

    def test_fresh_verification_failure_stops_before_next_producer(self):
        self.fail_verification = 0
        with self.assertRaises(protocol.ProofProtocolError):
            subject.run(**self.options)
        self.assertEqual(len(self.worker_calls()), 1)
        self.assertFalse((self.options["output"] / "leaf-000000.json").exists())
        self.assertFalse((self.options["output"] / "bundle.json").exists())

    def test_resume_recovers_candidate_but_retries_fresh_verification(self):
        self.fail_verification = 0
        for _ in range(2):
            with self.assertRaises(protocol.ProofProtocolError):
                subject.run(**self.options)
            self.assertFalse((self.options["output"] / "leaf-000000.json").exists())
        self.assertEqual(len(self.worker_calls()), 1)
        self.fail_verification = None
        self.calls.clear()
        subject.run(**self.options)
        self.assertEqual(self.calls[0][1], "verify-leaf")
        self.assertEqual(len(self.worker_calls()), 1)
        self.assertIn("leaf-000001-0000", " ".join(self.worker_calls()[0]))

    def test_resume_recovers_after_interruption_before_candidate_publication(self):
        real_publish = subject.store.publish_new_or_identical

        def interrupt_proof_publication(path, *args, **kwargs):
            if path.suffix == ".bin":
                raise KeyboardInterrupt
            return real_publish(path, *args, **kwargs)

        with patch.object(subject.store, "publish_new_or_identical", side_effect=interrupt_proof_publication):
            with self.assertRaises(KeyboardInterrupt):
                subject.run(**self.options)
        self.assertFalse(list(self.options["output"].glob("*.bin")))
        subject.run(**self.options)
        self.assertEqual(len(self.worker_calls()), 2)
        self.assertEqual(len(list((self.options["output"] / "attempts").glob("leaf-000000-*"))), 1)

    def test_pending_candidate_custody_failure_stops_before_any_child(self):
        self.fail_verification = 0
        with self.assertRaises(protocol.ProofProtocolError):
            subject.run(**self.options)
        attempt = self.options["output"] / "attempts" / "leaf-000000-0000"
        originals = {name: (attempt / name).read_bytes() for name in ("proof.bin", "request.json", "leaf.json")}
        for name in originals:
            with self.subTest(changed=name):
                for filename, raw in originals.items():
                    (attempt / filename).write_bytes(raw)
                if name == "proof.bin":
                    (attempt / name).write_bytes(b"changed proof")
                else:
                    value = json.loads(originals[name])
                    if name == "request.json":
                        value["plan_sha256"] = "00" * 32
                    else:
                        value["metadata"]["segment_index"] = 1
                    (attempt / name).write_bytes(protocol.canonical_bytes(value))
                self.calls.clear()
                with self.assertRaises(protocol.ProofProtocolError):
                    subject.run(**self.options)
                self.assertEqual(self.calls, [])

    def test_wrong_leaf_receipt_cannot_publish_progress(self):
        self.wrong_leaf_receipt = True
        with self.assertRaises(protocol.ProofProtocolError):
            subject.run(**self.options)
        self.assertEqual(len(self.worker_calls()), 1)
        self.assertFalse((self.options["output"] / "leaf-000000.json").exists())

    def test_resumed_leaf_is_reverified_before_new_production(self):
        self.fail_leaf = 1
        with self.assertRaises(protocol.ProofProtocolError):
            subject.run(**self.options)
        self.calls.clear()
        self.fail_leaf = None
        self.fail_verification = 0
        with self.assertRaises(protocol.ProofProtocolError):
            subject.run(**self.options)
        self.assertEqual(self.worker_calls(), [])

    def test_unknown_profile_fails_before_any_work(self):
        self.options["claim_admission"] = "guess-from-proof"
        with self.assertRaises(protocol.ProofProtocolError):
            subject.run(**self.options)
        self.assertEqual(self.calls, [])

    def configure_metal(self):
        bundle = self.root / "aot"
        bundle.mkdir()
        for name in ("stwo_zig_core.manifest.json", "stwo_zig_core.metal", "stwo_zig_core.metallib"):
            (bundle / name).write_bytes(name.encode())
        self.options.update(backend="metal", aot_bundle=bundle,
                            aot_manifest_sha256=hashlib.sha256(b"stwo_zig_core.manifest.json").hexdigest())

    def test_metal_uses_dedicated_product_and_pins_aot_without_cpu_reference(self):
        self.configure_metal()
        self.options["claim_admission"] = "fixed_program_narrow_v5"
        subject.run(**self.options)
        for call in self.worker_calls():
            self.assertEqual(call[1], "--retained-materialization-result")
            self.assertEqual(call[call.index("--aot-bundle") + 1], str(self.options["aot_bundle"].resolve()))
            self.assertEqual(call[call.index("--aot-manifest-sha256") + 1], self.options["aot_manifest_sha256"])
        plan = json.loads((self.options["output"] / "plan.json").read_text())
        self.assertEqual(plan["backend"], "metal")
        self.assertEqual(len(plan["aot"]["files"]), 3)
        self.calls.clear()
        (self.options["aot_bundle"] / "stwo_zig_core.metallib").write_bytes(b"replacement")
        with self.assertRaises(protocol.ProofProtocolError):
            subject.run(**self.options)
        self.assertEqual(self.calls, [])

    def test_metal_changed_library_during_production_cannot_publish_progress(self):
        self.configure_metal()
        self.change_aot = True
        with self.assertRaises(protocol.ProofProtocolError):
            subject.run(**self.options)
        self.assertFalse((self.options["output"] / "leaf-000000.json").exists())

    def test_metal_requires_independent_manifest_pin(self):
        self.configure_metal()
        self.options["aot_manifest_sha256"] = "00" * 32
        with self.assertRaises(protocol.ProofProtocolError):
            subject.run(**self.options)
        self.assertEqual(self.calls, [])

    def test_cpu_rejects_ignored_aot_options(self):
        self.configure_metal()
        self.options["backend"] = "cpu"
        with self.assertRaises(protocol.ProofProtocolError):
            subject.run(**self.options)
        self.assertEqual(self.calls, [])


if __name__ == "__main__":
    unittest.main()
