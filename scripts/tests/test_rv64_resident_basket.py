import copy
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rv64_resident_basket as R


class ResidentBasket(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.assets = []
        for name in ("driver", "receiver", "library", "elf", "input"):
            p = self.root / name
            p.write_bytes(name.encode())
            self.assets.append(p)
        self.request = {"elf": "elf", "input": "input", "elf_sha256": R.B.sha(self.assets[3]),
                        "input_sha256": R.B.sha(self.assets[4]), "execution_profile": "ethereum_services_v3", "expected_output": "abcd"}
        (self.root / "request.json").write_text(json.dumps(self.request))
        self.basket = {"blocks": [{"block": 1, "set": "scored", "new_payload_request_root": "0xabcd"}]}
        self.manifest = {"schema": "rv64-ethereum-basket-inputs/v1", "resources": {"fixed_setup_bytes": 100, "retained_frontend_bytes": 200,
                         "schedule": {"lanes": 2, "workers_per_lane": 4, "memory_cap_bytes": 1024}},
                         "blocks": {"1": {"request": "request.json", "expected_cpu_segments": 7}}}

    def plan(self, **kw):
        return R.build_plan(kw.get("basket", self.basket), kw.get("manifest", self.manifest), self.root,
                            *self.assets[:3], self.root / "output", kw.get("devices", [0, 1, 2, 3]),
                            kw.get("counts", [1, 2, 4]), 100, kw.get("runtime", R.B.sha(self.assets[2])))

    def test_matrix_same_authority_full_requests(self):
        p = self.plan()
        self.assertTrue(p["input_ready"])
        self.assertEqual([j["device_count"] for j in p["jobs"]], [1, 2, 4])
        self.assertEqual(len({j["request_sha256"] for j in p["jobs"]}), 1)
        self.assertTrue(all(j["resources"]["keccak_uniform_throughput"] for j in p["jobs"]))
        self.assertTrue(all(j["resources"]["park_main"] is False for j in p["jobs"]))

    def test_missing_cases_remain_explicit_in_report(self):
        self.manifest["blocks"] = {}
        p = self.plan()
        self.assertFalse(p["input_ready"])
        text = R.render(p, [])
        self.assertIn("0/3", text)
        self.assertEqual(text.count("not run"), 3)

    def test_multi_gpu_schedule_exposes_devices_without_adding_cpu_workers(self):
        schedules = [j["resources"]["schedule"] for j in self.plan()["jobs"]]
        self.assertEqual([s["lanes"] for s in schedules], [2, 2, 4])
        self.assertEqual(schedules[2]["lane_workers"], [2, 2, 2, 2])
        self.assertEqual(self.manifest["resources"]["schedule"]["lanes"], 2)
        self.assertTrue(all(s["memory_cap_bytes"] == 1024 for s in schedules))
        uneven = {"schedule": {"lanes": 2, "workers_per_lane": 4, "lane_workers": [3, 4]}}
        self.assertEqual(R.device_resources(uneven, 4)["schedule"]["lane_workers"], [2, 2, 2, 1])
        with self.assertRaisesRegex(ValueError, "CPU worker budget"):
            R.device_resources({"schedule": {"lanes": 1, "workers_per_lane": 2}}, 4)
        with self.assertRaisesRegex(ValueError, "explicit coordinator"):
            R.device_resources({}, 1)
        for schedule in ({"lanes": 2, "workers_per_lane": 32}, {"lanes": 1, "workers_per_lane": 33}):
            with self.assertRaisesRegex(ValueError, "32-worker limit"):
                R.device_resources({"schedule": schedule}, 1)
        with self.assertRaisesRegex(ValueError, "lane geometry"):
            R.device_resources({"schedule": {"lanes": 1, "workers_per_lane": 4, "lane_workers": [True]}}, 1)

    def test_runtime_hash_mismatch_fails(self):
        with self.assertRaisesRegex(ValueError, "runtime differs"):
            self.plan(runtime="0" * 64)

    def test_prefix_and_profile_rejected(self):
        for field, value in (("prefix_count", 1), ("jobs", "packets")):
            manifest = copy.deepcopy(self.manifest)
            manifest["blocks"]["1"][field] = value
            with self.assertRaises(ValueError):
                self.plan(manifest=manifest)
        self.manifest["profile"] = "nominal96"
        with self.assertRaises(ValueError):
            self.plan()

    def test_missing_or_duplicate_physical_devices_rejected(self):
        for devices, counts in (([0], [2]), ([0, 0], [1]), ([0, 1, 2], [3])):
            with self.assertRaises(ValueError):
                self.plan(devices=devices, counts=counts)

    def test_guest_and_input_hashes_checked(self):
        self.assets[4].write_bytes(b"tampered")
        with self.assertRaisesRegex(ValueError, "input hash"):
            self.plan()

    def test_markers_require_both_trials_and_device_count(self):
        text = "\n".join(f"GPU_RESIDENT_BLOCK block=1 trial={t} iteration=0 request_wall_ns=123 gpu_contexts=2" for t in (0, 1))
        self.assertEqual(R.request_markers(text, 1, 2), {0: 123, 1: 123})
        for wrong in (text.splitlines()[0], text + "\n" + text, text.replace("gpu_contexts=2", "gpu_contexts=1")):
            with self.assertRaises(ValueError):
                R.request_markers(wrong, 1, 2)

    def test_acceptance_is_full_output_and_geometry_bound(self):
        receiver = {"accepted": True, "completed_ethereum_block": True, "security_profile": R.PROFILE, "output": [171, 205]}
        report = {"completed_ethereum_block": True, "capture_source": "in_process_execution", "output": [171, 205],
                  "cpu_proofs": 7, "keccak_uniform_throughput": True, "retained_main": None}
        job = self.plan()["jobs"][0]
        R.check_trial(report, receiver, job, R.PROFILE)
        for key, value in (("cpu_proofs", 6), ("retained_main", {}), ("completed_ethereum_block", False), ("output", [0])):
            altered = dict(report, **{key: value})
            with self.assertRaises(ValueError):
                R.check_trial(altered, receiver, job, R.PROFILE)

    def exercise_run(self, corrupt_warm=False, deferred=False, corrupt_pending=False):
        plan = self.plan(counts=[1])
        job = plan["jobs"][0]
        target = Path(job["target"])
        calls = []
        def measure(argv, directory, name, environment=None):
            calls.append(name)
            if name == "producer":
                for trial in (0, 1):
                    proof = target / "batch" / f"trial-{trial}" / "1" / "proof"
                    proof.mkdir(parents=True)
                    report = {"completed_ethereum_block": True, "capture_source": "in_process_execution", "output": [171, 205],
                              "cpu_proofs": 7, "truth_proofs": 2, "keccak_uniform_throughput": True, "retained_main": None,
                              "capture_ns": 10, "setup_ns": 20, "prove_ns": 30, "same_process_verify_ns": 5,
                              "total_before_report_ns": 70, "total_steps": 100}
                    (proof / "report.json").write_text(json.dumps(report))
                    (proof / "bundle.json").write_text("{}")
                    (proof / "physical-0.bin").write_bytes(b"different" if trial and corrupt_warm else b"proof")
                log = "\n".join(f"GPU_RESIDENT_BLOCK block=1 trial={trial} iteration=0 request_wall_ns=100 gpu_contexts=1" for trial in (0, 1))
                (target / "producer.stdout").write_text("")
                (target / "producer.stderr").write_text(log + "\nGPU_GKR gkr_kernel_launches=2\nGPU_PCS_NATIVE device_ns=1000\n")
            else:
                (target / (name + ".stdout")).write_text(json.dumps({"accepted": True, "completed_ethereum_block": True,
                    "security_profile": R.PROFILE, "output": [171, 205]}))
            return {"wall_ns": 300, "exit_code": 0}
        monitor = MagicMock()
        monitor.finish.return_value = {"samples": 2, "peak_used_bytes": {"0": 100}}
        with patch.object(R.B, "measure", side_effect=measure), patch.object(R.B, "DeviceMonitor", return_value=monitor):
            if corrupt_warm:
                with self.assertRaisesRegex(ValueError, "warm bytes differ"):
                    R.run_job(plan, job)
            else:
                if deferred:
                    pending = R.produce_job(plan, job)
                    self.assertEqual(calls, ["producer"])
                    self.assertEqual(pending["status"], "produced_pending_verification")
                    self.assertIs(pending["accepted"], False)
                    self.assertFalse((target / "receiver-0.stdout").exists())
                    if corrupt_pending:
                        (target / "batch/trial-0/1/proof/physical-0.bin").write_bytes(b"changed")
                        with self.assertRaisesRegex(ValueError, "artifacts changed"):
                            R.qualify_job(plan, job)
                        self.assertEqual(calls, ["producer"])
                        return
                    result = R.qualify_job(plan, job)
                else:
                    result = R.run_job(plan, job)
                self.assertEqual(result["process_unattributed_wall_ns"], 100)
                self.assertTrue(result["trials"][0]["fresh_receiver_accepted"])
                self.assertFalse(result["trials"][1]["fresh_receiver_accepted"])
                self.assertIsNone(result["trials"][1]["fresh_receiver"])
        self.assertEqual(calls, ["producer", "receiver-0"])

    def test_deferred_production_never_accepts_before_cpu_qualification(self):
        self.exercise_run(deferred=True)

    def test_deferred_qualification_rejects_artifact_mutation_before_receiver(self):
        self.exercise_run(deferred=True, corrupt_pending=True)

    def test_warm_acceptance_inherits_only_exact_bytes_no_second_receiver(self):
        self.exercise_run()

    def test_warm_mutation_rejected_before_inheriting_acceptance(self):
        self.exercise_run(corrupt_warm=True)


    def test_receivers_cannot_create_gpu_context_or_change_producer_environment(self):
        producer = {"CUDA_VISIBLE_DEVICES": "0", "STWO_RV64_GPU_LIBRARY": "qualified.so",
                    "STWO_RV64_GPU_DEVICES": "0", "STWO_RV64_GPU_PCS_HELPER": "helper",
                    "STWO_RV64_GPU_CPU_REPLAY": "1", "STWO_RV64_GPU_DEVICE_TRACE": "1"}
        receiver = R.receiver_environment(producer)
        self.assertEqual(producer["CUDA_VISIBLE_DEVICES"], "0")
        self.assertEqual(producer["STWO_RV64_GPU_LIBRARY"], "qualified.so")
        self.assertEqual(receiver["CUDA_VISIBLE_DEVICES"], "")
        self.assertEqual(receiver["STWO_RV64_GPU_PCS_HELPER"], "/bin/false")
        self.assertNotIn("STWO_RV64_GPU_LIBRARY", receiver)
        self.assertNotIn("STWO_RV64_GPU_DEVICES", receiver)
        self.assertNotIn("STWO_RV64_GPU_CPU_REPLAY", receiver)
        self.assertNotIn("STWO_RV64_GPU_DEVICE_TRACE", receiver)

    def test_combined_plan_requires_one_gpu_and_pinned_recursive_receiver(self):
        kwargs = dict(expected_runtime=R.B.sha(self.assets[2]), combined=True, recursive_receiver=self.assets[1])
        def make(counts):
            return R.build_plan(self.basket, self.manifest, self.root, *self.assets[:3], self.root / "combined", [0, 1, 2, 3], counts, 28 << 30, **kwargs)
        plan = make([1])
        self.assertTrue(plan["combined"])
        self.assertIn("recursive_receiver", plan["asset_sha256"])
        self.assertEqual(plan["combined_immutable_device_bytes"], 2 << 30)
        for counts in ([2], [4], [1, 2, 4]):
            with self.assertRaisesRegex(ValueError, "one GPU"):
                make(counts)
        kwargs["recursive_receiver"] = None
        with self.assertRaisesRegex(ValueError, "recursive receiver"):
            make([1])

    def recursive_tree(self):
        proof = self.root / "recursive-proof"
        directory = proof / "recursion-om31"
        directory.mkdir(parents=True)
        nodes = [{"first_leaf": 0, "leaf_count": 1, "left": None, "right": None},
                 {"first_leaf": 1, "leaf_count": 1, "left": None, "right": None},
                 {"first_leaf": 0, "leaf_count": 2, "left": 0, "right": 1}]
        (directory / "tree.json").write_text(json.dumps({"root": 2, "nodes": nodes}))
        for name, data in (("leaf-000000.proof", b"left"), ("leaf-000001.proof", b"right"),
                           ("fold-000002.proof", b"root"), ("root.proof", b"root")):
            (directory / name).write_bytes(data)
        return proof, directory, nodes

    def test_recursive_snapshot_checks_physical_coverage_and_root_copy(self):
        proof, directory, nodes = self.recursive_tree()
        snapshot = R.recursive_snapshot(proof, 2)
        self.assertEqual(len(snapshot["proof_sha256"]), 4)
        (directory / "root.proof").write_bytes(b"corrupted")
        with self.assertRaisesRegex(ValueError, "physical final node"):
            R.recursive_snapshot(proof, 2)
        (directory / "root.proof").write_bytes(b"root")
        (directory / "leaf-000001.proof").unlink()
        with self.assertRaisesRegex(ValueError, "cannot re-prove"):
            R.recursive_snapshot(proof, 2)

    def test_recursive_snapshot_rejects_swapped_or_duplicated_children(self):
        proof, directory, nodes = self.recursive_tree()
        nodes[2]["left"], nodes[2]["right"] = 1, 0
        (directory / "tree.json").write_text(json.dumps({"root": 2, "nodes": nodes}))
        with self.assertRaisesRegex(ValueError, "adjacency"):
            R.recursive_snapshot(proof, 2)
        nodes[2]["left"] = 0
        (directory / "tree.json").write_text(json.dumps({"root": 2, "nodes": nodes}))
        with self.assertRaisesRegex(ValueError, "ordering"):
            R.recursive_snapshot(proof, 2)

    def test_recursive_reports_cannot_count_restores_as_proving_or_reprove_in_receiver(self):
        report = {"accepted": True, "leaf_proofs": 2, "fold_proofs": 1, "restored_leaves": 0,
                  "restored_folds": 0, "gpu_new_leaf_proofs": 2, "gpu_new_fold_proofs": 1,
                  "outer_backend": "cuda_trace_only", "assignment_source": "gpu_original_circuit_dag"}
        R.check_recursive_report(report, 2)
        with self.assertRaisesRegex(ValueError, "re-proved"):
            R.check_recursive_report(report, 2, restored=True)
        restored = dict(report, restored_leaves=2, restored_folds=1, gpu_new_leaf_proofs=0, gpu_new_fold_proofs=0)
        R.check_recursive_report(restored, 2, restored=True)
        with self.assertRaisesRegex(ValueError, "resumed"):
            R.check_recursive_report(restored, 2)
        with self.assertRaisesRegex(ValueError, "CPU assignment"):
            R.check_recursive_report(dict(report, assignment_source="cpu_circuit_builder"), 2)

    def exercise_combined(self, corruption=None, repeat=2, deferred=False, strict=False):
        self.manifest["blocks"]["1"]["expected_cpu_segments"] = 1
        plan = R.build_plan(self.basket, self.manifest, self.root, *self.assets[:3], self.root / "combined",
                            [0], [1], 28 << 30, R.B.sha(self.assets[2]), True, self.assets[1], repeat, strict)
        job = plan["jobs"][0]
        target = Path(job["target"])
        calls = []
        native = {"profile": "native-label", "completed_ethereum_block": True, "capture_source": "in_process_execution",
                  "output": [171, 205], "cpu_proofs": 1, "truth_proofs": 1, "keccak_uniform_throughput": True,
                  "retained_main": None, "capture_ns": 10, "setup_ns": 20, "prove_ns": 30,
                  "same_process_verify_ns": 5, "total_before_report_ns": 70, "total_steps": 100}
        recursive = {"accepted": True, "leaf_proofs": 2, "fold_proofs": 1, "restored_leaves": 0, "restored_folds": 0,
                     "gpu_new_leaf_proofs": 2, "gpu_new_fold_proofs": 1, "outer_backend": "cuda_trace_only",
                     "assignment_source": "gpu_original_circuit_dag", "root_proof_bytes": 4}
        nodes = [{"first_leaf": 0, "leaf_count": 1, "left": None, "right": None},
                 {"first_leaf": 1, "leaf_count": 1, "left": None, "right": None},
                 {"first_leaf": 0, "leaf_count": 2, "left": 0, "right": 1}]
        def measure(argv, directory, name, environment=None):
            calls.append(name)
            if name == "producer":
                self.assertEqual(argv[1], "combined-batch")
                for trial in range(repeat):
                    proof = target / "batch" / f"trial-{trial}" / "1" / "proof"
                    outer = proof / "recursion-om31"
                    outer.mkdir(parents=True)
                    (proof / "report.json").write_text(json.dumps(native))
                    (proof / "bundle.json").write_text("{}")
                    (proof / "cpu-0.bin").write_bytes(b"native")
                    combined = {"accepted": True, "completed_ethereum_block": True, "native_bundle_reload": False,
                                "restored_recursive_proofs": False, "native_authority_session_used": True,
                                "recursive": recursive, "recursion_ns": 50}
                    (proof / "combined-report.json").write_text(json.dumps(combined))
                    (proof / "combined-entry.json").write_text(json.dumps({"accepted": True, "device_lifecycle_audit": "all request leases released"}))
                    (outer / "tree.json").write_text(json.dumps({"root": 2, "nodes": nodes}))
                    for filename in ("leaf-000000.proof", "leaf-000001.proof", "fold-000002.proof", "root.proof"):
                        (outer / filename).write_bytes(b"changed" if trial and corruption == "warm" else b"root")
                lines = []
                for trial in range(repeat):
                    lines += ["GPU_OUTER assignment_bytes=0", "GPU_OUTER_ASSIGNMENT full_assignment_upload_words=0"] * 3
                    lines += [f"GPU_RESIDENT_BLOCK block=1 trial={trial} iteration=0 request_wall_ns=100 gpu_contexts=1"]
                (target / "producer.stdout").write_text("")
                (target / "producer.stderr").write_text("\n".join(lines) + "\nGPU_GKR gkr_kernel_launches=2\nGPU_PCS_NATIVE device_ns=1000\n")
            elif name == "receiver-0":
                self.assertEqual(environment["CUDA_VISIBLE_DEVICES"], "")
                self.assertEqual(environment["STWO_RV64_GPU_PCS_HELPER"], "/bin/false")
                self.assertNotIn("STWO_RV64_GPU_LIBRARY", environment)
                (target / (name + ".stdout")).write_text(json.dumps({"accepted": True, "completed_ethereum_block": True,
                    "security_profile": R.PROFILE, "output": [171, 205], "cpu_proofs": 1, "truth_proofs": 1}))
            elif name in ("recursive-receiver-0", "strict-receiver-0"):
                self.assertNotIn("STWO_RV64_GPU_DEVICES", environment)
                self.assertEqual(environment["CUDA_VISIBLE_DEVICES"], "")
                self.assertEqual(environment["STWO_RV64_GPU_PCS_HELPER"], "/bin/false")
                self.assertNotIn("STWO_RV64_GPU_LIBRARY", environment)
                restored = dict(recursive, restored_leaves=2, restored_folds=1, gpu_new_leaf_proofs=0, gpu_new_fold_proofs=0)
                if corruption == "reprove":
                    restored["restored_leaves"] = 1
                response = {"accepted": True, "completed_ethereum_block": True,
                            "native_profile": "native-label", "recursive": restored}
                if name == "strict-receiver-0":
                    self.assertEqual(argv[3], "verify-recursion-candidate")
                    response.update(shared_fresh_native_authority=True, native_verified_before_recursion=True,
                                    existing_recursive_proofs_only=True, trace_only_recursive_graphs=True,
                                    native={"accepted": True, "completed_ethereum_block": True, "security_profile": R.PROFILE,
                                            "output": [171, 205], "cpu_proofs": 1, "truth_proofs": 1})
                    if corruption == "shared-authority":
                        response["shared_fresh_native_authority"] = False
                (target / (name + ".stdout")).write_text(json.dumps(response))
                if corruption == "repair":
                    path = target / "batch/trial-0/1/proof/recursion-om31/root.proof"
                    path.write_bytes(b"repaired")
            return {"wall_ns": 300, "exit_code": 0}
        monitor = MagicMock()
        monitor.finish.return_value = {"samples": 2, "peak_used_bytes": {"0": 100}}
        with patch.object(R.B, "measure", side_effect=measure), patch.object(R.B, "DeviceMonitor", return_value=monitor):
            if corruption:
                with self.assertRaises(ValueError):
                    R.run_job(plan, job)
            else:
                if deferred:
                    pending = R.produce_job(plan, job)
                    self.assertEqual(calls, ["producer"])
                    self.assertEqual(pending["status"], "produced_pending_verification")
                    self.assertIs(pending["accepted"], False)
                    result = R.qualify_job(plan, job)
                else:
                    result = R.run_job(plan, job)
                self.assertTrue(result["trials"][0]["fresh_recursive_receiver_accepted"])
                self.assertEqual(len(result["trials"]), repeat)
                if repeat == 2:
                    self.assertFalse(result["trials"][1]["fresh_recursive_receiver_accepted"])
                    self.assertEqual(result["trials"][0]["recursive_snapshot"], result["trials"][1]["recursive_snapshot"])
                else:
                    self.assertNotIn("warm", result["trials"][0]["recursive_acceptance"])
                    self.assertIn("—", R.render(plan, [result]))
                self.assertIn("Cold recursion", R.render(plan, [result]))
        self.assertEqual(calls, ["producer", "strict-receiver-0"] if strict else ["producer", "receiver-0", "recursive-receiver-0"])

    def test_strict_receiver_checks_native_and_root_with_one_process(self):
        self.exercise_combined(repeat=1, strict=True)

    def test_strict_receiver_rejects_missing_shared_authority_and_new_proofs(self):
        self.exercise_combined("shared-authority", repeat=1, strict=True)

    def test_receiver_upgrade_cannot_change_pinned_production_authority(self):
        original = self.plan(counts=[1])
        upgraded = copy.deepcopy(original)
        upgraded["strict_recursive_receiver"] = True
        upgraded["assets"]["receiver"] = "new independently pinned CPU receiver"
        upgraded["asset_sha256"]["receiver"] = "new receiver digest"
        self.assertEqual(R.production_identity(original), R.production_identity(upgraded))
        self.assertEqual(R.qualification_view(original, original, upgraded), upgraded)
        for mutate in (lambda p: p.update(profile="different"),
                       lambda p: p["asset_sha256"].update(driver="different"),
                       lambda p: p["jobs"][0]["resources"].update(global_bytes=1)):
            changed = copy.deepcopy(upgraded)
            mutate(changed)
            self.assertNotEqual(R.production_identity(original), R.production_identity(changed))
            with self.assertRaisesRegex(ValueError, "production authority"):
                R.qualification_view(original, original, changed)

    def test_deferred_combined_requires_both_fresh_receivers_before_acceptance(self):
        self.exercise_combined(repeat=1, deferred=True)

    def test_combined_cold_fresh_receiver_and_warm_exact_root_parity(self):
        self.exercise_combined()

    def test_combined_single_cold_trial_requires_both_fresh_receivers(self):
        self.exercise_combined(repeat=1)

    def test_combined_rejects_warm_root_mutation(self):
        self.exercise_combined("warm")

    def test_combined_receiver_cannot_reprove_or_repair_proofs(self):
        self.exercise_combined("reprove")

    def test_combined_receiver_cannot_repair_root_after_verification(self):
        self.exercise_combined("repair")

    def test_inventory_checks_actual_model_and_ordinals(self):
        with patch.object(R.subprocess, "check_output", return_value="0, UUID, NVIDIA GeForce RTX 5090, 32768\n"):
            self.assertEqual(R.gpu_inventory([0])["0"]["memory_bytes"], 32768 << 20)
            with self.assertRaises(ValueError):
                R.gpu_inventory([0, 1])
        with patch.object(R.subprocess, "check_output", return_value="0, UUID, NVIDIA A100, 80000\n"):
            with self.assertRaises(ValueError):
                R.gpu_inventory([0])


if __name__ == "__main__":
    unittest.main()
