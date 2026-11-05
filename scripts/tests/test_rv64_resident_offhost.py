import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rv64_resident_offhost as O


class OffhostQualification(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.case = self.root / "case"
        self.case.mkdir()
        self.assets = {}
        for name in ("driver", "library", "receiver", "elf", "input"):
            path = self.root / name
            path.write_bytes(name.encode())
            self.assets[name] = path
        request = {"elf": str(self.assets["elf"]), "input": str(self.assets["input"]),
                   "elf_sha256": O.B.sha(self.assets["elf"]), "input_sha256": O.B.sha(self.assets["input"]),
                   "workers": 16, "execution_profile": "ethereum_services_v3", "expected_output": "abcd"}
        self.request = self.root / "request.json"
        O.B.atomic_json(self.request, request)
        self.job = {"block": 1, "device_count": 1, "request": "/remote/request.json", "target": "/remote/1gpu/1",
                    "request_sha256": O.B.sha(self.request), "input_sha256": request["input_sha256"],
                    "expected_output": "abcd", "segments": 1, "resources": {"fixed_setup_bytes": 1024}}
        self.plan = {"schema": O.R.SCHEMA, "combined": True, "repeat": 1, "profile": O.R.PROFILE,
                     "strict_recursive_receiver": False, "combined_host_bytes": 48 << 30,
                     "elf_sha256": request["elf_sha256"], "jobs": [copy.deepcopy(self.job)],
                     "assets": {k: "/remote/" + k for k in ("driver", "library", "receiver", "recursive_receiver")},
                     "asset_sha256": {"driver": O.B.sha(self.assets["driver"]), "library": O.B.sha(self.assets["library"]),
                                      "receiver": "old-linux-receiver", "recursive_receiver": "old-linux-recursive-receiver"}}
        self.plan_path = self.root / "original-plan.json"
        O.B.atomic_json(self.plan_path, self.plan)
        proof = self.case / "batch/trial-0/1/proof"
        recursion = proof / "recursion-om31"
        recursion.mkdir(parents=True)
        for name, data in {"leaf-000000.proof": b"left", "leaf-000001.proof": b"right", "fold-000002.proof": b"root", "root.proof": b"root"}.items():
            (recursion / name).write_bytes(data)
        O.B.atomic_json(recursion / "tree.json", {"root": 2, "nodes": [
            {"first_leaf": 0, "leaf_count": 1, "left": None, "right": None},
            {"first_leaf": 1, "leaf_count": 1, "left": None, "right": None},
            {"first_leaf": 0, "leaf_count": 2, "left": 0, "right": 1}]})
        (proof / "cpu.bin").write_bytes(b"native")
        O.B.atomic_json(proof / "bundle.json", {"native": "authority"})
        self.native = {"completed_ethereum_block": True, "capture_source": "in_process_execution", "output": [171, 205],
                       "cpu_proofs": 1, "truth_proofs": 1, "keccak_uniform_throughput": True, "retained_main": None,
                       "profile": "native-label", "capture_ns": 1, "setup_ns": 2, "prove_ns": 3,
                       "same_process_verify_ns": 4, "total_before_report_ns": 10}
        O.B.atomic_json(proof / "report.json", self.native)
        self.recursive = {"accepted": True, "leaf_proofs": 2, "fold_proofs": 1, "restored_leaves": 0, "restored_folds": 0,
                          "gpu_new_leaf_proofs": 2, "gpu_new_fold_proofs": 1, "outer_backend": "cuda_trace_only",
                          "assignment_source": "gpu_original_circuit_dag", "root_proof_bytes": 4}
        O.B.atomic_json(proof / "combined-report.json", {"accepted": True, "completed_ethereum_block": True,
            "native_bundle_reload": False, "restored_recursive_proofs": False, "native_authority_session_used": True,
            "recursive": self.recursive, "recursion_ns": 20})
        O.B.atomic_json(proof / "combined-entry.json", {"accepted": True, "device_lifecycle_audit": "all request leases released"})
        (self.case / "producer.stdout").write_text("")
        (self.case / "producer.stderr").write_text("GPU_GKR gkr_kernel_launches=1\nGPU_PCS_NATIVE device_ns=1000000\n" +
            "GPU_OUTER assignment_bytes=0\nGPU_OUTER_ASSIGNMENT full_assignment_upload_words=0\n" * 3 +
            "GPU_RESIDENT_BLOCK block=1 trial=0 iteration=0 request_wall_ns=100 gpu_contexts=1\n")
        pending = {"status": "produced_pending_verification", "accepted": False, "plan_sha256": O.R.plan_identity(self.plan),
                   "block": 1, "device_count": 1, "producer_process": {"exit_code": 0, "wall_ns": 120},
                   "physical_gpu_memory": {"samples": 1}, "gpu": O.B.gpu_diagnostics(self.case / "producer.stderr"),
                   "markers": {"0": 100}, "environment": {},
                   "artifact_snapshot": O.R.produced_snapshot(self.plan, dict(self.job, target=str(self.case))),
                   "log_sha256": {n: O.B.sha(self.case / n) for n in ("producer.stdout", "producer.stderr")}}
        O.B.atomic_json(self.case / "produced.json", pending)
        self.calls = []

    def measure(self, argv, directory, name, environment, cwd=None):
        self.calls.append(argv)
        self.assertEqual(cwd, O.RECEIVER_CWD)
        self.assertEqual(name, "strict-receiver")
        self.assertEqual(argv[6], "verify-recursion-candidate")
        self.assertEqual(argv[-1], str(32 << 30))
        operational = O.B.load(argv[7])
        original = O.B.load(self.request)
        self.assertEqual(operational, dict(original, workers=4))
        self.assertEqual(environment["CUDA_VISIBLE_DEVICES"], "")
        self.assertEqual(environment["STWO_RV64_GPU_PCS_HELPER"], "/bin/false")
        self.assertNotIn("STWO_RV64_GPU_LIBRARY", environment)
        native = dict(self.native, accepted=True, security_profile=O.R.PROFILE)
        recursive = dict(self.recursive, restored_leaves=2, restored_folds=1, gpu_new_leaf_proofs=0, gpu_new_fold_proofs=0)
        response = {"accepted": True, "completed_ethereum_block": True, "native_profile": "native-label", "native": native,
                    "recursive": recursive, "shared_fresh_native_authority": True, "native_verified_before_recursion": True,
                    "existing_recursive_proofs_only": True, "trace_only_recursive_graphs": True}
        O.B.atomic_json(directory / (name + ".stdout"), response)
        return {"argv": argv, "exit_code": 0, "wall_ns": 50, "peak_rss_bytes": 1000}

    def invoke(self):
        return O.qualify(self.plan_path, self.case, 1, 1, self.request, self.assets["driver"], self.assets["library"],
                         self.root / "qualification", self.assets["receiver"], O.B.sha(self.assets["receiver"]), lock=self.root / "receiver.lock")

    def test_measure_uses_explicit_receiver_working_directory(self):
        working = self.root / "receiver working directory"
        working.mkdir()
        O.B.measure([sys.executable, "-c", "import os; print(os.getcwd())"],
                    self.root, "cwd-probe", cwd=working)
        self.assertEqual((self.root / "cwd-probe.stdout").read_text().strip(), str(working.resolve()))

    def test_maps_io_without_rewriting_original_authority_and_runs_one_receiver(self):
        before = O.file_snapshot(self.case)
        plan_bytes = self.plan_path.read_bytes()
        with patch.object(O.B, "measure", side_effect=self.measure):
            result = self.invoke()
        self.assertTrue(result["accepted"])
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(result["production_plan_sha256"], O.R.plan_identity(self.plan))
        self.assertEqual(result["path_mapping"]["assets"]["driver"]["original"], "/remote/driver")
        self.assertEqual(self.plan_path.read_bytes(), plan_bytes)
        self.assertEqual(O.file_snapshot(self.case), before)
        self.assertEqual(len(result["trials"]), 1)

    def test_producer_asset_mutation_refuses_before_receiver(self):
        self.assets["driver"].write_bytes(b"mutant")
        with patch.object(O.B, "measure") as launch, self.assertRaisesRegex(ValueError, "asset changed"):
            self.invoke()
        launch.assert_not_called()

    def test_request_and_guest_mutation_refuse_before_receiver(self):
        self.assets["input"].write_bytes(b"mutant")
        with patch.object(O.B, "measure") as launch, self.assertRaisesRegex(ValueError, "guest/input"):
            self.invoke()
        launch.assert_not_called()

    def test_original_plan_mutation_cannot_be_relabelled_as_qualification(self):
        changed = copy.deepcopy(self.plan)
        changed["device_cap_bytes"] = 100
        O.B.atomic_json(self.plan_path, changed)
        with patch.object(O.B, "measure") as launch, self.assertRaisesRegex(ValueError, "pending production authority"):
            self.invoke()
        launch.assert_not_called()

    def test_proof_mutation_refuses_before_receiver(self):
        (self.case / "batch/trial-0/1/proof/cpu.bin").write_bytes(b"mutant")
        with patch.object(O.B, "measure") as launch, self.assertRaisesRegex(ValueError, "produced artifacts changed"):
            self.invoke()
        launch.assert_not_called()

    def test_receiver_repair_is_rejected_after_fresh_report(self):
        def repair(*args, **kwargs):
            usage = self.measure(*args, **kwargs)
            (self.case / "batch/trial-0/1/proof/recursion-om31/root.proof").write_bytes(b"evil")
            return usage
        with patch.object(O.B, "measure", side_effect=repair), self.assertRaisesRegex(ValueError, "root proof differs|changed"):
            self.invoke()


    def test_strict_receiver_cannot_report_new_recursive_proofs(self):
        def reprove(*args, **kwargs):
            usage = self.measure(*args, **kwargs)
            response = O.B.load(args[1] / "strict-receiver.stdout")
            response["recursive"]["gpu_new_leaf_proofs"] = 1
            O.B.atomic_json(args[1] / "strict-receiver.stdout", response)
            return usage
        with patch.object(O.B, "measure", side_effect=reprove), self.assertRaisesRegex(ValueError, "device proof counts"):
            self.invoke()
        self.assertFalse((self.root / "qualification/result.json").exists())

    def remote_request(self):
        request = O.B.load(self.request)
        request.update(elf="/workspace/original/guest.elf", input="/workspace/original/input.bin")
        O.B.atomic_json(self.request, request)
        self.plan["jobs"][0]["request_sha256"] = O.B.sha(self.request)
        O.B.atomic_json(self.plan_path, self.plan)
        pending = O.B.load(self.case / "produced.json")
        pending["plan_sha256"] = O.R.plan_identity(self.plan)
        O.B.atomic_json(self.case / "produced.json", pending)
    def mapped_invoke(self, mapping):
        return O.qualify(self.plan_path, self.case, 1, 1, self.request, self.assets["driver"], self.assets["library"], self.root / "qualification", self.assets["receiver"], O.B.sha(self.assets["receiver"]), lock=self.root / "receiver.lock", guest_paths=mapping)
    def test_explicit_paths_are_hashed_and_only_operational_copy_changes(self):
        self.remote_request()
        before = self.request.read_bytes()
        def measure(*args, **kwargs):
            operational = O.B.load(args[0][7])
            self.assertEqual(operational["elf"], str(self.assets["elf"].resolve()))
            self.assertEqual(operational["input"], str(self.assets["input"].resolve()))
            self.assertNotIn("STWO_ZIG_RV64_SETUP_CACHE", args[3])
            saved = self.request
            self.request = Path(args[0][7])
            try: return self.measure(*args, **kwargs)
            finally: self.request = saved
        with patch.dict(O.os.environ, {"STWO_ZIG_RV64_SETUP_CACHE": "/tmp/untrusted-cache"}), patch.object(O.B, "measure", side_effect=measure):
            result = self.mapped_invoke({"elf":self.assets["elf"],"input":self.assets["input"]})
        self.assertTrue(result["accepted"])
        self.assertEqual(self.request.read_bytes(), before)
        self.assertEqual(result["request_overrides"]["elf"]["from"], "/workspace/original/guest.elf")
        self.assertEqual(result["request_overrides"]["input"]["from"], "/workspace/original/input.bin")
    def test_mutated_mapped_bytes_refuse_before_receiver(self):
        self.remote_request();self.assets["input"].write_bytes(b"changed")
        with patch.object(O.B,"measure") as launch, self.assertRaisesRegex(ValueError,"guest/input"):
            self.mapped_invoke({"elf":self.assets["elf"],"input":self.assets["input"]})
        launch.assert_not_called()
    def test_unknown_mapping_refuses_before_receiver(self):
        with patch.object(O.B,"measure") as launch, self.assertRaisesRegex(ValueError,"unknown guest/input"):
            self.mapped_invoke({"secret":self.assets["elf"]})
        launch.assert_not_called()
