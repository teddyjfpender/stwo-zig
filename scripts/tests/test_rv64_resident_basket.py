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

    def exercise_run(self, corrupt_warm=False):
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
                result = R.run_job(plan, job)
                self.assertEqual(result["process_unattributed_wall_ns"], 100)
                self.assertTrue(result["trials"][0]["fresh_receiver_accepted"])
                self.assertFalse(result["trials"][1]["fresh_receiver_accepted"])
                self.assertIsNone(result["trials"][1]["fresh_receiver"])
        self.assertEqual(calls, ["producer", "receiver-0"])

    def test_warm_acceptance_inherits_only_exact_bytes_no_second_receiver(self):
        self.exercise_run()

    def test_warm_mutation_rejected_before_inheriting_acceptance(self):
        self.exercise_run(corrupt_warm=True)

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
