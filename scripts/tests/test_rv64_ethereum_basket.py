import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest

SOURCE = Path(__file__).resolve().parents[1] / "rv64_ethereum_basket.py"
SPEC = importlib.util.spec_from_file_location("basket", SOURCE)
B = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(B)


class BasketTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_cli_argument_contract_preserves_resource_filename_without_shell(self):
        cmd = B.command("driver", B.PROFILES[0], "produce-candidate", "request", "jobs", "out", 0, '/tmp/resources $(literal).json')
        self.assertEqual(cmd[3:8], ["produce-candidate", "request", "jobs", "out", "0"])
        self.assertEqual(cmd[-1], '/tmp/resources $(literal).json')

    def test_direct_job_uses_real_candidate_file_argument_and_hashes_inputs(self):
        (self.root / "guest").write_bytes(b"guest")
        (self.root / "input").write_bytes(b"input")
        output = "ab" * 32 + "00" * 11
        request = {"elf": "guest", "input": "input", "elf_sha256": B.sha(self.root / "guest"),
                   "input_sha256": B.sha(self.root / "input"), "expected_output": output}
        (self.root / "request.json").write_text(json.dumps(request))
        block = {"block": 1, "set": "scored", "gas_used": 10, "new_payload_request_root": "0x" + "ab" * 32}
        manifest = {"cpu_driver": sys.executable, "resources": {"fixed_setup_bytes": 100}}
        entry = {"request": "request.json", "jobs": "-"}
        job = B.job_for(block, entry, manifest, self.root, "cpu", self.root / "out", B.PROFILES[0])
        self.assertTrue(job["ready"])
        self.assertEqual(job["produce"][5], "-")
        self.assertTrue(job["produce"][-1].endswith("/1/resources.json"))
        (self.root / "input").write_bytes(b"mutated")
        with self.assertRaisesRegex(ValueError, "hash mismatch"):
            B.job_for(block, entry, manifest, self.root, "cpu", self.root / "out", B.PROFILES[0])

    def test_per_child_usage_reaps_exact_process(self):
        result = B.measure([sys.executable, "-c", "print('finished')"], self.root, "one")
        self.assertEqual(result["exit_code"], 0)
        self.assertGreater(result["wall_ns"], 0)
        self.assertEqual((self.root / "one.stdout").read_text().strip(), "finished")

    def test_memory_admission_serializes_credit_and_rejects_oversize(self):
        admission = B.Admission([{"device": 0, "capacity_bytes": 100, "device_caps_bytes": [100], "planned_cpu_workers": 1, "retained_scopes": 1}])
        with self.assertRaises(ValueError):
            admission.acquire(101)
        first, _ = admission.acquire(70)
        acquired = threading.Event()
        def worker():
            index, _ = admission.acquire(60)
            acquired.set()
            admission.release(index)
        thread = threading.Thread(target=worker)
        thread.start()
        self.assertFalse(acquired.wait(0.05))
        self.assertEqual(admission.live, [70])
        admission.release(first)
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertTrue(acquired.is_set())
        self.assertEqual(admission.live, [0])

    def test_host_memory_is_admitted_across_devices(self):
        admission = B.Admission([{"device": 0, "capacity_bytes": 100, "device_caps_bytes": [100], "planned_cpu_workers": 1, "retained_scopes": 1}, {"device": 1, "capacity_bytes": 100, "device_caps_bytes": [100], "planned_cpu_workers": 1, "retained_scopes": 1}], host_capacity=150)
        first, _ = admission.acquire(80, 100)
        with self.assertRaisesRegex(ValueError, "host memory"):
            admission.acquire(50, 151)
        acquired = threading.Event()
        def worker():
            index, _ = admission.acquire(80, 100)
            acquired.set()
            admission.release(index)
        thread = threading.Thread(target=worker)
        thread.start()
        self.assertFalse(acquired.wait(0.05))
        admission.release(first)
        thread.join(2)
        self.assertTrue(acquired.is_set())
        self.assertEqual(admission.host, [0, 0])

    def test_multigpu_group_maps_physical_devices_to_local_ordinals(self):
        env = B.worker_environment({"device": "2,5", "device_caps_bytes": [20, 30], "planned_cpu_workers": 7, "retained_scopes": 4}, {})
        self.assertEqual(env["CUDA_VISIBLE_DEVICES"], "2,5")
        self.assertEqual(env["STWO_RV64_GPU_DEVICES"], "0,1")
        self.assertEqual(env["STWO_RV64_GPU_DEVICE_CAPS"], "20,30")
        self.assertEqual(env["STWO_RV64_GPU_PLANNED_CPU_WORKERS"], "7")
        with self.assertRaises(ValueError):
            B.worker_environment({"device": "0,1", "device_caps_bytes": [20, 30], "planned_cpu_workers": 7, "retained_scopes": 3}, {})

    def test_gpu_log_evidence_preserves_scope_and_does_not_infer_wall(self):
        log = self.root / "producer.stderr"
        log.write_text("GPU_GKR_SPANS ordinal=0 ingress_ms=2.0 traversal_ms=3.5\nGPU_GKR ordinal=0 native_stage_wall_ns=90000000 gkr_kernel_launches=42\nGPU_PCS_NATIVE device_ns=2500000 total_ns=8000000\n")
        result = B.gpu_diagnostics(log)
        self.assertEqual(result["kernel_launches"], 42)
        self.assertEqual(result["device_ms"], 8.0)
        self.assertIn("not CUPTI", result["launch_count_scope"])
        log.write_text("CPU work finished in1ms\n")
        self.assertEqual(B.gpu_diagnostics(log)["kernel_launches"], 0)

    def job(self, gpu):
        target = self.root / "run"
        request = self.root / "request.json"
        request.write_text(json.dumps({"expected_output": "01"}))
        script = self.root / "producer.py"
        report = {"profile": "test", "total_steps": 10, "cpu_proofs": 1, "truth_proofs": 0,
                  "capture_ns": 1, "setup_ns": 2, "prove_ns": 100, "native_cells": 20,
                  "cell_scope": "native trace", "capture_source": "in_process_execution"}
        if gpu:
            report["gpu"] = {"kernel_launches": 3, "device_ms": 0.01}
        script.write_text("import pathlib,json\np=pathlib.Path(" + repr(str(target / "proof")) + ")\np.mkdir()\n" +
                          "(p/'report.json').write_text(" + repr(json.dumps(report)) + ")\n" +
                          "(p/'bundle.json').write_text('{}')\n(p/'cpu-0.bin').write_bytes(b'proof')\n")
        receiver = [sys.executable, "-c", "print('" + json.dumps({"accepted": True, "completed_ethereum_block": True, "output": [1]}) + "')"]
        return {"output": str(target), "produce": [sys.executable, str(script)], "verify": receiver,
                "prefix_count": 0, "resident_bytes": 50, "request": str(request), "block": 1, "profile": B.PROFILES[0]}

    def test_gpu_fallback_rejects_and_releases_worker(self):
        admission = B.Admission([{"device": 0, "capacity_bytes": 100, "device_caps_bytes": [100], "planned_cpu_workers": 1, "retained_scopes": 1}])
        with self.assertRaisesRegex(ValueError, "CPU fallback"):
            B.execute(self.job(False), "gpu", admission)
        self.assertEqual(admission.live, [0])

    def test_gpu_adapter_requires_fresh_receiver_and_records_cost_scope(self):
        admission = B.Admission([{"device": 1, "capacity_bytes": 100, "device_caps_bytes": [100], "planned_cpu_workers": 1, "retained_scopes": 1}])
        result = B.execute(self.job(True), "gpu", admission)
        self.assertTrue(result["fresh_receiver_accepted"])
        self.assertTrue(result["execution_included"])
        self.assertEqual(result["prove_ns_per_native_cell"], 5)
        self.assertEqual(result["gpu_device_ns_per_native_cell"], 500)
        self.assertEqual(result["worker"]["device"], 1)

    def test_prefix_receiver_has_no_terminal_output(self):
        job = self.job(True)
        job["prefix_count"] = 1
        job["verify"] = [sys.executable, "-c", "print('{\"accepted\": true, \"completed_ethereum_block\": false, \"output\": null}')"]
        admission = B.Admission([{"device": 0, "capacity_bytes": 100, "device_caps_bytes": [100], "planned_cpu_workers": 1, "retained_scopes": 1}])
        result = B.execute(job, "gpu", admission)
        self.assertTrue(result["fresh_receiver_accepted"])
        self.assertFalse(result["completed_block"])

    def test_rejected_receiver_never_publishes_result(self):
        job = self.job(True)
        job["verify"] = [sys.executable, "-c", "print('{\"accepted\": false}')"]
        admission = B.Admission([{"device": 0, "capacity_bytes": 100, "device_caps_bytes": [100], "planned_cpu_workers": 1, "retained_scopes": 1}])
        with self.assertRaisesRegex(ValueError, "fresh receiver"):
            B.execute(job, "gpu", admission)
        self.assertFalse((Path(job["output"]) / "result.json").exists())
        self.assertEqual(admission.live, [0])


if __name__ == "__main__":
    unittest.main()
