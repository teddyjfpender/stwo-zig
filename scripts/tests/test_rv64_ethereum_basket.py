import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

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
        manifest = {"cpu_driver": sys.executable, "resources": {"fixed_setup_bytes": 100, "disk_bytes": 200}, "disk_free_floor_bytes": 20, "remove_verified_proof_binaries": True}
        entry = {"request": "request.json", "jobs": "-"}
        job = B.job_for(block, entry, manifest, self.root, "cpu", self.root / "out", B.PROFILES[0])
        self.assertTrue(job["ready"])
        self.assertEqual(job["disk_reservation_bytes"], 200)
        self.assertEqual(job["disk_free_floor_bytes"], 20)
        self.assertTrue(job["remove_verified_proof_binaries"])
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

    def test_execution_order_preserves_all_selected_block_ids(self):
        blocks = [{"block": 1}, {"block": 2}, {"block": 3}]
        self.assertEqual([b["block"] for b in B.ordered_blocks(blocks, {1, 2, 3}, [2, 1, 3])], [2, 1, 3])
        self.assertEqual([b["block"] for b in B.ordered_blocks(blocks, {1, 3}, [2, 1, 3])], [1, 3])
        for order in ([1, 2], [1, 2, 2, 3], [1, 2, 3, 4]):
            with self.assertRaises(ValueError):
                B.ordered_blocks(blocks, {1, 2, 3}, order)

    def test_host_retained_hybrid_removes_device_only_custody_flags(self):
        inherited = {key: "1" for key in ("STWO_RV64_GPU_DEVICES", "STWO_RV64_GPU_DEVICE_CAPS",
                     "STWO_RV64_GPU_PLANNED_CPU_WORKERS", "STWO_RV64_GPU_DEVICE_TRACE", "STWO_RV64_GPU_DEVICE_BINDING")}
        env = B.worker_environment({"device": "3", "mode": "host-retained", "capacity_bytes": 100}, inherited)
        self.assertEqual(env["CUDA_VISIBLE_DEVICES"], "3")
        self.assertEqual(env["STWO_RV64_GPU_HOST_RETAINED"], "1")
        self.assertEqual(env["STWO_RV64_GPU_BYTE_CAP"], "100")
        self.assertEqual(env["STWO_RV64_GPU_RETAINED_SCOPES"], "2")
        self.assertNotIn("STWO_RV64_GPU_DEVICES", env)
        self.assertNotIn("STWO_RV64_GPU_DEVICE_TRACE", env)
        self.assertNotIn("STWO_RV64_GPU_DEVICE_BINDING", env)
        with self.assertRaises(ValueError):
            B.worker_environment({"device": "0,1", "mode": "host-retained", "capacity_bytes": 100}, {})
        with self.assertRaises(ValueError):
            B.worker_environment({"device": "0", "mode": "unknown"}, {})

    def test_gpu_log_evidence_preserves_scope_and_does_not_infer_wall(self):
        log = self.root / "producer.stderr"
        log.write_text("GPU_GKR_SPANS ordinal=0 ingress_ms=2.0 traversal_ms=3.5\nGPU_GKR ordinal=0 native_stage_wall_ns=90000000 gkr_kernel_launches=42\nGPU_PCS_NATIVE device_ns=2500000 total_ns=8000000\n")
        result = B.gpu_diagnostics(log)
        self.assertEqual(result["kernel_launches"], 42)
        self.assertEqual(result["device_ms"], 8.0)
        self.assertIn("not CUPTI", result["launch_count_scope"])
        log.write_text("CPU work finished in1ms\n")
        self.assertEqual(B.gpu_diagnostics(log)["kernel_launches"], 0)

    def test_recursive_assignment_counters_stay_separate_from_native_counters(self):
        log = self.root / "producer.stderr"
        log.write_text("GPU_GKR ordinal=0 gkr_kernel_launches=42\n"
                       "GPU_GKR_SPANS traversal_ms=3.5\n"
                       "GPU_OUTER_ASSIGNMENT_TIMING total_ns=9000000 seed_stream_ms=0.5 levels_stream_ms=7.0 launches=120000\n"
                       "GPU_OUTER_ASSIGNMENT_TIMING total_ns=5000000 levels_stream_ms=4.0 launches=9000\n")
        result = B.gpu_diagnostics(log)
        self.assertEqual(result["kernel_launches"], 42)
        self.assertEqual(result["device_ms"], 3.5)
        assignment = result["outer_assignment"]
        self.assertEqual(assignment["records"], 2)
        self.assertEqual(assignment["kernel_launches"], 129000)
        self.assertEqual(assignment["event_ms"], 11.5)
        self.assertEqual(assignment["node_wall_ns"], 14000000)
        self.assertIn("overlap", assignment["scope"])

    def test_monitor_retains_activity_and_memory_when_utilization_is_unavailable(self):
        monitor = B.DeviceMonitor("0,1")
        def sample(*args, **kwargs):
            monitor.stop.set()
            return B.subprocess.CompletedProcess([], 0,
                stdout="0, GPU-a, 100, 87\n0, GPU-a, 200, 13\n1, GPU-b, 300, N/A\n1, GPU-b, 400, 101\n2, GPU-c, 999, 100\n")
        with patch.object(B.subprocess, "run", side_effect=sample):
            monitor.run()
        monitor.thread = threading.Thread(target=lambda: None)
        monitor.thread.start()
        result = monitor.finish()
        self.assertEqual(result["errors"], [])
        self.assertEqual(result["samples"], 4)
        self.assertEqual(result["peak_used_bytes"], {"0": 200 << 20, "1": 400 << 20})
        self.assertEqual(result["kernel_activity"]["0"], {"samples": 2, "mean_percent": 50, "min_percent": 13, "max_percent": 87})
        self.assertEqual(result["kernel_activity"]["1"], {"samples": 0, "mean_percent": None, "min_percent": None, "max_percent": None})
        self.assertIn("not SM occupancy", result["kernel_activity_scope"])

    def test_guarded_monitor_freezes_before_release_and_releases_on_every_failure(self):
        from types import SimpleNamespace
        from unittest.mock import Mock
        for failure in (None, 'measurement', 'cleanup', 'write'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as tmp:
                events = []
                monitor = B.DeviceMonitor('0,1')
                def finish():
                    events.append('freeze')
                    if failure == 'measurement': raise RuntimeError('measurement failed')
                    return {'errors': []}
                def close():
                    events.append('release')
                    if failure == 'cleanup': raise RuntimeError('cleanup failed')
                def write(path, data):
                    events.append('write')
                    if failure == 'write': raise OSError('write failed')
                    path.write_text(json.dumps(data))
                monitor.finish = finish
                guard = SimpleNamespace(close=Mock(side_effect=close), record={'ready': {'devices': []}})
                with patch.object(B, 'atomic_json', side_effect=write):
                    if failure:
                        with self.assertRaises((RuntimeError, OSError)): monitor.finish_guarded(guard, Path(tmp) / 'resource-final.json', [1, 2], [])
                    else: monitor.finish_guarded(guard, Path(tmp) / 'resource-final.json', [1, 2], [])
                self.assertEqual(events, ['freeze', 'release', 'write'])
                guard.close.assert_called_once()

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

    def test_single_worker_stops_without_starting_any_later_block(self):
        called = []
        def fail(job, *_):
            called.append(job)
            raise RuntimeError("first block rejected")
        with patch.object(B, "execute", side_effect=fail):
            with self.assertRaisesRegex(RuntimeError, "first block rejected"):
                B.run_jobs([1, 2, 3], "gpu", None, None, 1)
        self.assertEqual(called, [1])

    def test_first_acceptance_gate_prevents_parallel_basket_after_rejection(self):
        called = []
        def fail(job, *_):
            called.append(job)
            raise RuntimeError("test block rejected")
        with patch.object(B, "execute", side_effect=fail):
            with self.assertRaisesRegex(RuntimeError, "test block rejected"):
                B.run_jobs([1, 2, 3], "gpu", None, None, 2, True)
        self.assertEqual(called, [1])

    def test_physical_disk_preflight_fails_before_producer(self):
        job = self.job(False)
        job["disk_reservation_bytes"] = 1 << 100
        with self.assertRaisesRegex(ValueError, "insufficient physical disk"):
            B.execute(job, "cpu", B.Admission([{"device": None, "capacity_bytes": 1}]))
        self.assertFalse((Path(job["output"]) / "proof").exists())

    def test_cleanup_only_after_fresh_acceptance_preserves_hashes_and_report(self):
        job = self.job(False)
        job["remove_verified_proof_binaries"] = True
        result = B.execute(job, "cpu", B.Admission([{"device": None, "capacity_bytes": 1}]))
        proof = Path(job["output"]) / "proof"
        self.assertFalse((proof / "cpu-0.bin").exists())
        self.assertTrue((proof / "bundle.json").is_file())
        self.assertTrue((proof / "report.json").is_file())
        self.assertIn("cpu-0.bin", result["artifact_sha256"])
        self.assertFalse(result["proof_binaries_retained"])

    def test_failed_producer_preserves_its_process_usage(self):
        job = self.job(False)
        job["produce"] = [sys.executable, "-c", "raise SystemExit(3)"]
        with self.assertRaises(RuntimeError):
            B.execute(job, "cpu", B.Admission([{"device": None, "capacity_bytes": 1}]))
        failure = B.load(Path(job["output"]) / "failure.json")
        self.assertEqual(failure["failed_process"]["exit_code"], 3)
        self.assertGreater(failure["failed_process"]["peak_rss_bytes"], 0)
        self.assertFalse(failure["accepted"])

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
