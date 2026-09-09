"""Scheduling tests use tiny subprocesses; they do not claim STARK acceptance."""
from contextlib import contextmanager
import copy
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts import ethereum_bounded_verifier as subject


class BoundedVerifierTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.binary = self.root / "verifier"
        self.binary.write_text(f"#!{sys.executable}\nimport time\ntime.sleep(0.3)\nprint('{{}}')\n")
        self.binary.chmod(0o700)
        self.materialization = self.root / "materialization.json"
        self.materialization.write_text("{}")
        self.proof = self.root / "proof.bin"
        self.proof.write_bytes(b"native proof transport fixture")
        self.metadata = self.root / "leaf.json"
        self.metadata.write_text(json.dumps({"proof_bytes": self.proof.stat().st_size,
                                             "proof_sha256": list(hashlib.sha256(self.proof.read_bytes()).digest())}))
        self.policy = {"schema": subject.POLICY_SCHEMA, "verifier": subject.identity(self.binary),
                       "materialization": subject.identity(self.materialization), "baselines": [],
                       "child_byte_budget": 3 * subject.GIB, "host_reserve_bytes": 6 * subject.GIB,
                       "maximum_proof_bytes": 128 * 1024 ** 2, "timeout_seconds": 180}
        self.argv = [str(self.binary), subject.MODE, str(self.proof), str(self.metadata),
                     str(self.materialization), self.policy["materialization"]["sha256"], "--workers", "1"]
        plan = self.write("plan.json", {"verifier": self.policy["verifier"]})
        request = self.write("request.json", {"argv": self.argv, "plan_sha256": plan["sha256"]})
        execution = self.write("execution.json", {"exit_code": 0})
        receipt = self.write("receipt.json", {"endpoint": subject.ENDPOINT, "verification": {
            "endpoint": "verified_native_selected_leaf", "worker_count": 1,
            "retained_admission_destroyed_before_proof": True,
            "materialization_sha256": list(bytes.fromhex(self.policy["materialization"]["sha256"])),
            "peak_footprint_bytes": 2 * subject.GIB, "request_ns": 90_000_000_000}})
        self.policy["baselines"] = [{"plan": plan, "request": request, "execution": execution, "receipt": receipt}]
        self.lane = patch.object(subject, "LANE_LOCK", str(self.root / "lane.lock"))
        self.lane.start()
        self.addCleanup(self.lane.stop)

    def write(self, name, value):
        path = self.root / name
        path.write_text(json.dumps(value))
        return subject.identity(path)

    def load(self, policy=None):
        pin = self.write("policy.json", self.policy if policy is None else policy)
        return subject.load_policy(Path(pin["path"]), pin["sha256"])

    @contextmanager
    def monitor(self, *, available=16 * subject.GIB, footprint=subject.GIB):
        with patch.object(subject, "host_headroom", return_value={"physical_bytes": 36 * subject.GIB, "available_bytes": available, "source": "test"}), \
                patch.object(subject, "child_footprint", return_value=footprint):
            yield

    def run_child(self, *, timeout=10, observation=None):
        if observation is None:
            observation = {}
        with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
            return subject.run(self.argv, self.load(), stdout=stdout, stderr=stderr, timeout=timeout, observation=observation)

    def test_pinned_measured_policy_admits_exact_leaf_route(self):
        subject.admit_command(self.load(), self.argv)

    def test_unpinned_or_unmeasured_policy_rejects(self):
        pin = self.write("policy.json", self.policy)
        with self.assertRaisesRegex(ValueError, "pin differs"):
            subject.load_policy(Path(pin["path"]), "0" * 64)
        for changes in ({"baselines": []}, {"child_byte_budget": 4 * subject.GIB},
                        {"host_reserve_bytes": subject.GIB}, {"timeout_seconds": 181},
                        {"maximum_proof_bytes": 129 * 1024 ** 2}, {"child_byte_budget": 2 * subject.GIB}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.load({**self.policy, **changes})

    def test_baseline_must_pin_same_binary_and_success(self):
        for field in ("plan", "execution", "receipt"):
            policy = copy.deepcopy(self.policy)
            value = json.loads(Path(policy["baselines"][0][field]["path"]).read_bytes())
            if field == "plan":
                value["verifier"]["sha256"] = "0" * 64
            elif field == "execution":
                value["exit_code"] = 1
            else:
                value["verification"]["worker_count"] = 2
            policy["baselines"][0][field] = self.write("changed.json", value)
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.load(policy)

    def test_compile_proof_wrapper_bundle_workers_and_binary_rejected_before_launch(self):
        policy = self.load()
        bad = []
        for mode in ("build", "prove", "verify-bundle-fixed-program-v5", "--initial-v1", "verify-leaf"):
            bad.append([self.argv[0], mode, *self.argv[2:]])
        bad.extend([["/bin/true", *self.argv[1:]], [*self.argv[:-1], "2"], [*self.argv, "--no-lock"]])
        for argv in bad:
            with self.subTest(argv=argv), patch.object(subject.subprocess, "Popen") as launch, self.assertRaises(ValueError):
                subject.admit_command(policy, argv)
            launch.assert_not_called()

    def test_changed_input_and_binary_reject(self):
        policy = self.load()
        self.proof.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, "metadata"):
            subject.admit_command(policy, self.argv)
        self.binary.write_text("changed executable")
        with self.assertRaises(ValueError):
            subject.admit_command(policy, self.argv)

    def test_bounded_leaf_completes_while_heavy_lock_is_held(self):
        heavy = self.root / "heavy.lock"
        with heavy.open("w") as lock, self.monitor(), patch.object(subject, "HELD_LOCK_ENV", "STWO_TEST_HEAVY_LOCK"):
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with patch.dict(os.environ, {"STWO_TEST_HEAVY_LOCK": str(heavy)}):
                observation = {}
                self.assertEqual(self.run_child(observation=observation).returncode, 0)
            self.assertTrue(observation["resource_envelope_passed"])
            self.assertFalse(observation["os_memory_limit"])

    def test_even_consistently_replaced_proof_and_metadata_fail_post_execution_custody(self):
        def replace_inputs(pid):
            self.proof.write_bytes(b"different proof")
            self.metadata.write_text(json.dumps({"proof_bytes": self.proof.stat().st_size,
                                                 "proof_sha256": list(hashlib.sha256(self.proof.read_bytes()).digest())}))
            return subject.GIB

        with self.monitor(), patch.object(subject, "child_footprint", side_effect=replace_inputs), \
                self.assertRaisesRegex(ValueError, "custody changed"):
            self.run_child()

    def test_second_bounded_verifier_is_rejected(self):
        with subject.lane(), self.assertRaisesRegex(ValueError, "already occupied"):
            with subject.lane():
                self.fail("second lane admitted")

    def test_low_headroom_never_starts_child(self):
        with self.monitor(available=8 * subject.GIB), patch.object(subject.subprocess, "Popen") as launch:
            with self.assertRaisesRegex(ValueError, "headroom"):
                self.run_child()
            launch.assert_not_called()

    def test_memory_overrun_kills_only_own_child(self):
        unrelated = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(5)"])
        self.addCleanup(lambda: unrelated.poll() is None and unrelated.terminate())
        observation = {}
        with self.monitor(footprint=4 * subject.GIB), self.assertRaisesRegex(ValueError, "footprint"):
            self.run_child(observation=observation)
        self.assertIsNone(unrelated.poll())
        self.assertFalse(observation["resource_envelope_passed"])
        with self.assertRaises(ProcessLookupError):
            os.kill(observation["pid"], 0)
        unrelated.terminate()
        unrelated.wait()

    def test_live_headroom_loss_and_monitor_failure_drain_child(self):
        for failure in (ValueError("unavailable monitor"), {"available_bytes": subject.GIB}):
            observation = {}
            initial = {"available_bytes": 16 * subject.GIB}
            with self.monitor(), patch.object(subject, "host_headroom", side_effect=[initial, failure]), self.assertRaises(ValueError):
                self.run_child(observation=observation)
            with self.assertRaises(ProcessLookupError):
                os.kill(observation["pid"], 0)

    def test_timeout_drains_child(self):
        with self.monitor(), self.assertRaisesRegex(ValueError, "timed out"):
            self.run_child(timeout=0.01)

    def test_real_current_process_monitor_is_available(self):
        self.assertGreater(subject.child_footprint(os.getpid()), 0)
        sample = subject.host_headroom()
        self.assertGreater(sample["physical_bytes"], 0)
        self.assertGreaterEqual(sample["available_bytes"], 0)


if __name__ == "__main__":
    unittest.main()
