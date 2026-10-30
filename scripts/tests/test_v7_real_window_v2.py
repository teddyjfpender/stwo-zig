"""Admission controls for durable real-window recursive measurements."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

SCRIPTS = Path(__file__).parents[1]
sys.path.insert(0, str(SCRIPTS))
SPEC = importlib.util.spec_from_file_location("v7_real_window_v2", SCRIPTS / "v7_real_window_v2.py")
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class RootAdmissionTests(unittest.TestCase):
    def exercise(self, root, *, canonical=True, wrong_artifact=False, policy=None):
        bundle, snapshots = root / "bundle", root / "snapshots"
        bundle.mkdir()
        snapshots.mkdir()
        elf = b"selected executable"
        (bundle / "guest.elf").write_bytes(elf)
        selected = {
            "elf_sha256": hashlib.sha256(elf).hexdigest(),
            "incoming_sha256": "1" * 64,
            "outgoing_sha256": "2" * 64,
            "window": {"skip_cycles": 1234, "cycles": 32768},
        }
        capture = json.dumps(selected).encode()
        (snapshots / "capture.json").write_bytes(capture)
        binary = root / "prover"
        binary.write_bytes(b"selected immutable binary")
        build = root / "build.json"
        build.write_text(json.dumps({"binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest()}))
        args = SimpleNamespace(bundle=bundle, snapshots=snapshots, capture_sha256=hashlib.sha256(capture).hexdigest(),
                               binary=binary, build_manifest=build, destination=root / "result",
                               segment_cycles=16384, workers=8, complete_root=True,
                               native_layout="canonical", sparse_initialization=False,
                               resident_memory=False, native_main_cache_mib=256, deep_group_mib=1,
                               root_preparation_mib=8192, root_row_log=25, root_batch_size=0,
                               root_parallel_families=1, root_parallel_preparation=1, reuse_native_compiler=False, shared_epoch_prefix=False, materialized_parent_polynomials=False,
                               native_compiler_mib=2048, profile_root=False, cuda_deep=False, cuda_reference=False,
                               cuda_device=0, cuda_sm=90, cuda_device_mib=16384, cuda_composition=False, cuda_interactions=False,
                               reuse_original_captures=False, original_capture_mib=4096)
        vars(args).update(policy or {})

        def execute(command, *, cwd, env, stdout, stderr, check):
            self.assertEqual("C", env["LC_ALL"])
            # A fresh invocation must override inherited diagnostic security and
            # source choices, and load capsules rather than replay the prefix.
            self.assertEqual("1", env["STWO_V7_WINDOW_CANONICAL"])
            self.assertEqual("8", env["STWO_V7_WINDOW_WORKERS"])
            self.assertEqual("1234", env["STWO_V7_WINDOW_SKIP"])
            self.assertNotIn("STWO_V7_WINDOW_INPUT", env)
            self.assertNotIn("STWO_RISCV_CUDA_CPU_REFERENCE", env)
            self.assertNotIn("STWO_RISCV_RECURSIVE_PARENT_PROFILE", env)
            if not args.materialized_parent_polynomials:
                self.assertNotIn("STWO_RISCV_MATERIALIZED_POLYNOMIALS", env)
            self.assertEqual(b"capsule", Path(env["STWO_V7_WINDOW_INCOMING"]).read_bytes())
            proof = b"detached root proof"
            measured = dict(selected, scope="declared_nonterminal_window_to_complete_recursive_root",
                            canonical_security=canonical, query_count=70 if canonical else 8,
                            pow_bits=26 if canonical else 0, external_capsules=True,
                            originals_destroyed=True, complete_global_closure=True, verified=True,
                            cycles=32768, skip_cycles=1234, worker_count=8, segment_cycles=16384,
                            ethereum_block=False, skipped_prefix_proved=False, root_bytes=len(proof),
                            root_sha256=hashlib.sha256(proof).hexdigest())
            Path(env["STWO_V7_WINDOW_REPORT"]).write_text(json.dumps(measured))
            Path(env["STWO_V7_WINDOW_ROOT_OUTPUT"]).write_bytes(proof + (b"changed" if wrong_artifact else b""))
            return subprocess.CompletedProcess(command, 0)

        with patch.dict(RUNNER.PINS, {"guest.elf": (selected["elf_sha256"], len(elf))}, clear=True), \
             patch.object(RUNNER, "snapshot_bytes", return_value=b"capsule"), \
             patch.object(RUNNER.subprocess, "run", side_effect=execute), \
             patch.dict(RUNNER.os.environ, {"STWO_V7_WINDOW_INPUT": "/stale/input", "STWO_V7_WINDOW_CANONICAL": "0", "STWO_RISCV_CUDA_CPU_REFERENCE": "1", "STWO_RISCV_RECURSIVE_PARENT_PROFILE": "1", "STWO_RISCV_MATERIALIZED_POLYNOMIALS": "1"}):
            return RUNNER.run(args)

    def test_complete_root_retains_exact_artifact_and_selected_boundary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            self.assertEqual(0, self.exercise(root))
            self.assertTrue((root / "result" / "root.proof").is_file())
            self.assertFalse(json.loads((root / "result" / "invocation.json").read_text())["preparation"]["prefix_replay"])

    def test_diagnostic_security_is_not_accepted_as_canonical_closure(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(RuntimeError, "canonical window closure"):
                self.exercise(Path(temporary), canonical=False)

    def test_root_artifact_must_match_attested_bytes(self):
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(RuntimeError, "artifact does not match"):
                self.exercise(Path(temporary), wrong_artifact=True)

    def test_old_gate_cannot_attest_new_protocol_or_resource_choices(self):
        for policy in ({"native_layout": "degree-bounded-q2"}, {"sparse_initialization": True},
                       {"resident_memory": True}, {"native_main_cache_mib": 1024},
                       {"deep_group_mib": 4}, {"root_preparation_mib": 16384},
                       {"root_batch_size": 2}, {"root_parallel_families": 4},
                       {"root_parallel_preparation": 4},
                       {"reuse_native_compiler": True}, {"shared_epoch_prefix": True}, {"materialized_parent_polynomials": True},
                       {"reuse_original_captures": True}, {"original_capture_mib": 8192}, {"native_compiler_mib": 4096}):
            with self.subTest(policy=policy), tempfile.TemporaryDirectory() as temporary:
                with self.assertRaises(RuntimeError):
                    self.exercise(Path(temporary), policy=policy)

    def test_partial_or_fallback_composition_is_rejected(self):
        report = {"external_composition_executor": True, "recursive_proof_count": 3}
        receipt = {"schema": "stwo-v7-cuda-framework-composition-v1", "complete_helper_succeeded": True,
                   "fallback_allowed": False, "resident_proof": False, "stats": {"calls": 3, "kernel_launches": 75}}
        RUNNER.validate_composition_receipt(receipt, report)
        for update in ({"fallback_allowed": True}, {"complete_helper_succeeded": False},
                       {"resident_proof": True}, {"stats": {"calls": 2, "kernel_launches": 50}},
                       {"stats": {"calls": 3, "kernel_launches": 0}}):
            with self.subTest(update=update), self.assertRaises(RuntimeError):
                RUNNER.validate_composition_receipt(receipt | update, report)
        for change in ({"external_composition_executor": False}, {"recursive_proof_count": False}):
            with self.subTest(change=change), self.assertRaises(RuntimeError):
                RUNNER.validate_composition_receipt(receipt, report | change)


if __name__ == "__main__":
    unittest.main()


class PortableTimingTests(unittest.TestCase):
    def test_host_time_flags_are_explicit(self):
        binary = Path("/tmp/prover").resolve()
        self.assertEqual(["/usr/bin/time", "-l", str(binary)], RUNNER.timed_command(binary, "Darwin"))
        self.assertEqual(["/usr/bin/time", "-v", str(binary)], RUNNER.timed_command(binary, "Linux"))
        with self.assertRaises(ValueError):
            RUNNER.timed_command(binary, "Windows")

    def test_rss_units_are_not_conflated(self):
        from scripts.v7_real_window_results import peak_rss_bytes
        self.assertEqual(1024, peak_rss_bytes("1024 maximum resident set size"))
        self.assertEqual(1024 * 1024, peak_rss_bytes("Maximum resident set size (kbytes): 1024"))
        self.assertIsNone(peak_rss_bytes("no measurement"))
