"""Device-free CLI and lifecycle checks for explicit small-tree AOT selection."""
import subprocess
import sys
import unittest
from pathlib import Path

from riscv_segment_v2_detached_gate import require_producer_lifecycle
from riscv_segment_v2_detached_parent_gate import require_metal_lifecycle

PIN = "a" * 64
SCRIPTS = Path(__file__).resolve().parent


def leaf_receipt(profile: str) -> str:
    lines = [f"SEGMENT_V2_NATIVE_METAL_AOT profile={profile} manifest_sha256={PIN}"]
    for index in range(2):
        lines += [
            f"SEGMENT_V2_NATIVE_MEMORY path=temporal segment={index} backend=metal "
            "producer_live_bytes_after_destroy=0 before_fresh_decode=true",
            f"SEGMENT_V2_TWO_CHILD_CANDIDATE segment={index} completed={'true' if index else 'false'} "
            f"first_cycle={64 if index else 0} retired_cycles={34 if index else 64} "
            "native_backend=metal producer_live_bytes_after_destroy=0 status=unverified_candidate "
            "parent_proof_created=false proof_bytes=100",
            f"SEGMENT_V2_TWO_CHILD_NATIVE_METAL segment={index} dispatches=1 poseidon_commits=1",
        ]
    lines += ["SEGMENT_V2_TWO_CHILD_PRODUCER status=unverified_candidates native_backend=metal "
              "owners_destroyed=true parent_proof_created=false"]
    return "\n".join(lines)


def parent_receipt(profile: str | None) -> str:
    line = ("DETACHED_PARENT_METAL dispatches=3 poseidon_commits=1 cpu_fallbacks=0 "
            "host_composition_components=31 pow_dispatches=2 runtime_released=true "
            f"manifest_sha256={PIN}")
    return line if profile is None else line + f" profile={profile}"


class AotProfileTests(unittest.TestCase):
    def test_leaf_profile_and_manifest_are_both_required(self):
        for option, tag in (("core-v2", "core_v2"), ("recursive-framework-v1", "recursive_framework_v1")):
            require_producer_lifecycle(leaf_receipt(tag), "metal", PIN, aot_profile=option)
            with self.assertRaisesRegex(RuntimeError, "selected Metal AOT profile"):
                require_producer_lifecycle(leaf_receipt(tag), "metal", "b" * 64, aot_profile=option)
        require_producer_lifecycle(leaf_receipt("core_v2"), "metal", PIN)
        with self.assertRaisesRegex(RuntimeError, "selected Metal AOT profile"):
            require_producer_lifecycle(leaf_receipt("core_v2"), "metal", PIN, aot_profile="recursive-framework-v1")

    def test_parent_profile_is_explicit_and_legacy_core_is_scoped(self):
        for option, tag in (("core-v2", "core_v2"), ("recursive-framework-v1", "recursive_framework_v1")):
            result = require_metal_lifecycle(parent_receipt(tag), PIN, option)
            self.assertEqual(result["profile"], tag)
            self.assertFalse(result["legacy_core_profile"])
            with self.assertRaises(RuntimeError):
                require_metal_lifecycle(parent_receipt(None), PIN, option)
        self.assertTrue(require_metal_lifecycle(parent_receipt(None), PIN)["legacy_core_profile"])
        for receipt, pin, selected in (
            (parent_receipt("core_v2"), PIN, "recursive-framework-v1"),
            (parent_receipt("recursive_framework_v1"), PIN, None),
            (parent_receipt("recursive_framework_v1"), "b" * 64, "recursive-framework-v1"),
            (parent_receipt("recursive_framework_v1") + "\n" + parent_receipt("recursive_framework_v1"), PIN, "recursive-framework-v1"),
        ):
            with self.assertRaises(RuntimeError):
                require_metal_lifecycle(receipt, pin, selected)

    def test_cpu_clis_reject_even_explicit_core_profile_before_file_access(self):
        tree = ["--admission", "missing", "--admission-sha256", PIN, "--output", "missing", "--backend", "cpu"]
        for role in ("leaf-producer", "parent-producer", "leaf-verifier", "parent-verifier"):
            tree += ["--" + role, "missing", "--" + role + "-sha256", PIN]
        cases = (
            ("riscv_segment_v2_detached_tree_gate.py", tree + ["--aot-profile", "core-v2"]),
            ("riscv_segment_v2_detached_gate.py", ["--verifier", "missing", "--bundle", "missing",
                "--key-sha256", PIN, "--expected-wire", "missing", "--output", "missing", "--aot-profile", "core-v2"]),
            ("riscv_segment_v2_detached_parent_gate.py", ["--verifier", "missing", "--verifier-sha256", PIN,
                "--bundle", "missing", "--key-sha256", PIN, "--expected-root", "missing", "--expected-root-sha256", PIN,
                "--output", "missing", "--metal-aot-profile", "core-v2"]),
        )
        for script, arguments in cases:
            with self.subTest(script=script):
                result = subprocess.run([sys.executable, str(SCRIPTS / script), *arguments], capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 2)
                self.assertIn("AOT profile", result.stderr)
                self.assertNotIn("Traceback", result.stderr)


if __name__ == "__main__":
    unittest.main()
