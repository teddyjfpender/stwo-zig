"""The end-to-end CPU receipt must fail closed on incomplete recursive coverage."""

import argparse
import copy
import json
import tempfile
import unittest
from pathlib import Path

from opstack import cpu_recursion as recursion
from opstack.native_profiles import D2_NATIVE_PROFILE
from opstack.tests.test_recursive_transition import receipt


class CpuRecursionTests(unittest.TestCase):
    def arguments(self, root):
        return argparse.Namespace(
            recursive_runner=root / "runner", recursive_profile=recursion.DEFAULT_OUTER,
            recursive_workers=16, workers=8, native_profile=D2_NATIVE_PROFILE,
            recursive_live_bytes=52 << 30, recursive_receiver_bytes=32 << 30,
            timeout=60, transition_statement=None,
        )

    def received(self, output):
        report = receipt(output)
        report["native"]["security_profile"] = D2_NATIVE_PROFILE
        report["outer_profile"] = "stwo/circuit/native-om31/m6-diet-k3-q108-p20-fold4/lens-v1"
        report["recursive"].update(fold_proofs=1, restored_folds=1)
        return report

    def exercise(self, report, failure=None, commands=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.arguments(root)
            rows = {}
            if commands is None:
                commands = []

            def measure(command, prefix, timeout, env, allow_failure):
                commands.append((command, dict(env)))
                if command[3] == "verify-recursion-candidate":
                    prefix.with_suffix(".stdout").write_text(json.dumps(report))
                return {"returncode": failure or 0, "timed_out": False, "wall_ns": 1}

            result = recursion.run(
                args, {"expected_output": bytes(range(43)).hex()}, root, 8 << 30,
                {}, measure, rows.__setitem__,
            )
            return result, commands, rows

    def test_fresh_native_and_recursive_authority_is_required(self):
        expected = bytes(range(43))
        report = self.received(expected)
        result, commands, rows = self.exercise(report)
        self.assertEqual(result["admitted"]["native_profile"], D2_NATIVE_PROFILE)
        self.assertEqual(result["admitted"]["recursive_leaves"], 3)
        self.assertEqual([c[0][3] for c in commands], [
            "recurse-candidate", "verify-recursion-candidate"
        ])
        self.assertEqual(commands[0][1]["STWO_RV64_FOLD_ARITY"], "3")
        self.assertNotIn("STWO_ZIG_RV64_SETUP_CACHE", commands[1][1])
        self.assertEqual(set(rows), {"recursive_produce", "recursive_receive"})
        for field in (
            "completed_ethereum_block", "existing_recursive_proofs_only",
            "trace_only_recursive_graphs", "native_verified_before_recursion",
            "shared_fresh_native_authority",
        ):
            bad = copy.deepcopy(report)
            bad[field] = False
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.exercise(bad)
        for location, key, value in (
            ("native", "security_profile", "conjectured128_b2_q108_p20_fold4"),
            ("native", "output", [0] * 43),
            ("recursive", "restored_leaves", 0),
            ("recursive", "leaf_proofs", 2),
        ):
            bad = copy.deepcopy(report)
            bad[location][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.exercise(bad)

    def test_producer_failure_never_starts_a_receiver(self):
        commands = []
        with self.assertRaisesRegex(RuntimeError, "production failed"):
            self.exercise(self.received(bytes(range(43))), failure=1, commands=commands)
        self.assertEqual(len(commands), 1)

    def test_fixed_admission_refuses_before_launching_children(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            args = self.arguments(root)
            with self.assertRaisesRegex(ValueError, "inside both"):
                recursion.run(args, {}, root, 53 << 30, {}, None, None)


if __name__ == "__main__":
    unittest.main()
