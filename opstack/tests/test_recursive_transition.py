"""Exercise the public statement and strict receiver admission boundary."""

import argparse
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from opstack import recursive_transition as transition

STATEMENT = {
    "schema": transition.STATEMENT,
    "chain_id": 10,
    "l1_chain_id": 1,
    "anchor_number": 100,
    "anchor_hash": "a1" * 32,
    "previous_number": 200,
    "previous_root": "b2" * 32,
    "next_number": 201,
    "next_root": "c3" * 32,
    "next_origin_number": 99,
    "next_origin_hash": "d4" * 32,
    "payload_commitment": "e5" * 32,
    "block_hash": "f6" * 32,
}


def receipt(output):
    return {
        "accepted": True,
        "completed_ethereum_block": True,
        "shared_fresh_native_authority": True,
        "native_verified_before_recursion": True,
        "existing_recursive_proofs_only": True,
        "trace_only_recursive_graphs": True,
        "security_qualified": False,
        "outer_profile": "stwo/circuit/native-om31/r1-b2-q108-p20-fold4/lens-v1",
        "output": list(output),
        "native": {
            "accepted": True,
            "completed_ethereum_block": True,
            "security_profile": transition.NATIVE_PROFILE,
            "output": list(output),
            "cpu_proofs": 1,
            "truth_proofs": 2,
        },
        "recursive": {
            "outer_backend": "cpu_trace_only_receiver",
            "assignment_source": "none_receiver_trace_only",
            "leaf_proofs": 3,
            "restored_leaves": 3,
            "fold_proofs": 2,
            "restored_folds": 2,
            "root_proof_bytes": 4096,
            "root_digest": [1] * 32,
            "root_authority": [2] * 32,
            "manifest": [3] * 32,
        },
    }


class RecursiveTransitionTests(unittest.TestCase):
    def test_cross_language_encoding_and_shared_fields(self):
        derivation, execution = transition.statement_outputs(STATEMENT)
        self.assertEqual(
            derivation.hex(),
            "79dc71b2ef04d3b09ab72857909758cc2d94b77d82907b8568d187e7b529ba72010a000000000000004f44",
        )
        self.assertEqual(
            execution.hex(),
            "a1070315845855c79cb5c43f2782fa954672205424a5b42a47d1962a0ca2a9ca010a000000000000004f50",
        )
        for field in (
            "anchor_hash",
            "previous_root",
            "next_root",
            "next_origin_hash",
            "payload_commitment",
            "block_hash",
        ):
            changed = transition.statement_outputs({**STATEMENT, field: "08" * 32})
            self.assertNotEqual(changed[0], derivation)
            self.assertEqual(
                changed[1] != execution, field in {"payload_commitment", "block_hash"}
            )
        for changes in (
            {"chain_id": 8453},
            {"l1_chain_id": True},
            {"next_number": 202},
            {"anchor_number": 98},
        ):
            with self.assertRaises(ValueError):
                transition.statement_outputs({**STATEMENT, **changes})

    def test_native_only_or_incomplete_tree_is_not_admitted(self):
        output = transition.statement_outputs(STATEMENT)[1]
        self.assertEqual(
            transition.admit_receipt(receipt(output), output)["service_proofs"], 2
        )
        native_only = receipt(output)
        del native_only["existing_recursive_proofs_only"]
        with self.assertRaises(ValueError):
            transition.admit_receipt(native_only, output)
        missing_truth = receipt(output)
        missing_truth["recursive"]["restored_leaves"] -= 1
        with self.assertRaises(ValueError):
            transition.admit_receipt(missing_truth, output)

    def test_join_needs_both_fresh_receivers_and_rejects_swapped_requests(self):
        outputs = transition.statement_outputs(STATEMENT)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            args = argparse.Namespace(
                runner=base / "runner",
                statement=base / "statement.json",
                derivation_request=base / "derivation.json",
                execution_request=base / "execution.json",
                derivation_proof=base / "derivation",
                execution_proof=base / "execution",
                fixed_setup_bytes=10,
                receiver_bytes=20,
                timeout=30,
            )
            args.runner.touch()
            args.statement.write_text(json.dumps(STATEMENT))
            for name, output, program in zip(
                ("derivation", "execution"), outputs, ("ab", "cd"), strict=True
            ):
                getattr(args, name + "_proof").mkdir()
                getattr(args, name + "_request").write_text(
                    json.dumps(
                        {
                            "elf": str(base / f"{name}.elf"),
                            "input": str(base / f"{name}.opx"),
                            "expected_output": output.hex(),
                            "elf_sha256": program * 32,
                            "input_sha256": "ef" * 32,
                        }
                    )
                )
            received = [
                subprocess.CompletedProcess([], 0, json.dumps(receipt(o)))
                for o in outputs
            ]
            with patch.object(
                transition.subprocess, "run", side_effect=received
            ) as run:
                self.assertTrue(transition.verify(args)["accepted"])
                self.assertEqual(
                    [call.args[0][3] for call in run.call_args_list],
                    ["verify-recursion-candidate"] * 2,
                )
            corrupt = subprocess.CalledProcessError(1, "verify-recursion-candidate")
            with (
                patch.object(
                    transition.subprocess, "run", side_effect=[received[0], corrupt]
                ),
                self.assertRaises(subprocess.CalledProcessError),
            ):
                transition.verify(args)
            raw_request = args.execution_request.read_text()
            args.execution_request.write_text(
                json.dumps({**json.loads(raw_request), "input": "relative.opx"})
            )
            with self.assertRaisesRegex(ValueError, "path must be absolute"):
                transition.verify(args)
            args.execution_request.write_text(raw_request)
            args.derivation_request, args.execution_request = (
                args.execution_request,
                args.derivation_request,
            )
            with patch.object(transition.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "request output"):
                    transition.verify(args)
                run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
