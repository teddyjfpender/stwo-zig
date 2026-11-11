"""Mantle admission binds actual input; these tests never accept a mock proof."""

import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from opstack.mantle import input as M

F = Path(__file__).parents[1] / "mantle/tests/fixtures"


def fixture():
    return {
        "schema": 1,
        "fixture": json.loads((F / "block-103132217.json").read_text()),
        "expected": {
            "config_sha256": "0xb9583f9b493763c945cc961535b9298070c92d538be1af77523b27053f4a23de",
            "block_hash": "0xbac88cdc801196ab975bb07717bd964f87b14b093ac94997f47f768ed7ff1fcc",
        },
        "preimages": json.loads((F / "block-103132217-preimages.json").read_text()),
    }


class MantleInputTests(unittest.TestCase):
    def test_wrong_nested_types_reject_before_execution(self):
        for field in ("fixture", "expected", "preimages"):
            value = fixture()
            value[field] = None
            with self.assertRaises(ValueError):
                M.statement(json.dumps(value).encode())
        value = fixture()
        value["fixture"]["rollup_config"]["l1_chain_id"] = True
        with self.assertRaisesRegex(ValueError, "network"):
            M.statement(json.dumps(value).encode())

    def test_exact_input_bound_public_statement_and_mutations(self):
        value = fixture()
        raw = json.dumps(value, separators=(",", ":")).encode()
        digest = hashlib.sha256(
            b"stwo/mantle/execution/v1\0"
            + hashlib.sha256(raw).digest()
            + bytes.fromhex(value["expected"]["block_hash"][2:])
        ).digest()
        public = digest + b"\x01" + (5000).to_bytes(8, "little") + b"ME"
        self.assertEqual(M.statement(raw), public)
        self.assertNotEqual(M.statement(raw + b" "), public)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.json"
            path.write_bytes(raw)
            self.assertEqual(M.read(path), (raw, public))
        for change in (
            "schema",
            "chain",
            "fork",
            "config",
            "parent",
            "adjacency",
            "preimage",
            "block",
        ):
            bad = copy.deepcopy(value)
            if change == "schema":
                bad["schema"] = True
            elif change == "chain":
                bad["fixture"]["rollup_config"]["l2_chain_id"] = 10
            elif change == "fork":
                bad["fixture"]["rollup_config"]["mantle_arsia_time"] += 1
            elif change == "config":
                bad["expected"]["config_sha256"] = "0x" + "11" * 32
            elif change == "parent":
                bad["fixture"]["expected_parent_hash"] = "0x" + "11" * 32
            elif change == "adjacency":
                bad["fixture"]["payload"]["timestamp"] = "0x6af44a7b"
            elif change == "preimage":
                bad["preimages"][0]["data"] = "0x00"
            else:
                bad["expected"]["block_hash"] = "0x" + "11" * 32
            mutated = json.dumps(bad).encode()
            if change == "block":
                self.assertNotEqual(M.statement(mutated), public)
            else:
                with self.assertRaises(ValueError, msg=change):
                    M.statement(mutated)
        for bad in (
            raw.replace(b'"schema":1', b'"schema":1,"schema":1'),
            b"{}",
            b" " * (M.MAX_INPUT + 1),
        ):
            with self.assertRaises(ValueError):
                M.statement(bad)
        self.assertNotEqual(public[:-2] + b"OP", public)
        self.assertNotEqual(public[:33] + (10).to_bytes(8, "little") + b"ME", public)

    def test_benchmark_uses_existing_host_guest_input_mode(self):
        from unittest.mock import patch
        import sys
        from opstack import benchmark

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            block = root / "fixtures/block-103132217"
            block.mkdir(parents=True)
            (block / "guest-input.json").write_text(json.dumps(fixture()))
            argv = [
                "benchmark.py",
                "--network",
                "mantle",
                "--profile",
                "ethereum_services_v3",
                "--fixtures",
                str(root / "fixtures"),
                "--artifacts",
                str(root / "out"),
                "--samples",
                "1",
            ]
            with (
                patch.object(sys, "argv", argv),
                patch.object(
                    benchmark, "run", side_effect=RuntimeError("host boundary")
                ) as native,
            ):
                with self.assertRaisesRegex(RuntimeError, "host boundary"):
                    benchmark.main()
            self.assertEqual(native.call_args.args[0][1], "guest-input")
            self.assertEqual(
                (root / "out/103132217.guest-input.json").read_bytes(),
                (block / "guest-input.json").read_bytes(),
            )


if __name__ == "__main__":
    unittest.main()
