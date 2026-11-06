"""Fresh receiver reports must bind successful complete mainnet output."""

import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "cpu", Path(__file__).parents[1] / "cpu.py"
)
cpu = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(cpu)


class CPUReceiptTests(unittest.TestCase):
    def test_accept_complete_output(self):
        report = {
            "accepted": True,
            "completed_ethereum_block": True,
            "security_qualified": False,
            "output": [255] * 43,
        }
        cpu.accept(report, "ff" * 43)
        for field, value in (
            ("accepted", False),
            ("completed_ethereum_block", False),
            ("security_qualified", True),
            ("output", [0] * 43),
        ):
            bad = dict(report)
            bad[field] = value
            with self.assertRaises(ValueError):
                cpu.accept(bad, "ff" * 43)

    def test_timeout_writes_failure_receipt_and_reaps_child(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory) / "timeout"
            receipt = cpu.measured(
                [sys.executable, "-c", "import time; time.sleep(2)"],
                prefix,
                0.01,
                dict(os.environ),
                True,
            )
            self.assertFalse(prefix.with_suffix(".heartbeat.json").exists())
            self.assertTrue(receipt["timed_out"])
            self.assertLess(receipt["returncode"], 0)
            self.assertEqual(
                json.loads(prefix.with_suffix(".json").read_text()), receipt
            )

    def test_valid_utf8_wire_output(self):
        cpu.accept(
            {
                "accepted": True,
                "completed_ethereum_block": True,
                "security_qualified": False,
                "output": "A" * 43,
            },
            "41" * 43,
        )


if __name__ == "__main__":
    unittest.main()
