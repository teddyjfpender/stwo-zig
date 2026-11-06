"""Fresh receiver reports must bind successful complete mainnet output."""

import importlib.util
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
