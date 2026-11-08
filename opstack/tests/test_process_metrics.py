"""Resource receipts must retain the operating system's actual RSS units."""

import os
import platform
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from opstack.cpu import measured
from opstack.process_metrics import peak_rss_bytes


class ProcessMetricsTests(unittest.TestCase):
    def test_wait4_units_are_platform_specific(self):
        usage = SimpleNamespace(ru_maxrss=123456)
        self.assertEqual(peak_rss_bytes(usage, "Darwin"), 123456)
        self.assertEqual(peak_rss_bytes(usage, "Linux"), 123456 * 1024)
        with self.assertRaisesRegex(ValueError, "unsupported"):
            peak_rss_bytes(usage, "unknown")

    @unittest.skipUnless(platform.system() in ("Linux", "Darwin"), "wait4 units")
    def test_receipt_measures_a_real_allocating_child(self):
        with tempfile.TemporaryDirectory() as directory:
            row = measured(
                [sys.executable, "-c", "buffer = bytearray(16 * 1024 * 1024)"],
                Path(directory) / "allocate", 10, dict(os.environ),
            )
        self.assertEqual(row["returncode"], 0)
        self.assertGreaterEqual(row["peak_rss_bytes"], 16 << 20)
        # A small Python process must not be recorded as consuming tens of GiB.
        self.assertLess(row["peak_rss_bytes"], 1 << 30)
