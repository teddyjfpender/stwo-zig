from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
CLI_ROOT = ROOT / "autoresearch" / "cli"
if str(CLI_ROOT) not in sys.path:
    sys.path.insert(0, str(CLI_ROOT))

from stwo_prof import cudatools


class CudaToolsTests(unittest.TestCase):
    def test_caps_parses_explicit_device_identity(self) -> None:
        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="0, NVIDIA RTX 4090, GPU-deadbeef, 8.9, 24564, 580.1, 2520, 10501\n",
            stderr="",
        )
        with mock.patch.object(cudatools.shutil, "which", return_value="/bin/tool"):
            with mock.patch.object(
                cudatools.subprocess,
                "run",
                return_value=completed,
            ):
                devices = cudatools.caps()
        self.assertEqual(devices[0]["compute_cap"], "8.9")
        self.assertEqual(devices[0]["uuid"], "GPU-deadbeef")

    def test_stage_report_requires_cuda_schema_v2(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text(json.dumps({
                "schema_version": 2,
                "backend": "cuda",
                "device_stage_timing_ns": {"total": 7},
            }))
            self.assertEqual(
                cudatools.load_stage_report(path)["device_stage_timing_ns"]["total"],
                7,
            )
            path.write_text(json.dumps({
                "schema_version": 1,
                "backend": "cuda",
            }))
            with self.assertRaisesRegex(cudatools.ProfError, "stage timing"):
                cudatools.load_stage_report(path)


if __name__ == "__main__":
    unittest.main()
