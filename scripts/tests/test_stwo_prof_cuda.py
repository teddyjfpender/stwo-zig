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

    def test_stage_report_accepts_current_and_historical_cuda_schemas(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            for schema_version in (2, 3, 4, 5):
                path.write_text(json.dumps({
                    "schema_version": schema_version,
                    "backend": "cuda",
                    "device_stage_timing_ns": {"total": 7},
                }))
                self.assertEqual(
                    cudatools.load_stage_report(path)["device_stage_timing_ns"]["total"],
                    7,
                )
            path.write_text(json.dumps({
                "schema_version": 6,
                "backend": "cuda",
                "plan": {"semantic_sha256": "a" * 64},
                "device_stage_timing_ns": {"total": 7},
            }))
            self.assertEqual(
                cudatools.load_stage_report(path)["plan"]["semantic_sha256"],
                "a" * 64,
            )
            path.write_text(json.dumps({
                "schema_version": 6,
                "backend": "cuda",
                "device_stage_timing_ns": {"total": 7},
            }))
            with self.assertRaisesRegex(cudatools.ProfError, "semantic identity"):
                cudatools.load_stage_report(path)
            path.write_text(json.dumps({
                "schema_version": 1,
                "backend": "cuda",
                "device_stage_timing_ns": {"total": 7},
            }))
            with self.assertRaisesRegex(cudatools.ProfError, "stage timing"):
                cudatools.load_stage_report(path)

    def test_compute_profile_bounds_kernel_replay(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "profile.ncu-rep"
            artifact = output.with_suffix("")
            artifact = artifact.with_suffix(".ncu-rep")

            def run(arguments: list[str], timeout: int):
                artifact.touch()
                return subprocess.CompletedProcess(arguments, 0, "", "")

            with mock.patch.object(cudatools, "_tool", return_value="/bin/ncu"):
                with mock.patch.object(cudatools, "_run", side_effect=run) as execute:
                    self.assertEqual(
                        cudatools.compute_profile(
                            ["--", "prove"],
                            output,
                            kernel="n2b_stage",
                            set_name="detailed",
                            launch_skip=3,
                            launch_count=1,
                            timeout=60,
                        ),
                        artifact,
                    )

            arguments = execute.call_args.args[0]
            self.assertEqual(arguments[arguments.index("--launch-skip") + 1], "3")
            self.assertEqual(arguments[arguments.index("--launch-count") + 1], "1")
            self.assertIn("regex:n2b_stage", arguments)

    def test_compute_profile_rejects_unbounded_launch_count(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(cudatools.ProfError, "positive"):
                cudatools.compute_profile(
                    ["prove"],
                    Path(directory) / "profile.ncu-rep",
                    kernel=None,
                    set_name="basic",
                    launch_skip=0,
                    launch_count=0,
                    timeout=60,
                )


if __name__ == "__main__":
    unittest.main()
