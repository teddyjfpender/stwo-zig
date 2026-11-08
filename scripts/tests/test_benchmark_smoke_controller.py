#!/usr/bin/env python3
"""Unit tests for the benchmark smoke controller."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts.bench.benchmark_smoke_lib import controller


class BenchmarkSmokeControllerTests(unittest.TestCase):
    def test_each_generated_sample_retires_the_previous_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            artifact = Path(temp_dir) / "proof.json"

            def publish(_cmd, _env):
                self.assertFalse(artifact.exists())
                artifact.write_text("proof", encoding="utf-8")
                return {"seconds": 1.0, "peak_rss_kb": None}

            with mock.patch.object(controller, "run_timed", side_effect=publish):
                result = controller.summarize_samples(
                    "prove",
                    ["prover"],
                    warmups=1,
                    repeats=2,
                    generated_artifact_path=artifact,
                )

            self.assertEqual(len(result["raw_runs"]), 3)
            self.assertTrue(artifact.exists())

    def test_latency_summary_is_robust_to_a_single_scheduler_outlier(self) -> None:
        samples = iter([0.0037] * 10 + [0.068954])

        def measure(_cmd, _env):
            return {"seconds": next(samples), "peak_rss_kb": None}

        with mock.patch.object(controller, "run_timed", side_effect=measure):
            result = controller.summarize_samples(
                "prove",
                ["prover"],
                warmups=0,
                repeats=11,
            )

        self.assertEqual(result["median_seconds"], 0.0037)
        self.assertGreater(result["avg_seconds"], 0.009)


if __name__ == "__main__":
    unittest.main()
