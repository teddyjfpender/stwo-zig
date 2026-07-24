from __future__ import annotations

import os
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.native_cuda_benchmark_lib import (  # noqa: E402
    BenchmarkError,
    Settings,
    Workload,
    run_benchmark,
)
from scripts.native_cuda_diagnostic_lib.model import Shape  # noqa: E402
from scripts.tests.test_native_cuda_diagnostic import (  # noqa: E402
    FAKE_PRODUCT,
)


class NativeCudaBenchmarkTests(unittest.TestCase):
    def make_product(self, root: Path, name: str) -> Path:
        product = root / name
        product.write_text(textwrap.dedent(FAKE_PRODUCT).lstrip())
        product.chmod(0o755)
        return product

    def settings(
        self,
        root: Path,
        candidate: Path,
        *,
        baseline: Path | None = None,
        rounds: int = 1,
    ) -> Settings:
        return Settings(
            candidate_bin=candidate,
            baseline_bin=baseline,
            output_path=root / "summary.json",
            repo_root=REPO_ROOT,
            profile_name="smoke",
            warmups=1,
            samples=2,
            rounds=rounds,
            cold_samples=1,
            cooldown_seconds=0.0,
            timeout_seconds=10.0,
            device_ordinal="0",
            bootstrap_resamples=1_000,
            workloads=(
                Workload(
                    "fake_latency",
                    "latency",
                    Shape(5, 8),
                    True,
                ),
            ),
        )

    def test_candidate_smoke_separates_lifecycle_and_steady_work(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings(
                root,
                self.make_product(root, "candidate-product"),
            )
            document, encoded = run_benchmark(settings)

            self.assertEqual(
                document["schema"],
                "native_cuda_structural_benchmark_v1",
            )
            self.assertFalse(document["headline_eligible"])
            self.assertFalse(document["portfolio"]["available"])
            self.assertFalse(document["coverage"]["activation_ready"])
            self.assertIn("hash_heavy", document["coverage"]["missing_classes"])
            self.assertEqual(settings.output_path.read_bytes(), encoded)

            workload = document["workloads"][0]
            self.assertTrue(workload["proof_gate"]["all_arms_byte_identical"])
            session = workload["sessions"][0]
            self.assertEqual(
                len(session["metrics"]["raw_repetition"]["resident_prove_ns"]),
                4,
            )
            self.assertEqual(
                session["metrics"]["mechanism"]["aot"]["cache_hits"],
                0,
            )
            self.assertEqual(
                session["metrics"]["mechanism"]["plan"]["reuse_count"],
                4,
            )

    def test_paired_rounds_produce_class_equal_portfolio(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = self.make_product(root, "candidate-product")
            baseline = self.make_product(root, "baseline-product")
            settings = self.settings(
                root,
                candidate,
                baseline=baseline,
                rounds=3,
            )
            document, _ = run_benchmark(settings)

            comparison = document["workloads"][0]["comparison"]
            self.assertAlmostEqual(
                comparison["candidate_over_baseline"],
                0.5,
                places=2,
            )
            self.assertTrue(comparison["passes_regression_ceiling"])
            self.assertTrue(document["portfolio"]["available"])
            self.assertGreater(document["portfolio"]["speedup"], 1.9)
            self.assertTrue(document["portfolio"]["passes_1_3x_target"])

    def test_fallback_telemetry_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings(
                root,
                self.make_product(root, "candidate-product"),
            )
            with mock.patch.dict(
                os.environ,
                {"FAKE_CUDA_MODE": "fallback"},
            ), self.assertRaisesRegex(BenchmarkError, "fallback"):
                run_benchmark(settings)
            self.assertFalse(settings.output_path.exists())

    def test_judge_profile_cannot_weaken_sampling_or_omit_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings(
                root,
                self.make_product(root, "candidate-product"),
            )
            weakened = Settings(
                **{
                    **settings.__dict__,
                    "profile_name": "judge",
                    "warmups": 9,
                }
            )
            with self.assertRaisesRegex(BenchmarkError, "baseline"):
                weakened.validate()


if __name__ == "__main__":
    unittest.main()
