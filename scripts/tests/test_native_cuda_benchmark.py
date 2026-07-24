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
from scripts.native_cuda_diagnostic_lib.model import (  # noqa: E402
    BlakeShape,
    Shape,
    XorShape,
)
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
        workload: Workload | None = None,
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
                workload
                or Workload(
                    "fake_latency", "latency", Shape(5, 8), True
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
                "native_cuda_structural_benchmark_v2",
            )
            self.assertFalse(document["headline_eligible"])
            self.assertFalse(document["portfolio"]["available"])
            self.assertFalse(document["coverage"]["activation_ready"])
            self.assertNotIn(
                "hash_heavy",
                document["coverage"]["missing_classes"],
            )
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

    def test_xor_workload_uses_its_own_protocol_shape_and_throughput(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shape = XorShape(14, 2, 3)
            settings = self.settings(
                root,
                self.make_product(root, "candidate-product"),
                workload=Workload(
                    "fake_xor",
                    "lookup_periodic",
                    shape,
                    True,
                ),
            )
            document, _ = run_benchmark(settings)

            workload = document["workloads"][0]
            self.assertEqual(shape.statement(), workload["statement"])
            session = workload["sessions"][0]
            command = session["raw"]["command"]
            self.assertIn("raw-stwo-xor-v1", command)
            self.assertIn("--log-size", command)
            self.assertNotIn("--log-n-rows", command)
            self.assertEqual("xor", session["raw"]["proof"]["example"])
            self.assertAlmostEqual(
                shape.trace_cells
                / (
                    session["metrics"]["steady"]["verified_ms"]["median"]
                    * 1000.0
                ),
                session["metrics"]["steady"][
                    "verified_committed_mcells_per_second"
                ],
            )

    def test_xor_workload_rejects_noncanonical_periodic_offset(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings(
                root,
                self.make_product(root, "candidate-product"),
                workload=Workload(
                    "invalid_xor",
                    "lookup_periodic",
                    XorShape(14, 2, 4),
                    True,
                ),
            )
            with self.assertRaisesRegex(BenchmarkError, "XOR offset"):
                settings.validate()

    def test_blake_shape_binds_rounds_cli_and_committed_cells(self) -> None:
        shape = BlakeShape(12, 10)
        shape.validate()
        self.assertEqual(
            ["--log-n-rows", "12", "--n-rounds", "10"],
            shape.cli_shape_args(),
        )
        self.assertEqual(
            4096 * 10 * 96,
            shape.trace_cells,
        )
        self.assertEqual(
            {
                "log_n_rows": 12,
                "n_rounds": 10,
            },
            shape.artifact_statement(),
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

    def test_historical_schema_v4_is_normalized_only_for_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings(
                root,
                self.make_product(root, "candidate-product"),
                baseline=self.make_product(root, "schema-v4-baseline"),
                rounds=3,
            )
            document, _ = run_benchmark(settings)

            baseline = next(
                session
                for session in document["workloads"][0]["sessions"]
                if session["arm"] == "baseline"
            )
            self.assertEqual("direct", baseline["raw"]["execution_mode"])
            self.assertTrue(
                baseline["raw"]["repetition"]["zero_final_pool_usage"]
            )
            self.assertEqual(
                0,
                baseline["raw"]["residency"]["graph_launches"],
            )

    def test_historical_schema_v5_is_admitted_only_for_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings(
                root,
                self.make_product(root, "candidate-product"),
                baseline=self.make_product(root, "schema-v5-baseline"),
            )
            document, _ = run_benchmark(settings)

            gate = document["workloads"][0]["proof_gate"]
            self.assertTrue(gate["historical_baseline"])
            self.assertEqual(
                "canonical_proof_statement_protocol_device",
                gate["semantic_comparison"],
            )
            self.assertEqual(
                {"baseline": 5, "candidate": 6},
                gate["report_schema_versions_by_arm"],
            )
            self.assertNotIn("baseline", gate["semantic_sha256_by_arm"])

    def test_historical_schema_v4_is_rejected_as_candidate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings(
                root,
                self.make_product(root, "schema-v4-candidate"),
            )
            with self.assertRaisesRegex(BenchmarkError, "schema_version"):
                run_benchmark(settings)

    def test_historical_schema_v4_rejects_graph_activity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings(
                root,
                self.make_product(root, "candidate-product"),
                baseline=self.make_product(root, "schema-v4-baseline"),
            )
            with mock.patch.dict(
                os.environ,
                {"FAKE_V4_GRAPH_ACTIVITY": "1"},
            ), self.assertRaisesRegex(BenchmarkError, "graph activity"):
                run_benchmark(settings)

    def test_historical_schema_v4_rejects_new_graph_fields(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings(
                root,
                self.make_product(root, "candidate-product"),
                baseline=self.make_product(root, "schema-v4-baseline"),
            )
            with mock.patch.dict(
                os.environ,
                {"FAKE_V4_GRAPH_CACHE_FIELD": "1"},
            ), self.assertRaisesRegex(BenchmarkError, "wrong fields"):
                run_benchmark(settings)

    def test_full_program_identity_may_differ_across_current_arms(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings(
                root,
                self.make_product(root, "candidate-product"),
                baseline=self.make_product(root, "program-drift-baseline"),
            )
            document, _ = run_benchmark(settings)

            gate = document["workloads"][0]["proof_gate"]
            self.assertIsNone(gate["program_sha256"])
            self.assertEqual(
                "schema_v6_semantic_digest",
                gate["semantic_comparison"],
            )
            self.assertEqual(
                gate["semantic_sha256_by_arm"]["candidate"],
                gate["semantic_sha256_by_arm"]["baseline"],
            )

    def test_semantic_identity_must_match_across_current_arms(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings(
                root,
                self.make_product(root, "candidate-product"),
                baseline=self.make_product(root, "semantic-drift-baseline"),
            )
            with self.assertRaisesRegex(BenchmarkError, "semantic ProofProgram"):
                run_benchmark(settings)

    def test_full_program_identity_must_be_stable_within_each_arm(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings(
                root,
                self.make_product(root, "candidate-product"),
            )
            with mock.patch.dict(
                os.environ,
                {"FAKE_FULL_PROGRAM_DRIFT": "1"},
            ), self.assertRaisesRegex(BenchmarkError, "full ProofProgram"):
                run_benchmark(settings)

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
