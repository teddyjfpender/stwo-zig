from __future__ import annotations

import os
import sys
import tempfile
import textwrap
import hashlib
import json
import unittest
from pathlib import Path
from unittest import mock


REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from scripts.native_cuda_benchmark_lib import (  # noqa: E402
    BenchmarkError,
    COVERAGE_MATRIX,
    Settings,
    SustainedShape,
    Workload,
    run_benchmark,
)
from scripts.native_cuda_benchmark_lib import runner as benchmark_runner  # noqa: E402
from scripts.native_cuda_benchmark_lib import sustained  # noqa: E402
from scripts.native_cuda_diagnostic_lib.model import (  # noqa: E402
    BlakeShape,
    DiagnosticError,
    PlonkShape,
    PoseidonShape,
    Shape,
    StateMachineShape,
    XorShape,
)
from scripts.tests.test_native_cuda_diagnostic import (  # noqa: E402
    FAKE_PRODUCT,
)


class NativeCudaBenchmarkTests(unittest.TestCase):
    def test_sustained_public_and_internal_cycle_contracts_are_distinct(
        self,
    ) -> None:
        with self.assertRaisesRegex(DiagnosticError, r"must be in \[2, 4\]"):
            SustainedShape(1).validate()
        self.assertEqual(1, sustained.validate_invocation_cycles(1))
        self.assertEqual(4, sustained.validate_invocation_cycles(4))
        for cycles in (0, 5):
            with self.subTest(cycles=cycles), self.assertRaisesRegex(
                BenchmarkError,
                r"must be in \[1, 4\]",
            ):
                sustained.validate_invocation_cycles(cycles)

    def test_mixed_service_is_executable_but_not_headline_scored(self) -> None:
        workload = next(
            item
            for item in COVERAGE_MATRIX
            if item.workload_id == "mixed_shape_queue"
        )
        self.assertTrue(workload.enabled)
        self.assertFalse(workload.headline_scored)
        self.assertEqual(SustainedShape(4), workload.shape)
        workload.validate()

    def test_sustained_command_names_distinct_product_path(self) -> None:
        command = sustained.command(
            Path("/product"),
            Path("/artifacts"),
            Path("/report.json"),
            4,
        )
        self.assertEqual("/product", command[0])
        self.assertEqual("sustain", command[1])
        self.assertNotIn("prove", command)
        self.assertEqual("4", command[command.index("--cycles") + 1])
        self.assertEqual(
            sustained.queue_digest(4),
            sustained.queue_digest(4),
        )
        self.assertNotEqual(
            sustained.queue_digest(3),
            sustained.queue_digest(4),
        )

    def test_sustained_result_is_excluded_from_portfolio(self) -> None:
        result = benchmark_runner._portfolio(
            [
                {
                    "headline_scored": False,
                    "structural_class": "sustained",
                    "comparison": {
                        "candidate_over_baseline": 0.01,
                        "round_ratios": [0.01],
                    },
                }
            ],
            1_000,
        )
        self.assertFalse(result["available"])

    def test_sustained_identity_binds_the_exact_artifact_catalog(self) -> None:
        catalog = {
            family: {
                "canonical_sha256": str(index) * 64,
                "canonical_bytes": index + 1,
                "artifact_sha256": str(index + 3) * 64,
                "artifact_bytes": index + 4,
            }
            for index, family in enumerate(sustained.FAMILIES)
        }
        raw = {
            "arm": "candidate",
            "proof_catalog": catalog,
            "device": {"uuid": "1" * 32},
            "product_identity": {"identity_sha256": "2" * 64},
        }
        gate = sustained.proof_identity(
            {"candidate": [raw]},
            [{"raw": raw}],
        )
        self.assertTrue(gate["all_arms_byte_identical"])

        changed = json.loads(json.dumps(raw))
        changed["proof_catalog"]["poseidon"]["artifact_sha256"] = "f" * 64
        with self.assertRaisesRegex(BenchmarkError, "proof catalog"):
            sustained.proof_identity(
                {"candidate": [raw]},
                [{"raw": changed}],
            )

    def test_coverage_matrix_includes_large_transform_regime(self) -> None:
        workload = next(
            item
            for item in COVERAGE_MATRIX
            if item.workload_id == "large_wf_log20x100"
        )
        self.assertTrue(workload.enabled)
        self.assertEqual("large", workload.structural_class)
        self.assertEqual(Shape(20, 100), workload.shape)

    def make_product(self, root: Path, name: str) -> Path:
        product = root / name
        product.write_text(textwrap.dedent(FAKE_PRODUCT).lstrip())
        product.chmod(0o755)
        return product

    def make_oracle(self, root: Path) -> tuple[Path, str]:
        oracle = root / "rust-oracle"
        oracle.write_text("#!/bin/sh\nexit 0\n")
        oracle.chmod(0o755)
        return oracle, hashlib.sha256(oracle.read_bytes()).hexdigest()

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
            self.assertFalse(
                document["coverage"]["structural_coverage_ready"]
            )
            self.assertEqual(
                1,
                document["coverage"]["native_air_activation"][
                    "release_ready_family_count"
                ],
            )
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
            self.assertFalse(workload["rust_oracle"]["accepted"])
            self.assertIsNone(workload["cold_comparison"])

    def test_paired_workload_has_separate_cold_gate_and_rust_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            candidate = self.make_product(root, "candidate-product")
            baseline = self.make_product(root, "baseline-product")
            oracle, oracle_sha256 = self.make_oracle(root)
            settings = Settings(
                **{
                    **self.settings(
                        root,
                        candidate,
                        baseline=baseline,
                    ).__dict__,
                    "rust_oracle_bin": oracle,
                    "rust_oracle_sha256": oracle_sha256,
                }
            )
            document, _ = run_benchmark(settings)

            workload = document["workloads"][0]
            self.assertTrue(workload["rust_oracle"]["accepted"])
            self.assertEqual(
                oracle_sha256,
                workload["rust_oracle"]["oracle_binary_sha256"],
            )
            self.assertEqual(
                "cold_process_external_wall",
                workload["cold_comparison"]["boundary"],
            )
            self.assertEqual(
                1,
                len(workload["cold_comparison"]["sample_ratios"]),
            )

    def test_rust_oracle_pin_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            oracle, _ = self.make_oracle(root)
            settings = Settings(
                **{
                    **self.settings(
                        root,
                        self.make_product(root, "candidate-product"),
                    ).__dict__,
                    "rust_oracle_bin": oracle,
                    "rust_oracle_sha256": "0" * 64,
                }
            )
            with self.assertRaisesRegex(BenchmarkError, "SHA-256 pin"):
                run_benchmark(settings)

    def test_headline_requires_target_oracle_and_both_time_boundaries(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = Settings(
                **{
                    **self.settings(
                        root,
                        self.make_product(root, "candidate-product"),
                    ).__dict__,
                    "profile_name": "judge",
                }
            )
            coverage = {"activation_ready": True}
            portfolio = {
                "available": True,
                "passes_1_3x_target": False,
            }
            workload = {
                "rust_oracle": {"accepted": True},
                "comparison": {"passes_regression_ceiling": True},
                "cold_comparison": {"passes_regression_ceiling": True},
            }
            self.assertFalse(
                benchmark_runner._headline_eligible(
                    settings, coverage, portfolio, [workload]
                )
            )
            portfolio["passes_1_3x_target"] = True
            self.assertTrue(
                benchmark_runner._headline_eligible(
                    settings, coverage, portfolio, [workload]
                )
            )
            workload["headline_scored"] = False
            self.assertFalse(
                benchmark_runner._headline_eligible(
                    settings, coverage, portfolio, [workload]
                )
            )
            workload["headline_scored"] = True
            workload["cold_comparison"]["passes_regression_ceiling"] = False
            self.assertFalse(
                benchmark_runner._headline_eligible(
                    settings, coverage, portfolio, [workload]
                )
            )

    def test_graph_capture_allows_multiple_distinct_aot_functions(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            settings = self.settings(
                root,
                self.make_product(root, "candidate-product"),
            )
            with mock.patch.dict(
                os.environ,
                {"FAKE_CUDA_AOT_LOADS": "2"},
            ):
                document, _ = run_benchmark(settings)

            aot = document["workloads"][0]["sessions"][0]["metrics"][
                "mechanism"
            ]["aot"]
            self.assertEqual(2, aot["loads"])
            self.assertEqual(2, aot["launches"])
            self.assertEqual(0, aot["cache_hits"])

    def test_poseidon_is_a_real_hash_heavy_structural_row(self) -> None:
        workload = next(
            item
            for item in COVERAGE_MATRIX
            if item.workload_id == "poseidon_log13_instances"
        )
        self.assertTrue(workload.enabled)
        self.assertEqual("hash_heavy", workload.structural_class)
        self.assertEqual(PoseidonShape(13), workload.shape)

    def test_state_machine_is_a_real_irregular_structural_row(self) -> None:
        workload = next(
            item
            for item in COVERAGE_MATRIX
            if item.workload_id == "irregular_state_machine_log16"
        )
        self.assertTrue(workload.enabled)
        self.assertEqual("irregular", workload.structural_class)
        self.assertEqual(StateMachineShape(16, 9, 3), workload.shape)

    def test_state_machine_shape_binds_public_input_and_protocol(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shape = StateMachineShape(14, 9, 3)
            settings = self.settings(
                root,
                self.make_product(root, "candidate-product"),
                workload=Workload(
                    "fake_state_machine",
                    "irregular",
                    shape,
                    True,
                ),
            )
            with mock.patch.dict(
                os.environ,
                {"FAKE_CUDA_AOT_LOADS": "3"},
            ):
                document, _ = run_benchmark(settings)

            workload = document["workloads"][0]
            self.assertEqual(shape.statement(), workload["statement"])
            session = workload["sessions"][0]
            command = session["raw"]["command"]
            self.assertIn("raw-stwo-state-machine-v1", command)
            self.assertIn("--initial-x", command)
            self.assertIn("--initial-y", command)
            self.assertEqual(
                "state_machine",
                session["raw"]["proof"]["example"],
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

    def test_plonk_workload_uses_structured_arithmetic_shape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shape = PlonkShape(14)
            settings = self.settings(
                root,
                self.make_product(root, "candidate-product"),
                workload=Workload(
                    "fake_plonk",
                    "structured_arithmetic",
                    shape,
                    True,
                ),
            )
            document, _ = run_benchmark(settings)

            workload = document["workloads"][0]
            self.assertEqual(shape.statement(), workload["statement"])
            command = workload["sessions"][0]["raw"]["command"]
            self.assertIn("raw-stwo-plonk-v1", command)
            self.assertIn("--log-n-rows", command)
            self.assertNotIn("--sequence-len", command)
            self.assertEqual(
                "plonk",
                workload["sessions"][0]["raw"]["proof"]["example"],
            )

    def test_blake_shape_binds_rounds_cli_and_committed_cells(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shape = BlakeShape(12, 10)
            settings = self.settings(
                root,
                self.make_product(root, "candidate-product"),
                workload=Workload(
                    "fake_blake",
                    "seeded_wide",
                    shape,
                    True,
                ),
            )
            document, _ = run_benchmark(settings)

            workload = document["workloads"][0]
            self.assertEqual(shape.statement(), workload["statement"])
            command = workload["sessions"][0]["raw"]["command"]
            self.assertIn("raw-stwo-blake-v1", command)
            self.assertIn("--n-rounds", command)
            self.assertEqual(
                "blake",
                workload["sessions"][0]["raw"]["proof"]["example"],
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
