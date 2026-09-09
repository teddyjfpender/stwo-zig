from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest import mock

from scripts import ethereum_block_proof_protocol as proof_protocol


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "autoresearch/benchmarks/ethereum_block_benchmark_matrix.py"
SPEC = importlib.util.spec_from_file_location("ethereum_block_benchmark_matrix_tested", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
subject = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(subject)
import ethereum_block_benchmark_zisk_final_admission as zisk_final_cli  # noqa: E402


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def reseal(value: dict) -> dict:
    value.pop("content_sha256", None)
    value["content_sha256"] = proof_protocol.content_sha256(value)
    return value


def empty_system() -> dict:
    return {
        "status": "incomplete",
        "timings": {
            "execution": None,
            "witness_generation": None,
            "proving": None,
            "verification": None,
            "total_wall_ns": None,
        },
        "trace_generation": None,
        "execution_work": None,
        "proof_custody": None,
        "geometry": {field: None for field in subject.benchmark_protocol.GEOMETRY_FIELDS},
        "security": {field: None for field in subject.benchmark_protocol.SECURITY_FIELDS},
        "hardware": {field: None for field in subject.benchmark_protocol.HARDWARE_FIELDS},
    }


class EthereumBlockBenchmarkMatrixTests(unittest.TestCase):
    def setUp(self) -> None:
        self.matrix = subject.build_matrix(
            subject.corpus_authority.DEFAULT_CORPUS,
            subject.comparison.DEFAULT_MANIFEST,
        )

    def test_matrix_is_exactly_five_by_two_by_six_and_nonpromotable(self) -> None:
        subject.validate_matrix(self.matrix)
        self.assertEqual(5, len(self.matrix["fixtures"]))
        self.assertEqual(list(subject.SYSTEMS), list(self.matrix["fixtures"][0]["systems"]))
        for fixture in self.matrix["fixtures"]:
            self.assertFalse(fixture["comparison_ready"])
            for system in subject.SYSTEMS:
                self.assertEqual(set(subject.SCOPES),
                                 set(fixture["systems"][system]["stages"]))
        self.assertEqual(5_000_000_000,
                         self.matrix["aggregate"]["target_average_wall_ns"])
        self.assertIsNone(
            self.matrix["aggregate"]["observed_end_to_end_average_wall_ns"],
        )
        self.assertFalse(self.matrix["comparison_ready"])
        checklist = self.matrix["aggregate"]["promotion_checklist"]
        self.assertTrue(checklist["all_five_fixtures_present"])
        self.assertTrue(checklist["both_systems_present"])
        for gate, satisfied in checklist.items():
            if gate not in {"all_five_fixtures_present", "both_systems_present"}:
                self.assertFalse(satisfied, gate)
        diagnostic = self.matrix["contract"]["diagnostic_models"][0]
        self.assertEqual(318_960_000,
                         diagnostic["median_ordinary_cycles_per_second"])
        self.assertEqual("2.76",
                         diagnostic["projection"]["rounded_replay_only_seconds"])
        self.assertFalse(diagnostic["matrix_timing_admissible"])
        self.assertFalse(diagnostic["headline_eligible"])
        self.assertEqual(0, sum(
            stage["timing"] is not None
            for fixture in self.matrix["fixtures"]
            for system in fixture["systems"].values()
            for stage in system["stages"].values()
        ))

    def test_zisk_inner_proof_and_final_boundaries_are_explicit(self) -> None:
        reference = self.matrix["fixtures"][0]["systems"]["zisk"]["stages"]
        self.assertEqual("retained_nonpromotable", reference["execution"]["status"])
        self.assertIsNone(reference["execution"]["timing"])
        self.assertEqual(
            "retained-inner-proof-log-is-not-a-canonical-base-proof-receipt",
            reference["base_proofs"]["reason"],
        )
        self.assertEqual("no-retained-final-aggregation-proof",
                         reference["aggregation"]["reason"])
        self.assertEqual("no-retained-final-proof", reference["end_to_end"]["reason"])

    def test_zisk_final_admission_changes_only_correctness_cells(self) -> None:
        evidence = {
            "kind": subject.zisk_final.EVIDENCE_KIND,
            "receipt": {"path": "/retained/zisk-final.json"},
            "projection": {"proof": {"sha256": digest("zisk-final")}},
        }

        def stage(_evidence, _fixture, _manifest, scope):
            return {
                "scope": scope,
                "status": ("retained_nonpromotable" if scope == "end_to_end"
                           else "complete_nonpromotable"),
                "reason": f"retained-zisk-final-{scope}-without-promotion",
                "evidence": evidence,
                "timing": None,
                "timing_authority": None,
                "security_target_bits": None,
                "fresh_verification": scope != "aggregation",
            }

        with tempfile.TemporaryDirectory() as raw:
            receipt = Path(raw) / "receipt.json"
            receipt.write_bytes(b"receipt\n")
            with mock.patch.object(
                zisk_final_cli.evidence_protocol, "evidence", return_value=evidence,
            ), mock.patch.object(
                zisk_final_cli.admission, "validate_stage", side_effect=stage,
            ):
                matrix = zisk_final_cli.admit(
                    self.matrix, self.matrix["fixtures"][0]["fixture_id"], receipt,
                )
                subject.validate_matrix(matrix)
                stages = matrix["fixtures"][0]["systems"]["zisk"]["stages"]
                self.assertEqual("unavailable", stages["base_proofs"]["status"])
                self.assertEqual("complete_nonpromotable", stages["aggregation"]["status"])
                self.assertEqual("complete_nonpromotable",
                                 stages["fresh_verification"]["status"])
                self.assertEqual("retained_nonpromotable", stages["end_to_end"]["status"])
                self.assertTrue(all(stages[name]["timing"] is None for name in (
                    "aggregation", "fresh_verification", "end_to_end",
                )))
                self.assertFalse(matrix["comparison_ready"])
                mutation = copy.deepcopy(matrix)
                mutation["fixtures"][0]["systems"]["zisk"]["stages"][
                    "fresh_verification"
                ]["timing"] = {"wall_ns": 1, "user_ns": 1, "system_ns": 0}
                reseal(mutation)
                with self.assertRaises(subject.MatrixError):
                    subject.validate_matrix(mutation)

    def _fake_leaf(
        self, root: Path, *, corpus_match: bool,
    ) -> tuple[Path, dict]:
        fixture = self.matrix["fixtures"][0]
        if corpus_match:
            source_input = fixture["systems"]["stwo_zig"]["input_transport"]
            source_output = fixture["systems"]["stwo_zig"]["output_transport"]
        else:
            source_input = {"bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()}
            source_output = {"bytes": 20, "sha256": digest("smoke-output")}
        source = root / "source.json"
        source.write_bytes(proof_protocol.canonical_bytes({
            "input": {**source_input, "path": "/retained/input"},
            "expected_output": {**source_output, "path": "/retained/output"},
        }))
        receipt = root / "leaf-join.json"
        receipt.write_bytes(b"retained-leaf-join\n")
        value = {
            "files": {"source_request": {"path": str(source)}},
            "bindings": {
                "segment_index": 0,
                "proof_sha256": digest("proof"),
                "source_public_statement_sha256": digest("source-statement"),
                "recursive_statement_sha256": digest("recursive-statement"),
                "security_identity_sha256": digest("security"),
            },
            "timing": {
                "prove": {"wall_ns": 11, "user_ns": 12, "system_ns": 13},
                "verify": {"wall_ns": 17, "user_ns": 18, "system_ns": 19},
            },
            "status": "joined_evidence_complete_descriptor_unavailable",
            "evidence_complete": True,
            "performance_claim_eligible": True,
            "recursive_admissible": False,
        }
        return receipt, value

    def test_current_style_leaf_is_capability_only_not_corpus_timing(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            receipt, value = self._fake_leaf(Path(raw), corpus_match=False)
            with mock.patch.object(subject.leaf_join, "validate_receipt", return_value=value):
                matrix = subject.admit_leaf_capability(self.matrix, receipt)
                subject.validate_matrix(matrix)
            capability = matrix["capability_evidence"][0]
            self.assertIsNone(capability["corpus_fixture_id"])
            self.assertEqual("non-corpus-leaf-proof-capability-only",
                             capability["claim_boundary"])
            self.assertFalse(capability["corpus_comparison_eligible"])
            self.assertEqual(
                "unavailable",
                matrix["fixtures"][0]["systems"]["stwo_zig"]["stages"]
                ["base_proofs"]["status"],
            )

    def test_even_matching_one_leaf_never_becomes_a_block_comparison(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            receipt, value = self._fake_leaf(Path(raw), corpus_match=True)
            with mock.patch.object(subject.leaf_join, "validate_receipt", return_value=value):
                matrix = subject.admit_leaf_capability(self.matrix, receipt)
                subject.validate_matrix(matrix)
            capability = matrix["capability_evidence"][0]
            self.assertEqual(self.matrix["fixtures"][0]["fixture_id"],
                             capability["corpus_fixture_id"])
            self.assertFalse(capability["corpus_comparison_eligible"])
            self.assertFalse(matrix["comparison_ready"])

    def _fake_execution(self, root: Path, output_sha: str) -> tuple[Path, dict]:
        bundle = root / "bundle"
        bundle.mkdir()
        guest_input = self.matrix["fixtures"][0]["systems"]["stwo_zig"]["input_transport"]
        plan = {
            "execution_profile": "rv32im-zkvm-ethereum-v1",
            "source": {"clean": False},
            "elf": {"bytes": 10, "sha256": digest("elf")},
            "input": {"bytes": guest_input["bytes"], "sha256": guest_input["sha256"]},
        }
        (bundle / "plan.json").write_text(json.dumps(plan) + "\n")
        (bundle / "execution.ndjson").write_bytes(b"{}\n")
        (bundle / "receipt.json").write_bytes(b"{}\n")
        receipt = {
            "segment_count": 210,
            "total_cycles": 880_760_229,
            "total_core_trace_rows": 880_727_328,
            "total_external_trace_rows": 32_901,
            "max_segment_cycle_count": 4_194_304,
            "clock_frame": "leaf_local",
            "segment_statement_v2_admissible": False,
            "output_sha256": output_sha,
        }
        return bundle, receipt

    def test_real_execution_receipt_is_admitted_without_invented_timing(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            expected = self.matrix["fixtures"][0]["systems"]["stwo_zig"][
                "output_transport"
            ]["sha256"]
            bundle, receipt = self._fake_execution(Path(raw), expected)
            with mock.patch.object(
                subject.segmented_execution, "validate_bundle", return_value=receipt,
            ):
                matrix = subject.admit_stwo_execution(
                    self.matrix, self.matrix["fixtures"][0]["fixture_id"], bundle,
                )
                subject.validate_matrix(matrix)
            stage = matrix["fixtures"][0]["systems"]["stwo_zig"]["stages"]["execution"]
            self.assertEqual("retained_nonpromotable", stage["status"])
            self.assertIsNone(stage["timing"])
            self.assertIn("execution-only", stage["reason"])

    def test_execution_output_must_match_the_corpus(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            bundle, receipt = self._fake_execution(Path(raw), digest("wrong-output"))
            with mock.patch.object(
                subject.segmented_execution, "validate_bundle", return_value=receipt,
            ), self.assertRaisesRegex(subject.MatrixError, "output differs"):
                subject.admit_stwo_execution(
                    self.matrix, self.matrix["fixtures"][0]["fixture_id"], bundle,
                )

    def _result(self, *, execution: bool) -> dict:
        protocol = subject.comparison.load_manifest()["benchmark_protocol"]
        systems = {"zisk": empty_system(), "stwo": empty_system()}
        if execution:
            systems["stwo"]["timings"]["execution"] = {
                "wall_ns": 100, "user_ns": 80, "system_ns": 20,
            }
        return {
            "schema": subject.benchmark_protocol.RESULT_SCHEMA,
            "statement_sha256": protocol["statement_sha256"],
            "systems": systems,
            "comparison_ready": False,
        }

    def test_typed_result_path_accepts_partial_scope_but_not_empty_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            result_path = Path(raw) / "result.json"
            result_path.write_bytes(proof_protocol.canonical_bytes(self._result(execution=False)))
            with self.assertRaisesRegex(subject.MatrixError, "no retained stage evidence"):
                subject.admit_benchmark_result(
                    self.matrix, self.matrix["fixtures"][0]["fixture_id"], result_path,
                )
            result_path.write_bytes(proof_protocol.canonical_bytes(self._result(execution=True)))
            matrix = subject.admit_benchmark_result(
                self.matrix, self.matrix["fixtures"][0]["fixture_id"], result_path,
            )
            subject.validate_matrix(matrix)
            stage = matrix["fixtures"][0]["systems"]["stwo_zig"]["stages"]["execution"]
            self.assertEqual("typed-result-measured", stage["timing_authority"])
            self.assertFalse(matrix["comparison_ready"])

    def test_resealed_claim_timing_contract_and_average_mutations_reject(self) -> None:
        mutations = (
            lambda value: value.__setitem__("comparison_ready", True),
            lambda value: value["contract"]["hardware_policy"].__setitem__(
                "current_battery_diagnostics_promotable", True,
            ),
            lambda value: value["contract"]["diagnostic_models"][0].update({
                "matrix_timing_admissible": True, "headline_eligible": True,
            }),
            lambda value: value["fixtures"][0]["systems"]["zisk"]["stages"]
            ["aggregation"].__setitem__("reason", "complete"),
            lambda value: value["fixtures"][0]["systems"]["stwo_zig"]["stages"]
            ["base_proofs"].__setitem__(
                "timing", {"wall_ns": 1, "user_ns": 1, "system_ns": 0},
            ),
            lambda value: value["aggregate"].update({
                "observed_end_to_end_average_wall_ns": 1, "target_met": True,
            }),
            lambda value: value["aggregate"]["promotion_checklist"].__setitem__(
                "security_matched", True,
            ),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(self.matrix)
                mutation(value)
                reseal(value)
                with self.assertRaises(subject.MatrixError):
                    subject.validate_matrix(value)

    def test_report_is_machine_generated_and_has_no_inferred_timing(self) -> None:
        report = subject.render_report(self.matrix)
        self.assertEqual(60, sum(line.startswith("| mainnet-")
                                 for line in report.splitlines()))
        self.assertIn("Missing values are rendered as `null`", report)
        self.assertIn("AC/no-interference host envelope", report)
        self.assertIn("Inner proofs and isolated leaves are not E2E", report)
        self.assertIn("Diagnostic model (not a benchmark result)", report)
        self.assertIn("replay-only projection of about `2.76` s", report)
        self.assertIn("cannot populate any matrix timing cell", report)
        self.assertIn("Apples-to-apples promotion checklist", report)
        self.assertIn("| security_matched | `false` |", report)
        self.assertIn("| execution_scope_complete | `false` |", report)

    def test_advertised_direct_cli_materializes_validates_and_renders(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            staging = root / "staging"
            staging.mkdir()
            matrix = root / "matrix.json"
            report = root / "report.md"
            commands = (
                ["python3", str(MODULE_PATH), "validate-corpus"],
                ["python3", str(MODULE_PATH), "materialize", "--output", str(matrix),
                 "--staging-directory", str(staging)],
                ["python3", str(MODULE_PATH), "validate", "--matrix", str(matrix)],
                ["python3", str(MODULE_PATH), "render-report", "--matrix", str(matrix),
                 "--output", str(report), "--staging-directory", str(staging)],
            )
            for command in commands:
                completed = subprocess.run(
                    command, cwd=ROOT, capture_output=True, text=True,
                    timeout=30, check=False,
                )
                self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertTrue(matrix.is_file() and report.is_file())


if __name__ == "__main__":
    unittest.main()
