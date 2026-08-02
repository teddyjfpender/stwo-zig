from __future__ import annotations

import contextlib
import copy
import io
import json
import tempfile
import unittest
from pathlib import Path

from autoresearch.benchmarks import cairo_csp_comparison as comparison
from autoresearch.benchmarks import cairo_csp_comparison_support as support


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "vectors/cairo/csp/comparison-manifest-v1.json"


class CairoCspComparisonTests(unittest.TestCase):
    def setUp(self) -> None:
        self.manifest = comparison.load_json(MANIFEST)

    def test_committed_plan_authenticates_exact_inputs_outputs_and_evidence(self) -> None:
        plan = comparison.validate_manifest(self.manifest, root=ROOT)
        self.assertEqual(plan["runnable_rows"], 0)
        self.assertEqual(plan["pending_rows"], 4)
        self.assertEqual(
            [row["id"] for row in plan["rows"]],
            [
                "sha256_2048_bytes",
                "keccak256_2048_bytes",
                "poseidon2_m31_16_elements",
                "ecdsa_secp256k1_32_byte_digest",
            ],
        )
        self.assertEqual(
            plan["rows"][0]["logical_input_sha256"],
            "f11d48451256c7133c5e465ea9cb93b594b0cc0c5f9a6c4faf48e608f157a126",
        )
        self.assertEqual(
            plan["rows"][1]["expected_output_hex"],
            "4239a7a63551619c764842fa2d46777df6bd00792b06b4555e41cfaceb197308",
        )
        self.assertEqual(
            plan["rows"][0]["relationship"],
            "exact_constrained_source_prepared_proof_pending",
        )
        self.assertEqual(
            plan["rows"][1]["relationship"],
            "exact_constrained_source_prepared_proof_pending",
        )
        self.assertEqual(plan["rows"][2]["relationship"], "analogy_only")
        self.assertEqual(plan["rows"][3]["relationship"], "analogy_only")

    def test_exact_vectors_are_explicit_not_filename_inferences(self) -> None:
        poseidon = self.manifest["rows"][2]
        self.assertEqual(len(poseidon["logical_input"]["exact_value"]["elements"]), 16)
        self.assertEqual(
            poseidon["expected_output"]["exact_value"]["elements"],
            [
                1219947694,
                1958311843,
                386768187,
                383282517,
                1539980231,
                1770892248,
                1452077376,
                1496370507,
            ],
        )
        ecdsa = self.manifest["rows"][3]
        exact = ecdsa["logical_input"]["exact_value"]
        self.assertEqual(len(bytes.fromhex(exact["digest_hex"])), 32)
        self.assertEqual(len(bytes.fromhex(exact["public_key_sec1_hex"])), 65)
        self.assertEqual(bytes.fromhex(exact["public_key_sec1_hex"])[0], 4)
        self.assertEqual(len(bytes.fromhex(exact["signature_rs_hex"])), 64)

    def test_sha_logical_digest_name_distinguishes_normalized_and_framed_input(self) -> None:
        sha_row = self.manifest["rows"][0]
        self.assertNotEqual(
            sha_row["riscv"]["input_sha256"],
            sha_row["logical_input"]["logical_input_sha256"],
        )
        self.assertEqual(
            sha_row["logical_input"]["logical_input_sha256"],
            sha_row["expected_output"]["hex"],
        )

    def test_hash_rows_require_constrained_pr171_programs_and_finalizers(self) -> None:
        for index, base, finalizer in (
            (0, "sha2", "finalize_sha256"),
            (1, "sha3", "finalize_keccak"),
        ):
            with self.subTest(row=self.manifest["rows"][index]["id"]):
                candidate = self.manifest["rows"][index]["cairo_candidate"]
                self.assertEqual(candidate["relationship"], "analogy_only")
                self.assertIsNotNone(candidate["semantic_gap"])
                self.assertEqual(
                    candidate["proof_sound_path"],
                    {
                        "base_program": base,
                        "required_finalizer": finalizer,
                        "requires_public_digest_output": True,
                    },
                )

    def test_exact_hash_sources_are_formally_prepared_but_not_promoted(self) -> None:
        preparation = self.manifest["cairo_authority"][
            "exact_hash_fixture_preparation"
        ]
        self.assertEqual(
            preparation["prepared_fixtures"],
            ["sha256_2048_bytes", "keccak256_2048_bytes"],
        )
        self.assertEqual(
            preparation["proof_sound_role"],
            "exact_constrained_source_prepared_proof_pending",
        )
        provenance = comparison.load_json(ROOT / preparation["provenance_path"])
        for name in preparation["prepared_fixtures"]:
            fixture = provenance["fixtures"][name]
            self.assertEqual(
                fixture["status"], "source_ready_compilation_pending"
            )
            self.assertIsNone(fixture["compiled_program"])
            self.assertIsNone(fixture["proof"])
            self.assertIsNone(fixture["verifier_receipt"])

    def test_prepared_fixture_provenance_pin_mutation_fails_closed(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["cairo_authority"]["exact_hash_fixture_preparation"][
            "provenance_sha256"
        ] = "0" * 64
        with self.assertRaisesRegex(comparison.ComparisonError, "digest mismatch"):
            comparison.validate_manifest(changed, root=ROOT)

    def test_prepared_source_cannot_be_called_runnable_without_evidence(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["cairo_authority"]["exact_hash_fixture_preparation"]["verdict"] = (
            "exact_runnable"
        )
        with self.assertRaisesRegex(comparison.ComparisonError, "promoted without evidence"):
            comparison.validate_manifest(changed, root=ROOT)

    def test_driver_refuses_to_time_pending_rows(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            status = comparison.main(
                [
                    "--root",
                    str(ROOT),
                    "--manifest",
                    str(MANIFEST),
                    "--require-runnable",
                ]
            )
        self.assertEqual(status, 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("no exact_runnable Cairo rows", stderr.getvalue())

    def test_json_driver_reports_classification_without_running_a_prover(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = comparison.main(
                ["--root", str(ROOT), "--manifest", str(MANIFEST), "--json"]
            )
        self.assertEqual(status, 0)
        result = json.loads(stdout.getvalue())
        self.assertEqual(result["runnable_rows"], 0)
        self.assertEqual(result["pending_rows"], 4)

    def test_riscv_input_pin_mutation_fails_closed(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["rows"][0]["riscv"]["input_sha256"] = "0" * 64
        with self.assertRaisesRegex(comparison.ComparisonError, "RISC-V input_sha256"):
            comparison.validate_manifest(changed, root=ROOT)

    def test_expected_output_mutation_fails_independent_sha_check(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["rows"][0]["expected_output"]["hex"] = "0" * 64
        with self.assertRaisesRegex(comparison.ComparisonError, "not the input digest"):
            comparison.validate_manifest(changed, root=ROOT)

    def test_keccak_reference_matches_known_legacy_vectors(self) -> None:
        self.assertEqual(
            support.keccak256(b"").hex(),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
        )
        self.assertEqual(
            support.keccak256(b"abc").hex(),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45",
        )

    def test_keccak_output_mutation_fails_independent_reference(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["rows"][1]["expected_output"]["hex"] = "00" * 32
        changed["rows"][1]["expected_output"]["exact_value"]["u256_le_decimal"] = "0"
        with self.assertRaisesRegex(comparison.ComparisonError, "not the input digest"):
            comparison.validate_manifest(changed, root=ROOT)

    def test_v1_schema_rejects_every_exact_runnable_promotion(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["rows"][0]["status"] = "exact_runnable"
        changed["rows"][0]["relationship"] = "exact_equivalent"
        changed["rows"][0]["cairo_candidate"]["relationship"] = (
            "exact_equivalent_candidate"
        )
        changed["rows"][0]["cairo_candidate"]["semantic_gap"] = None
        with self.assertRaisesRegex(comparison.ComparisonError, "schema upgrade"):
            comparison.validate_manifest(changed, root=ROOT)

    def test_unconstrained_corelib_syscall_cannot_be_relabelled_exact(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["rows"][0]["cairo_candidate"]["relationship"] = (
            "exact_equivalent_candidate"
        )
        changed["rows"][0]["cairo_candidate"]["semantic_gap"] = None
        with self.assertRaisesRegex(
            comparison.ComparisonError, "unconstrained syscall reference"
        ):
            comparison.validate_manifest(changed, root=ROOT)

    def test_required_hash_finalizer_and_public_output_cannot_be_dropped(self) -> None:
        for field, value in (
            ("required_finalizer", "not_the_finalizer"),
            ("requires_public_digest_output", False),
        ):
            with self.subTest(field=field):
                changed = copy.deepcopy(self.manifest)
                changed["rows"][1]["cairo_candidate"]["proof_sound_path"][field] = value
                with self.assertRaisesRegex(
                    comparison.ComparisonError, "constrained hash proof path"
                ):
                    comparison.validate_manifest(changed, root=ROOT)

    def test_modern_corelib_remains_semantic_reference_only(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["cairo_authority"]["corelib"]["proof_soundness_role"] = (
            "proof_sound_implementation"
        )
        with self.assertRaisesRegex(
            comparison.ComparisonError, "promoted beyond semantic reference"
        ):
            comparison.validate_manifest(changed, root=ROOT)

    def test_field_or_curve_near_match_cannot_be_relabelled_exact(self) -> None:
        for index in (2, 3):
            with self.subTest(row=self.manifest["rows"][index]["id"]):
                changed = copy.deepcopy(self.manifest)
                changed["rows"][index]["relationship"] = "exact_equivalent"
                with self.assertRaisesRegex(
                    comparison.ComparisonError, "near-match was relabelled as exact"
                ):
                    comparison.validate_manifest(changed, root=ROOT)

    def test_public_input_binding_cannot_be_dropped(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["rows"][1]["public_statement"]["required_bindings"].remove(
            "logical_input_sha256"
        )
        with self.assertRaisesRegex(comparison.ComparisonError, "public statement bindings"):
            comparison.validate_manifest(changed, root=ROOT)

    def test_pr171_iteration_fixture_cannot_be_silently_promoted(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["cairo_authority"]["pr171_fixture_assessment"]["verdict"] = (
            "exact_csp_input"
        )
        with self.assertRaisesRegex(comparison.ComparisonError, "must remain fail-closed"):
            comparison.validate_manifest(changed, root=ROOT)

    def test_pr171_finalizer_assessment_is_pinned(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["cairo_authority"]["pr171_fixture_assessment"][
            "required_finalizers"
        ]["sha2"] = "optional_finalize"
        with self.assertRaisesRegex(comparison.ComparisonError, "required-finalizer"):
            comparison.validate_manifest(changed, root=ROOT)

    def test_ecdsa_negative_output_and_rejection_are_mandatory(self) -> None:
        changed = copy.deepcopy(self.manifest)
        changed["rows"][3]["negative_gate"]["expected_output_hex"] = "1" + "0" * 63
        with self.assertRaisesRegex(comparison.ComparisonError, "must be all zero"):
            comparison.validate_manifest(changed, root=ROOT)

    def test_duplicate_json_keys_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "duplicate.json"
            path.write_text('{"schema":"first","schema":"second"}', encoding="utf-8")
            with self.assertRaisesRegex(comparison.ComparisonError, "duplicate JSON key"):
                comparison.load_json(path)


if __name__ == "__main__":
    unittest.main()
