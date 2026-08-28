"""Exact generated-Sail publication and model-assumption policy tests."""

from __future__ import annotations

import hashlib
import json

from scripts import riscv_refinement_publication as publication
from scripts.tests.riscv_refinement_test_support import *


class RefinementPublicationPolicyTest(unittest.TestCase):
    def test_pilot_composition_digests_follow_generated_air(self) -> None:
        composition = (
            ROOT / sail_lean_bridge.COMPOSITION_SOURCE
        ).read_text(encoding="utf-8")
        sections = {
            "fence": composition.split(
                "def FenceAcceptedGeneratedComposition",
                1,
            )[1].split("theorem FENCE_accepted_air_refines", 1)[0],
            "lui": composition.split(
                "structure LuiPublicationResult",
                1,
            )[1].split("theorem LUI_accepted_air_refines", 1)[0],
        }
        for family, section in sections.items():
            payload = json.loads(
                (
                    ROOT
                    / f"formal/riscv-refinement/generated/air/{family}.air-ir-v2.json"
                ).read_text(encoding="utf-8")
            )
            self.assertEqual(1, section.count(f'"{payload["content_digest"]}"'))

    def test_public_composition_requires_constructive_state_indexed_execution(
        self,
    ) -> None:
        composition = (
            ROOT / sail_lean_bridge.COMPOSITION_SOURCE
        ).read_text(encoding="utf-8")
        generic = composition.split(
            "structure AcceptedGeneratedOpcodeComposition",
            1,
        )[1].split("theorem successfulTraceDecode_of_certificate", 1)[0]
        self.assertIn(
            "Functions.GeneratedDecodeCertificateAt "
            "inputWord decoded initial",
            generic,
        )
        self.assertIn("constructiveExecution :", generic)
        self.assertNotIn("successfulTraceDecode", generic)
        self.assertNotIn("Functions.GeneratedDecodeCertificate ", generic)

        lui = composition.split(
            "structure LuiPublicationResult",
            1,
        )[1].split("theorem LUI_accepted_air_refines", 1)[0]
        self.assertIn("Functions.GeneratedDecodeCertificateAt", lui)
        self.assertIn("GeneratedLuiConstructiveExecution", lui)
        self.assertIn(
            "def GeneratedLuiConstructiveExecution",
            composition,
        )
        self.assertIn(
            "Functions.ConstructiveGeneratedExecution",
            composition.split(
                "def GeneratedLuiConstructiveExecution",
                1,
            )[1].split("structure LuiPublicationResult", 1)[0],
        )
        self.assertNotIn("successfulTraceDecode", lui)

    def test_publication_receipt_uses_exact_bridge_axiom_policy(self) -> None:
        self.assertEqual(
            publication.APPROVED_SAIL_AXIOMS,
            sail_lean_bridge.APPROVED_AXIOMS,
        )
        self.assertEqual(len(publication.APPROVED_SAIL_AXIOMS), 73)

    def test_generated_sail_publication_boundary_is_explicit(self) -> None:
        self.assertEqual(len(sail_lean_bridge.NORMALIZED_THEOREMS), 46)
        self.assertEqual(len(sail_lean_bridge.PUBLICATION_THEOREMS), 46)
        self.assertEqual(len(sail_lean_bridge.THEOREMS), 94)
        self.assertEqual(
            sail_lean_bridge.THEOREMS,
            (
                *sail_lean_bridge.NORMALIZED_THEOREMS,
                *sail_lean_bridge.PUBLICATION_THEOREMS,
                sail_lean_bridge.FULL_STEP_THEOREM,
                sail_lean_bridge.UNIVERSAL_PUBLICATION_THEOREM,
            ),
        )
        self.assertEqual(
            sail_lean_bridge.CLAIM_BOUNDARY[
                "normalized_retirement_selectors"
            ],
            sail_lean_bridge.ADMITTED_SELECTORS,
        )
        self.assertEqual(
            sail_lean_bridge.CLAIM_BOUNDARY["input_bound_selectors"],
            sail_lean_bridge.ADMITTED_SELECTORS,
        )
        self.assertTrue(
            sail_lean_bridge.CLAIM_BOUNDARY[
                "generated_execute_clause_input_binding"
            ],
        )
        self.assertTrue(
            sail_lean_bridge.CLAIM_BOUNDARY[
                "generated_retirement_composition"
            ],
        )
        self.assertTrue(
            sail_lean_bridge.CLAIM_BOUNDARY[
                "fetch_interrupt_trap_and_step_loop_framing"
            ],
        )
        self.assertTrue(
            sail_lean_bridge.CLAIM_BOUNDARY[
                "constructive_row_local_execution"
            ],
        )
        self.assertTrue(
            sail_lean_bridge.CLAIM_BOUNDARY["publication_binding"],
        )
        self.assertEqual(
            len(sail_lean_bridge.SELECTOR_SOURCE_DIGESTS),
            46,
        )
        self.assertEqual(
            [
                identity["selector"]
                for identity in sail_lean_bridge.SELECTOR_SOURCE_DIGESTS
            ],
            sail_lean_bridge.ADMITTED_SELECTORS,
        )
        self.assertEqual(
            sail_lean_bridge.CLAIM_BOUNDARY[
                "pinned_generated_model_axioms"
            ],
            sorted(sail_lean_bridge.PINNED_GENERATED_MODEL_AXIOMS),
        )
        self.assertEqual(
            len(sail_lean_bridge.PINNED_GENERATED_MODEL_AXIOMS),
            70,
        )
        extern_inventory = (
            "\n".join(
                sorted(sail_lean_bridge.PINNED_GENERATED_MODEL_AXIOMS)
            )
            + "\n"
        ).encode("utf-8")
        self.assertEqual(
            hashlib.sha256(extern_inventory).hexdigest(),
            "a0c92c7b4fe36e9bcf192526627db2f304d0c460852a2d09ad1ef9215a84c0bf",
        )
        self.assertTrue(
            {
                "cancel_reservation",
                "get_16_random_bits",
                "load_reservation",
                "match_reservation",
                "plat_term_write",
                "sys_enable_experimental_extensions",
                "valid_reservation",
            }.issubset(
                sail_lean_bridge.PINNED_GENERATED_MODEL_AXIOMS
            )
        )

    def test_cli_and_product_labels_publish_the_current_boundary(self) -> None:
        summary = riscv_refinement.FV_CLAIM_SUMMARY
        self.assertIn("46/46 normalized retirements", summary)
        self.assertIn("46/46 publication implications", summary)
        self.assertIn("whole_frontend_verified=false", summary)
        self.assertIn("proof_system_soundness=false", summary)

        product = (
            ROOT / "build_support/products/riscv_refinement.zig"
        ).read_text(encoding="utf-8")
        catalog = (
            ROOT / "build_support/products/catalog.zig"
        ).read_text(encoding="utf-8")
        workflow = (
            ROOT / ".github/workflows/riscv-sail-formal.yml"
        ).read_text(encoding="utf-8")
        for source in (product, catalog, workflow):
            self.assertIn("46-opcode FV-1/FV-2 publication", source)
        self.assertNotIn("Sail-present Level-1 refinement gate", workflow)

    def test_verify_and_receipt_print_the_bounded_claim(self) -> None:
        audit = audit_transcript(riscv_refinement.AUDITED_THEOREMS)

        def run(argv: list[str], *args: object, **kwargs: object) -> str:
            del args, kwargs
            return audit if tuple(argv) == riscv_refinement.AUDIT_COMMAND else ""

        with tempfile.TemporaryDirectory() as raw, mock.patch.object(
            riscv_refinement,
            "_check_generated_with_evidence",
            return_value=mock.Mock(),
        ), mock.patch.object(
            riscv_refinement,
            "coverage",
        ), mock.patch.object(
            riscv_refinement,
            "negative_controls",
        ), mock.patch.object(
            riscv_refinement,
            "_scan_forbidden_proof_terms",
        ), mock.patch.object(
            riscv_refinement,
            "_run",
            side_effect=run,
        ), mock.patch.object(
            riscv_refinement.riscv_team_a,
            "check_axiom_bindings",
            return_value="axiom bindings checked",
        ), mock.patch("builtins.print") as printing:
            riscv_refinement.verify(Namespace(), Paths(Path(raw)))

        verify_output = "\n".join(
            str(call.args[0])
            for call in printing.call_args_list
            if call.args
        )
        self.assertIn(riscv_refinement.FV_CLAIM_SUMMARY, verify_output)

        arguments = Namespace(
            no_export_air=False,
            reuse_committed_sail_evidence=False,
        )
        live_evidence = mock.Mock()
        with tempfile.TemporaryDirectory() as raw, mock.patch.object(
            riscv_refinement,
            "_verify_with_evidence",
            return_value=(
                riscv_refinement.Verification(theorem_axioms={}),
                live_evidence,
            ),
        ), mock.patch.object(
            riscv_refinement,
            "evidence",
            side_effect=AssertionError("receipt recollected Sail evidence"),
        ), mock.patch.object(
            riscv_refinement,
            "_repository_state",
            return_value=("0" * 40, []),
        ), mock.patch.object(
            riscv_refinement,
            "_build_receipt_payload",
            return_value={"canonical_digest": "1" * 64},
        ) as build_payload, mock.patch.object(
            riscv_refinement.codec,
            "atomic_write",
        ), mock.patch("builtins.print") as printing:
            riscv_refinement.receipt(arguments, Paths(Path(raw)))

        self.assertIs(build_payload.call_args.args[2], live_evidence)

        receipt_output = "\n".join(
            str(call.args[0])
            for call in printing.call_args_list
            if call.args
        )
        self.assertIn(riscv_refinement.FV_CLAIM_SUMMARY, receipt_output)

    def test_receipt_replay_reuses_verified_live_sail_evidence(self) -> None:
        arguments = Namespace(
            no_export_air=False,
            reuse_committed_sail_evidence=False,
        )
        live_evidence = mock.Mock()
        payload = {
            "canonical_digest": "1" * 64,
            "repository_revision": "0" * 40,
            "theorem_axiom_index": {"entries": {}},
        }
        with tempfile.TemporaryDirectory() as raw, mock.patch.object(
            riscv_refinement.codec,
            "load_json",
            return_value=payload,
        ), mock.patch.object(
            riscv_refinement,
            "_validate_receipt_structure",
        ), mock.patch.object(
            riscv_refinement,
            "_receipt_revision_matches",
        ), mock.patch.object(
            riscv_refinement,
            "_verify_with_evidence",
            return_value=(
                riscv_refinement.Verification(theorem_axioms={}),
                live_evidence,
            ),
        ), mock.patch.object(
            riscv_refinement,
            "evidence",
            side_effect=AssertionError("receipt replay recollected Sail evidence"),
        ), mock.patch.object(
            riscv_refinement,
            "_build_receipt_payload",
            return_value=payload,
        ) as build_payload:
            riscv_refinement.verify_receipt(arguments, Paths(Path(raw)))

        self.assertIs(build_payload.call_args.args[2], live_evidence)

    def test_generated_sail_model_axioms_are_exactly_scoped(self) -> None:
        for selector in sail_lean_bridge.ADMITTED_SELECTORS:
            normalizer_expected = set(sail_lean_bridge.KERNEL_AXIOMS)
            normalizer_expected |= set(
                sail_lean_bridge._selector_theorem_axioms(selector)
            )
            normalizer = (
                "LeanRV32IM.Functions."
                f"complete_{selector}_normalizes"
            )
            publication = (
                "LeanRV32IM.Publication."
                f"{selector}_accepted_air_refines"
            )
            self.assertEqual(
                set(
                    sail_lean_bridge.EXPECTED_THEOREM_AXIOMS[
                        normalizer
                    ]
                ),
                normalizer_expected,
            )
            self.assertEqual(
                set(
                    sail_lean_bridge.EXPECTED_THEOREM_AXIOMS[
                        publication
                    ]
                ),
                set(sail_lean_bridge.APPROVED_AXIOMS),
            )
        self.assertEqual(
            set(
                sail_lean_bridge.EXPECTED_THEOREM_AXIOMS[
                    sail_lean_bridge.FULL_STEP_THEOREM
                ]
            ),
            set(sail_lean_bridge.APPROVED_AXIOMS),
        )
        self.assertEqual(
            set(
                sail_lean_bridge.EXPECTED_THEOREM_AXIOMS[
                    sail_lean_bridge.UNIVERSAL_PUBLICATION_THEOREM
                ]
            ),
            set(sail_lean_bridge.APPROVED_AXIOMS),
        )

    def test_generated_sail_axiom_parser_enforces_each_scope(self) -> None:
        def output(inventories: dict[str, list[str]]) -> str:
            return "\n".join(
                f"'{theorem}' depends on axioms: "
                f"[{', '.join(inventories[theorem])}]"
                for theorem in sail_lean_bridge.THEOREMS
            )

        expected = copy.deepcopy(
            sail_lean_bridge.EXPECTED_THEOREM_AXIOMS
        )
        self.assertEqual(
            sail_lean_bridge._proof_axioms(output(expected)),
            expected,
        )
        missing_model_input = copy.deepcopy(expected)
        jump_theorem = (
            "LeanRV32IM.Publication.JAL_accepted_air_refines"
        )
        missing_model_input[jump_theorem].remove("riscv_f16Add")
        with self.assertRaisesRegex(
            RefinementError,
            "per-theorem contract",
        ):
            sail_lean_bridge._proof_axioms(output(missing_model_input))
