"""Regression tests for the generated RISC-V refinement pilot."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

from scripts import riscv_refinement
from scripts.riscv_refinement_lib import air, codec, negative, render, sail
from scripts.riscv_refinement_lib.model import Paths, RefinementError

ROOT = Path(__file__).resolve().parents[2]
GENERATED_AIR = ROOT / "formal" / "riscv-refinement" / "generated" / "air"


class RefinementAirTest(unittest.TestCase):
    def test_source_closure_is_version_controlled_and_cache_free(self) -> None:
        digests = render._source_digests(Paths(ROOT))
        self.assertIn("src/core/fields/m31.zig", digests)
        self.assertIn("src/frontends/riscv/air/extract/mod.zig", digests)
        self.assertFalse(
            any("/.zig-cache/" in relative for relative in digests),
        )

    def test_existing_air_export_requires_the_exact_nonempty_family_set(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            for family in render.EXPORTED_FAMILIES:
                (directory / f"{family}.json").write_text("{}\n", encoding="utf-8")
            render.validate_air_export(directory)
            (directory / "stale.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(RefinementError, "coverage drifted"):
                render.validate_air_export(directory)

    def test_committed_pilot_air_has_the_exact_reviewed_shape(self) -> None:
        air.validate_family(codec.load_json(GENERATED_AIR / "lui.json"), "lui")
        air.validate_family(
            codec.load_json(GENERATED_AIR / "addi.json"),
            "base_alu_imm",
        )

    def test_lui_low_limb_mutation_fails_closed(self) -> None:
        payload = codec.load_json(GENERATED_AIR / "lui.json")
        del payload["constraints"][4]
        with self.assertRaises(RefinementError):
            air.validate_family(payload, "lui")

    def test_addi_carry_and_range_mutations_fail_closed(self) -> None:
        payload = codec.load_json(GENERATED_AIR / "addi.json")
        carry_mutation = copy.deepcopy(payload)
        del carry_mutation["constraints"][9]
        with self.assertRaises(RefinementError):
            air.validate_family(carry_mutation, "base_alu_imm")

        range_mutation = copy.deepcopy(payload)
        del range_mutation["lookups"][1]
        with self.assertRaises(RefinementError):
            air.validate_family(range_mutation, "base_alu_imm")

    def test_mutation_witnesses_satisfy_the_weakened_systems(self) -> None:
        results = negative.run(GENERATED_AIR)
        self.assertEqual(
            ["lui-free-low-limb", "addi-free-high-carry"],
            [result["name"] for result in results],
        )
        self.assertTrue(all(result["status"] == "passed" for result in results))

    def test_canonical_digest_rejects_payload_drift(self) -> None:
        payload = codec.load_json(GENERATED_AIR / "lui.json")
        expected = payload["canonical_digest"]
        self.assertEqual(expected, codec.content_digest(payload))
        payload["opcode"]["id"] = 34
        self.assertNotEqual(expected, codec.content_digest(payload))

    def test_air_schema_rejects_column_and_index_coercions(self) -> None:
        payload = codec.load_json(GENERATED_AIR / "lui.json")

        reordered = copy.deepcopy(payload)
        reordered["columns"][0], reordered["columns"][1] = (
            reordered["columns"][1],
            reordered["columns"][0],
        )
        reordered["canonical_digest"] = codec.content_digest(reordered)
        with self.assertRaises(RefinementError):
            air.validate_family(reordered, "lui")

        negative_root = copy.deepcopy(payload)
        negative_root["constraints"][0] = -1
        negative_root["canonical_digest"] = codec.content_digest(negative_root)
        with self.assertRaises(RefinementError):
            air.validate_family(negative_root, "lui")

        string_index = copy.deepcopy(payload)
        string_index["lookups"][0]["tuple"][0] = "2"
        string_index["canonical_digest"] = codec.content_digest(string_index)
        with self.assertRaises(RefinementError):
            air.validate_family(string_index, "lui")

    def test_air_schema_rejects_packaging_and_unused_dag_drift(self) -> None:
        payload = codec.load_json(GENERATED_AIR / "lui.json")

        projection = copy.deepcopy(payload)
        projection["projection"]["program_lookup"] = 1
        projection["canonical_digest"] = codec.content_digest(projection)
        with self.assertRaises(RefinementError):
            air.validate_family(projection, "lui")

        unused = copy.deepcopy(payload)
        unused["nodes"].append({"op": "const", "value": 0})
        unused["canonical_digest"] = codec.content_digest(unused)
        with self.assertRaises(RefinementError):
            air.validate_family(unused, "lui")

    def test_axiom_audit_allows_only_declared_foundations(self) -> None:
        lines = "\n".join(
            line
            for index, theorem in enumerate(
                riscv_refinement.AUDITED_THEOREMS,
            )
            for line in (
                f"REFINEMENT_THEOREM {theorem}",
                *(
                    ()
                    if index == 0
                    else (
                        f"REFINEMENT_AXIOM {theorem} propext",
                        f"REFINEMENT_AXIOM {theorem} Quot.sound",
                    )
                ),
            )
        )
        report = riscv_refinement._audit_axioms(lines)
        self.assertEqual(
            set(riscv_refinement.AUDITED_THEOREMS),
            set(report),
        )
        self.assertEqual(
            [],
            report[riscv_refinement.AUDITED_THEOREMS[0]],
        )

        poisoned = lines.replace(
            " propext",
            " hidden.native_axiom",
            1,
        )
        with self.assertRaises(RefinementError):
            riscv_refinement._audit_axioms(poisoned)

        duplicate = (
            lines
            + "\n"
            + "REFINEMENT_THEOREM "
            + riscv_refinement.AUDITED_THEOREMS[0]
        )
        with self.assertRaisesRegex(RefinementError, "repeated theorem"):
            riscv_refinement._audit_axioms(duplicate)

        extra = (
            lines
            + "\nREFINEMENT_THEOREM "
            + "RiscvRefinement.Future.attributed_multiline"
        )
        with self.assertRaisesRegex(RefinementError, "unexpected"):
            riscv_refinement._audit_axioms(extra)

        with self.assertRaisesRegex(RefinementError, "malformed theorem"):
            riscv_refinement._audit_axioms(
                lines + "\nREFINEMENT_THEOREM malformed name",
            )

    def test_release_receipt_cannot_reuse_stale_air(self) -> None:
        with self.assertRaisesRegex(RefinementError, "fresh production AIR"):
            riscv_refinement.receipt(
                Namespace(no_export_air=True),
                Paths(ROOT),
            )

    def test_receipt_theorem_axiom_schema_fails_closed(self) -> None:
        for malformed in (None, [], {"unknown.theorem": []}):
            with self.assertRaisesRegex(RefinementError, "theorem set"):
                riscv_refinement._validate_receipt_theorem_axioms(malformed)
        malformed_axioms = {
            theorem: [] for theorem in riscv_refinement.AUDITED_THEOREMS
        }
        malformed_axioms[riscv_refinement.AUDITED_THEOREMS[0]] = [1]
        with self.assertRaisesRegex(RefinementError, "theorem-axiom schema"):
            riscv_refinement._validate_receipt_theorem_axioms(
                malformed_axioms,
            )

    def test_receipt_numeric_identity_rejects_bool_and_float_coercions(
        self,
    ) -> None:
        valid = {
            "schema_version": 1,
            "coverage": {
                "proved_normalized_opcodes": 2,
                "production_opcodes": 46,
            },
        }
        riscv_refinement._validate_receipt_numeric_identity(valid)
        for field, replacement in (
            ("schema_version", True),
            ("schema_version", 1.0),
        ):
            malformed = copy.deepcopy(valid)
            malformed[field] = replacement
            with self.assertRaisesRegex(RefinementError, "numeric identity"):
                riscv_refinement._validate_receipt_numeric_identity(
                    malformed,
                )
        for replacement in (True, 2.0):
            malformed = copy.deepcopy(valid)
            malformed["coverage"]["proved_normalized_opcodes"] = replacement
            with self.assertRaisesRegex(RefinementError, "numeric identity"):
                riscv_refinement._validate_receipt_numeric_identity(
                    malformed,
                )

    def test_lean_comment_stripper_covers_lines_blocks_and_strings(self) -> None:
        line = "theorem ok : True := trivial -- axiom lives in a comment\n"
        self.assertNotIn("axiom", riscv_refinement._strip_lean_comments(line))

        block = (
            "/-! This module documents the axiom set it never uses. -/\n"
            "/- sorry and native_decide appear only as prose -/\n"
            "theorem ok : True := trivial\n"
        )
        stripped = riscv_refinement._strip_lean_comments(block)
        for term in ("axiom", "sorry", "native_decide"):
            self.assertNotIn(term, stripped)
        self.assertIn("theorem ok : True := trivial", stripped)

        nested = "/- outer /- inner axiom -/ still comment -/ theorem ok : True := trivial\n"
        nested_stripped = riscv_refinement._strip_lean_comments(nested)
        self.assertNotIn("axiom", nested_stripped)
        self.assertIn("theorem ok : True := trivial", nested_stripped)

        literal = 'def dashes : String := "-- not a comment"\naxiom cheat : True\n'
        self.assertIn("axiom cheat", riscv_refinement._strip_lean_comments(literal))

        same_line = 'def dashes : String := "a -- b"; axiom cheat : True\n'
        self.assertIn("axiom cheat", riscv_refinement._strip_lean_comments(same_line))

        for text in (line, block, nested, literal, same_line):
            with self.subTest(text=text):
                rewritten = riscv_refinement._strip_lean_comments(text)
                self.assertEqual(len(text), len(rewritten))
                self.assertEqual(
                    len(text.splitlines()),
                    len(rewritten.splitlines()),
                )

    def test_proof_escape_scan_sees_through_comments_and_string_literals(self) -> None:
        cases = {
            "Line.lean": "theorem ok : True := trivial -- axiom in a comment\n",
            "Block.lean": "/-! An axiom-free development. -/\ntheorem ok : True := trivial\n",
            "Nested.lean": "/- outer /- sorry -/ -/\ntheorem ok : True := trivial\n",
        }
        for name, text in cases.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as raw:
                paths = self._lean_tree(Path(raw), {name: text})
                riscv_refinement._scan_forbidden_proof_terms(paths)

        breaches = {
            # Splitting on the first "--" would stop inside the literal and never
            # reach the escape that follows it on the same line.
            "Literal.lean": (
                'def dashes : String := "a -- b"; axiom cheat : True\n',
                "forbidden proof escape",
            ),
            "Bare.lean": (
                "theorem broken : True := by sorry\n",
                "forbidden proof escape",
            ),
            # An unterminated block comment would blank the rest of the file, so
            # the scan must refuse it instead of reporting a clean sweep.
            "Unterminated.lean": (
                "/- opened and never closed\naxiom cheat : True\n",
                r"Unterminated\.lean: unterminated Lean block comment",
            ),
        }
        for name, (text, expected) in breaches.items():
            with self.subTest(name=name), tempfile.TemporaryDirectory() as raw:
                paths = self._lean_tree(Path(raw), {name: text})
                with self.assertRaisesRegex(RefinementError, expected):
                    riscv_refinement._scan_forbidden_proof_terms(paths)

    def test_proof_escape_scan_reports_the_line_the_term_is_on(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            paths = self._lean_tree(
                Path(raw),
                {
                    "Late.lean": (
                        "/- a block comment\n   spanning three lines\n   ends here -/\n"
                        "theorem broken : True := by sorry\n"
                    ),
                },
            )
            with self.assertRaisesRegex(
                RefinementError,
                r"RiscvRefinement/Late\.lean:4",
            ):
                riscv_refinement._scan_forbidden_proof_terms(paths)

    @staticmethod
    def _lean_tree(root: Path, sources: dict[str, str]) -> Paths:
        formal = root / "formal" / "riscv-refinement"
        (formal / "RiscvRefinement").mkdir(parents=True)
        (formal / "RiscvRefinement.lean").write_text(
            "import RiscvRefinement.Common\n",
            encoding="utf-8",
        )
        for name, text in sources.items():
            (formal / "RiscvRefinement" / name).write_text(text, encoding="utf-8")
        return Paths(root)

    def test_sail_configuration_comment_parser_preserves_strings(self) -> None:
        source = '{"repository":"https://example.test/x",// comment\n"value":32}'
        self.assertEqual(
            {
                "repository": "https://example.test/x",
                "value": 32,
            },
            json.loads(sail._strip_line_comments(source)),
        )


if __name__ == "__main__":
    unittest.main()
