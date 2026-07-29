"""Regression tests for the generated RISC-V refinement pilot."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path

from scripts import riscv_refinement
from scripts.riscv_refinement_lib import (
    air,
    air_program,
    codec,
    negative,
    render,
    sail,
)
from scripts.riscv_refinement_lib.model import Paths, RefinementError

ROOT = Path(__file__).resolve().parents[2]
GENERATED_AIR = ROOT / "formal" / "riscv-refinement" / "generated" / "air"


def air_ir_v2_fixture() -> dict[str, object]:
    fixed_tables = [
        {
            "id": table_id,
            "domain": table_id,
            "arity": arity,
            "log_size": log_size,
            "schema_sha256": air_program.table_schema_digest(
                table_id,
                table_id,
                arity,
                log_size,
            ),
        }
        for table_id, arity, log_size in air_program.FIXED_TABLES
    ]
    files = [
        {
            "path": "src/frontends/riscv/air/constraint_program.zig",
            "sha256": "1" * 64,
        }
    ]
    payload: dict[str, object] = {
        "schema_version": air_program.AIR_IR_SCHEMA_VERSION,
        "kind": air_program.AIR_IR_KIND,
        "field": {
            "name": "M31",
            "modulus": air_program.M31_MODULUS,
        },
        "family": "lui",
        "columns": [
            {
                "index": 0,
                "name": "enabler",
                "role": "input",
                "type": "m31",
                "width": 1,
            }
        ],
        "nodes": [
            {"op": "col", "column": 0},
            {"op": "const", "value": 1},
            {"op": "add", "args": [0, 1]},
            {"op": "sub", "args": [2, 1]},
            {"op": "mul", "args": [3, 1]},
            {"op": "neg", "args": [0]},
            {"op": "const", "value": 35},
            {"op": "const", "value": 0},
        ],
        "active_row": 0,
        "opcode_selector": {
            "manifest_id": 35,
            "mnemonic": "lui",
            "expression": 6,
        },
        "fixed_tables": fixed_tables,
        "events": [
            {"ordinal": 0, "kind": "constraint", "root": 4},
            {
                "ordinal": 1,
                "kind": "lookup",
                "role": "request",
                "domain": "program_access",
                "numerator": 5,
                "tuple": [0, 6, 7, 7, 7],
                "table_id": None,
                "liveness": "nonzero_numerator",
                "access_ordinal": None,
            },
            {
                "ordinal": 2,
                "kind": "lookup",
                "role": "consume",
                "domain": "registers_state",
                "numerator": 5,
                "tuple": [0, 1],
                "table_id": None,
                "liveness": "nonzero_numerator",
                "access_ordinal": None,
            },
            {
                "ordinal": 3,
                "kind": "lookup",
                "role": "emit",
                "domain": "registers_state",
                "numerator": 0,
                "tuple": [2, 1],
                "table_id": None,
                "liveness": "nonzero_numerator",
                "access_ordinal": None,
            },
            {
                "ordinal": 4,
                "kind": "lookup",
                "role": "request",
                "domain": "range_check_20",
                "numerator": 5,
                "tuple": [0],
                "table_id": "range_check_20",
                "liveness": "nonzero_numerator",
                "access_ordinal": None,
            },
            {
                "ordinal": 5,
                "kind": "lookup",
                "role": "consume",
                "domain": "memory_access",
                "numerator": 5,
                "tuple": [0, 1, 7, 7, 7, 7, 7],
                "table_id": None,
                "liveness": "nonzero_numerator",
                "access_ordinal": 1,
            },
            {
                "ordinal": 6,
                "kind": "lookup",
                "role": "emit",
                "domain": "memory_access",
                "numerator": 0,
                "tuple": [0, 1, 2, 7, 7, 7, 7],
                "table_id": None,
                "liveness": "nonzero_numerator",
                "access_ordinal": 1,
            },
            {
                "ordinal": 7,
                "kind": "lookup",
                "role": "request",
                "domain": "range_check_20",
                "numerator": 5,
                "tuple": [0],
                "table_id": "range_check_20",
                "liveness": "nonzero_numerator",
                "access_ordinal": 1,
            },
        ],
        "projection": {
            "program_event": 1,
            "state_events": [2, 3],
            "source_events": [],
            "destination_events": [5, 6],
            "next_pc": 2,
        },
        "source_identity": {
            "builder": "src/frontends/riscv/air/constraint_program.zig",
            "files": files,
            "source_closure_sha256": codec.sha256_bytes(
                codec.canonical_bytes(files)
            ),
        },
        "content_digest": "",
    }
    payload["content_digest"] = air_program.content_digest(payload)
    return payload


def resign_air_ir_v2(payload: dict[str, object]) -> None:
    payload["content_digest"] = air_program.content_digest(payload)


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

    def test_air_ir_v2_contract_accepts_canonical_typed_program(self) -> None:
        payload = air_ir_v2_fixture()
        air_program.validate(payload)

    def test_air_ir_v2_decoder_fails_closed_on_nodes_and_events(self) -> None:
        base = air_ir_v2_fixture()
        mutations = []

        unknown_operation = copy.deepcopy(base)
        unknown_operation["nodes"][4]["op"] = "div"
        mutations.append(unknown_operation)

        forward_reference = copy.deepcopy(base)
        forward_reference["nodes"][4]["args"][0] = 4
        mutations.append(forward_reference)

        invalid_constant = copy.deepcopy(base)
        invalid_constant["nodes"][1]["value"] = air_program.M31_MODULUS
        mutations.append(invalid_constant)

        floating_schema = copy.deepcopy(base)
        floating_schema["schema_version"] = 2.0
        mutations.append(floating_schema)

        boolean_constant = copy.deepcopy(base)
        boolean_constant["nodes"][1]["value"] = True
        mutations.append(boolean_constant)

        invalid_arity = copy.deepcopy(base)
        invalid_arity["events"][4]["tuple"].append(1)
        mutations.append(invalid_arity)

        dead_lookup = copy.deepcopy(base)
        dead_lookup["events"][4]["numerator"] = 7
        mutations.append(dead_lookup)

        reordered = copy.deepcopy(base)
        reordered["events"][4]["ordinal"] = 3
        mutations.append(reordered)

        wrong_table = copy.deepcopy(base)
        wrong_table["events"][4]["table_id"] = "range_check_8_8"
        mutations.append(wrong_table)

        gapped_access = copy.deepcopy(base)
        for event in gapped_access["events"][5:8]:
            event["access_ordinal"] = 2
        mutations.append(gapped_access)

        missing_access_gap = copy.deepcopy(base)
        missing_access_gap["events"][7]["access_ordinal"] = None
        mutations.append(missing_access_gap)

        misplaced_access = copy.deepcopy(base)
        misplaced_access["events"][1]["access_ordinal"] = 1
        mutations.append(misplaced_access)

        dead_node = copy.deepcopy(base)
        dead_node["nodes"].append({"op": "const", "value": 7})
        mutations.append(dead_node)

        duplicate_node = copy.deepcopy(base)
        duplicate_node["nodes"].append({"op": "sub", "args": [2, 1]})
        duplicate_node["events"][0]["root"] = len(duplicate_node["nodes"]) - 1
        mutations.append(duplicate_node)

        for payload in mutations:
            resign_air_ir_v2(payload)
            with self.subTest(payload=payload):
                with self.assertRaises(RefinementError):
                    air_program.validate(payload)

    def test_air_ir_v2_canonical_loader_rejects_duplicates_and_pretty_json(
        self,
    ) -> None:
        payload = air_ir_v2_fixture()
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            canonical = directory / "canonical.json"
            canonical.write_bytes(codec.canonical_bytes(payload))
            self.assertEqual(payload, air_program.load_canonical(canonical))

            pretty = directory / "pretty.json"
            pretty.write_bytes(codec.pretty_bytes(payload))
            with self.assertRaisesRegex(RefinementError, "not compact canonical"):
                air_program.load_canonical(pretty)

            duplicate = directory / "duplicate.json"
            duplicate.write_text(
                '{"kind":"first","kind":"second"}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RefinementError, "duplicate JSON key"):
                air_program.load_canonical(duplicate)

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
