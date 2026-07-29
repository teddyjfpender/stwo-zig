"""Regression tests for the generated RISC-V refinement pilot."""

from __future__ import annotations

import ast
import copy
import json
import re
import shutil
import tempfile
import unittest
from argparse import Namespace
from pathlib import Path
from unittest import mock

from scripts import riscv_refinement
from scripts.riscv_refinement_lib import (
    air,
    air_program,
    air_program_contract,
    codec,
    negative,
    render,
    sail,
)
from scripts.riscv_refinement_lib.model import Paths, RefinementError

ROOT = Path(__file__).resolve().parents[2]
GENERATED_AIR = ROOT / "formal" / "riscv-refinement" / "generated" / "air"
MANIFEST = Path("generated-manifest.json")


def carried_fixture(root: Path) -> Paths:
    """Copy exactly the inputs a reused-evidence run is allowed to read."""
    paths = Paths(root)
    for relative in sail.CARRIED_INPUTS:
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, destination)
    for relative in (
        MANIFEST,
        sail.COMMITTED_CONFIGURATION,
        sail.COMMITTED_CAPSULE,
        sail.COMMITTED_TRANSLATION_RECEIPT,
        *sail.COMMITTED_DEFINITIONS.values(),
    ):
        destination = paths.formal / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(Paths(ROOT).formal / relative, destination)
    return paths


def pinned_literal(text: str) -> tuple[str, ...]:
    """Read back an AUDITED_THEOREMS block exactly as Python would."""
    block = riscv_refinement.AUDITED_THEOREMS_BLOCK.search(text)
    if block is None:
        raise AssertionError("no AUDITED_THEOREMS block")
    return ast.literal_eval(
        block.group(0).split("=", 1)[1].strip(),
    )


def audit_transcript(theorems: tuple[str, ...]) -> str:
    return "".join(
        f"REFINEMENT_THEOREM {theorem}\n"
        f"REFINEMENT_AXIOM {theorem} propext\n"
        for theorem in theorems
    )


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
            "path": path,
            "sha256": "1" * 64,
        }
        for path in air_program.LUI_SOURCE_PATHS
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
            *[
                {"ordinal": ordinal, "kind": "constraint", "root": 4}
                for ordinal in range(9)
            ],
            {
                "ordinal": 9,
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
                "ordinal": 10,
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
                "ordinal": 11,
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
                "ordinal": 12,
                "kind": "lookup",
                "role": "request",
                "domain": "range_check_8_8_4",
                "numerator": 5,
                "tuple": [0, 0, 0],
                "table_id": "range_check_8_8_4",
                "liveness": "nonzero_numerator",
                "access_ordinal": None,
            },
            {
                "ordinal": 13,
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
                "ordinal": 14,
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
                "ordinal": 15,
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
            "program_event": 9,
            "state_events": [10, 11],
            "source_events": [],
            "destination_events": [13, 14],
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

    def test_committed_lui_air_ir_v2_is_source_bound_production_program(
        self,
    ) -> None:
        path = GENERATED_AIR / "lui.air-ir-v2.json"
        payload = air_program.load_canonical(path)
        air_program.verify_source_files(payload, ROOT)
        self.assertEqual("lui", payload["family"])
        self.assertEqual(18, len(payload["columns"]))
        self.assertEqual(53, len(payload["nodes"]))
        self.assertEqual(16, len(payload["events"]))
        self.assertEqual(
            9,
            sum(event["kind"] == "constraint" for event in payload["events"]),
        )
        self.assertEqual(
            7,
            sum(event["kind"] == "lookup" for event in payload["events"]),
        )
        self.assertFalse(
            any(
                column["name"].startswith("bus_value_")
                for column in payload["columns"]
            )
        )

        reordered = copy.deepcopy(payload)
        reordered["events"][13], reordered["events"][14] = (
            reordered["events"][14],
            reordered["events"][13],
        )
        reordered["events"][13]["ordinal"] = 13
        reordered["events"][14]["ordinal"] = 14
        resign_air_ir_v2(reordered)
        with self.assertRaises(RefinementError):
            air_program.validate(reordered)

        stale_source = copy.deepcopy(payload)
        stale_source["source_identity"]["files"][0]["sha256"] = "0" * 64
        stale_source["source_identity"]["source_closure_sha256"] = (
            codec.sha256_bytes(
                codec.canonical_bytes(stale_source["source_identity"]["files"])
            )
        )
        resign_air_ir_v2(stale_source)
        air_program.validate(stale_source)
        with self.assertRaisesRegex(RefinementError, "source digest drifted"):
            air_program.verify_source_files(stale_source, ROOT)

        semantic_mutation = copy.deepcopy(payload)
        semantic_mutation["events"][9]["tuple"][0] = 51
        resign_air_ir_v2(semantic_mutation)
        air_program.validate(semantic_mutation)
        air_program.verify_source_files(semantic_mutation, ROOT)
        unsigned = {
            key: value
            for key, value in payload.items()
            if key in air_program.UNSIGNED_TOP_LEVEL_KEYS
        }
        with self.assertRaisesRegex(RefinementError, "fresh production"):
            air_program.verify_production_binding(
                semantic_mutation,
                unsigned,
                ROOT,
            )

    def test_committed_air_ir_v2_exactly_covers_the_opcode_manifest(
        self,
    ) -> None:
        expected = {
            f"{mnemonic}.air-ir-v2.json"
            for _, mnemonic, _ in air_program.OPCODES
        }
        actual = {
            path.name for path in GENERATED_AIR.glob("*.air-ir-v2.json")
        }
        self.assertEqual(expected, actual)
        self.assertEqual(46, len(actual))

        for manifest_id, mnemonic, family in air_program.OPCODES:
            with self.subTest(mnemonic=mnemonic):
                payload = air_program.load_canonical(
                    GENERATED_AIR / f"{mnemonic}.air-ir-v2.json"
                )
                air_program.verify_source_files(payload, ROOT)
                self.assertEqual(family, payload["family"])
                self.assertEqual(
                    {
                        "expression": payload["opcode_selector"]["expression"],
                        "manifest_id": manifest_id,
                        "mnemonic": mnemonic,
                    },
                    payload["opcode_selector"],
                )
                self.assertEqual(
                    air_program.FAMILY_SOURCE_PATHS[family],
                    tuple(
                        item["path"]
                        for item in payload["source_identity"]["files"]
                    ),
                )

    def test_each_family_source_closure_includes_its_semantics(self) -> None:
        self.assertEqual(
            set(air_program_contract.FAMILIES),
            set(air_program.FAMILY_SOURCE_PATHS),
        )
        for (
            family,
            semantic_paths,
        ) in air_program_contract.FAMILY_SEMANTIC_PATHS.items():
            with self.subTest(family=family):
                closure = set(air_program.FAMILY_SOURCE_PATHS[family])
                self.assertTrue(
                    set(air_program_contract.COMMON_SOURCE_PATHS) <= closure
                )
                self.assertTrue(set(semantic_paths) <= closure)

    def test_same_family_artifacts_share_one_production_program(self) -> None:
        canonical_by_family: dict[str, bytes] = {}
        for _, mnemonic, family in air_program.OPCODES:
            payload = air_program.load_canonical(
                GENERATED_AIR / f"{mnemonic}.air-ir-v2.json"
            )
            semantic = copy.deepcopy(payload)
            semantic.pop("content_digest")
            semantic["opcode_selector"] = {
                "expression": semantic["opcode_selector"]["expression"]
            }
            canonical = codec.canonical_bytes(semantic)
            with self.subTest(mnemonic=mnemonic, family=family):
                if family in canonical_by_family:
                    self.assertEqual(canonical_by_family[family], canonical)
                else:
                    canonical_by_family[family] = canonical
        self.assertEqual(17, len(canonical_by_family))

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

        zero_active = copy.deepcopy(base)
        zero_active["active_row"] = 7
        mutations.append(zero_active)

        wrong_manifest_family = copy.deepcopy(base)
        wrong_manifest_family["family"] = "auipc"
        mutations.append(wrong_manifest_family)

        invalid_arity = copy.deepcopy(base)
        invalid_arity["events"][12]["tuple"].append(1)
        mutations.append(invalid_arity)

        dead_lookup = copy.deepcopy(base)
        dead_lookup["events"][12]["numerator"] = 7
        mutations.append(dead_lookup)

        reordered = copy.deepcopy(base)
        reordered["events"][12]["ordinal"] = 11
        mutations.append(reordered)

        wrong_table = copy.deepcopy(base)
        wrong_table["events"][12]["table_id"] = "range_check_8_8"
        mutations.append(wrong_table)

        gapped_access = copy.deepcopy(base)
        for event in gapped_access["events"][13:16]:
            event["access_ordinal"] = 2
        mutations.append(gapped_access)

        missing_access_gap = copy.deepcopy(base)
        missing_access_gap["events"][15]["access_ordinal"] = None
        mutations.append(missing_access_gap)

        misplaced_access = copy.deepcopy(base)
        misplaced_access["events"][9]["access_ordinal"] = 1
        mutations.append(misplaced_access)

        relabelled_projection = copy.deepcopy(base)
        relabelled_projection["projection"]["source_events"] = [13, 14]
        relabelled_projection["projection"]["destination_events"] = []
        mutations.append(relabelled_projection)

        wrong_builder = copy.deepcopy(base)
        wrong_builder["source_identity"]["builder"] = (
            "src/frontends/riscv/air/semantic_eval.zig"
        )
        mutations.append(wrong_builder)

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

    def test_carried_sail_evidence_reproduces_the_committed_provenance(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            paths = carried_fixture(Path(raw))
            evidence = sail.carried_evidence(paths)
            committed = codec.load_json(paths.manifest)["sail"]
            provenance = sail.provenance(evidence)
            self.assertEqual(
                sail.CARRIED_EVIDENCE,
                provenance["evidence_source"],
            )
            # The grade marker is compared separately above; every other field
            # must be reproduced exactly, whichever grade the committed
            # manifest was last generated under.
            self.assertEqual(
                {
                    key: value
                    for key, value in committed.items()
                    if key != "evidence_source"
                },
                {
                    key: value
                    for key, value in provenance.items()
                    if key != "evidence_source"
                },
            )
            self.assertIsNone(evidence.compiler_sha256)
            with self.assertRaisesRegex(RefinementError, "live Sail evidence"):
                sail.toolchain(evidence)

    def test_carried_sail_evidence_requires_every_named_input(self) -> None:
        for relative in sail.CARRIED_INPUTS:
            with tempfile.TemporaryDirectory() as raw:
                paths = carried_fixture(Path(raw))
                (paths.root / relative).unlink()
                with self.assertRaisesRegex(
                    RefinementError,
                    f"{re.escape(relative.as_posix())}.*absent",
                ):
                    sail.carried_evidence(paths)

    def test_carried_sail_evidence_rejects_a_mutated_profile(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            paths = carried_fixture(Path(raw))
            profile = codec.load_json(paths.root / sail.PROFILE_PATH)
            profile["authorities"]["sail"]["revision"] = "0" * 40
            codec.atomic_write(
                paths.root / sail.PROFILE_PATH,
                codec.pretty_bytes(profile),
            )
            with self.assertRaisesRegex(
                RefinementError,
                f"{re.escape(sail.PROFILE_PATH.as_posix())}.*changed since",
            ):
                sail.carried_evidence(paths)

    def test_carried_sail_evidence_rejects_a_mutated_override(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            paths = carried_fixture(Path(raw))
            override = paths.root / sail.OVERRIDE_PATHS[0]
            override.write_bytes(override.read_bytes() + b"\n")
            with self.assertRaisesRegex(RefinementError, "changed since"):
                sail.carried_evidence(paths)

    def test_carried_sail_evidence_rejects_mutated_pinned_constants(
        self,
    ) -> None:
        mutations = (
            (
                "GENERATED_DEFINITION_HASHES",
                {name: "0" * 64 for name in sail.GENERATED_DEFINITION_HASHES},
            ),
            (
                "SOURCE_SLICE_HASHES",
                {name: "0" * 64 for name in sail.SOURCE_SLICE_HASHES},
            ),
            ("SAIL_REVISION", "0" * 40),
            ("SAIL_VERSION", "0.0.0"),
            ("SAIL_REPOSITORY", "https://example.test/sail-riscv"),
        )
        for name, replacement in mutations:
            with tempfile.TemporaryDirectory() as raw:
                paths = carried_fixture(Path(raw))
                with mock.patch.object(sail, name, replacement):
                    with self.assertRaisesRegex(
                        RefinementError,
                        "does not match the pin",
                    ):
                        sail.carried_evidence(paths)

    def test_carried_sail_evidence_cannot_mint_new_sail_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            paths = carried_fixture(Path(raw))
            capsule = paths.formal / sail.COMMITTED_CAPSULE
            capsule.write_bytes(capsule.read_bytes() + b"-- drift\n")
            with self.assertRaisesRegex(RefinementError, "would rewrite"):
                sail.carried_evidence(paths)

        with tempfile.TemporaryDirectory() as raw:
            paths = carried_fixture(Path(raw))
            configuration = paths.formal / sail.COMMITTED_CONFIGURATION
            configuration.write_bytes(b"{}\n")
            with self.assertRaisesRegex(
                RefinementError,
                "does not match the committed provenance digest",
            ):
                sail.carried_evidence(paths)

        with tempfile.TemporaryDirectory() as raw:
            paths = carried_fixture(Path(raw))
            receipt = paths.formal / sail.COMMITTED_TRANSLATION_RECEIPT
            receipt.write_bytes(receipt.read_bytes() + b"\n")
            with self.assertRaisesRegex(
                RefinementError,
                "not canonical pretty JSON",
            ):
                sail.carried_evidence(paths)

        with tempfile.TemporaryDirectory() as raw:
            paths = carried_fixture(Path(raw))
            definition = (
                paths.formal
                / sail.COMMITTED_DEFINITIONS["execute_UTYPE"]
            )
            definition.write_bytes(definition.read_bytes() + b"-- drift\n")
            with self.assertRaisesRegex(
                RefinementError,
                "does not match the pinned backend",
            ):
                sail.carried_evidence(paths)

    def test_carried_sail_evidence_rejects_a_tampered_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            paths = carried_fixture(Path(raw))
            manifest = codec.load_json(paths.manifest)
            manifest["sail"]["source_file_sha256"] = "0" * 64
            codec.atomic_write(paths.manifest, codec.pretty_bytes(manifest))
            with self.assertRaisesRegex(RefinementError, "identity is invalid"):
                sail.carried_evidence(paths)

        with tempfile.TemporaryDirectory() as raw:
            paths = carried_fixture(Path(raw))
            manifest = codec.load_json(paths.manifest)
            manifest["sail"]["checkout_state"] = "trust-me"
            manifest["canonical_digest"] = codec.content_digest(manifest)
            codec.atomic_write(paths.manifest, codec.pretty_bytes(manifest))
            with self.assertRaisesRegex(
                RefinementError,
                "unknown checkout state",
            ):
                sail.carried_evidence(paths)

    def test_receipts_refuse_carried_sail_evidence(self) -> None:
        arguments = Namespace(
            no_export_air=False,
            reuse_committed_sail_evidence=True,
        )
        for command in (riscv_refinement.receipt, riscv_refinement.verify_receipt):
            with self.assertRaisesRegex(
                RefinementError,
                "--reuse-committed-sail-evidence is forbidden",
            ):
                command(arguments, Paths(ROOT))

    def test_carried_sail_evidence_refuses_live_toolchain_options(self) -> None:
        with self.assertRaisesRegex(RefinementError, "--sail-bin"):
            riscv_refinement.evidence(
                Namespace(
                    reuse_committed_sail_evidence=True,
                    sail_riscv_dir=None,
                    sail_bin=Path("/usr/bin/sail"),
                    sail_generated_file=None,
                ),
                Paths(ROOT),
            )

    def test_audited_theorem_pin_round_trips_through_its_source_block(
        self,
    ) -> None:
        theorems = (
            "RiscvRefinement.Opcodes.lui_refines",
            "RiscvRefinement.Outcome.retirement?_retired",
        )
        rendered = riscv_refinement._render_audited_theorems(theorems)
        self.assertEqual(theorems, pinned_literal(rendered + "\n"))
        with self.assertRaisesRegex(RefinementError, "no refinement theorems"):
            riscv_refinement._render_audited_theorems(())
        with self.assertRaisesRegex(RefinementError, "source literal"):
            riscv_refinement._render_audited_theorems(('Riscv"Refinement.x',))

    def test_audited_theorem_write_mode_repins_from_the_audit(self) -> None:
        live = (
            *riscv_refinement.AUDITED_THEOREMS,
            "RiscvRefinement.Memory.lh_refines",
        )
        with tempfile.TemporaryDirectory() as raw:
            directory = Path(raw)
            pin_file = directory / "riscv_refinement.py"
            shutil.copyfile(ROOT / "scripts" / "riscv_refinement.py", pin_file)
            transcript = directory / "audit.txt"
            transcript.write_text(audit_transcript(live), encoding="utf-8")
            riscv_refinement.audited_theorems(
                Namespace(
                    write=True,
                    audit_output=transcript,
                    pin_file=pin_file,
                ),
                Paths(ROOT),
            )
            self.assertEqual(
                tuple(sorted(live)),
                pinned_literal(pin_file.read_text(encoding="utf-8")),
            )

    def test_audited_theorem_check_mode_diffs_and_fails(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            transcript = Path(raw) / "audit.txt"
            arguments = Namespace(
                write=False,
                audit_output=transcript,
                pin_file=None,
            )
            transcript.write_text(
                audit_transcript(riscv_refinement.AUDITED_THEOREMS),
                encoding="utf-8",
            )
            riscv_refinement.audited_theorems(arguments, Paths(ROOT))

            transcript.write_text(
                audit_transcript(
                    (
                        *riscv_refinement.AUDITED_THEOREMS,
                        "RiscvRefinement.Memory.lh_refines",
                    ),
                ),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                RefinementError,
                "unpinned RiscvRefinement.Memory.lh_refines",
            ):
                riscv_refinement.audited_theorems(arguments, Paths(ROOT))

            transcript.write_text(
                audit_transcript(riscv_refinement.AUDITED_THEOREMS[1:]),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                RefinementError,
                "retired " + re.escape(riscv_refinement.AUDITED_THEOREMS[0]),
            ):
                riscv_refinement.audited_theorems(arguments, Paths(ROOT))

    def test_audited_theorem_equality_gate_is_still_enforced(self) -> None:
        extra = audit_transcript(
            (
                *riscv_refinement.AUDITED_THEOREMS,
                "RiscvRefinement.Memory.lh_refines",
            ),
        )
        with self.assertRaisesRegex(RefinementError, "coverage drifted"):
            riscv_refinement._audit_axioms(extra)

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
