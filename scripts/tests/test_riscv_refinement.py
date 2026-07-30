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
    sail_lean_bridge,
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
        sail.COMMITTED_MONAD_BRIDGE_RECEIPT,
        sail.COMMITTED_TRANSLATION_RECEIPT,
        *sail.COMMITTED_DEFINITIONS.values(),
    ):
        destination = paths.formal / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(Paths(ROOT).formal / relative, destination)
    for relative in (
        sail_lean_bridge.BRIDGE_SOURCE,
        sail_lean_bridge.SUPPORT_PATCH,
    ):
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / relative, destination)
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


def receipt_mapping_fixture() -> tuple[
    list[dict[str, object]],
    dict[str, dict[str, object]],
]:
    """Build exact aggregate/source certificate projections for receipt tests."""
    team_a = riscv_refinement.riscv_team_a
    team_b = riscv_refinement.riscv_team_b
    team_a_families = set(team_a.TEAM_A_FAMILIES)
    mappings: list[dict[str, object]] = []
    team_a_sources: list[dict[str, object]] = []
    team_b_sources: list[dict[str, object]] = []
    for manifest_id, mnemonic, family in air_program_contract.OPCODES:
        is_team_a = family in team_a_families
        common = {
            "family": family,
            "manifest_id": manifest_id,
            "mnemonic": mnemonic,
            "mutation": f"{mnemonic}-mutation",
            "mutation_theorem": f"RiscvRefinement.{mnemonic}.mutation",
            "non_vacuity_theorem":
                f"RiscvRefinement.{mnemonic}.exists",
            "refinement_theorem":
                f"RiscvRefinement.{mnemonic}.refines",
            "tuple_theorem": f"RiscvRefinement.{mnemonic}.tuple",
        }
        if is_team_a:
            sail_binding = (
                "generated-retirement"
                if mnemonic in team_a.GENERATED_SAIL_RETIREMENT_THEOREMS
                else "generated-clause-input"
            )
            sail_theorem = (
                team_a.GENERATED_SAIL_RETIREMENT_THEOREMS[mnemonic]
                if sail_binding == "generated-retirement"
                else team_a.GENERATED_SAIL_INPUT_THEOREMS[mnemonic]
            )
            source = {
                **common,
                "air_digest": "a" * 64,
                "axioms": [],
                "proof_target": f"RiscvRefinement.{mnemonic}.Proof",
                "proof_time_ms": manifest_id + 1,
                "sail_binding": sail_binding,
                "sail_digest": "b" * 64,
                "sail_receipt":
                    "formal/riscv-refinement/generated/sail/"
                    "generated-monad-bridge-receipt-v1.json",
                "sail_theorem": sail_theorem,
                "selector_theorem":
                    f"RiscvRefinement.{mnemonic}.selector",
                "state": "air-proved",
            }
            team_a_sources.append(source)
            mapping = {
                key: value
                for key, value in source.items()
                if key != "proof_target"
            }
            mapping.update({
                "air_binding": "exact-generated-local-program",
                "team": "A",
            })
        else:
            source = {
                **common,
                "sail_binding": team_b.DEFAULT_SAIL_BINDING,
                "state": "proved",
            }
            team_b_sources.append(source)
            mapping = {
                **source,
                "air_binding": "reviewed-family-capsule",
                "air_digest": "a" * 64,
                "axioms": None,
                "proof_time_ms": None,
                "selector_theorem": None,
                "team": "B",
            }
        mappings.append(mapping)
    return mappings, {
        "team_a": {"payload": {"certificates": team_a_sources}},
        "team_b": {"payload": {"certificates": team_b_sources}},
    }


class RefinementAirTest(unittest.TestCase):
    def test_generated_sail_team_a_input_boundary_is_explicit(self) -> None:
        self.assertEqual(
            sail_lean_bridge.CLAIM_BOUNDARY[
                "input_bound_team_a_selectors"
            ],
            [
                "LUI", "AUIPC",
                "ADDI", "XORI", "ORI", "ANDI", "SLTI", "SLTIU",
                "ADD", "SUB", "XOR", "OR", "AND", "SLT", "SLTU",
                "BEQ", "BNE", "BLT", "BGE", "BLTU", "BGEU",
                "JAL", "JALR", "FENCE",
            ],
        )
        self.assertEqual(
            sail_lean_bridge.CLAIM_BOUNDARY[
                "normalized_retirement_selectors"
            ],
            ["LUI", "ADDI"],
        )
        self.assertFalse(
            sail_lean_bridge.CLAIM_BOUNDARY[
                "team_a_normalized_retirement_composition"
            ],
        )
        self.assertFalse(
            sail_lean_bridge.CLAIM_BOUNDARY[
                "fetch_interrupt_trap_and_step_loop_framing"
            ],
        )
        self.assertEqual(
            sail_lean_bridge.CLAIM_BOUNDARY[
                "pinned_generated_model_axioms"
            ],
            ["sys_enable_experimental_extensions"],
        )

    def test_generated_sail_control_flow_axioms_are_scoped(self) -> None:
        jump_theorems = {
            theorem
            for theorem in sail_lean_bridge.THEOREMS
            if (
                "execute_BTYPE_" in theorem
                or theorem.endswith("execute_JAL_eq")
                or theorem.endswith("execute_JALR_eq")
            )
        }
        self.assertEqual(
            jump_theorems,
            sail_lean_bridge._JUMP_INPUT_THEOREMS,
        )
        for theorem in sail_lean_bridge.THEOREMS:
            expected = set(sail_lean_bridge.KERNEL_AXIOMS)
            if theorem in jump_theorems:
                expected |= set(
                    sail_lean_bridge.PINNED_GENERATED_MODEL_AXIOMS
                )
            self.assertEqual(
                set(sail_lean_bridge.EXPECTED_THEOREM_AXIOMS[theorem]),
                expected,
            )

    def test_generated_sail_axiom_parser_enforces_each_scope(self) -> None:
        def output(
            inventories: dict[str, list[str]],
        ) -> str:
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
        jump_theorem = next(
            iter(sail_lean_bridge._JUMP_INPUT_THEOREMS)
        )
        missing_model_input[jump_theorem].remove(
            "sys_enable_experimental_extensions"
        )
        with self.assertRaisesRegex(
            RefinementError,
            "per-theorem contract",
        ):
            sail_lean_bridge._proof_axioms(
                output(missing_model_input)
            )

    def test_source_closure_is_version_controlled_and_cache_free(self) -> None:
        digests = render._source_digests(Paths(ROOT))
        self.assertIn("src/core/fields/m31.zig", digests)
        self.assertIn("src/frontends/riscv/air/extract/mod.zig", digests)
        self.assertFalse(
            any("/.zig-cache/" in relative for relative in digests),
        )

    def test_proof_closure_covers_all_handwritten_lean_and_certificates(
        self,
    ) -> None:
        digests = render._proof_digests(Paths(ROOT))
        self.assertIn(
            "formal/riscv-refinement/RiscvRefinement/Air/Bridge/"
            "BaseAluReg.lean",
            digests,
        )
        self.assertIn(
            "formal/riscv-refinement/RiscvRefinement/Opcodes/Branches.lean",
            digests,
        )
        self.assertIn(
            "formal/riscv-refinement/generated-sail-bridge/Pilot.lean",
            digests,
        )
        self.assertIn(
            "formal/riscv-refinement/team-b-coverage.json",
            digests,
        )
        self.assertNotIn(
            "formal/riscv-refinement/RiscvRefinement/Air/Generated/"
            "Programs.lean",
            digests,
        )
        self.assertNotIn(
            "formal/riscv-refinement/RiscvRefinement/Sail/Generated/"
            "Pilot.lean",
            digests,
        )

    def test_generator_closure_covers_team_gates(self) -> None:
        digests = render._generator_digests(Paths(ROOT))
        for relative in (
            "scripts/riscv_opcode_coverage.py",
            "scripts/riscv_team_a.py",
            "scripts/riscv_team_b.py",
            "scripts/riscv_team_b_inventory.py",
            "scripts/riscv_team_b_refresh.py",
            "scripts/riscv_team_b_witnesses.py",
        ):
            self.assertIn(relative, digests)

    def test_empty_generated_lake_manifest_resolves_pinned_sail_once(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            project = Path(raw)
            manifest = project / "lake-manifest.json"
            manifest.write_text('{"packages":[]}\n', encoding="utf-8")

            def lake_update(
                argv: list[str],
                cwd: Path,
                **_: object,
            ) -> str:
                self.assertEqual(argv, ["lake", "update"])
                self.assertEqual(cwd, project)
                manifest.write_text(
                    json.dumps(
                        {
                            "packages": [
                                {
                                    "name": "Sail",
                                    "rev":
                                        sail_lean_bridge.LEAN_SAIL_REVISION,
                                }
                            ]
                        }
                    ),
                    encoding="utf-8",
                )
                return ""

            with mock.patch.object(
                sail_lean_bridge,
                "_run",
                side_effect=lake_update,
            ) as run:
                revision = sail_lean_bridge._lean_sail_revision(project)

            self.assertEqual(
                revision,
                sail_lean_bridge.LEAN_SAIL_REVISION,
            )
            run.assert_called_once()

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
            "schema_version": riscv_refinement.RECEIPT_SCHEMA_VERSION,
            "claim_boundary": copy.deepcopy(
                riscv_refinement.RECEIPT_CLAIM_BOUNDARY
            ),
        }
        riscv_refinement._validate_receipt_numeric_identity(valid)
        for field, replacement in (
            ("schema_version", 1),
            ("schema_version", True),
            ("schema_version", 2.0),
        ):
            malformed = copy.deepcopy(valid)
            malformed[field] = replacement
            with self.assertRaisesRegex(RefinementError, "numeric identity"):
                riscv_refinement._validate_receipt_numeric_identity(
                    malformed,
                )
        for replacement in (True, 24.0):
            malformed = copy.deepcopy(valid)
            malformed["claim_boundary"]["team_a_production_air"][
                "proved"
            ] = replacement
            with self.assertRaisesRegex(RefinementError, "numeric identity"):
                riscv_refinement._validate_receipt_numeric_identity(
                    malformed,
                )

    def test_receipt_v2_boundary_is_explicitly_non_publication(self) -> None:
        boundary = riscv_refinement.RECEIPT_CLAIM_BOUNDARY
        self.assertEqual(
            boundary["team_a_production_air"],
            {"proved": 24, "total": 24},
        )
        self.assertEqual(
            boundary["graded_opcode_index"],
            {"covered": 46, "total": 46},
        )
        self.assertEqual(
            boundary["team_a_generated_sail_input_bindings"],
            {"bound": 24, "total": 24},
        )
        self.assertEqual(
            boundary["normalized_retirements"]["proved"],
            2,
        )
        self.assertEqual(boundary["publication_level"]["proved"], 0)
        self.assertFalse(boundary["full_generated_sail_step"])
        self.assertFalse(boundary["proof_system_soundness"])
        self.assertEqual(
            boundary["external_signoffs"]["status"],
            "not-established",
        )
        signoffs = boundary["external_signoffs"]
        shared = signoffs["shared_interface_signoff"]
        self.assertEqual(shared["status"], "not-established")
        self.assertEqual(shared["required_signoffs"], 5)
        self.assertEqual(len(shared["required_roles"]), 5)
        self.assertEqual(shared["established"], [])
        family_reviews = signoffs["team_a_family_non_author_signoffs"]
        self.assertEqual(family_reviews["status"], "not-established")
        self.assertEqual(family_reviews["required_per_family"], 3)
        self.assertEqual(
            family_reviews["required_roles"],
            [
                "air-tuple-reviewer",
                "team-b-sail-profile-reviewer",
                "lean-soundness-non-vacuity-reviewer",
            ],
        )
        self.assertEqual(
            family_reviews["families"],
            list(riscv_refinement.riscv_team_a.TEAM_A_FAMILIES),
        )
        self.assertEqual(
            family_reviews["established"],
            {
                family: []
                for family
                in riscv_refinement.riscv_team_a.TEAM_A_FAMILIES
            },
        )
        joint = signoffs["joint_issue_137_gate"]
        self.assertEqual(
            joint,
            {
                "status": "not-established",
                "issue": 137,
                "established": False,
            },
        )

    def test_receipt_binds_all_six_fixed_table_schemas(self) -> None:
        schemas = riscv_refinement._fixed_table_schemas()
        self.assertEqual(
            [
                (entry["id"], entry["arity"], entry["log_size"])
                for entry in schemas
            ],
            list(air_program_contract.FIXED_TABLES),
        )
        for entry in schemas:
            self.assertRegex(entry["schema_sha256"], r"^[0-9a-f]{64}$")
            self.assertEqual(entry["domain"], entry["id"])

    def test_receipt_full_payload_identity_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            paths = Paths(Path(raw))
            relative = Path(
                "formal/riscv-refinement/team-a-coverage.json"
            )
            artifact = paths.root / relative
            artifact.parent.mkdir(parents=True)
            payload = {
                "schema_version": 1,
                "kind": "stwo-riscv-team-a-coverage",
                "certificates": [],
            }
            payload["canonical_digest"] = codec.content_digest(payload)
            artifact.write_bytes(codec.pretty_bytes(payload))
            identity = riscv_refinement._payload_identity(
                paths,
                relative,
                expected_kind="stwo-riscv-team-a-coverage",
                expected_schema=1,
            )
            riscv_refinement._validate_payload_identity(
                identity,
                "fixture",
            )

            resigned = copy.deepcopy(identity)
            resigned["payload"]["certificates"].append({"mnemonic": "lui"})
            resigned["payload"]["canonical_digest"] = codec.content_digest(
                resigned["payload"]
            )
            resigned["canonical_digest"] = resigned["payload"][
                "canonical_digest"
            ]
            with self.assertRaisesRegex(
                RefinementError,
                "full payload identity",
            ):
                riscv_refinement._validate_payload_identity(
                    resigned,
                    "fixture",
                )

    def test_receipt_coverage_payloads_cross_bind_source_indexes(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            paths = Paths(Path(raw))
            team_a = {
                "schema_version": 1,
                "kind": "stwo-riscv-team-a-coverage",
                "issue": 136,
                "families": [],
                "claim_boundary": {},
                "certificates": [
                    {"mnemonic": f"a{index}"} for index in range(24)
                ],
            }
            team_b = {
                "schema_version": 1,
                "kind": "stwo-riscv-team-b-coverage",
                "issue": 137,
                "families": [],
                "claim_boundary": "",
                "air_level_counterexample_gate": "",
                "certificates": [
                    {"mnemonic": f"b{index}"} for index in range(22)
                ],
            }
            for relative, payload in (
                (riscv_refinement.TEAM_A_INDEX_RELATIVE, team_a),
                (riscv_refinement.TEAM_B_INDEX_RELATIVE, team_b),
            ):
                payload["canonical_digest"] = codec.content_digest(payload)
                path = paths.root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(codec.pretty_bytes(payload))
            aggregate = {
                "schema_version": 1,
                "kind": "stwo-riscv-opcode-coverage",
                "claim_boundary": {},
                "source_indexes": {
                    "team_a": team_a["canonical_digest"],
                    "team_b": team_b["canonical_digest"],
                },
                "certificates": [
                    {"mnemonic": f"op{index}"} for index in range(46)
                ],
            }
            aggregate["canonical_digest"] = codec.content_digest(aggregate)
            aggregate_path = (
                paths.root / riscv_refinement.OPCODE_INDEX_RELATIVE
            )
            aggregate_path.parent.mkdir(parents=True, exist_ok=True)
            aggregate_path.write_bytes(codec.pretty_bytes(aggregate))

            identities = (
                riscv_refinement._certificate_index_identities(paths)
            )
            self.assertEqual(set(identities), {"team_a", "team_b", "aggregate"})
            self.assertEqual(
                identities["aggregate"]["payload"]["source_indexes"],
                {
                    "team_a": identities["team_a"]["canonical_digest"],
                    "team_b": identities["team_b"]["canonical_digest"],
                },
            )

            aggregate["source_indexes"]["team_a"] = "0" * 64
            aggregate["canonical_digest"] = codec.content_digest(aggregate)
            aggregate_path.write_bytes(codec.pretty_bytes(aggregate))
            with self.assertRaisesRegex(
                RefinementError,
                "does not bind both source indexes",
            ):
                riscv_refinement._certificate_index_identities(paths)

    def test_receipt_theorem_axiom_index_binds_every_entry(self) -> None:
        report = {
            theorem: []
            for theorem in riscv_refinement.AUDITED_THEOREMS
        }
        index = riscv_refinement._theorem_axiom_index(report)
        riscv_refinement._validate_theorem_axiom_index(index)
        malformed = copy.deepcopy(index)
        malformed["theorem_count"] = True
        with self.assertRaisesRegex(
            RefinementError,
            "index identity",
        ):
            riscv_refinement._validate_theorem_axiom_index(malformed)

    def test_receipt_exact_mappings_bind_mutations_and_diagnostics(
        self,
    ) -> None:
        mappings, indexes = receipt_mapping_fixture()
        validated = riscv_refinement._validate_certificate_mappings(
            mappings,
            indexes,
        )
        self.assertEqual(
            len(riscv_refinement._opcode_mutations(validated)),
            46,
        )
        diagnostics = (
            riscv_refinement._team_a_proof_time_diagnostics(validated)
        )
        self.assertEqual(len(diagnostics["measurements"]), 24)
        self.assertTrue(diagnostics["diagnostic_only"])
        self.assertFalse(diagnostics["semantic_evidence"])

        duplicate = copy.deepcopy(mappings)
        duplicate[1]["mutation"] = duplicate[0]["mutation"]
        with self.assertRaisesRegex(RefinementError, "reuses opcode mutation"):
            riscv_refinement._validate_certificate_mappings(
                duplicate,
                indexes,
            )

        reordered = copy.deepcopy(mappings)
        reordered[0], reordered[1] = reordered[1], reordered[0]
        with self.assertRaisesRegex(
            RefinementError,
            "mapping drifted",
        ):
            riscv_refinement._validate_certificate_mappings(
                reordered,
                indexes,
            )

    def test_receipt_mapping_rejects_theorem_substitution(self) -> None:
        mappings, indexes = receipt_mapping_fixture()
        mappings[0]["refinement_theorem"] = mappings[1][
            "refinement_theorem"
        ]
        with self.assertRaisesRegex(
            RefinementError,
            "differs from its embedded source certificate",
        ):
            riscv_refinement._validate_certificate_mappings(
                mappings,
                indexes,
            )

    def test_receipt_mapping_rejects_unapproved_source_axioms(self) -> None:
        mappings, indexes = receipt_mapping_fixture()
        source = indexes["team_a"]["payload"]["certificates"][0]
        source["axioms"] = ["trustMe"]
        mappings[0]["axioms"] = ["trustMe"]
        with self.assertRaisesRegex(
            RefinementError,
            "Team A receipt axioms drifted",
        ):
            riscv_refinement._validate_certificate_mappings(
                mappings,
                indexes,
            )

    def test_receipt_mapping_rejects_sail_grade_and_metadata_drift(
        self,
    ) -> None:
        mappings, indexes = receipt_mapping_fixture()
        team_a_index = next(
            index
            for index, mapping in enumerate(mappings)
            if (
                mapping["team"] == "A"
                and mapping["sail_binding"] == "generated-clause-input"
            )
        )
        team_b_index = next(
            index
            for index, mapping in enumerate(mappings)
            if mapping["team"] == "B"
        )

        swapped = copy.deepcopy(mappings)
        swapped[team_a_index]["sail_binding"], swapped[team_b_index][
            "sail_binding"
        ] = (
            swapped[team_b_index]["sail_binding"],
            swapped[team_a_index]["sail_binding"],
        )
        with self.assertRaisesRegex(
            RefinementError,
            "differs from its embedded source certificate",
        ):
            riscv_refinement._validate_certificate_mappings(
                swapped,
                indexes,
            )

        missing_metadata = copy.deepcopy(mappings)
        del missing_metadata[team_a_index]["sail_theorem"]
        with self.assertRaisesRegex(
            RefinementError,
            "differs from its embedded source certificate",
        ):
            riscv_refinement._validate_certificate_mappings(
                missing_metadata,
                indexes,
            )

    def test_receipt_production_digests_cross_bind_certificates(
        self,
    ) -> None:
        mappings, _ = receipt_mapping_fixture()
        production_inputs = {
            "opcode_air_programs": [
                {
                    "manifest_id": mapping["manifest_id"],
                    "mnemonic": mapping["mnemonic"],
                    "family": mapping["family"],
                    "content_digest": mapping["air_digest"],
                }
                for mapping in mappings
            ]
        }
        riscv_refinement._validate_production_certificate_bindings(
            production_inputs,
            mappings,
        )
        production_inputs["opcode_air_programs"][0][
            "content_digest"
        ] = "f" * 64
        with self.assertRaisesRegex(
            RefinementError,
            "production AIR digest differs",
        ):
            riscv_refinement._validate_production_certificate_bindings(
                production_inputs,
                mappings,
            )

    def test_receipt_sail_metadata_cross_binds_monad_bridge(self) -> None:
        mappings, _ = receipt_mapping_fixture()
        paths = Paths(ROOT)
        monad = riscv_refinement._payload_identity(
            paths,
            (
                paths.formal / sail.COMMITTED_MONAD_BRIDGE_RECEIPT
            ).relative_to(paths.root),
        )
        for mapping in mappings:
            if mapping["team"] == "A":
                mapping["sail_digest"] = monad["canonical_digest"]
        sail_inputs = {"monad_bridge_receipt": monad}
        riscv_refinement._validate_certificate_sail_bindings(
            sail_inputs,
            mappings,
        )
        mappings[0]["sail_digest"] = "f" * 64
        with self.assertRaisesRegex(
            RefinementError,
            "generated Sail metadata differs",
        ):
            riscv_refinement._validate_certificate_sail_bindings(
                sail_inputs,
                mappings,
            )

    def test_receipt_sail_definition_hashes_cross_bind_provenance(
        self,
    ) -> None:
        paths = Paths(ROOT)
        translation = riscv_refinement._payload_identity(
            paths,
            (
                paths.formal / sail.COMMITTED_TRANSLATION_RECEIPT
            ).relative_to(paths.root),
        )
        monad = riscv_refinement._payload_identity(
            paths,
            (
                paths.formal / sail.COMMITTED_MONAD_BRIDGE_RECEIPT
            ).relative_to(paths.root),
        )
        definition_hashes = {
            name: chr(ord("a") + index) * 64
            for index, name in enumerate(
                sorted(sail.COMMITTED_DEFINITIONS)
            )
        }
        provenance = {
            "evidence_source": sail.LIVE_EVIDENCE,
            "generated_backend_file_sha256": "d" * 64,
            "exact_configuration_sha256": "e" * 64,
            "generated_definition_sha256": definition_hashes,
            "generated_ast_translation_receipt": {
                "canonical_digest": translation["canonical_digest"],
            },
            "generated_monad_bridge_receipt": {
                "canonical_digest": monad["canonical_digest"],
            },
        }
        value = {
            "provenance": provenance,
            "provenance_digest": codec.sha256_bytes(
                codec.canonical_bytes(provenance)
            ),
            "generated_backend": {
                "artifact": sail.GENERATED_FILE.as_posix(),
                "sha256": "d" * 64,
                "size_bytes": 1,
            },
            "exact_configuration": {
                "artifact": (
                    "formal/riscv-refinement/"
                    + sail.COMMITTED_CONFIGURATION.as_posix()
                ),
                "sha256": "e" * 64,
            },
            "generated_definitions": [
                {
                    "name": name,
                    "artifact": (
                        "formal/riscv-refinement/"
                        + sail.COMMITTED_DEFINITIONS[name].as_posix()
                    ),
                    "sha256": definition_hashes[name],
                }
                for name in sorted(sail.COMMITTED_DEFINITIONS)
            ],
            "translation_receipt": translation,
            "monad_bridge_receipt": monad,
        }
        riscv_refinement._validate_sail_inputs(value)
        value["generated_definitions"][0]["sha256"] = "f" * 64
        with self.assertRaisesRegex(
            RefinementError,
            "definitions do not cross-bind to provenance",
        ):
            riscv_refinement._validate_sail_inputs(value)

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
            with self.assertRaisesRegex(
                RefinementError,
                "normalized_capsule_sha256 drifted",
            ):
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
            receipt = paths.formal / sail.COMMITTED_MONAD_BRIDGE_RECEIPT
            receipt.write_bytes(receipt.read_bytes() + b"\n")
            with self.assertRaisesRegex(
                RefinementError,
                "monad bridge receipt is not canonical pretty JSON",
            ):
                sail.carried_evidence(paths)

        with tempfile.TemporaryDirectory() as raw:
            paths = carried_fixture(Path(raw))
            bridge = paths.root / sail_lean_bridge.BRIDGE_SOURCE
            bridge.write_bytes(bridge.read_bytes() + b"-- drift\n")
            with self.assertRaisesRegex(
                RefinementError,
                "bridge field bridge_source_sha256 drifted",
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

    def test_carried_monad_bridge_rejects_a_resigned_axiom_escape(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as raw:
            paths = carried_fixture(Path(raw))
            receipt_path = (
                paths.formal / sail.COMMITTED_MONAD_BRIDGE_RECEIPT
            )
            receipt = codec.load_json(receipt_path)
            theorem = sail_lean_bridge.THEOREMS[0]
            receipt["theorem_axioms"][theorem].append("trustMe")
            receipt["canonical_digest"] = codec.content_digest(receipt)
            codec.atomic_write(receipt_path, codec.pretty_bytes(receipt))

            manifest = codec.load_json(paths.manifest)
            manifest["artifacts"][
                sail.COMMITTED_MONAD_BRIDGE_RECEIPT.as_posix()
            ] = codec.sha256_file(receipt_path)
            manifest["sail"]["generated_monad_bridge_receipt"][
                "canonical_digest"
            ] = receipt["canonical_digest"]
            manifest["canonical_digest"] = codec.content_digest(manifest)
            codec.atomic_write(paths.manifest, codec.pretty_bytes(manifest))

            with self.assertRaisesRegex(
                RefinementError,
                "proof inventory is invalid",
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
