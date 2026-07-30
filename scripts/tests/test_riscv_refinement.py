"""Core AIR and generated-Sail boundary regression tests."""

from __future__ import annotations

from scripts.tests.riscv_refinement_test_support import *
from scripts.tests.test_riscv_refinement_audit import (
    RefinementAuditPinTest,
)
from scripts.tests.test_riscv_refinement_receipt import (
    RefinementReceiptTest,
)
from scripts.tests.test_riscv_refinement_sail import RefinementSailTest

for _test_case in (
    RefinementAuditPinTest,
    RefinementReceiptTest,
    RefinementSailTest,
):
    _test_case.__module__ = __name__
del _test_case


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

    def test_live_sail_workflow_provisions_its_runtime_solver(self) -> None:
        workflow = (
            ROOT / ".github/workflows/riscv-sail-formal.yml"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "device-tree-compiler z3",
            workflow,
        )
        self.assertIn("z3 --version", workflow)

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
            ".github/workflows/riscv-sail-formal.yml",
            ".github/workflows/riscv-team-b-refinement.yml",
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


def load_tests(
    loader: unittest.TestLoader,
    tests: unittest.TestSuite,
    pattern: str | None,
) -> unittest.TestSuite:
    # Explicit facade invocations retain the historical complete suite. During
    # broad discovery, the three split `test_*.py` modules own their cases so
    # the imported classes are not executed twice.
    if pattern is None or pattern == "test_riscv_refinement.py":
        return tests
    return loader.loadTestsFromTestCase(RefinementAirTest)


if __name__ == "__main__":
    unittest.main()
