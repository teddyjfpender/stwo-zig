"""Core AIR and generated-Sail boundary regression tests."""

from __future__ import annotations

import subprocess
import sys
import textwrap

from scripts.tests.riscv_refinement_test_support import *
from scripts.tests.test_riscv_refinement_audit import (
    RefinementAuditPinTest,
)
from scripts.tests.test_riscv_refinement_receipt import (
    RefinementReceiptTest,
)
from scripts.tests.test_riscv_refinement_manifest_identity import (
    RefinementManifestIdentityTest,
)
from scripts.tests.test_riscv_refinement_sail_policy import (
    RefinementPublicationPolicyTest,
)
from scripts.tests.test_riscv_refinement_sail import RefinementSailTest

for _test_case in (
    RefinementAuditPinTest,
    RefinementManifestIdentityTest,
    RefinementPublicationPolicyTest,
    RefinementReceiptTest,
    RefinementSailTest,
):
    _test_case.__module__ = __name__
del _test_case


class RefinementAirTest(unittest.TestCase):
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
            ".github/workflows/riscv-refinement.yml",
            "scripts/riscv_air_ir_equivalence.py",
            "scripts/riscv_air_program_layout.py",
            "scripts/riscv_opcode_coverage.py",
            "scripts/riscv_team_a.py",
            "scripts/riscv_team_b.py",
            "scripts/riscv_team_b_inventory.py",
            "scripts/riscv_team_b_refresh.py",
            "scripts/riscv_team_b_witnesses.py",
            "scripts/riscv_refinement_lib/air_program_layout.py",
            "scripts/tests/test_riscv_air_ir_equivalence.py",
            "scripts/tests/test_riscv_air_program_layout.py",
            "formal/riscv-refinement/air-program-node-layout-v1.json",
            "formal/riscv-refinement/team-b-air-semantic-equivalence-v1.json",
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

    def test_an_escaped_quote_cannot_reopen_comment_scanning_inside_a_literal(
        self,
    ) -> None:
        """The fail-open branch of ``_skip_lean_string``, exercised end to end.

        ``"x \\" /- y"`` is one literal. Drop the backslash-escape branch and the
        skip stops at the escaped quote, back in code mode but still inside the
        literal, where the ``/-`` opens a block comment. Everything up to the next
        ``-/`` is then blanked -- including the ``axiom`` on the following line --
        and the scan reports a clean sweep over a file that declares an axiom.

        This is the one direction in which the skipper can hide a proof escape, so
        it is asserted on the scanner rather than on the stripper: the obligation
        is that the term is *reported*, not merely that some characters survive.
        """
        text = (
            'def s : String := "x \\" /- y"\n'
            "axiom cheat : True\n"
            "def t : Nat := 1 -/\n"
        )
        with tempfile.TemporaryDirectory() as raw:
            paths = self._lean_tree(Path(raw), {"Escaped.lean": text})
            with self.assertRaisesRegex(
                RefinementError,
                r"RiscvRefinement/Escaped\.lean:2",
            ):
                riscv_refinement._scan_forbidden_proof_terms(paths)
        # And the mechanism, so a failure says which half broke: the literal's own
        # text is skipped, not blanked, and the line after it is still code.
        stripped = riscv_refinement._strip_lean_comments(text)
        self.assertIn("/- y", stripped)
        self.assertIn("axiom cheat", stripped)

    def test_a_stray_quote_is_bounded_to_its_line_so_later_prose_stays_prose(
        self,
    ) -> None:
        """The newline-recovery branch, which fails closed rather than open.

        A literal is skipped, never blanked, so an unterminated one hides nothing.
        What it can do is switch comment stripping off for everything up to the
        next quote in the file. The comment two lines below would then be read as
        code and its prose reported as a proof escape -- a breach report about a
        sentence. Recovery at the newline is what keeps the stripper working.
        """
        text = (
            'def a : String := "unterminated\n'
            "-- prose about sorry, axiom and native_decide\n"
            'def b : String := "closed"\n'
        )
        stripped = riscv_refinement._strip_lean_comments(text)
        for term in ("sorry", "axiom", "native_decide"):
            self.assertNotIn(term, stripped)
        self.assertIn('def b : String := "closed"', stripped)
        self.assertEqual(len(text), len(stripped))
        with tempfile.TemporaryDirectory() as raw:
            paths = self._lean_tree(Path(raw), {"Stray.lean": text})
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

    #: Reached under a bare top-level name, as direct execution reaches it.
    _ONE_IDENTITY_PROGRAM = textwrap.dedent(
        """
        import importlib
        import sys

        root = sys.argv[1]
        # Exactly what `python3 scripts/riscv_refinement.py` puts on sys.path:
        # the scripts directory, and no repository root.
        sys.path.insert(0, root + "/scripts")
        module = importlib.import_module("riscv_refinement")

        # Now reach the library the way every test and sibling script reaches it.
        sys.path.insert(0, root)
        from scripts.riscv_refinement_lib.model import RefinementError

        assert module.RefinementError is RefinementError, (
            "two identities: "
            f"{module.RefinementError.__module__} vs {RefinementError.__module__}"
        )
        # The consequence, stated as the thing that actually broke: an
        # `except`/`assertRaises` written against one class must catch what the
        # library raises.
        try:
            raise module.RefinementError("boom")
        except RefinementError:
            pass
        print("one identity")
        """
    )

    def test_the_library_has_one_identity_however_the_script_is_reached(self) -> None:
        """``RefinementError`` cannot become two classes, whatever is on sys.path.

        Direct execution puts ``scripts/`` on ``sys.path`` rather than the
        repository root, so a bare ``riscv_refinement_lib`` import would load the
        same files under a second module name. ``assertRaises(RefinementError)``
        against the qualified class then cannot see the bare class, and the
        assertion passes vacuously -- four of them did.

        Run in a subprocess from a neutral working directory: an in-process check
        would find the repository root already importable through ``''`` and prove
        nothing, and importing the module twice would leave both identities in this
        interpreter's ``sys.modules`` for every later test.
        """
        with tempfile.TemporaryDirectory() as neutral:
            completed = subprocess.run(
                [sys.executable, "-c", self._ONE_IDENTITY_PROGRAM, str(ROOT)],
                cwd=neutral,
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(
            0,
            completed.returncode,
            f"{completed.stdout}\n{completed.stderr}",
        )
        self.assertIn("one identity", completed.stdout)

    def test_direct_execution_still_works_without_a_second_spelling(self) -> None:
        """The fallback's purpose is kept; only its second module name is gone.

        The bare spelling existed so ``python3 scripts/riscv_refinement.py`` would
        run at all. Removing it without this would trade a silent-vacuity bug for a
        broken entry point, so both halves are asserted: the script runs from a
        working directory that makes the repository root unimportable, and its
        source names the library under one spelling only.
        """
        with tempfile.TemporaryDirectory() as neutral:
            completed = subprocess.run(
                [sys.executable, str(ROOT / "scripts" / "riscv_refinement.py"), "--help"],
                cwd=neutral,
                check=False,
                capture_output=True,
                text=True,
            )
        self.assertEqual(0, completed.returncode, completed.stderr)
        self.assertIn("usage: riscv_refinement.py", completed.stdout)

        source = (ROOT / "scripts" / "riscv_refinement.py").read_text(encoding="utf-8")
        bare = re.compile(r"^\s*(?:from|import)\s+riscv_refinement_lib\b", re.MULTILINE)
        self.assertIsNone(
            bare.search(source),
            "the bare spelling is back; it gives the library a second identity",
        )
        self.assertIn("from scripts.riscv_refinement_lib import", source)

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
