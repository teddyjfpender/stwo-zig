"""Fail-closed tests for the Team B coverage, certificate, and AIR-binding gate."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import riscv_team_b as team_b


EXPECTED_TEAM_B_OPCODES = {
    "sll", "srl", "sra",
    "slli", "srli", "srai",
    "lb", "lh", "lw", "lbu", "lhu", "sb", "sh", "sw",
    "mul", "mulh", "mulhsu", "mulhu",
    "div", "divu", "rem", "remu",
}


class TeamBCoverageTest(unittest.TestCase):
    def _index(self) -> dict:
        return json.loads(
            team_b.CERTIFICATE_INDEX.read_text(encoding="utf-8")
        )

    def _with_index(self, index: dict):
        """Write ``index`` to a temporary certificate path and patch it in."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "team-b-coverage.json"
        path.write_text(json.dumps(index, indent=2, sort_keys=True) + "\n")
        return mock.patch.object(team_b, "CERTIFICATE_INDEX", path)

    def test_team_b_owns_exactly_the_twenty_two_issue_137_opcodes(self):
        opcodes = team_b.team_b_opcodes()
        self.assertEqual(len(opcodes), 22)
        self.assertEqual({m for m, _, _ in opcodes}, EXPECTED_TEAM_B_OPCODES)

    def test_manifest_ids_match_the_production_protocol_order(self):
        by_mnemonic = {m: i for m, _, i in team_b.manifest_opcodes()}
        # Spot-check the boundaries of each Team B family against the
        # hand-verified protocol IDs in opcode_manifest.zig.
        self.assertEqual(by_mnemonic["sll"], 2)
        self.assertEqual(by_mnemonic["slli"], 16)
        self.assertEqual(by_mnemonic["lb"], 19)
        self.assertEqual(by_mnemonic["sw"], 26)
        self.assertEqual(by_mnemonic["mul"], 37)
        self.assertEqual(by_mnemonic["remu"], 44)

    def test_committed_index_passes_every_gate(self):
        self.assertIn("team B coverage", team_b.check_coverage())
        self.assertIn("team B certificates", team_b.check_theorems())

    def test_tampered_index_digest_fails_closed(self):
        index = self._index()
        index["canonical_digest"] = "0" * 64
        with self._with_index(index):
            with self.assertRaisesRegex(team_b.TeamBError, "digest mismatch"):
                team_b.check_coverage()

    def test_missing_certificate_fails_closed(self):
        index = self._index()
        index["certificates"] = [
            entry for entry in index["certificates"] if entry["mnemonic"] != "lh"
        ]
        index["canonical_digest"] = team_b.canonical_digest(index)
        with self._with_index(index):
            with self.assertRaisesRegex(team_b.TeamBError, "coverage drifted"):
                team_b.check_coverage()

    def test_duplicate_certificate_fails_closed(self):
        index = self._index()
        index["certificates"].append(copy.deepcopy(index["certificates"][0]))
        index["canonical_digest"] = team_b.canonical_digest(index)
        with self._with_index(index):
            with self.assertRaisesRegex(team_b.TeamBError, "duplicate certificate"):
                team_b.check_coverage()

    def test_wrong_manifest_id_fails_closed(self):
        index = self._index()
        index["certificates"][0]["manifest_id"] = 999
        index["canonical_digest"] = team_b.canonical_digest(index)
        with self._with_index(index):
            with self.assertRaisesRegex(team_b.TeamBError, "manifest id"):
                team_b.check_coverage()

    def test_boolean_manifest_id_is_not_accepted_as_an_integer(self):
        index = self._index()
        target = next(
            entry for entry in index["certificates"] if entry["manifest_id"] == 2
        )
        target["manifest_id"] = True
        index["canonical_digest"] = team_b.canonical_digest(index)
        with self._with_index(index):
            with self.assertRaisesRegex(team_b.TeamBError, "manifest id"):
                team_b.check_coverage()

    def test_unrecognised_certificate_state_fails_closed(self):
        index = self._index()
        index["certificates"][0]["state"] = "mostly-proved"
        index["canonical_digest"] = team_b.canonical_digest(index)
        with self._with_index(index):
            with self.assertRaisesRegex(team_b.TeamBError, "unrecognised state"):
                team_b.check_coverage()

    def test_family_relabelling_fails_closed(self):
        index = self._index()
        target = next(
            entry for entry in index["certificates"] if entry["mnemonic"] == "div"
        )
        target["family"] = "mul"
        index["canonical_digest"] = team_b.canonical_digest(index)
        with self._with_index(index):
            with self.assertRaisesRegex(team_b.TeamBError, "records family"):
                team_b.check_coverage()

    def test_a_state_may_not_overstate_what_exists(self):
        for state, field in (
            ("refined", "refinement_theorem"),
            ("refined", "tuple_theorem"),
            ("proved", "refinement_theorem"),
            ("proved", "non_vacuity_theorem"),
            ("proved", "mutation"),
            ("proved", "mutation_theorem"),
        ):
            index = self._index()
            target = index["certificates"][0]
            target["state"] = state
            for present in team_b.REQUIRED_CERTIFICATE_FIELDS[state]:
                target[present] = f"RiscvRefinement.Opcodes.{present}"
            target[field] = None
            index["canonical_digest"] = team_b.canonical_digest(index)
            with self.subTest(state=state, missing=field):
                with self._with_index(index):
                    with self.assertRaisesRegex(
                        team_b.TeamBError, "may not overstate"
                    ):
                        team_b.check_coverage()

    def test_only_proved_entries_count_toward_coverage(self):
        index = self._index()
        # Every entry fully populated but still only "refined" must report zero
        # proved: a refinement without a load-bearing mutation is not coverage.
        for certificate in index["certificates"]:
            certificate["state"] = "refined"
            certificate["refinement_theorem"] = "RiscvRefinement.Opcodes.mul_refines"
            certificate["tuple_theorem"] = "RiscvRefinement.Opcodes.mul_refines"
            certificate["non_vacuity_theorem"] = "RiscvRefinement.Opcodes.mul_exists"
        index["canonical_digest"] = team_b.canonical_digest(index)
        with self._with_index(index):
            self.assertIn("0/22 proved", team_b.check_coverage())

    def test_an_unrecognised_sail_binding_fails_closed(self):
        index = self._index()
        index["certificates"][0]["sail_binding"] = "vibes"
        index["canonical_digest"] = team_b.canonical_digest(index)
        with self._with_index(index):
            with self.assertRaisesRegex(
                team_b.TeamBError, "unrecognised sail_binding"
            ):
                team_b.check_coverage()

    def test_a_generated_binding_without_a_receipt_fails_closed(self):
        # This is the gate that lets the coverage number survive the
        # acceptance bar moving: an entry may not claim the generated-Sail
        # binding on the strength of nothing.
        index = self._index()
        index["certificates"][0]["sail_binding"] = "generated"
        index["canonical_digest"] = team_b.canonical_digest(index)
        with self._with_index(index):
            with self.assertRaisesRegex(
                team_b.TeamBError, "records no\\s+sail_receipt"
            ):
                team_b.check_coverage()

    def test_an_empty_receipt_does_not_support_a_generated_binding(self):
        index = self._index()
        index["certificates"][0]["sail_binding"] = "generated"
        index["certificates"][0]["sail_receipt"] = ""
        index["canonical_digest"] = team_b.canonical_digest(index)
        with self._with_index(index):
            with self.assertRaisesRegex(
                team_b.TeamBError, "records no\\s+sail_receipt"
            ):
                team_b.check_coverage()

    def test_a_generated_binding_with_a_receipt_is_accepted(self):
        index = self._index()
        index["certificates"][0]["sail_binding"] = "generated"
        index["certificates"][0]["sail_receipt"] = (
            "formal/riscv-refinement/generated-manifest.json"
        )
        index["canonical_digest"] = team_b.canonical_digest(index)
        with self._with_index(index):
            self.assertIn("team B coverage", team_b.check_coverage())

    def test_a_missing_sail_binding_defaults_to_reviewed_capsule(self):
        # Certificates written before the field existed keep validating; the
        # default is the weaker claim, so nothing is overstated.
        index = self._index()
        for certificate in index["certificates"]:
            certificate.pop("sail_binding", None)
        index["canonical_digest"] = team_b.canonical_digest(index)
        with self._with_index(index):
            self.assertIn("team B coverage", team_b.check_coverage())

    def test_every_committed_certificate_states_its_sail_binding(self):
        for certificate in self._index()["certificates"]:
            self.assertIn(
                certificate.get("sail_binding"),
                team_b.SAIL_BINDINGS,
                certificate["mnemonic"],
            )

    def test_named_theorem_that_does_not_exist_fails_closed(self):
        index = self._index()
        index["certificates"][0]["refinement_theorem"] = (
            "RiscvRefinement.Opcodes.this_theorem_does_not_exist"
        )
        index["canonical_digest"] = team_b.canonical_digest(index)
        with self._with_index(index):
            with self.assertRaisesRegex(team_b.TeamBError, "do not exist"):
                team_b.check_theorems()

    def _with_certificate(self, mnemonic: str, **fields):
        index = self._index()
        target = next(
            entry
            for entry in index["certificates"]
            if entry["mnemonic"] == mnemonic
        )
        for field, value in fields.items():
            if value is None:
                target.pop(field, None)
            else:
                target[field] = value
        index["canonical_digest"] = team_b.canonical_digest(index)
        return self._with_index(index)

    def test_proved_without_a_mutation_theorem_is_refused(self):
        # Reproduces the audited attack: srl claims "proved" carrying only a
        # junk free-form mutation label and no mutation_theorem. Before the
        # fix, check_coverage and check_theorems both passed and the headline
        # number inflated to 3/22.
        with self._with_certificate(
            "srl",
            state="proved",
            mutation="srl-claimed-but-unnamed-mutation",
            mutation_theorem=None,
        ):
            with self.assertRaisesRegex(
                team_b.TeamBError, "mutation_theorem is\\s+absent"
            ):
                team_b.check_coverage()

    def test_a_junk_mutation_theorem_name_is_refused_by_the_theorem_gate(self):
        # Second stage of the same attack: naming a mutation_theorem that is
        # not a real, correctly-attributed Lean theorem satisfies the field
        # requirement but is refused by check_theorems.
        with self._with_certificate(
            "srl",
            state="proved",
            mutation="srl-claimed-but-unnamed-mutation",
            mutation_theorem="RiscvRefinement.Opcodes.srl_junk_mutation",
        ):
            self.assertIn("team B coverage", team_b.check_coverage())
            with self.assertRaisesRegex(team_b.TeamBError, "do not exist"):
                team_b.check_theorems()

    def test_a_bogus_namespace_is_refused(self):
        # Reproduces the audited attack: the trailing name exists in the Lean
        # sources, the namespace it is attributed to does not.
        with self._with_certificate(
            "srl",
            refinement_theorem="Totally.Bogus.Namespace.srl_refines",
        ):
            with self.assertRaisesRegex(
                team_b.TeamBError, "Totally.Bogus.Namespace.srl_refines"
            ):
                team_b.check_theorems()

    def test_a_real_theorem_attributed_to_the_wrong_namespace_is_refused(self):
        # RiscvRefinement.Sail.Reviewed is a real namespace and sll_refines a
        # real theorem -- but it lives in RiscvRefinement.Opcodes, so the
        # attribution is a lie and must be refused.
        with self._with_certificate(
            "sll",
            refinement_theorem="RiscvRefinement.Sail.Reviewed.sll_refines",
        ):
            with self.assertRaisesRegex(team_b.TeamBError, "do not exist"):
                team_b.check_theorems()

    def test_an_attribution_coarser_than_the_file_namespace_is_refused(self):
        # Opcodes/Shifts.lean opens `namespace RiscvRefinement.Opcodes` in one
        # declaration; attributing its theorems to bare RiscvRefinement elides
        # part of that declaration and must be refused.
        with self._with_certificate(
            "srl", refinement_theorem="RiscvRefinement.srl_refines"
        ):
            with self.assertRaisesRegex(team_b.TeamBError, "do not exist"):
                team_b.check_theorems()

    def test_a_bare_theorem_name_is_refused(self):
        with self._with_certificate("srl", refinement_theorem="srl_refines"):
            with self.assertRaisesRegex(team_b.TeamBError, "do not exist"):
                team_b.check_theorems()

    def test_the_exact_nested_namespace_attribution_is_accepted(self):
        # lb_exists is declared inside the organizational NonVacuity
        # sub-namespace of Opcodes/LoadStore.lean. Its exact fully-qualified
        # name must be accepted alongside the enclosing-namespace attribution
        # the committed index uses.
        with self._with_certificate(
            "lb",
            non_vacuity_theorem="RiscvRefinement.Opcodes.NonVacuity.lb_exists",
        ):
            self.assertIn("team B certificates", team_b.check_theorems())

    def test_the_committed_index_resolves_in_its_attributed_namespaces(self):
        self.assertIn(
            "named theorems present in", team_b.check_theorems()
        )


class TeamBLeanNamespaceParserTest(unittest.TestCase):
    """The namespace resolution that closes the theorem-attribution hole."""

    def _claimable(self, text: str) -> set:
        return team_b.lean_claimable_theorems(text, "Scratch.lean")

    def test_nested_namespaces_allow_enclosing_attribution_only(self):
        text = (
            "namespace A.B\n"
            "namespace C\n"
            "theorem inner : True := trivial\n"
            "end C\n"
            "theorem outer : True := trivial\n"
            "end A.B\n"
        )
        self.assertEqual(
            self._claimable(text),
            {"A.B.C.inner", "A.B.inner", "A.B.outer"},
        )

    def test_a_dotted_namespace_declaration_never_splits(self):
        # `namespace A.B` is one declaration; `A.t` would attribute t more
        # coarsely than the outermost declaration and is not claimable.
        text = "namespace A.B\ntheorem t : True := trivial\nend A.B\n"
        self.assertEqual(self._claimable(text), {"A.B.t"})

    def test_segment_wise_ends_are_followed(self):
        # Lean lets `end B` close the inner segment of `namespace A.B`.
        text = (
            "namespace A.B\n"
            "end B\n"
            "theorem t : True := trivial\n"
            "end A\n"
        )
        self.assertEqual(self._claimable(text), {"A.t"})

    def test_dotted_theorem_names_are_kept_whole(self):
        text = (
            "namespace A\n"
            "theorem Row.holds : True := trivial\n"
            "end A\n"
        )
        self.assertEqual(self._claimable(text), {"A.Row.holds"})

    def test_sections_and_attributes_are_transparent(self):
        text = (
            "namespace A\n"
            "section\n"
            "@[simp] theorem t : True := trivial\n"
            "end\n"
            "end A\n"
        )
        self.assertEqual(self._claimable(text), {"A.t"})

    def test_comments_do_not_open_or_close_scopes(self):
        text = (
            "namespace A\n"
            "/-! end A\nnamespace Bogus -/\n"
            "-- end A\n"
            "theorem t : True := trivial\n"
            "end A\n"
        )
        self.assertEqual(self._claimable(text), {"A.t"})

    def test_an_unbalanced_end_fails_closed(self):
        with self.assertRaisesRegex(team_b.TeamBError, "cannot parse"):
            self._claimable("end A\n")

    def test_a_mismatched_end_fails_closed(self):
        with self.assertRaisesRegex(team_b.TeamBError, "cannot parse"):
            self._claimable("namespace A\nend B\n")

    def test_a_dangling_scope_fails_closed(self):
        with self.assertRaisesRegex(team_b.TeamBError, "cannot parse"):
            self._claimable("namespace A\ntheorem t : True := trivial\n")

    def test_every_lean_source_parses(self):
        # The gate refuses files it cannot follow, so every committed source
        # must stay within the scope grammar the parser models.
        for path in sorted(team_b.LEAN_ROOT.rglob("*.lean")):
            with self.subTest(path=str(path.relative_to(team_b.LEAN_ROOT))):
                team_b.lean_claimable_theorems(
                    path.read_text(encoding="utf-8"), path.name
                )


class TeamBInventoryTest(unittest.TestCase):
    def _index(self) -> dict:
        return json.loads(
            team_b.CERTIFICATE_INDEX.read_text(encoding="utf-8")
        )

    def _with_index(self, index: dict):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "team-b-coverage.json"
        path.write_text(json.dumps(index, indent=2, sort_keys=True) + "\n")
        return mock.patch.object(team_b, "CERTIFICATE_INDEX", path)

    def _rows(self, table: str) -> dict[str, list[str]]:
        lines = table.splitlines()
        return {
            line.split()[0]: line.split()
            for line in lines[1:-1]  # strip the header and the summary
        }

    def test_inventory_lists_every_team_b_opcode_once(self):
        rows = self._rows(team_b.inventory())
        self.assertEqual(set(rows), EXPECTED_TEAM_B_OPCODES)

    def test_inventory_reports_the_four_theorem_slots(self):
        table = team_b.inventory()
        header = table.splitlines()[0].split()
        self.assertEqual(
            header,
            [
                "mnemonic", "family", "id", "state",
                "refine", "tuple", "witness", "mutation",
                "sail-binding",
            ],
        )
        rows = self._rows(table)
        # lh is proved: every slot populated, including the mutation control.
        self.assertEqual(
            rows["lh"],
            ["lh", "load_store", "20", "proved", "x", "x", "x", "x",
             "reviewed-capsule"],
        )
        # Every row must agree with the certificate index rather than with a
        # hardcoded snapshot. Snapshotting a state here made this test fail on
        # every legitimate promotion, which trains people to edit the test
        # instead of reading it.
        index = json.loads(
            team_b.CERTIFICATE_INDEX.read_text(encoding="utf-8")
        )
        certificates = {c["mnemonic"]: c for c in index["certificates"]}
        for mnemonic, row in rows.items():
            certificate = certificates[mnemonic]
            with self.subTest(opcode=mnemonic):
                self.assertEqual(row[1], certificate["family"])
                self.assertEqual(row[2], str(certificate["manifest_id"]))
                self.assertEqual(row[3], certificate["state"])
                # Slots 4-7 are refinement / tuple / non-vacuity / mutation:
                # "x" exactly when the corresponding field is populated.
                for offset, field in enumerate(
                    (
                        "refinement_theorem",
                        "tuple_theorem",
                        "non_vacuity_theorem",
                        "mutation_theorem",
                    )
                ):
                    expected = "x" if certificate.get(field) else "-"
                    self.assertEqual(row[4 + offset], expected)

    def test_inventory_summarises_state_counts(self):
        summary = team_b.inventory().splitlines()[-1]
        self.assertIn("team B inventory: 22 opcodes", summary)
        self.assertIn("proved", summary)

    def test_inventory_fails_closed_on_a_tampered_index(self):
        index = self._index()
        index["canonical_digest"] = "0" * 64
        with self._with_index(index):
            with self.assertRaisesRegex(team_b.TeamBError, "digest mismatch"):
                team_b.inventory()

    def test_inventory_is_a_cli_subcommand(self):
        import contextlib
        import io

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            status = team_b.main(["inventory"])
        self.assertEqual(status, 0)
        self.assertIn("team B inventory: 22 opcodes", stdout.getvalue())


class TeamBProfileMutationTest(unittest.TestCase):
    """Stage B5 requires Sail/profile mutations. These are them.

    Section 4 of the Team B contract erases Sail state -- reservations, CSRs,
    privileged modes, PMP configuration, vector and floating-point state -- on
    the strength of specific profile settings. If one silently flips, the
    erasure argument is void, so every claim is restated here as a check and
    every check has a mutation proving it fires.
    """

    def _profile(self) -> dict:
        return json.loads(team_b.PROFILE_PATH.read_text(encoding="utf-8"))

    def _override(self) -> dict:
        return json.loads(team_b.OVERRIDE_PATH.read_text(encoding="utf-8"))

    def _set(self, payload: dict, dotted: str, value) -> dict:
        node = payload
        parts = dotted.split(".")
        for part in parts[:-1]:
            node = node[part]
        node[parts[-1]] = value
        return payload

    def test_the_committed_profile_supports_every_contract_claim(self):
        self.assertIn("21 contract claims hold", team_b.check_profile())

    def test_the_contract_prose_still_names_the_profile_facts(self):
        self.assertIn("prose still names", team_b.check_contract_binding())

    def test_every_profile_claim_has_a_live_mutation(self):
        for dotted, expected in team_b.PROFILE_CLAIMS:
            mutated = self._set(
                self._profile(),
                dotted,
                "mutated" if not isinstance(expected, bool) else not expected,
            )
            with self.subTest(claim=dotted):
                with self.assertRaisesRegex(team_b.TeamBError, "contract requires"):
                    team_b.check_profile(profile=mutated)

    def test_every_override_claim_has_a_live_mutation(self):
        for dotted, expected, _ in team_b.OVERRIDE_CLAIMS:
            if isinstance(expected, bool):
                replacement = not expected
            elif isinstance(expected, int):
                replacement = expected + 1
            else:
                replacement = "mutated"
            mutated = self._set(self._override(), dotted, replacement)
            with self.subTest(claim=dotted):
                with self.assertRaisesRegex(team_b.TeamBError, "contract requires"):
                    team_b.check_profile(override=mutated)

    def test_enabling_an_erased_extension_is_caught(self):
        # Turning the A extension back on would reintroduce the reservation
        # set that contract section 4 erases.
        mutated = self._set(self._override(), "extensions.A.supported", True)
        with self.assertRaisesRegex(team_b.TeamBError, "reservation set"):
            team_b.check_profile(override=mutated)

    def test_enabling_csrs_is_caught(self):
        mutated = self._set(self._override(), "extensions.Zicsr.supported", True)
        with self.assertRaisesRegex(team_b.TeamBError, "CSR state"):
            team_b.check_profile(override=mutated)

    def test_dropping_the_decode_narrowing_is_caught(self):
        mutated = self._profile()
        mutated["isa"]["decode_exclusions"] = []
        with self.assertRaisesRegex(team_b.TeamBError, "exactly one instruction"):
            team_b.check_profile(profile=mutated)

    def test_widening_the_decode_narrowing_is_caught(self):
        mutated = self._profile()
        mutated["isa"]["decode_exclusions"].append(
            {"instruction": "MUL", "word": 0x02000033, "reason": "no"}
        )
        with self.assertRaisesRegex(team_b.TeamBError, "exactly one instruction"):
            team_b.check_profile(profile=mutated)

    def test_relabelling_the_excluded_instruction_is_caught(self):
        mutated = self._profile()
        mutated["isa"]["decode_exclusions"][0]["instruction"] = "FENCE"
        with self.assertRaisesRegex(team_b.TeamBError, "not FENCE.I"):
            team_b.check_profile(profile=mutated)

    def test_changing_the_excluded_word_is_caught(self):
        mutated = self._profile()
        mutated["isa"]["decode_exclusions"][0]["word"] = 0x0000000F
        with self.assertRaisesRegex(team_b.TeamBError, "names word"):
            team_b.check_profile(profile=mutated)

    def test_hiding_the_pinned_sail_divergence_is_caught(self):
        # Dropping the disposition would turn a documented divergence -- the
        # pinned model retires FENCE.I, the zkVM rejects it -- into a silent
        # one.
        mutated = self._profile()
        del mutated["isa"]["decode_exclusions"][0]["pinned_sail_disposition"]
        with self.assertRaisesRegex(team_b.TeamBError, "no longer records"):
            team_b.check_profile(profile=mutated)

    def test_a_trap_policy_change_is_caught(self):
        # "successful_retirements_only" is what makes Outcome.rejected mean
        # "outside the admitted language" rather than "the model trapped".
        mutated = self._set(self._profile(), "isa.traps", "traps_modelled")
        with self.assertRaisesRegex(team_b.TeamBError, "contract requires"):
            team_b.check_profile(profile=mutated)

    def test_a_missing_profile_path_fails_closed(self):
        mutated = self._profile()
        del mutated["isa"]["xlen"]
        with self.assertRaisesRegex(team_b.TeamBError, "is absent"):
            team_b.check_profile(profile=mutated)


class TeamBAirBindingTest(unittest.TestCase):
    def _workspace(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        lean_root = root / "lean"
        (lean_root / "Air/Family").mkdir(parents=True)
        ir_dir = root / "ir"
        ir_dir.mkdir()
        return lean_root, ir_dir

    def test_matching_digest_passes(self):
        lean_root, ir_dir = self._workspace()
        exported = ir_dir / "div.json"
        exported.write_text('{"family":"div"}')
        digest = team_b.sha256_file(exported)
        (lean_root / "Air/Family/Div.lean").write_text(
            f'def divIrDigest : String := "{digest}"\n'
        )
        with mock.patch.object(team_b, "LEAN_ROOT", lean_root):
            report = team_b.check_ir_digests(ir_dir)
        self.assertIn("1 family digests", report)

    def test_stale_digest_fails_closed(self):
        lean_root, ir_dir = self._workspace()
        (ir_dir / "div.json").write_text('{"family":"div"}')
        (lean_root / "Air/Family/Div.lean").write_text(
            f'def divIrDigest : String := "{"a" * 64}"\n'
        )
        with mock.patch.object(team_b, "LEAN_ROOT", lean_root):
            with self.assertRaisesRegex(
                team_b.TeamBError, "no longer describes the shipped AIR"
            ):
                team_b.check_ir_digests(ir_dir)

    def test_capsule_without_a_digest_fails_closed(self):
        lean_root, ir_dir = self._workspace()
        (ir_dir / "div.json").write_text('{"family":"div"}')
        (lean_root / "Air/Family/Div.lean").write_text("-- no digest here\n")
        with mock.patch.object(team_b, "LEAN_ROOT", lean_root):
            with self.assertRaisesRegex(team_b.TeamBError, "records no AIR IR digest"):
                team_b.check_ir_digests(ir_dir)

    def test_capsule_missing_one_of_its_two_families_fails_closed(self):
        lean_root, ir_dir = self._workspace()
        for family in ("mul", "mulh"):
            (ir_dir / f"{family}.json").write_text(f'{{"family":"{family}"}}')
        digest = team_b.sha256_file(ir_dir / "mul.json")
        (lean_root / "Air/Family/Multiply.lean").write_text(
            f'def mulIrDigest : String := "{digest}"\n'
        )
        with mock.patch.object(team_b, "LEAN_ROOT", lean_root):
            with self.assertRaisesRegex(team_b.TeamBError, "mulhIrDigest"):
                team_b.check_ir_digests(ir_dir)

    def test_absent_export_fails_closed(self):
        lean_root, ir_dir = self._workspace()
        (lean_root / "Air/Family/Div.lean").write_text(
            f'def divIrDigest : String := "{"a" * 64}"\n'
        )
        with mock.patch.object(team_b, "LEAN_ROOT", lean_root):
            with self.assertRaisesRegex(team_b.TeamBError, "exported AIR for family"):
                team_b.check_ir_digests(ir_dir)

    def test_absent_export_directory_fails_closed(self):
        with self.assertRaisesRegex(team_b.TeamBError, "directory is absent"):
            team_b.check_ir_digests(Path("/nonexistent/team-b-ir"))


if __name__ == "__main__":
    unittest.main()
