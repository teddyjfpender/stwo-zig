"""Fail-closed tests for the Team A and aggregate opcode certificate gates."""

from __future__ import annotations

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import riscv_opcode_coverage as aggregate
from scripts import riscv_team_a as team_a
from scripts.riscv_refinement_lib import codec


EXPECTED_TEAM_A = {
    "add",
    "sub",
    "xor",
    "or",
    "and",
    "addi",
    "xori",
    "ori",
    "andi",
    "slt",
    "sltu",
    "slti",
    "sltiu",
    "beq",
    "bne",
    "blt",
    "bge",
    "bltu",
    "bgeu",
    "lui",
    "auipc",
    "jal",
    "jalr",
    "fence",
}


class TeamAGateTest(unittest.TestCase):
    def _index(self) -> dict:
        return json.loads(
            team_a.CERTIFICATE_INDEX.read_text(encoding="utf-8")
        )

    def _with_index(self, index: dict):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "team-a-coverage.json"
        path.write_text(json.dumps(index, indent=2, sort_keys=True) + "\n")
        return mock.patch.object(team_a, "CERTIFICATE_INDEX", path)

    def _fresh_unsigned_export(self) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        for packaged_path in sorted(
            team_a.AIR_PROGRAM_ROOT.glob("*.air-ir-v2.json")
        ):
            packaged = team_a.air_program.load_canonical(packaged_path)
            unsigned = dict(packaged)
            unsigned.pop("content_digest")
            unsigned.pop("source_identity")
            mnemonic = packaged["opcode_selector"]["mnemonic"]
            (root / f"{mnemonic}.unsigned.json").write_bytes(
                codec.canonical_bytes(unsigned)
            )
        return root

    def _generated_sail_fixture(
        self,
        root: Path,
        normalized: object,
        mnemonic: str = "lui",
    ) -> dict[str, object]:
        theorem = team_a.GENERATED_SAIL_INPUT_THEOREMS[mnemonic]
        theorems = [theorem]
        retirement_theorem = (
            team_a.GENERATED_SAIL_RETIREMENT_THEOREMS.get(mnemonic)
        )
        if retirement_theorem is not None:
            theorems.append(retirement_theorem)
        payload = {
            "schema_version": "stwo-generated-sail-monad-bridge-v1",
            "evidence_source": "exact-pinned-generated-backend",
            "claim_boundary": {
                "generated_execute_clause_monad_normalization": True,
                "team_a_execute_clause_input_binding": True,
                "input_bound_team_a_selectors": [
                    selector.upper()
                    for selector in team_a.GENERATED_SAIL_INPUT_THEOREMS
                ],
                "normalized_retirement_selectors": normalized,
            },
            "theorems": theorems,
        }
        payload["canonical_digest"] = team_a.shared.canonical_digest(payload)
        (root / "receipt.json").write_text(
            json.dumps(payload),
            encoding="utf-8",
        )
        return {
            "sail_receipt": "receipt.json",
            "sail_digest": payload["canonical_digest"],
            "sail_theorem": theorem,
        }

    def test_manifest_partition_is_exactly_twenty_four(self):
        entries = team_a.team_a_opcodes()
        self.assertEqual(len(entries), 24)
        self.assertEqual({mnemonic for mnemonic, _, _ in entries}, EXPECTED_TEAM_A)

    def test_committed_index_passes_all_team_a_gates(self):
        self.assertIn("24/24", team_a.check_coverage())
        self.assertIn("24 exact", team_a.check_air_programs())
        self.assertIn("named theorem", team_a.check_theorems())

    def test_committed_index_rebuilds_from_its_bound_diagnostics(self):
        index = self._index()
        report = {
            certificate[field]: list(certificate["axioms"])
            for certificate in index["certificates"]
            for field in team_a.THEOREM_FIELDS
        }
        proof_times = {
            certificate["proof_target"]: certificate["proof_time_ms"]
            for certificate in index["certificates"]
        }
        self.assertEqual(
            team_a.build_index(report, proof_times),
            index,
        )

    def test_tampered_digest_fails_closed(self):
        index = self._index()
        index["canonical_digest"] = "0" * 64
        with self._with_index(index):
            with self.assertRaisesRegex(team_a.TeamAError, "digest mismatch"):
                team_a.check_coverage()

    def test_missing_and_duplicate_certificates_fail_closed(self):
        for mutation in ("missing", "duplicate"):
            index = self._index()
            if mutation == "missing":
                index["certificates"].pop()
            else:
                index["certificates"].append(
                    copy.deepcopy(index["certificates"][0])
                )
            index["canonical_digest"] = team_a.shared.canonical_digest(index)
            with self.subTest(mutation=mutation), self._with_index(index):
                with self.assertRaises(team_a.TeamAError):
                    team_a.check_coverage()

    def test_wrong_manifest_id_and_family_fail_closed(self):
        for field, value in (("manifest_id", 999), ("family", "div")):
            index = self._index()
            index["certificates"][0][field] = value
            index["canonical_digest"] = team_a.shared.canonical_digest(index)
            with self.subTest(field=field), self._with_index(index):
                with self.assertRaises(team_a.TeamAError):
                    team_a.check_coverage()

    def test_only_air_proved_state_is_accepted(self):
        index = self._index()
        index["certificates"][0]["state"] = "almost-proved"
        index["canonical_digest"] = team_a.shared.canonical_digest(index)
        with self._with_index(index):
            with self.assertRaisesRegex(team_a.TeamAError, "not 'air-proved'"):
                team_a.check_coverage()

    def test_every_required_theorem_slot_is_nonempty(self):
        for field in team_a.THEOREM_FIELDS:
            index = self._index()
            index["certificates"][0][field] = ""
            index["canonical_digest"] = team_a.shared.canonical_digest(index)
            with self.subTest(field=field), self._with_index(index):
                with self.assertRaisesRegex(team_a.TeamAError, field):
                    team_a.check_coverage()

    def test_per_selector_theorems_and_mutations_are_distinct(self):
        for field in (*team_a.THEOREM_FIELDS, "mutation"):
            index = self._index()
            index["certificates"][1][field] = (
                index["certificates"][0][field]
            )
            index["canonical_digest"] = team_a.shared.canonical_digest(index)
            with self.subTest(field=field), self._with_index(index):
                with self.assertRaisesRegex(
                    team_a.TeamAError,
                    "reuse",
                ):
                    team_a.check_coverage()

    def test_selector_specific_proof_bindings_cannot_be_swapped(self):
        for field in (*team_a.THEOREM_FIELDS, "mutation"):
            index = self._index()
            first = index["certificates"][0]
            second = index["certificates"][1]
            first[field], second[field] = second[field], first[field]
            index["canonical_digest"] = team_a.shared.canonical_digest(index)
            with self.subTest(field=field), self._with_index(index):
                with self.assertRaisesRegex(
                    team_a.TeamAError,
                    "pinned selector-specific proof binding",
                ):
                    team_a.check_coverage()

    def test_proof_target_is_selector_specific_and_pinned(self):
        index = self._index()
        certificate = index["certificates"][0]
        expected = team_a.PROOF_TIMING_TARGETS[certificate["mnemonic"]]
        replacement = next(
            target
            for target in set(team_a.PROOF_TIMING_TARGETS.values())
            if target != expected
        )
        certificate["proof_target"] = replacement
        index["canonical_digest"] = team_a.shared.canonical_digest(index)
        with self._with_index(index):
            with self.assertRaisesRegex(
                team_a.TeamAError,
                "not its pinned build target",
            ):
                team_a.check_coverage()

    def test_generated_sail_claim_requires_existing_receipt(self):
        index = self._index()
        certificate = index["certificates"][0]
        certificate["sail_binding"] = "generated-retirement"
        certificate.pop("sail_receipt", None)
        certificate.pop("sail_digest", None)
        certificate.pop("sail_theorem", None)
        index["canonical_digest"] = team_a.shared.canonical_digest(index)
        with self._with_index(index):
            with self.assertRaisesRegex(
                team_a.TeamAError,
                "without a complete receipt binding",
            ):
                team_a.check_coverage()

    def test_generated_input_binding_does_not_imply_retirement(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            certificate = self._generated_sail_fixture(
                root,
                ["LUI", "ADDI"],
                mnemonic="auipc",
            )
            with mock.patch.object(team_a, "REPOSITORY_ROOT", root):
                team_a._check_generated_sail_binding(
                    "auipc",
                    "generated-clause-input",
                    certificate,
                )
                with self.assertRaisesRegex(
                    team_a.TeamAError,
                    "expected None",
                ):
                    team_a._check_generated_sail_binding(
                        "auipc",
                        "generated-retirement",
                        certificate,
                    )

    def test_generated_receipt_rejects_malformed_normalized_selector_set(self):
        for malformed in ("LUI,ADDI", ["LUI", "LUI"], ["LUI", 1]):
            with tempfile.TemporaryDirectory() as raw:
                root = Path(raw)
                certificate = self._generated_sail_fixture(
                    root,
                    malformed,
                )
                with (
                    self.subTest(malformed=malformed),
                    mock.patch.object(team_a, "REPOSITORY_ROOT", root),
                    self.assertRaisesRegex(
                        team_a.TeamAError,
                        "malformed normalized selector set",
                    ),
                ):
                    team_a._check_generated_sail_binding(
                        "lui",
                        "generated-clause-input",
                        certificate,
                    )

    def test_generated_receipt_must_name_each_input_bound_selector(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            certificate = self._generated_sail_fixture(
                root,
                ["LUI", "ADDI"],
                mnemonic="auipc",
            )
            payload = json.loads(
                (root / "receipt.json").read_text(encoding="utf-8")
            )
            payload["claim_boundary"]["input_bound_team_a_selectors"] = [
                "LUI"
            ]
            payload["canonical_digest"] = team_a.shared.canonical_digest(
                payload
            )
            (root / "receipt.json").write_text(
                json.dumps(payload),
                encoding="utf-8",
            )
            certificate["sail_digest"] = payload["canonical_digest"]
            with (
                    mock.patch.object(team_a, "REPOSITORY_ROOT", root),
                    self.assertRaisesRegex(
                        team_a.TeamAError,
                        "does not bind exactly",
                    ),
            ):
                team_a._check_generated_sail_binding(
                    "auipc",
                    "generated-clause-input",
                    certificate,
                )

    def test_generated_receipt_cannot_substitute_another_selector_theorem(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            certificate = self._generated_sail_fixture(
                root,
                ["LUI", "ADDI"],
            )
            certificate["sail_theorem"] = (
                team_a.GENERATED_SAIL_INPUT_THEOREMS["auipc"]
            )
            with (
                mock.patch.object(team_a, "REPOSITORY_ROOT", root),
                self.assertRaisesRegex(
                    team_a.TeamAError,
                    "expected",
                ),
            ):
                team_a._check_generated_sail_binding(
                    "lui",
                    "generated-clause-input",
                    certificate,
                )

    def test_unbound_sail_claim_cannot_carry_proof_metadata(self):
        index = self._index()
        certificate = index["certificates"][0]
        certificate["sail_binding"] = "unbound"
        certificate["sail_digest"] = "0" * 64
        index["canonical_digest"] = team_a.shared.canonical_digest(index)
        with self._with_index(index):
            with self.assertRaisesRegex(team_a.TeamAError, "Sail-unbound"):
                team_a.check_coverage()

    def test_air_digest_tampering_fails_exact_program_binding(self):
        index = self._index()
        index["certificates"][0]["air_digest"] = "0" * 64
        index["canonical_digest"] = team_a.shared.canonical_digest(index)
        with self._with_index(index):
            with self.assertRaisesRegex(
                team_a.TeamAError,
                "does not bind its exact",
            ):
                team_a.check_air_programs()

    def test_fresh_unsigned_export_binds_all_team_a_programs(self):
        export = self._fresh_unsigned_export()
        with mock.patch.object(
            team_a.air_program,
            "verify_production_binding",
            wraps=team_a.air_program.verify_production_binding,
        ) as verify:
            self.assertIn(
                "fresh 46-program unsigned export",
                team_a.check_air_programs(export),
            )
        self.assertEqual(verify.call_count, team_a.TEAM_A_OPCODE_COUNT)
        with mock.patch("builtins.print"):
            self.assertEqual(
                team_a.main(
                    [
                        "check",
                        "--air-program-ir-dir",
                        str(export),
                    ]
                ),
                0,
            )

    def test_fresh_unsigned_export_rejects_missing_and_extra_files(self):
        export = self._fresh_unsigned_export()
        (export / "mul.unsigned.json").unlink()
        with self.assertRaisesRegex(
            team_a.TeamAError,
            "coverage drifted",
        ):
            team_a.check_air_programs(export)

        export = self._fresh_unsigned_export()
        (export / "unexpected.unsigned.json").write_bytes(b"{}")
        with self.assertRaisesRegex(
            team_a.TeamAError,
            "coverage drifted",
        ):
            team_a.check_air_programs(export)

    def test_fresh_unsigned_export_rejects_wrong_selector_payload(self):
        export = self._fresh_unsigned_export()
        (export / "sub.unsigned.json").write_bytes(
            (export / "add.unsigned.json").read_bytes()
        )
        with self.assertRaisesRegex(
            team_a.TeamAError,
            "manifest/family selector drifted",
        ):
            team_a.check_air_programs(export)

    def test_fresh_unsigned_export_rejects_semantic_mutation(self):
        export = self._fresh_unsigned_export()
        path = export / "lui.unsigned.json"
        payload = json.loads(path.read_text(encoding="utf-8"))
        constant = next(
            node
            for node in payload["nodes"]
            if node == {"op": "const", "value": 4096}
        )
        constant["value"] = 8192
        path.write_bytes(codec.canonical_bytes(payload))
        with self.assertRaisesRegex(
            team_a.TeamAError,
            "does not match the fresh unsigned",
        ):
            team_a.check_air_programs(export)

    def test_fresh_unsigned_export_rejects_stale_source_payload(self):
        export = self._fresh_unsigned_export()
        source_directory = tempfile.TemporaryDirectory()
        self.addCleanup(source_directory.cleanup)
        source_root = Path(source_directory.name)
        source_paths = team_a.air_program.FAMILY_SOURCE_PATHS[
            "base_alu_reg"
        ]
        for relative in source_paths:
            source = team_a.REPOSITORY_ROOT / relative
            destination = source_root / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(source.read_bytes())
        stale_source = source_root / source_paths[0]
        stale_source.write_bytes(stale_source.read_bytes() + b"\n")
        with (
            mock.patch.object(team_a, "REPOSITORY_ROOT", source_root),
            self.assertRaisesRegex(
                team_a.TeamAError,
                "does not match the fresh unsigned",
            ),
        ):
            team_a.check_air_programs(export)

    def test_axiom_inventory_and_proof_time_fail_closed(self):
        mutations = (
            ("axioms", ["not.an.approved.axiom"], "axiom inventory"),
            ("proof_time_ms", 0, "proof-time diagnostic"),
            (
                "proof_time_ms",
                team_a.MAX_PROOF_TIME_MS + 1,
                "proof-time diagnostic",
            ),
        )
        for field, value, message in mutations:
            index = self._index()
            index["certificates"][0][field] = value
            index["canonical_digest"] = team_a.shared.canonical_digest(index)
            with self.subTest(field=field, value=value), self._with_index(index):
                with self.assertRaisesRegex(team_a.TeamAError, message):
                    team_a.check_coverage()

    def test_live_axiom_binding_tampering_fails_closed(self):
        index = self._index()
        report = {
            certificate[field]: list(certificate["axioms"])
            for certificate in index["certificates"]
            for field in team_a.THEOREM_FIELDS
        }
        with self._with_index(index):
            self.assertIn("24 certificate", team_a.check_axiom_bindings(report))
        first = index["certificates"][0]
        first["axioms"] = (
            []
            if first["axioms"]
            else ["propext"]
        )
        index["canonical_digest"] = team_a.shared.canonical_digest(index)
        with self._with_index(index):
            with self.assertRaisesRegex(
                team_a.TeamAError,
                "axiom inventory drifted",
            ):
                team_a.check_axiom_bindings(report)

    def test_axiom_transcript_parser_fails_closed(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "audit.txt"
        path.write_text(
            "REFINEMENT_AXIOM RiscvRefinement.Demo propext\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(team_a.TeamAError, "before theorem"):
            team_a.parse_audit_output(path)

    def test_nonexistent_theorem_fails_attribution(self):
        index = self._index()
        index["certificates"][0]["refinement_theorem"] = (
            "RiscvRefinement.Opcodes.not_a_real_theorem"
        )
        index["canonical_digest"] = team_a.shared.canonical_digest(index)
        with self._with_index(index):
            with self.assertRaisesRegex(team_a.TeamAError, "absent"):
                team_a.check_theorems()

    def test_raw_column_guard_rejects_architecture_by_construction(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        root = Path(directory.name)
        relative = "Air/Bridge/Demo.lean"
        path = root / relative
        path.parent.mkdir(parents=True)
        path.write_text(
            "\n"
            "def columns (row : Row) : Nat → M31\n"
            "  | 0 => boolM31 (taken row)\n"
            "  | _ => 0\n"
            "\n"
            "def evaluation := true\n",
            encoding="utf-8",
        )
        contract = {
            relative: {
                "blocks": 1,
                "forbidden": ("taken row",),
            }
        }
        with (
            mock.patch.object(team_a, "LEAN_ROOT", root),
            mock.patch.object(team_a, "RAW_COLUMN_MODELS", contract),
        ):
            with self.assertRaisesRegex(
                team_a.TeamAError,
                "constructs a production column",
            ):
                team_a.check_raw_column_models()

    def test_aggregate_index_is_exact_and_current(self):
        message = aggregate.check_index()
        self.assertIn("46/46", message)
        self.assertIn("current production-source identities", message)
        payload = aggregate.build_index()
        self.assertEqual(
            [entry["manifest_id"] for entry in payload["certificates"]],
            list(range(46)),
        )
        self.assertFalse(payload["claim_boundary"]["whole_frontend_verified"])
        self.assertEqual(
            payload["claim_boundary"]["publication_level_opcodes"],
            0,
        )
        self.assertEqual(
            payload["claim_boundary"]["generated_sail_input_only_bindings"]
            + payload["claim_boundary"]["generated_sail_retirement_bindings"]
            + payload["claim_boundary"]["reviewed_sail_capsule_bindings"]
            + payload["claim_boundary"]["unbound_sail_selectors"],
            46,
        )

    def test_aggregate_index_fails_when_a_production_source_identity_drifts(self):
        with mock.patch.object(
            aggregate.air_program,
            "verify_source_files",
            side_effect=aggregate.RefinementError("source digest drifted"),
        ):
            with self.assertRaisesRegex(
                aggregate.CoverageError,
                "not canonically bound to the current source tree",
            ):
                aggregate.build_index()


if __name__ == "__main__":
    unittest.main()
