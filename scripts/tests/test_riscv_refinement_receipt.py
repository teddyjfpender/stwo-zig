"""Receipt identity and cross-binding regression tests."""

from __future__ import annotations

from scripts.tests.riscv_refinement_test_support import *


class RefinementReceiptTest(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
