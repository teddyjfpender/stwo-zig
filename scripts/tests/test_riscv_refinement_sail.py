"""Carried and live Sail evidence regression tests."""

from __future__ import annotations

from scripts.tests.riscv_refinement_test_support import *


class RefinementSailTest(unittest.TestCase):
    def test_live_bridge_command_pins_the_external_lean_root(self) -> None:
        paths = Paths(ROOT)
        command = sail_lean_bridge._bridge_lean_command(paths)
        bridge = ROOT / sail_lean_bridge.BRIDGE_SOURCE
        self.assertEqual(command[command.index("-R") + 1], str(bridge.parent))
        self.assertEqual(command[-1], str(bridge))

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
