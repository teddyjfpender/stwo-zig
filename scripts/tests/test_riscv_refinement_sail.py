"""Carried and live Sail evidence regression tests."""

from __future__ import annotations

import os

from scripts.tests.riscv_refinement_test_support import *


class RefinementSailTest(unittest.TestCase):
    def test_live_bridge_commands_pin_the_external_lean_root(self) -> None:
        paths = Paths(ROOT)
        self.assertEqual(len(sail_lean_bridge.BRIDGE_SOURCES), 47)
        self.assertEqual(
            [source.name for source in sail_lean_bridge.BRIDGE_SOURCES],
            [
                "Pilot.lean",
                "Composition.lean",
                "ExecutionClosure.lean",
                "ExecutionCompare.lean",
                "DecodeAluBase.lean",
                "DecodeAluBaseState.lean",
                "DecodeAluIType.lean",
                "DecodeAluShift.lean",
                "DecodeAluSlli.lean",
                "DecodeAluSrli.lean",
                "DecodeAluSrai.lean",
                "DecodeAluShiftCertificates.lean",
                "DecodeMulDivEncoding.lean",
                "DecodeMulDivState.lean",
                "DecodeMulDivGate.lean",
                "DecodeMulDivMul.lean",
                "DecodeMulDivMulh.lean",
                "DecodeMulDivMulhsu.lean",
                "DecodeMulDivMulhu.lean",
                "DecodeMulDivDiv.lean",
                "DecodeMulDivDivu.lean",
                "DecodeMulDivRem.lean",
                "DecodeMulDivRemu.lean",
                "DecodeMulDiv.lean",
                "MulDivArithmetic.lean",
                "DecodeControl.lean",
                "DecodeControlState.lean",
                "ExecutionControl.lean",
                "ExecutionControlBranches.lean",
                "ExecutionControlJump.lean",
                "DecodeMemory.lean",
                "DecodeMemoryState.lean",
                "ExecutionMemory.lean",
                "ExecutionMemoryWrite.lean",
                "ExecutionMemoryVmem.lean",
                "ExecutionMemoryStore.lean",
                "PublicationAlu.lean",
                "PublicationCompare.lean",
                "PublicationShifts.lean",
                "PublicationControl.lean",
                "PublicationMemory.lean",
                "PublicationMemoryTheorem.lean",
                "PublicationMulDivMultiply.lean",
                "PublicationMulDivHighMultiply.lean",
                "PublicationMulDivDivision.lean",
                "PublicationMulDiv.lean",
                "Publication.lean",
            ],
        )
        bridge_root = str(
            (ROOT / sail_lean_bridge.PILOT_SOURCE).parent
        )
        for source in sail_lean_bridge.BRIDGE_SOURCES:
            with self.subTest(source=source):
                output = Path("/tmp") / source.with_suffix(".olean").name
                command = sail_lean_bridge._bridge_lean_command(
                    paths,
                    source,
                    output,
                )
                self.assertEqual(
                    command[command.index("-R") + 1],
                    bridge_root,
                )
                self.assertEqual(
                    command[command.index("-o") + 1],
                    str(output),
                )
        self.assertEqual(
            sail_lean_bridge.BRIDGE_SOURCE,
            sail_lean_bridge.PUBLICATION_SOURCE,
        )
        self.assertEqual(
            sail_lean_bridge.BRIDGE_SOURCES[-1],
            sail_lean_bridge.PUBLICATION_SOURCE,
        )

    def test_live_bridge_kernel_build_follows_the_declared_closure(self) -> None:
        paths = Paths(ROOT)
        project = Path("/tmp/generated-sail-project")
        output_dir = Path("/tmp/stwo-test-bridge-oleans")
        environment = {"LEAN_PATH": "/tmp/formal-oleans"}

        def run(
            argv: list[str],
            cwd: Path,
            *,
            env: dict[str, str] | None = None,
            timeout: int = 0,
        ) -> str:
            source = Path(argv[-1])
            self.assertEqual(cwd, project)
            self.assertEqual(timeout, 600)
            self.assertIsNotNone(env)
            assert env is not None
            self.assertEqual(
                env["LEAN_PATH"],
                f"{output_dir}{os.pathsep}/tmp/formal-oleans",
            )
            self.assertEqual(
                argv[argv.index("-o") + 1],
                str(output_dir / source.with_suffix(".olean").name),
            )
            return source.stem

        with mock.patch.object(
            sail_lean_bridge,
            "_run",
            side_effect=run,
        ) as kernel_run:
            output = sail_lean_bridge._kernel_build_bridge_sources(
                paths,
                project,
                environment,
                output_dir,
            )

        self.assertEqual(
            output.splitlines(),
            [source.stem for source in sail_lean_bridge.BRIDGE_SOURCES],
        )
        self.assertEqual(
            [
                Path(call.args[0][-1]).relative_to(ROOT)
                for call in kernel_run.call_args_list
            ],
            list(sail_lean_bridge.BRIDGE_SOURCES),
        )
        self.assertEqual(environment, {"LEAN_PATH": "/tmp/formal-oleans"})

    def test_live_bridge_scans_every_declared_source_for_escapes(self) -> None:
        sources = (Path("bridge/First.lean"), Path("bridge/Second.lean"))
        with tempfile.TemporaryDirectory() as raw:
            paths = Paths(Path(raw))
            for source in sources:
                absolute = paths.root / source
                absolute.parent.mkdir(parents=True, exist_ok=True)
                absolute.write_text(
                    "/-! Prose about an axiom. -/\n"
                    "theorem clean : True := trivial\n",
                    encoding="utf-8",
                )
            with mock.patch.object(
                sail_lean_bridge,
                "BRIDGE_SOURCES",
                sources,
            ):
                identities = sail_lean_bridge._bridge_source_identities(paths)
                self.assertEqual(
                    [identity["path"] for identity in identities],
                    [source.as_posix() for source in sources],
                )
                (paths.root / sources[-1]).write_text(
                    "theorem escaped : True := by sorry\n",
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(
                    RefinementError,
                    re.escape(sources[-1].as_posix()),
                ):
                    sail_lean_bridge._bridge_source_identities(paths)

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
            manifest["canonical_digest"] = render.manifest_content_digest(
                manifest
            )
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
            manifest["canonical_digest"] = render.manifest_content_digest(
                manifest
            )
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
