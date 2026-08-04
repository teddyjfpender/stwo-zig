"""Grade-blind generated-manifest identity regression tests."""

from __future__ import annotations

import copy
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from scripts import (
    riscv_refinement,
    riscv_refinement_receipt_identity as receipt_identity,
)
from scripts.riscv_refinement_lib import codec, render, sail
from scripts.riscv_refinement_lib.model import (
    SCHEMA_VERSION,
    Paths,
    RefinementError,
)


MANIFEST = Path("generated-manifest.json")


def manifest_fixture(source: str) -> dict[str, object]:
    manifest: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "kind": "stwo-riscv-refinement-generated-manifest",
        "tier": "level-1-normalized-pilot",
        "claim_boundary": dict(render.MANIFEST_CLAIM_BOUNDARY),
        "sail": {"evidence_source": source},
        "payload": {"value": 1},
    }
    manifest["canonical_digest"] = render.manifest_content_digest(manifest)
    return manifest


def manifest_identity(manifest: dict[str, object]) -> dict[str, object]:
    return {
        "artifact": "formal/riscv-refinement/generated-manifest.json",
        "canonical_digest": manifest["canonical_digest"],
        "payload": manifest,
        "payload_sha256": codec.sha256_bytes(codec.canonical_bytes(manifest)),
        "sha256": codec.sha256_bytes(codec.pretty_bytes(manifest)),
    }


class RefinementManifestIdentityTest(unittest.TestCase):
    def test_digest_ignores_only_the_evidence_grade(self) -> None:
        live = manifest_fixture(sail.LIVE_EVIDENCE)
        carried = copy.deepcopy(live)
        carried["sail"]["evidence_source"] = sail.CARRIED_EVIDENCE
        carried["canonical_digest"] = render.manifest_content_digest(carried)

        self.assertEqual(live["canonical_digest"], carried["canonical_digest"])
        mutated = copy.deepcopy(carried)
        mutated["payload"]["value"] = 2
        self.assertNotEqual(
            carried["canonical_digest"],
            render.manifest_content_digest(mutated),
        )

        mutated["sail"]["evidence_source"] = "unknown-grade"
        with self.assertRaisesRegex(RefinementError, "evidence source"):
            render.manifest_content_digest(mutated)

    def test_check_accepts_both_grades_and_rejects_all_other_drift(self) -> None:
        live = manifest_fixture(sail.LIVE_EVIDENCE)
        carried = manifest_fixture(sail.CARRIED_EVIDENCE)
        with tempfile.TemporaryDirectory() as raw:
            paths = Paths(Path(raw))
            paths.formal.mkdir(parents=True)

            paths.manifest.write_bytes(codec.pretty_bytes(carried))
            render.check_artifacts(
                paths,
                {MANIFEST: codec.pretty_bytes(live)},
            )
            paths.manifest.write_bytes(codec.pretty_bytes(live))
            render.check_artifacts(
                paths,
                {MANIFEST: codec.pretty_bytes(carried)},
            )

            drifted = copy.deepcopy(carried)
            drifted["payload"]["value"] = 2
            drifted["canonical_digest"] = render.manifest_content_digest(
                drifted
            )
            with self.assertRaisesRegex(
                RefinementError,
                "generated artifact drifted",
            ):
                render.check_artifacts(
                    paths,
                    {MANIFEST: codec.pretty_bytes(drifted)},
                )

            unknown = copy.deepcopy(live)
            unknown["sail"]["evidence_source"] = "unknown-grade"
            paths.manifest.write_bytes(codec.pretty_bytes(unknown))
            with self.assertRaisesRegex(RefinementError, "evidence source"):
                render.check_artifacts(
                    paths,
                    {MANIFEST: codec.pretty_bytes(live)},
                )

            paths.manifest.write_bytes(codec.canonical_bytes(live))
            with self.assertRaisesRegex(
                RefinementError,
                "generated artifact drifted",
            ):
                render.check_artifacts(
                    paths,
                    {MANIFEST: codec.pretty_bytes(live)},
                )

            paths.manifest.write_text(
                '{"sail":{},"sail":{}}\n',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(RefinementError, "duplicate JSON key"):
                render.check_artifacts(
                    paths,
                    {MANIFEST: codec.pretty_bytes(live)},
                )

    def test_carried_generation_cannot_downgrade_a_live_manifest(self) -> None:
        live = manifest_fixture(sail.LIVE_EVIDENCE)
        carried = manifest_fixture(sail.CARRIED_EVIDENCE)
        with tempfile.TemporaryDirectory() as raw:
            paths = Paths(Path(raw))
            paths.formal.mkdir(parents=True)
            live_bytes = codec.pretty_bytes(live)
            carried_bytes = codec.pretty_bytes(carried)

            paths.manifest.write_bytes(live_bytes)
            render.write_artifacts(paths, {MANIFEST: carried_bytes})
            self.assertEqual(paths.manifest.read_bytes(), live_bytes)

            paths.manifest.write_bytes(carried_bytes)
            render.write_artifacts(paths, {MANIFEST: live_bytes})
            self.assertEqual(paths.manifest.read_bytes(), live_bytes)

            changed = copy.deepcopy(carried)
            changed["payload"]["value"] = 2
            changed["canonical_digest"] = render.manifest_content_digest(
                changed
            )
            changed_bytes = codec.pretty_bytes(changed)
            render.write_artifacts(paths, {MANIFEST: changed_bytes})
            self.assertEqual(paths.manifest.read_bytes(), changed_bytes)

    def test_framing_claim_agrees_with_sail_provenance(self) -> None:
        evidence = mock.Mock(
            checkout_state="clean",
            profile_file_sha256={},
            model_entry_sha256="1" * 64,
            base_configuration_sha256="2" * 64,
            exact_configuration_sha256="3" * 64,
            source_file_sha256="4" * 64,
            generated_file_sha256="5" * 64,
            definition_hashes={},
            source_slice_hashes={},
            translation_receipt={
                "canonical_digest": "6" * 64,
                "definitions": {
                    name: {"ast_sha256": "7" * 64}
                    for name in sail.GENERATED_DEFINITION_HASHES
                },
            },
            monad_bridge_receipt={
                "canonical_digest": "8" * 64,
                "theorems": [],
                "claim_boundary": {},
            },
            evidence_source=sail.LIVE_EVIDENCE,
        )
        provenance = sail.provenance(evidence)
        self.assertTrue(provenance["generated_step_loop_framing_theorem"])
        self.assertEqual(
            render.MANIFEST_CLAIM_BOUNDARY[
                "lean_generated_sail_step_loop_framing"
            ],
            provenance["generated_step_loop_framing_theorem"],
        )

    def test_manifest_consumers_use_the_grade_blind_digest(self) -> None:
        manifest = manifest_fixture(sail.CARRIED_EVIDENCE)
        self.assertNotEqual(
            manifest["canonical_digest"],
            codec.content_digest(manifest),
        )
        with tempfile.TemporaryDirectory() as raw:
            paths = Paths(Path(raw))
            paths.formal.mkdir(parents=True)
            paths.manifest.write_bytes(codec.pretty_bytes(manifest))

            with self.assertRaisesRegex(RefinementError, "does not match the pin"):
                sail.carried_evidence(paths)
            with self.assertRaisesRegex(RefinementError, "does not match the pin"):
                sail.capture_pinned_generated_evidence(
                    paths,
                    Path(raw) / "backend.lean",
                )
            with self.assertRaisesRegex(RefinementError, "opcode mapping"):
                riscv_refinement.coverage(paths)

            with mock.patch.object(
                receipt_identity.render,
                "validate_committed_manifest",
            ):
                identity = receipt_identity._generated_manifest_identity(paths)
            self.assertEqual(
                identity["canonical_digest"],
                manifest["canonical_digest"],
            )

        identity = manifest_identity(manifest)
        with self.assertRaisesRegex(RefinementError, "full payload identity"):
            receipt_identity._validate_payload_identity(identity, "manifest")
        receipt_identity._validate_payload_identity(
            identity,
            "manifest",
            content_digest=render.manifest_content_digest,
        )


if __name__ == "__main__":
    unittest.main()
