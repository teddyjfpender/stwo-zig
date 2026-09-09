from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import unittest

from scripts import ethereum_block_proof_profile_plan as subject
from scripts import ethereum_block_proof_protocol as protocol
from scripts.tests.ethereum_block_proof_fixture import profile_plan_projection


class TemporalProfilePlanAdmissionTests(unittest.TestCase):
    def test_exact_production_projection_and_profile_selection(self) -> None:
        projection = profile_plan_projection()
        self.assertIs(subject.validate_projection(projection), projection)
        binding = {
            "schema": subject.BINDING_SCHEMA,
            "artifact": {
                "schema": subject.TRANSPORT_SCHEMA, "path": "profile-plan.json",
                "bytes": 1, "sha256": "11" * 32,
            },
            "projection": projection,
        }
        self.assertEqual(
            subject.parent_entry(binding, parent_height=1, child_kind="real"),
            projection["entries"][0],
        )
        self.assertEqual(
            subject.parent_entry(binding, parent_height=1, child_kind="empty"),
            projection["entries"][1],
        )
        self.assertEqual(
            subject.parent_entry(binding, parent_height=7, child_kind="mixed"),
            projection["entries"][7],
        )

    def test_canonical_file_binding_is_reopened_exactly(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            path = root / "profile-plan.json"
            path.write_bytes(protocol.canonical_bytes(profile_plan_projection()))
            binding = subject.binding(path)
            binding["artifact"]["path"] = path.name
            self.assertEqual(
                subject.reopen_binding(binding, root), binding["projection"],
            )

            path.write_bytes(protocol.canonical_bytes({
                **profile_plan_projection(), "profile_plan_sha256": "22" * 32,
            }))
            with self.assertRaises(protocol.ProofProtocolError):
                subject.reopen_binding(binding, root)

    def test_mutations_fail_closed_without_recreating_zig_digests(self) -> None:
        mutations = (
            lambda value: value["entries"].reverse(),
            lambda value: value["entries"][2]["admitted_child_security"].update({
                "kind": "recursive_parent_functional",
            }),
            lambda value: value["entries"][0]["admitted_child_security"].update({
                "identity_sha256": "22" * 32,
            }),
            lambda value: value["entries"][1]["admitted_child_security"].update({
                "identity_sha256": "33" * 32,
            }),
            lambda value: value["entries"][4]["transcript"].update({
                "kind": "temporal_parent_v3",
            }),
            lambda value: value["entries"][5].update({
                "next_parent_vk_sha256": "44" * 32,
            }),
            lambda value: value["entries"][3].update({
                "child_composition_manifest_sha256": "00" * 32,
            }),
            lambda value: value["entries"][6].update({
                "parent_outer_manifest_sha256": "00" * 32,
            }),
            lambda value: value["entries"][8].update({
                "entry_sha256": value["entries"][7]["entry_sha256"],
            }),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                value = copy.deepcopy(profile_plan_projection())
                mutate(value)
                with self.assertRaises(protocol.ProofProtocolError):
                    subject.validate_projection(value)

    def test_symlink_transport_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            target = root / "target.json"
            target.write_bytes(protocol.canonical_bytes(profile_plan_projection()))
            link = root / "profile-plan.json"
            link.symlink_to(target)
            with self.assertRaises(protocol.ProofProtocolError):
                subject.read(link)


if __name__ == "__main__":
    unittest.main()
