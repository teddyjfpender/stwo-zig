from __future__ import annotations

import copy
from pathlib import Path
import tempfile
import unittest

from scripts import ethereum_block_proof_plan_authority as authority
from scripts import ethereum_block_proof_protocol as protocol
from scripts import ethereum_block_proof_stream_request as source
from scripts.tests.ethereum_block_proof_fixture import build_plan


class EthereumProofSecurityTests(unittest.TestCase):
    def test_selected_leaf_is_recursive_poseidon_not_native_blake(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            plan, paths = build_plan(Path(raw))
            protocol.validate_plan(plan)
            request = source.validate_source_file(
                paths["segment_root"] / plan["leaf_stream_request"]["path"],
                require_recursive=True,
            )
            self.assertEqual(request["schema"], source.SOURCE_SCHEMA_V2)
            self.assertEqual(request["pcs"], source.RECURSIVE_POSEIDON_PCS)
            self.assertEqual(
                plan["security_parameters"]["recursive_ethereum_leaf"],
                authority.recursive_leaf_from_source(
                    request["pcs"], request["proof_profile"],
                ),
            )
            self.assertEqual(
                request["proof_profile"]["configured_pcs_bits"], 209,
            )
            self.assertEqual(
                request["proof_profile"]["conjectured_security_bits"], 120,
            )

    def test_recursive_profile_and_security_mutations_fail_closed(self) -> None:
        mutations = (
            lambda value: value["recursive_ethereum_leaf"]["proof_profile"].update(
                {"conjectured_security_bits": 209}
            ),
            lambda value: value["recursive_ethereum_leaf"]["proof_profile"].update(
                {"extension_component_count": 13}
            ),
            lambda value: value["recursive_ethereum_leaf"]["proof_profile"].update(
                {"air_program_id_m31_le": "ffffff7f" + "01000000" * 7}
            ),
            lambda value: value["recursive_ethereum_leaf"]["pcs"].update(
                {"commitment_hash": "Blake2s"}
            ),
            lambda value: value["recursive_node"].update(
                {"security_identity_sha256": "00" * 32}
            ),
            lambda value: value.update({"native_blake_leaf": {}}),
            lambda value: value.update({"conservative_end_to_end_target_bits": 209}),
            lambda value: value.update({"independent_verifier": False}),
        )
        with tempfile.TemporaryDirectory() as raw:
            plan, _ = build_plan(Path(raw))
            for mutate in mutations:
                with self.subTest(mutate=mutate):
                    security = copy.deepcopy(plan["security_parameters"])
                    mutate(security)
                    with self.assertRaises(authority.PlanAuthorityError):
                        authority.require_production_security(security, "test security")

    def test_scope_conditioned_receipts_bind_distinct_profiles(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            plan, _ = build_plan(Path(raw))
            security = plan["security_parameters"]
            leaf = authority.receipt_security(security, leaf=True)
            parent = authority.receipt_security(security, leaf=False)
            self.assertEqual(leaf["profile_kind"], "recursive_ethereum_leaf")
            self.assertEqual(leaf["proof_profile"]["extension_component_count"], 14)
            self.assertEqual(parent["profile_kind"], "recursive_node")
            self.assertNotIn("proof_profile", parent)
            self.assertNotEqual(leaf, parent)


if __name__ == "__main__":
    unittest.main()
