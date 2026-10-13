"""Hostile source controls for the scoped CAS05 BCS/ROM theorem-input ledger."""

import hashlib
import struct
import subprocess
import sys
import unittest

from scripts.check_cas05_bcs_join import ROOT, SOURCES, audit_sources


class Cas05BcsJoinTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.sources = {key: (ROOT / path).read_text() for key, path in SOURCES.items()}

    def mutated(self, key: str, old: str, new: str) -> None:
        changed = self.sources.copy()
        self.assertIn(old, changed[key])
        changed[key] = changed[key].replace(old, new, 1)
        with self.assertRaises(ValueError):
            audit_sources(changed)

    def test_current_source_is_scoped_and_unproven(self) -> None:
        report = audit_sources(self.sources)
        self.assertIsNone(report["native_proven_security_bits"])
        self.assertFalse(report["full_theorem_join_complete"])
        self.assertTrue(report["BCS_theorem_inputs"]["CAS05_no_grinding"])
        self.assertFalse(report["role_framing"]["global_transcript_merkle_hash_input_disjointness_proven"])
        self.assertTrue(report["role_framing"]["accepted_CAS05_call_roster_input_disjointness_source_checked"])
        self.assertEqual([3, 6], report["accepted_call_roster_input_lengths"]["claim_felt_counts_requiring_digest_guard"])
        self.assertEqual(2048, report["max_query_hash_blocks"])

    def test_root_after_ood_draw_rejected(self) -> None:
        self.mutated("verifier",
                     "blake2_merkle.Blake2sMerkleChannel.mixRoot(&staged, root);",
                     "// removed root absorption")

    def test_claim_after_batch_draw_rejected(self) -> None:
        self.mutated("verifier", "staged.mixFelts(height);",
                     "_ = height;")

    def test_merkle_overlap_rejection_is_required(self) -> None:
        self.mutated("verifier", "felt_count == 3", "felt_count == 2")
        self.mutated("verifier", "felt_count == 6", "felt_count == 5")
        self.mutated("verifier", "try checkClaimInputSeparation(staged.digestBytes(), height.len);",
                     "// removed input separation")

    def test_typed_roles_and_indices_are_required(self) -> None:
        self.mutated("verifier", "staged.mixU64(SOURCE_ROOT_TAG);", "staged.mixU64(PROFILE_TAG);")
        self.mutated("verifier", "staged.mixU64(CLAIM_HEIGHT_TAG);",
                     "staged.mixU64(CLAIM_GROUP_TAG);")
        self.mutated("verifier", "staged.mixU64(index);", "staged.mixU64(0);")
        self.mutated("verifier", "channel.mixU64(coefficients.len);",
                     "channel.mixU64(0);")

    def test_exact_old_preimage_collision_and_new_first_step_separation(self) -> None:
        digest = bytes(range(32))
        canonical_two_felts = struct.pack("<8I", 1, 2, 3, 4, 5, 6, 7, 8)
        root = canonical_two_felts
        self.assertEqual(digest + root, digest + canonical_two_felts)
        source_tag = struct.pack("<Q", 0x5333_3153_5243_3036)
        terminal_tag = struct.pack("<Q", 0x5333_3154_524d_3036)
        self.assertNotEqual(digest + source_tag, digest + terminal_tag)

    def test_conditional_line_merkle_leaf_vs_three_felts_overlap(self) -> None:
        # This is a byte-level equality at a specially fixed channel digest,
        # not a claim that a prover can reach that digest in the actual game.
        line_prefix = b"leaf" + bytes(60)
        digest = line_prefix[:32]
        row = struct.pack("<4I", 1, 2, 3, 4)
        three_felts = bytes(32) + row
        self.assertEqual(80, len(digest + three_felts))
        self.assertEqual(digest + three_felts, line_prefix + row)
        self.assertEqual(hashlib.blake2s(digest + three_felts).digest(),
                         hashlib.blake2s(line_prefix + row).digest())
        node_prefix = b"node" + bytes(60)
        node_digest = node_prefix[:32]
        children = struct.pack("<16I", *range(1, 17))
        six_felts = bytes(32) + children
        self.assertEqual(128, len(node_digest + six_felts))
        self.assertEqual(node_digest + six_felts, node_prefix + children)

    def test_line_commitment_before_its_challenge_rejected(self) -> None:
        self.mutated("verifier", "alpha.* = staged.drawSecureFelt();",
                     "alpha.* = staged.drawSecureFeltOther();")

    def test_raw_query_count_or_mask_change_rejected(self) -> None:
        self.mutated("queries", "word & query_mask", "word % query_mask")
        self.mutated("verifier", "source.query_count,", "source.query_count + 1,")

    def test_counter_wrap_and_channel_switch_rejected(self) -> None:
        self.mutated("channel", "self.n_draws = nextDrawCounter(self.n_draws) catch",
                     "self.n_draws +%= 1;")
        self.mutated("relation", "channel: *blake2s_channel.Blake2sChannel,",
                     "channel: *blake2s_channel.Blake2sM31Channel,")

    def test_missing_merkle_role_tag_rejected(self) -> None:
        self.mutated("merkle", 'h.update("S31XDI03");', 'h.update("S31XDU03");')
        self.mutated("line_merkle", 'pub const LEAF_PREFIX = makePrefix("leaf");',
                     'pub const LEAF_PREFIX = makePrefix("node");')

    def test_require_proven_exits_nonzero(self) -> None:
        result = subprocess.run(
            [sys.executable, "-B", "scripts/check_cas05_bcs_join.py", "--require-proven"],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        self.assertEqual(2, result.returncode)
        self.assertIn('"full_theorem_join_complete": false', result.stdout)


if __name__ == "__main__":
    unittest.main()
