"""Hostile source controls for the scoped CAS05 BCS/ROM theorem-input ledger."""

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
        self.assertEqual(2048, report["max_query_hash_blocks"])

    def test_root_after_ood_draw_rejected(self) -> None:
        self.mutated("shared",
                     "staged.updateDigest(blake2_hash.Blake2sHasher.concatAndHash(staged.digestBytes(), root));",
                     "// removed root absorption")

    def test_claim_after_batch_draw_rejected(self) -> None:
        self.mutated("shared", "for (claims) |height| channel.mixFelts(height);",
                     "for (claims) |height| _ = height;")

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

    def test_require_proven_exits_nonzero(self) -> None:
        result = subprocess.run(
            [sys.executable, "-B", "scripts/check_cas05_bcs_join.py", "--require-proven"],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        self.assertEqual(2, result.returncode)
        self.assertIn('"full_theorem_join_complete": false', result.stdout)


if __name__ == "__main__":
    unittest.main()
