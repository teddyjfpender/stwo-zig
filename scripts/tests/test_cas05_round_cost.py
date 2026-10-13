"""Arithmetic and hostile source controls for CAS05 internal hash budgets."""

import tempfile
import unittest
from fractions import Fraction
from pathlib import Path

from scripts.check_cas05_round_cost import (
    budget,
    check_cost_sources,
    check_secure_sampler_sources,
    secure_sampler_tail,
)
from scripts.check_cas05_bcs_join import ROOT


class Cas05RoundCostTests(unittest.TestCase):
    def test_source_roster_and_three_height_hand_count(self) -> None:
        check_cost_sources()
        result = budget(7, 3, 2, 13, (2, 2, 2))
        self.assertEqual(5, result["rounds"]["native_commitment_challenge_barriers"])
        self.assertEqual(6, result["rounds"]["logical_random_reductions"])
        self.assertIsNone(result["rounds"]["BCS_R_for_CAS05_proven_applicable"])
        hashes = result["hash_finalizations"]
        self.assertEqual(35, hashes["transcript_absorptions_exact"])
        self.assertEqual(2, hashes["query_blocks_exact"])
        self.assertEqual(42, hashes["transcript_if_no_secure_rejections"])
        self.assertEqual(62, hashes["transcript_on_ideal_five_block_good_event_upper"])
        self.assertEqual(260, hashes["source_merkle_verifier_upper"])
        self.assertEqual([182, 156], hashes["line_merkle_verifier_upper_by_height"])
        self.assertEqual(640, hashes["complete_verifier_if_no_secure_rejections_upper"])
        self.assertEqual(660, hashes["complete_verifier_on_ideal_five_block_good_event_upper"])
        self.assertEqual(351, hashes["dense_host_source_tree_exact_if_admitted"])
        self.assertEqual(190, hashes["dense_host_line_trees_exact_if_admitted"])
        self.assertEqual(583, hashes["dense_host_prover_if_no_secure_rejections_exact_if_admitted"])
        self.assertIsNone(result["native_security_bits"])

    def test_acceptance_envelope_and_counter_ceiling(self) -> None:
        result = budget(22, 8, 1, 16384, (1,) * 8)
        hashes = result["hash_finalizations"]
        self.assertFalse(result["profile"]["host_dense_prover_admitted"])
        self.assertEqual(2048, hashes["query_blocks_exact"])
        self.assertEqual(8 * 8 + 11, hashes["transcript_absorptions_exact"])
        self.assertEqual(2 * 16384 * (22 + 8), hashes["source_merkle_verifier_upper"])
        self.assertEqual((8 + 1) * ((1 << 32) - 1) + 75 + 2048,
                         hashes["transcript_hard_nontrapping_upper"])
        self.assertEqual(2173, hashes["transcript_on_ideal_five_block_good_event_upper"])
        self.assertEqual(136, result["conditional_ideal_secure_sampler"][
            "any_draw_needs_more_than_attempts_upper_dyadic_bits"])
        self.assertIsNone(hashes["dense_host_source_tree_exact_if_admitted"])

    def test_exact_secure_sampler_law_and_bound(self) -> None:
        check_secure_sampler_sources()
        draws = 10
        result = secure_sampler_tail(draws)
        p = (1 << 31) - 1
        self.assertEqual((1 << 32) - 2, 2 * p)
        success = Fraction(2 * p, 1 << 32) ** 8
        failure = 1 - success
        self.assertEqual(f"{success.numerator}/{success.denominator}",
                         result["block_acceptance_exact"])
        self.assertEqual(f"{failure.numerator}/{failure.denominator}",
                         result["block_rejection_exact"])
        tail = draws * failure ** 5
        self.assertEqual(f"{tail.numerator}/{tail.denominator}",
                         result["any_draw_needs_more_than_attempts_union_bound_exact"])
        self.assertLess(tail, Fraction(1, 1 << 136))
        self.assertGreater(tail, Fraction(1, 1 << 137))
        self.assertFalse(result["protocol_enforces_attempt_cap"])

    def test_secure_sampler_mutations_invalidate_audit(self) -> None:
        paths = [
            Path("src/core/channel/blake2s.zig"),
            Path("src/core/fields/m31.zig"),
            Path("src/core/fields/qm31.zig"),
        ]
        mutations = [
            (paths[0], "if (x >= two_p)", "if (x > two_p)"),
            (paths[0], "const felts = self.drawBaseFelts();",
             "const felts = self.drawBaseFeltsNoReject();"),
            (paths[0], "pub const FELTS_PER_HASH: usize = 8;",
             "pub const FELTS_PER_HASH: usize = 7;"),
            (paths[0], "(@as(u32, bytes[1]) << 8)",
             "(@as(u32, bytes[1]) << 7)"),
            (paths[0], "return std.math.add(u32, current, 1)",
             "return std.math.add(u32, current, 2)"),
            (paths[1], "pub const Modulus: u32 = 0x7fffffff;",
             "pub const Modulus: u32 = 0x7ffffffe;"),
            (paths[2], "pub const SECURE_EXTENSION_DEGREE: usize = 4;",
             "pub const SECURE_EXTENSION_DEGREE: usize = 3;"),
        ]
        for path, original, changed in mutations:
            with self.subTest(path=str(path), original=original):
                with tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    for source_path in paths:
                        dest = root / source_path
                        dest.parent.mkdir(parents=True, exist_ok=True)
                        dest.write_bytes((ROOT / source_path).read_bytes())
                    source = (root / path).read_text()
                    self.assertIn(original, source)
                    (root / path).write_text(source.replace(original, changed, 1))
                    with self.assertRaises(ValueError):
                        check_secure_sampler_sources(root)

    def test_profile_rejects_outside_xdm04_admission(self) -> None:
        for case in ((7, 3, 2, 0, (1, 1, 1)),
                     (23, 3, 2, 1, (1, 1, 1)),
                     (7, 3, 5, 1, (1, 1, 1)),
                     (7, 3, 2, 1, (65, 1, 1)),
                     (7, 3, 2, 1, (1, 1))):
            with self.subTest(case=case), self.assertRaises(ValueError):
                budget(*case)
        with self.assertRaises(ValueError):
            budget(22, 8, 1, 16384, (64,) * 8)

    def test_extra_source_hash_site_is_rejected(self) -> None:
        path = Path("src/core/pcs/transposed_merkle_sparse.zig")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            # The existing BCS audit checks all its files, so copy the small
            # source roster rather than rewriting the real worktree.
            from scripts.check_cas05_bcs_join import SOURCES
            extra = {
                path,
                Path("src/core/pcs/transposed_merkle_cascade.zig"),
                Path("src/prover/pcs/transposed_cascade_experimental.zig"),
                Path("src/core/vcs_lifted/verifier.zig"),
                Path("src/prover/vcs_lifted/prover.zig"),
                Path("src/core/vcs_lifted/blake2_merkle.zig"),
                Path("src/core/fields/m31.zig"),
                Path("src/core/fields/qm31.zig"),
            }
            for source_path in set(map(Path, SOURCES.values())) | extra:
                dest = root / source_path
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes((ROOT / source_path).read_bytes())
            fixture = Path("design/pcs/fixtures/cas05_bcs_transcript.json")
            (root / fixture).parent.mkdir(parents=True, exist_ok=True)
            (root / fixture).write_bytes((ROOT / fixture).read_bytes())
            source = (root / path).read_text()
            (root / path).write_text(source.replace(
                "tree.hashUpper(left, right)",
                "tree.hashUpper(left, right) orelse tree.hashUpper(left, right)", 1,
            ))
            with self.assertRaises(ValueError):
                check_cost_sources(root)


if __name__ == "__main__":
    unittest.main()
