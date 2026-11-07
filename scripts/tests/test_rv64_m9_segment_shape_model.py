#!/usr/bin/env python3
"""Tests for scripts/rv64_m9/segment_shape_model.py and its SEG23/SEG24 levers in plan_model.py (CPU only).

  python3 -I scripts/tests/test_rv64_m9_segment_shape_model.py
"""
import os, sys, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, 'scripts', 'rv64_m9'))
sys.path.insert(0, os.path.join(ROOT, 'scripts'))
import segment_shape_model as S  # noqa: E402
import plan_model as P  # noqa: E402
import rv64_m9_leaf_fanin_model as FM  # noqa: E402


class SegmentShape(unittest.TestCase):
    def test_segment_counts_match_m3(self):
        # the 2^22 - 1 step cap reproduces every M3 CPU segment count [M]
        for r in P.basket():
            self.assertEqual(S.segments(r['mi'], 22)[0], r['seg'], r['block'])

    def test_bigger_cpu_leaf_stays_in_its_padded_class(self):
        # a log-23/24 CPU proof adds a Merkle level and FRI layer, but the leaf keeps the 2^22 leaf's padded rungs
        for sc in ('pess', 'central', 'opt'):
            for log in (23, 24):
                self.assertEqual(FM.shape(S.cpu_rows(log, sc)), FM.shape(FM.NATIVE['cpu']), (log, sc))
                self.assertEqual(FM.cells(S.cpu_rows(log, sc)), FM.cells(FM.NATIVE['cpu']))

    def test_identity_at_2_22(self):
        for r in P.basket():
            e = S.entry(r['mi'], r['truths'], 22, False)
            self.assertAlmostEqual(e[0], 1.0)
            self.assertEqual(S.native_factor(22, r['mi']), 1.0)

    def test_fanin_matches_fewer_leaves_receipt(self):
        # 2^22 + k-leaf reproduces plan_model.FANIN_SAME (fewer-leaves receipt); 24647140 differs because its last
        # segment is 3.63 M instr (log 22, a full CPU class) while the receipt took it as a tail [D]
        for b, v in P.FANIN_SAME.items():
            r = next(x for x in P.basket() if x['block'] == b)
            got = S.entry(r['mi'], r['truths'], 22, True)[0]
            self.assertLess(abs(got - v[0]), 0.05 if b == 24647140 else 0.002, b)

    def test_seg23_halves_cpu_leaves_and_cuts_cells(self):
        for r in P.basket():
            e = S.entry(r['mi'], r['truths'], 23, False)
            self.assertEqual(e[4], S.segments(r['mi'], 23)[0])
            self.assertLess(e[0], 1.0)
            self.assertLessEqual(e[4], (r['seg'] + 1) // 2 + 1)

    def test_plan_levers(self):
        Pc = {k: v[1] for k, v in P.SC.items()}
        mi = 29.11 * 3.198; sh = P.shape(mi)
        base = P.model(mi, sh, Pc)
        rev4 = P.model(mi, sh, Pc, on=S.REV4_BEST['central'])
        self.assertAlmostEqual(rev4['wall_s'], 11.04, delta=0.05)  # plan rev 4 receipt p50 [E]
        seg = P.model(mi, sh, Pc, on=S.REV4_BEST['central'] + ('SEG23',))
        self.assertLess(seg['kernel_gpu_s'], rev4['kernel_gpu_s'])
        self.assertLess(P.model(mi, sh, Pc, on=('SEG23',))['kernel_gpu_s'], base['kernel_gpu_s'])

    def test_memory_says_2_24_needs_streamed_gkr(self):
        m = S.memory_table({'p50': 23})
        self.assertFalse(m['24']['stage1_fits_p50'])
        self.assertFalse(m['23']['stage1_fits_p50'])
        self.assertGreater(m['24']['gkr_workspace_gb'], 28)

    def test_central_cells_use_the_existing_wide47_class(self):
        # review: soundness is argued for the existing wide-clock (wide47) CPU23 class, so central cells must not be
        # below its census (x1.017..x1.050); the compact37 extension (new source mode) is the opt case only
        self.assertGreaterEqual(S.CELLS[23]['central'], 1.017)
        self.assertLess(S.CELLS[23]['opt'], 1.0)
        self.assertGreater(S.native_factor(23, 93.1, 'central', P.N_PER_MI, 16), 1.03)

    def test_fft_growth_skips_truths_and_small_tails(self):
        # truth proofs and a block below 2^22 instr keep their log: no FFT growth there
        self.assertEqual(S.grown_share(3.0, 23, 10), 0.0)
        g = S.grown_share(93.1, 23, 16)
        self.assertLess(g, 0.95)
        self.assertGreater(g, 0.75)

    def test_p95_seg23_needs_main_spill_where_2_22_fits(self):
        # review: post-P1, one 2^22 job fits the p95 arena but one 2^23 job does not; two jobs (OCC) fit at neither
        m = S.memory_table({'p95': 43})
        self.assertTrue(m['22']['stage1_fits_post_p1_p95'])
        self.assertFalse(m['23']['stage1_fits_post_p1_cc_p95'])
        self.assertFalse(m['22']['two_jobs_fit_post_p1_p95'])


if __name__ == '__main__':
    unittest.main()
