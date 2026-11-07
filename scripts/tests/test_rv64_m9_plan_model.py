"""Smoke tests for scripts/rv64_m9/plan_model.py (no GPU, no gas sample needed)."""
import os, sys, unittest
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'rv64_m9'))
import plan_model as pm  # noqa: E402


class PlanModelTest(unittest.TestCase):
    def setUp(self):
        self.res, self.blocks, self.P = pm.run(dict(pm.GAS_PCT_EMBEDDED))

    def test_bench15_fits(self):
        k = self.res['fits']['kernel_gpu_s']
        self.assertGreater(k['r2'], 0.95)
        self.assertAlmostEqual(k['b_per_minstr'], 0.284, places=2)

    def test_segments_match_m3(self):
        for r in pm.basket():
            self.assertEqual(pm.shape(r['mi'], r['truths'])['seg'], r['seg'], r['block'])

    def test_basket_bias(self):
        b = self.res['basket']
        self.assertEqual(b['over40m_blocks'], 5)
        self.assertGreater(b['over40m_gas_share'], 0.6)

    def test_no_central_2gpu_set_reaches_60pct(self):
        # Stream results 2026-11-07 (k-leaf fan-in, reviewed Poseidon2, held-out canonical tax): the best central 2-GPU
        # set stays below 60% on min(p50, p95, basket); only the optimistic case has sets.
        self.assertEqual(self.res['combos']['central'], [])
        self.assertGreater(self.res['best_2gpu']['central']['min_cut'], 0.55)
        self.assertLess(self.res['best_2gpu']['central']['min_cut'], 0.60)
        self.assertTrue(self.res['combos']['opt'])

    def test_fanin_matches_receipt_on_607(self):
        p = self.P['central']; mi, sh = self.blocks['24628607']
        base = pm.model(mi, sh, p); k = pm.model(mi, sh, p, on=('LEAVES',))
        self.assertAlmostEqual(k['recursion_gpu_s'] / base['recursion_gpu_s'], 0.822, places=3)
        self.assertEqual(k['leaves'], 9); self.assertEqual(k['nodes'], 12)

    def test_p2_loses_after_recursion_cuts(self):
        p = self.P['central']; mi, sh = self.blocks['p50 (29.1M gas)']
        on = ('STREAM', 'WITNESS', 'OCC', 'LEAVES', 'NGKR', 'OGKR')
        self.assertGreater(pm.model(mi, sh, p, on=on + ('P2',))['wall_s'], pm.model(mi, sh, p, on=on)['wall_s'])

    def test_canon_as_built_is_bench_loss(self):
        p = self.P['central']; mi, sh = self.blocks['26235168']
        self.assertGreater(pm.model(mi, sh, p, on=('CANON',))['wall_s'], pm.model(mi, sh, p)['wall_s'] + 3.0)

    def test_pessimistic_has_no_2gpu_set(self):
        self.assertEqual(self.res['combos']['pess'], [])
        self.assertLess(self.res['best_2gpu']['pess']['min_cut'], 0.60)

    def test_recursion_fit_on_nodes(self):
        r = self.res['fits']['recursion_gpu_s_per_node']
        self.assertGreater(r['r2'], 0.95)
        self.assertAlmostEqual(r['b_per_node'], 0.306, places=2)

    def test_leaf_only_factors_spare_folds(self):
        # D2 revert and native GKR touch the leaf share only: a fold-heavy shape loses less than R / d2_leaf
        p = self.P['central']; mi, sh = self.blocks['p50 (29.1M gas)']
        base = pm.model(mi, sh, p); rev = pm.model(mi, sh, p, on=('D2REV',))
        self.assertLess(rev['recursion_gpu_s'], base['recursion_gpu_s'] / p['d2_leaf'] - 1e-6)

    def test_k607_is_default_t2_off(self):
        self.assertAlmostEqual(pm.K607, 8.333, places=3)

    def test_d2_revert_sign(self):
        # Alone the revert loses; with the stream-corrected recursion levers (no P2) it still loses in the central case.
        p = self.P['central']; mi, sh = self.blocks['p95 (55.8M gas)']
        base = pm.model(mi, sh, p)['wall_s']
        self.assertGreater(pm.model(mi, sh, p, on=('D2REV',))['wall_s'], base)
        before = ('STREAM', 'WITNESS', 'OCC', 'LEAVES', 'NGKR', 'OGKR')
        self.assertGreater(pm.model(mi, sh, p, on=before + ('D2REV',))['wall_s'], pm.model(mi, sh, p, on=before)['wall_s'])

if __name__ == '__main__':
    unittest.main()
