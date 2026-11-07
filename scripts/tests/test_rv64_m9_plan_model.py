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

    def test_no_2gpu_set_reaches_60pct(self):
        # r4 (wave-2 streams: outer GKR, streaming commit, witness rowpar, GPU replay, all reviewed): no 2-GPU set reaches
        # 60% on min(p50, p95, basket) in any scenario; the best central set is about -43%.
        for n in ('pess', 'central', 'opt'):
            self.assertEqual(self.res['combos'][n], [], n)
        self.assertGreater(self.res['best_2gpu']['central']['min_cut'], 0.40)
        # recursion-arch joins the search; RECBATCH excludes OCC (a 4.2 G-cell batch job cannot share a GPU), so the
        # original bound holds: best central is about -45% (with RECNB3, a native proof-format change)
        self.assertLess(self.res['best_2gpu']['central']['min_cut'], 0.47)
        self.assertNotIn('RECBATCH', self.res['best_2gpu']['central']['levers'])
        self.assertIn('OGKR_ENG', self.res['best_2gpu']['central']['levers'])

    def test_outer_gkr_as_built_loses(self):
        # reviewed factor on recursion GPU-s: x1.07 (post-M8 tree), x1.13 (fan-in tree); engineered x0.81 gains
        p = self.P['central']
        for name in ('p50 (29.1M gas)', '26235168', '26235159'):
            mi, sh = self.blocks[name]
            base = pm.model(mi, sh, p)
            self.assertGreater(pm.model(mi, sh, p, on=('OGKR',))['kernel_gpu_s'], base['kernel_gpu_s'], name)
            self.assertLess(pm.model(mi, sh, p, on=('OGKR_ENG',))['kernel_gpu_s'], base['kernel_gpu_s'], name)
            k = pm.model(mi, sh, p, on=('LEAVES',)); kg = pm.model(mi, sh, p, on=('LEAVES', 'OGKR'))
            self.assertAlmostEqual(kg['recursion_gpu_s'] / k['recursion_gpu_s'], 1.13, places=3)

    def test_witness_rowpar_class_hits_only(self):
        # production (new block): leaves miss, so rowpar touches only the fold hits; bench gets the whole x0.70
        p = self.P['central']; mi, sh = self.blocks['26235168']
        bench = pm.model(mi, sh, p)['recursion_gpu_s'] - pm.model(mi, sh, p, on=('WITNESS',))['recursion_gpu_s']
        prod = pm.model(mi, sh, p, production=True)['recursion_gpu_s'] - pm.model(mi, sh, p, on=('WITNESS',), production=True)['recursion_gpu_s']
        self.assertGreater(bench, 0.5)
        self.assertLess(prod, 0.05 * bench)

    def test_gpu_capture_floor_is_first_pass(self):
        # full GPU capture is bounded by the serial seeded first pass (services fixed); replay alone keeps most CPU capture
        p = self.P['central']; mi, sh = self.blocks['26235168']
        full = pm.model(mi, sh, p, on=('GPUCAP',))['capture_s']; rep = pm.model(mi, sh, p, on=('REPLAY',))['capture_s']
        base = pm.model(mi, sh, p)['capture_s']
        self.assertAlmostEqual(full, p['head'] + pm._fp_fixed(pm.FIRST_PASS[26235168]) + 0.2, places=6)
        self.assertLess(full, rep); self.assertLess(rep, base)

    def test_4gpu_needs_engineered_outer_gkr(self):
        # 4 GPUs, central: the full order (with OGKR_ENG) clears 60% on the basket (~-63.6%); without OGKR_ENG it misses (~-59.6%)
        t = self.res['basket_totals']
        self.assertGreater(1 - t['GPU4']['central'] / t['baseline']['central'], 0.62)
        p = self.P['central']; on = tuple(l for l in pm.LEVER_ORDER if l != 'OGKR_ENG')
        tot = sum(pm.model(*self.blocks[str(r['block'])], p, on=on, gpus=4)['wall_s'] for r in pm.basket())
        self.assertLess(1 - tot / t['baseline']['central'], 0.60)
        self.assertGreater(1 - tot / t['baseline']['central'], 0.58)

    def test_fanin_matches_receipt_on_607(self):
        p = self.P['central']; mi, sh = self.blocks['24628607']
        base = pm.model(mi, sh, p); k = pm.model(mi, sh, p, on=('LEAVES',))
        self.assertAlmostEqual(k['recursion_gpu_s'] / base['recursion_gpu_s'], 0.822, places=3)
        self.assertEqual(k['leaves'], 9); self.assertEqual(k['nodes'], 12)

    def test_p2_loses_after_recursion_cuts(self):
        p = self.P['central']; mi, sh = self.blocks['p50 (29.1M gas)']
        on = ('STREAM', 'WITNESS', 'OCC', 'LEAVES', 'NGKR', 'OGKR_ENG', 'GPUCAP')
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
