#!/usr/bin/env python3
"""Tests for scripts/rv64_m9/proof_params.py and the PARAMS lever of plan_model.py (stream m9-proof-params)."""
import os, sys, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), 'rv64_m9'))
import proof_params as pp  # noqa: E402
import plan_model as pm  # noqa: E402


class ProofParams(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.leaves, cls.folds = pp.fit_leaves(10)
        cls.P = {n: {k: v[i] for k, v in pp.SCN.items()} for i, n in enumerate(['pess', 'central', 'opt'])}

    def test_production_layers_are_128_conjectured(self):
        for r in pp.security_table():
            if 'production' in r['profile']:
                self.assertEqual(r['conjectured_bits'], 128, r)
        for lb in (1, 2, 3, 4):
            for p in pp.POW_GRID:
                self.assertGreaterEqual(pp.conj_bits(lb, pp.min_queries(lb, p), p), 128)
                self.assertLess(pp.conj_bits(lb, pp.min_queries(lb, p) - 1, p), 128)

    def test_fit_reproduces_both_recorded_profiles(self):
        self.assertEqual(len(self.leaves), 28)   # 11 + 17 leaves on 26235156 / 24628607
        for b, m6, d2 in pp.PAIRS:
            a, d = pp.node_shapes(m6), pp.node_shapes(d2)
            for lf in self.leaves:
                if lf.block != b:
                    continue
                for got, want in zip(lf.rows(1, 108), a[lf.node][1]):
                    self.assertAlmostEqual(got, want, delta=1e-6 * max(1, want))
                for got, want in zip(lf.rows(2, 54), d[lf.node][1]):
                    self.assertAlmostEqual(got, want, delta=1e-6 * max(1, want))

    def test_cells_match_receipt_widths(self):
        # node 0 of 24628607 D2: 1,096,894,720 cells (derived-recursive-cells.json)
        lf = [x for x in self.leaves if x.block == '24628607' and x.node == 0][0]
        self.assertEqual(pp.cells(lf.y2), 1096894720)

    def test_current_is_identity_and_caps_only_help(self):
        f = pp.evaluate(pp.CURRENT, self.leaves, self.folds, self.P['central'])
        for k in ('native', 'leaf', 'fold'):
            self.assertAlmostEqual(f[k], 1.0, places=9)
        a = pp.evaluate(pp.SETS['A_caps5'], self.leaves, self.folds, self.P['central'], pad=False)
        self.assertLess(a['leaf'], 1.0); self.assertLess(a['fold'], 1.0); self.assertEqual(a['native'], 1.0)

    def test_measured_native_blowup_ab(self):
        for b, (m6, d2) in pp.NATIVE_AB.items():
            self.assertTrue(1.13 < d2 / m6 < 1.15, b)

    def test_pow_cost_is_monotone_and_engineered_is_cheaper_from_20_bits(self):
        for k in ('as_built', 'check64'):
            xs = [pp.pow_gpu_s(p, k) for p in range(18, 33)]
            self.assertTrue(all(b >= a for a, b in zip(xs, xs[1:])), k)
        for p in range(20, 33):
            self.assertLess(pp.pow_gpu_s(p, 'check64'), pp.pow_gpu_s(p, 'as_built'))

    def test_blowup_changes_lose_at_p50(self):
        # the classic high-blowup levers are losses on this stack (leaves dominate recursion GPU-s)
        sc = self.P['central']
        for name in ('X_native_b8_q36_p20', 'X_outer_b4_q51_p26_all', 'X_native_b2_q108_p20_revert_d2'):
            f = pp.evaluate(pp.SETS[name], self.leaves, self.folds, sc, pad=False)
            N, Rl, Rf = 8.0, 5.7, 2.2
            self.assertGreater(N * f['native'] + Rl * f['leaf'] + Rf * f['fold'], N + Rl + Rf, name)


class PlanModelParamsLever(unittest.TestCase):
    def test_params_lever_cuts_recursion_only(self):
        P = {k: v[1] for k, v in pm.SC.items()}
        mi = 93.0; sh = pm.shape(mi)
        base = pm.model(mi, sh, P, on=('LEAVES',))
        on = pm.model(mi, sh, P, on=('LEAVES', 'PARAMS'))
        self.assertAlmostEqual(on['native_gpu_s'], base['native_gpu_s'], places=9)
        self.assertLess(on['recursion_gpu_s'], base['recursion_gpu_s'])
        self.assertLess(on['wall_s'], base['wall_s'])
        pw = pm.model(mi, sh, P, on=('LEAVES', 'PARAMS_POW'))
        self.assertGreater(pw['native_gpu_s'], base['native_gpu_s'])   # PoW 24 costs native GPU-s


if __name__ == '__main__':
    unittest.main()
