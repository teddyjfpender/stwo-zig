import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools" / "perf"))
from stwo_perf import stats


class HodgesLehmannTest(unittest.TestCase):
    def test_symmetric_values(self):
        self.assertAlmostEqual(stats.hodges_lehmann([0.9, 1.0, 1.1]), 1.0)

    def test_robust_to_one_outlier(self):
        clean = stats.hodges_lehmann([0.95, 0.96, 0.94, 0.95, 0.96])
        dirty = stats.hodges_lehmann([0.95, 0.96, 0.94, 0.95, 1.8])
        self.assertLess(abs(dirty - clean), 0.12)

    def test_empty_rejected(self):
        with self.assertRaises(ValueError):
            stats.hodges_lehmann([])


class BootstrapTest(unittest.TestCase):
    def test_deterministic_for_seed(self):
        ratios = [0.97, 0.96, 0.98, 0.95, 0.97, 0.96, 0.99]
        a = stats.bootstrap_ci(ratios, seed=7)
        b = stats.bootstrap_ci(ratios, seed=7)
        self.assertEqual(a, b)

    def test_ci_brackets_estimate(self):
        ratios = [0.97, 0.96, 0.98, 0.95, 0.97, 0.96, 0.99]
        lo, hi = stats.bootstrap_ci(ratios, seed=1)
        est = stats.hodges_lehmann(ratios)
        self.assertLessEqual(lo, est)
        self.assertGreaterEqual(hi, est)

    def test_too_few_rounds_rejected(self):
        with self.assertRaises(ValueError):
            stats.bootstrap_ci([0.9, 1.0], seed=0)


class ThetaTest(unittest.TestCase):
    def test_floor_when_no_dispersion(self):
        self.assertEqual(stats.theta(None, 0.01, 2.0), 0.01)

    def test_dispersion_scales(self):
        self.assertEqual(stats.theta(0.02, 0.01, 2.0), 0.04)

    def test_floor_wins_when_dispersion_small(self):
        self.assertEqual(stats.theta(0.001, 0.01, 2.0), 0.01)


class GeomeanTest(unittest.TestCase):
    def test_known_value(self):
        self.assertAlmostEqual(stats.geometric_mean([0.5, 2.0]), 1.0)

    def test_rejects_nonpositive(self):
        with self.assertRaises(ValueError):
            stats.geometric_mean([1.0, 0.0])


class PortfolioBootstrapTest(unittest.TestCase):
    def test_deterministic_with_different_round_counts(self):
        ratios = [
            [0.90, 0.91, 0.89],
            [1.02, 1.01, 1.03, 1.00, 1.02],
        ]
        first = stats.portfolio_geomean_ci(ratios, iterations=1000, seed=17)
        second = stats.portfolio_geomean_ci(ratios, iterations=1000, seed=17)
        self.assertEqual(first, second)
        estimate, ci = first
        self.assertAlmostEqual(
            estimate,
            stats.geometric_mean([stats.hodges_lehmann(row) for row in ratios]),
        )
        self.assertLessEqual(ci[0], estimate)
        self.assertGreaterEqual(ci[1], estimate)

    def test_fast_first_row_does_not_define_portfolio_significance(self):
        estimate, ci = stats.portfolio_geomean_ci(
            [
                [0.50, 0.50, 0.50],
                [2.20, 2.20, 2.20],
            ],
            iterations=200,
            seed=3,
        )
        self.assertAlmostEqual(estimate, 1.048808848, places=8)
        self.assertGreater(ci[0], 1.0)

    def test_rejects_any_workload_without_three_rounds(self):
        with self.assertRaisesRegex(ValueError, "per workload"):
            stats.portfolio_geomean_ci([[0.9, 0.9, 0.9], [1.0, 1.0]])


if __name__ == "__main__":
    unittest.main()
