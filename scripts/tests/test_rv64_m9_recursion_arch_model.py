#!/usr/bin/env python3
"""Tests for scripts/rv64_m9/recursion_arch_model.py and its plan_model levers (CPU only)."""
import importlib.util
import json
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def load(name, rel):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, rel))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


RA = load("recursion_arch_model", "scripts/rv64_m9/recursion_arch_model.py")
PM = load("plan_model", "scripts/rv64_m9/plan_model.py")


class Census(unittest.TestCase):
    def test_production_rows_pinned_to_unmodified_verify(self):
        checked = [r for r in RA.BY.values() if "production_match" in r]
        self.assertGreaterEqual(len(checked), 6)
        self.assertTrue(all(r["production_match"] for r in checked))
        for r in checked:
            self.assertEqual(r["total"], r["production_verify"])

    def test_census_reproduces_measured_fold_child_blake_rows(self):
        # RECURSION_NODE_SHAPE fold4/4 of the D2 receipts: 1,941,780 blake_g_gate rows per log-23 child [D]; the
        # census child is the bare verifier (no T_rec admission / summary binding), so it may differ by < 1%.
        got = RA.per_child("fold4_log23", "prod_b2_q108_p20_f4_cap3")[4]
        self.assertLess(abs(got / 1941780 - 1), 0.01)

    def test_merkle_hashing_dominates(self):
        r = RA.BY[("fold4_log23", "prod_b2_q108_p20_f4_cap3")]
        ph = r["phases"]
        hashing = sum(ph[k][5] for k in ("trace_leaf", "trace_path", "fri_leaf", "fri_path"))
        self.assertGreater(hashing / r["total"][5], 0.88)
        self.assertLess(ph["composition"][5] / r["total"][5], 0.01)

    def test_g_rows_per_compression(self):
        self.assertEqual(RA.META["g_rows_per_compression"], 80)
        self.assertEqual(RA.META["node_rows_blake3"][4], 56)

    def test_per_child_orderings(self):
        f = lambda v: RA.per_child("fold4_log23", v)
        cells = lambda rows: sum(w * x for w, x in zip(RA.FL.WIDTH, rows))
        prod = cells(f("prod_b2_q108_p20_f4_cap3"))
        self.assertLess(cells(f("b2_q102_p26_f4_cap3")), prod)
        self.assertGreater(cells(f("b2_q108_p20_f4_cap7")), prod)  # cap mux is linear in 2^c
        self.assertLess(cells(f("batch4_cap3")), cells(f("batch2_cap3")))
        self.assertLess(cells(f("batch4_combo_ll4")), cells(f("batch4_cap3")))

    def test_batch_opens_one_fixed_tree_per_circuit(self):
        # A child's FIXED root is admitted per circuit (T_rec) and bound into the fold digest, so a batch proof keeps
        # one FIXED tree per circuit; the shared-tree-0 geometry is a reference row only and is cheaper.
        cells = lambda v: RA.BY[("fold4_log23", v)]["total"][5]
        self.assertGreater(cells("batch2_cap3"), cells("batch2_sharedfixed_cap3"))
        self.assertGreater(cells("batch2_combo_ll4"), cells("batch2_combo_ll4_sharedfixed"))
        self.assertFalse(RA.BY[("fold4_log23", "batch2_cap3")]["batch_shared_fixed"])
        # B FIXED trees + combined main/interaction + composition
        r = RA.BY[("fold4_log23", "batch4_cap3")]
        one = RA.BY[("fold4_log23", "prod_b2_q108_p20_f4_cap3")]
        self.assertEqual(r["hash_calls"]["trace_leaf"], (4 + 3) * one["queries"])

    def test_plan_rec_arch_table_is_the_receipt(self):
        trees = json.load(open(os.path.join(ROOT, "vectors/reports/rv64-m9-prep/m9-recursion-arch/model.json")))["trees"]
        for lk, t in PM.REC_ARCH.items():
            self.assertEqual(t["arity"], trees[t["key"]]["arity"])
            self.assertEqual(t["job_fits_post_p1"], trees[t["key"]]["max_job_post_p1_ok"])
        self.assertFalse(PM.REC_ARCH[("RECBATCH", "fan")]["job_fits_post_p1"])


class Tree(unittest.TestCase):
    def test_production_tree_matches_fanin_model(self):
        for block in (24628607, 26235156, 26235168):
            _, _, nodes, _ = RA.FL.plan(block)
            ours = RA.build(block, "prod", 1, arity=4)
            self.assertEqual(ours["nodes"], len(nodes))
            self.assertEqual(ours["cells"], sum(n.cells for n in nodes))

    def test_fanin_production_tree_matches(self):
        _, _, nodes, _ = RA.FL.plan(26235168, kmax=4, cap_log="blake23", homogeneous="class")
        ours = RA.build(26235168, "prod", 4, arity=4)
        self.assertEqual(ours["nodes"], len(nodes))
        self.assertEqual(ours["cells"], sum(n.cells for n in nodes))

    def test_diet_folds_fit_and_cut_cells(self):
        r = RA.build(26235168, "diet", 4, cap_log="blake23", arity=6)
        base = RA.build(26235168, "prod", 4, arity=4)
        self.assertTrue(r["fold_ok"])
        self.assertLess(r["cells"], base["cells"])
        self.assertLessEqual(r["max_job_cells"], RA.P2_CAP_CELLS)


class Plan(unittest.TestCase):
    def test_rec_levers_off_are_identity(self):
        P = {k: v[1] for k, v in PM.SC.items()}
        sh = PM.shape(93.1)
        self.assertEqual(PM.model(93.1, sh, P)["wall_s"], PM.model(93.1, sh, P, on=())["wall_s"])

    def test_rec_levers_cut_recursion_only(self):
        P = {k: v[1] for k, v in PM.SC.items()}
        all2 = tuple(l for l in PM.LEVER_ORDER if l != "GPU4")
        sh = PM.shape(93.1)
        a = PM.model(93.1, sh, P, on=all2)
        for lv in PM.REC_LEVERS:
            b = PM.model(93.1, sh, P, on=all2 + (lv,))
            self.assertLess(b["recursion_gpu_s"], a["recursion_gpu_s"])
            if lv != "RECNB3":
                self.assertAlmostEqual(b["native_gpu_s"], a["native_gpu_s"])
            self.assertLess(b["wall_s"], a["wall_s"])


if __name__ == "__main__":
    unittest.main()
