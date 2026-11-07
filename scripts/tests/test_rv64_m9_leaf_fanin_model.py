#!/usr/bin/env python3
"""Mirror checks for scripts/rv64_m9_leaf_fanin_model.py; the Zig planner pins the same expected counts
(src/integrations/riscv_cpu/rv64_recursion/om31_native/leaf_fanin.zig `fixture.basket`)."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import rv64_m9_leaf_fanin_model as m  # noqa: E402

# block: (baseline nodes, fan-in leaves, fan-in nodes) under kmax=4, blake23 caps, same-class grouping.
EXPECTED = {
    26235156: (15, 7, 10), 24647140: (17, 9, 12), 24628607: (19, 9, 12), 25229957: (19, 9, 12),
    24628608: (23, 11, 15), 24626900: (26, 12, 16), 24697070: (38, 16, 21), 24697073: (34, 14, 19),
    26235168: (62, 24, 33), 25229955: (62, 24, 33), 24628590: (71, 28, 38), 25229951: (74, 29, 39),
    24628595: (84, 32, 43), 24628611: (85, 32, 43), 26235159: (97, 36, 48),
}
SAME = m.OPTIONS["leafk_blake23_same"]


class LeafFaninModel(unittest.TestCase):
    def test_reproduces_receipts(self):
        check = m.self_check()
        self.assertEqual(check[24628607]["cells"], 21658004224)
        self.assertLessEqual(abs(check[26235156]["cells"] - 17844864768), 49152)

    def test_basket_counts_match_zig_fixture(self):
        for block, (base, leaves, nodes) in EXPECTED.items():
            _, _, bn, _ = m.plan(block)
            self.assertEqual(len(bn), base, block)
            items, groups, fn, root = m.plan(block, **SAME)
            self.assertEqual(len(groups), leaves, block)
            self.assertEqual(len(fn), nodes, block)
            self.assertEqual(fn[root].count, len(groups))
            self.assertEqual(sum(k for _, k in groups), len(items))
            for first, k in groups:
                self.assertEqual(len(set(items[first:first + k])), 1)
            for n in fn:
                self.assertLessEqual(m.plog(n.rows[4]), 23)
                self.assertLessEqual(n.cells, m.NODE_CELL_CAP)

    def test_fanin_never_increases_cells(self):
        for block in EXPECTED:
            base = sum(n.cells for n in m.plan(block)[2])
            fan = sum(n.cells for n in m.plan(block, **SAME)[2])
            self.assertLess(fan, base, block)


if __name__ == "__main__":
    unittest.main()
