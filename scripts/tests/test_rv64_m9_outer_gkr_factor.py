"""CPU checks for scripts/rv64_m9/outer_gkr_factor.py (no GPU, no tool needed: uses the committed gate cache)."""
import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("ogkr", ROOT / "scripts/rv64_m9/outer_gkr_factor.py")
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)
RECEIPT = ROOT / "vectors/reports/rv64-m9-prep/m9-outer-gkr"
D2_LEAF = [179654, 5533212, 337632, 875134, 3376320]


class OuterGkrFactor(unittest.TestCase):
    def test_widths_and_columns(self):
        self.assertEqual(G.WIDTH_CLASSIC, [12, 28, 73, 31, 167])
        self.assertEqual(G.WIDTH_HYBRID, [12, 28, 41, 23, 79])
        # 304 classic INTER columns -> 128 hybrid (hybrid_air.zig), incl. the fixed tables.
        classic = sum(G.CLASSIC_INTER) + 8 + 64 + 8 * 4
        hybrid = sum(G.HYBRID_INTER) + 8 + 16 + 8 * 4
        self.assertEqual((classic, hybrid), (G.COLS_CLASSIC, G.COLS_HYBRID))
        self.assertEqual(G.HASH_SAVED_G, 108 * 11 * 80)

    def test_facts_and_layers_match_the_zig_class(self):
        # Zig: m9_node_test "real D2 leaf class" and rv64-m9-outer-gkr-tool cost-raw leaf-cpu-d2.
        self.assertEqual(G.facts(D2_LEAF), 137_363_456)
        self.assertEqual(G.layers(D2_LEAF), 26)
        gates = json.loads((RECEIPT / "gates.json").read_text())
        g = gates[",".join(map(str, G.row_logs(D2_LEAF)))]
        self.assertEqual((g["blake_g_gate"], g["qm31_ops"], g["m31_to_u32"], g["triple_xor"], g["eq"]),
                         (183840, 209107, 19192, 18384, 1516))

    def test_receipt_reproduces(self):
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "factor.json"
            gates = Path(d) / "gates.json"
            gates.write_text((RECEIPT / "gates.json").read_text())
            subprocess.run([sys.executable, str(ROOT / "scripts/rv64_m9/outer_gkr_factor.py"), "--gates", str(gates),
                            "--out", str(out)], check=True, capture_output=True, cwd=ROOT)
            got = json.loads(out.read_text())["blocks"]
        want = json.loads((RECEIPT / "factor.json").read_text())["blocks"]
        for block in ("24628607", "26235168", "26235159"):
            for tree in ("baseline", "fanin_same"):
                for case in ("pess", "central", "opt", "engineered"):
                    self.assertAlmostEqual(got[block][tree][case]["kernel_factor"], want[block][tree][case]["kernel_factor"], 9)
        # The cell factor the plan quotes holds; the GPU-s factor does not (central GKR rate).
        c = want["24628607"]["baseline"]["central"]
        self.assertLess(c["cell_factor"], 0.60)
        self.assertGreater(c["kernel_factor"], 1.0)


if __name__ == "__main__":
    unittest.main()
