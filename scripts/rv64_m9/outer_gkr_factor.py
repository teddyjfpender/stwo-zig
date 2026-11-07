#!/usr/bin/env python3
"""M9 stream m9-outer-gkr: re-derive the outer-GKR recursion factor (plan rev 3 #8, `ogkr_alone` = x0.57 [E])
on the CURRENT recursion trees, per block, from the circuit code and measured receipts.

CPU only. No GPU, no service, no proof. Labels: [M] measured, [D] arithmetic on measured / counted from code,
[E] estimate.

Inputs
  * Trees and per-node raw rows of the five variable components (eq, qm31_ops, triple_xor, m31_to_u32, blake_g_gate)
    for the D2 coalesced default, from `scripts/rv64_m9_leaf_fanin_model.py` (exact on 24628607/26235156 against
    RECURSION_NODE_SHAPE receipts [D]); options `baseline` (post-M8 tree) and `leafk_blake23_same` (k-leaf fan-in,
    the tree the plan's cumulative order applies outer GKR to).
  * Per-node kernel GPU-s = r_k * committed cells (bench15 fit, fan-in model calibration [D]).
  * In-circuit outer-GKR verifier gate counts per child class [D, counted from the circuit code by
    `rv64-m9-outer-gkr-tool cost-raw` on a shape-exact section; the method reproduces the M5 [M] counts exactly].
  * GPU GKR prover ns per fact: M5 fused route 148.2 ms / 257.9 M facts [M]; projection overhead from the native
    GKR stage spans [M, production-negative prod3 GPU_GKR_SPANS]; workspace bytes per fact [M, GPU_OUTER_GKR_PLAN].

  python3 scripts/rv64_m9/outer_gkr_factor.py --tool zig-out/bin/rv64-m9-outer-gkr-tool \
      --out vectors/reports/rv64-m9-prep/m9-outer-gkr/factor.json
  (without --tool, the gate table cached in --gates is used)
"""
import argparse
import importlib.util
import json
import math
import os
import subprocess
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("fanin", HERE.parent / "rv64_m9_leaf_fanin_model.py")
F = importlib.util.module_from_spec(spec)
spec.loader.exec_module(F)

FOCUS = (24628607, 26235168, 26235159)
TREES = {"baseline": F.OPTIONS["baseline"], "fanin_same": F.OPTIONS["leafk_blake23_same"]}

# ---- widths (profile.zig FACTS = component_list.zig component_facts) [D] --------------------------------------------
MAIN = [4, 12, 20, 4, 52]
PP = [0, 0, 5, 3, 11]
CLASSIC_INTER = [8, 16, 48, 24, 104]          # OM31 = 2x QM31-counted facts
BINDING = 16                                  # Eq + cyclic prefix, OM31 (binding v2)
GKR_BOUND = [c > BINDING for c in CLASSIC_INTER]  # triple_xor, m31_to_u32, blake_g_gate (+ xor12 table)
HYBRID_INTER = [BINDING if g else c for c, g in zip(CLASSIC_INTER, GKR_BOUND)]
WIDTH_CLASSIC = [m + i + p for m, i, p in zip(MAIN, CLASSIC_INTER, PP)]
WIDTH_HYBRID = [m + i + p for m, i, p in zip(MAIN, HYBRID_INTER, PP)]
assert WIDTH_CLASSIC == F.WIDTH
LOOKUPS = [2, 3, 12, 5, 26]
XOR12_LOG, XOR12_LOOKUPS = 20, 16
FIXED_CELLS_HYBRID = F.FIXED_CELLS - (64 - BINDING) * (1 << XOR12_LOG)   # xor12 table interaction 64 -> 16
COLS_CLASSIC, COLS_HYBRID = 304, 128          # committed INTER base columns per node [M: M4.0 item 8; hybrid_air 128]
DCOLS = COLS_CLASSIC - COLS_HYBRID            # 176 fewer child columns opened per query

# ---- child-opening savings in the parent (outer profile conjectured128_b2_q108_p20_fold4) --------------------------
Q = 108
WORDS_PER_COMPRESSION, G_PER_COMPRESSION = 16, 80
HASH_SAVED_G = Q * math.ceil(DCOLS / WORDS_PER_COMPRESSION) * G_PER_COMPRESSION   # [D] leaf-hash words per query
OODS_MIX_SAVED_G = math.ceil(DCOLS * 8 / WORDS_PER_COMPRESSION) * G_PER_COMPRESSION  # [E] 1 OM31 sample per column
DEEP_SAVED_QM31 = {"pess": 0, "central": 2 * DCOLS * Q, "opt": 4 * DCOLS * Q}       # [E] rows per column per query

# ---- GPU constants ---------------------------------------------------------------------------------------------------
NS_PER_FACT_M5_FUSED = 148.2e6 / 257_949_696          # [M] rv64-m5-outer-gkr.md §6, materialised inputs
NATIVE_STAGE = [(262.459648e6, 152_086_336), (193.453080e6, 108_668_224), (164.287317e6, 115_240_256), (159.381200e6, 117_983_552)]
NS_PER_FACT_NATIVE_ALLIN = sum(t for t, _ in NATIVE_STAGE) / sum(n for _, n in NATIVE_STAGE)  # [M] projected-source all-in
PROJECTION = [(60.534977e6, 152_086_336), (15.403424e6, 108_668_224), (17.406303e6, 115_240_256), (27.265600e6, 117_983_552)]
NS_PER_FACT_PROJECTION = sum(t for t, _ in PROJECTION) / sum(n for _, n in PROJECTION)       # [M] spans
NS_PER_FACT = {"opt": NS_PER_FACT_M5_FUSED, "central": NS_PER_FACT_M5_FUSED + NS_PER_FACT_PROJECTION,
               "pess": NS_PER_FACT_NATIVE_ALLIN}
# [E] engineered GKR prover: ~1.5x the HBM floor (~4 passes x 64 B/fact at 1.5 TB/s), lazy projection fused in.
NS_PER_FACT_ENGINEERED = 0.25
# [E] plan lever #3 streaming commit: x0.70 on FFT+Merkle = 53% of GPU-s -> committed-cell rate x0.841.
STREAM_RK_FACTOR = 1 - 0.53 * 0.30
CASES = ("pess", "central", "opt", "engineered", "central_after_stream")
WORKSPACE_B_PER_FACT = 16_573_396_480 / 257_949_696    # [M] consumed-tree Eq reuse (production-negative README)
PARTIAL_FRONTIER_B_PER_FACT = 15_046_661_376 / 257_949_696  # [M] partial-frontier model (allocation, not peak)
ADMISSION_FREE_B = 15_737_028_608                        # [M] mapped free bytes at the refused fold
# Witness (MAIN, chain_run) share of recursion kernel GPU-s: scales with gate rows, not with INTER columns.
WITNESS_SHARE = {"opt": 0.10, "central": 0.19, "pess": 0.30}   # [D] chain_run 19% of recursion (plan §2); range [E]
PLAN_FACTOR = {"pess": 0.65, "central": 0.57, "opt": 0.50}    # plan_model.py ogkr_alone [E]

# ---- soundness (rv64-m5-outer-gkr.md §2 ledger, strict OM31 draws) ---------------------------------------------------
LOG2_P8 = 8 * math.log2((1 << 31) - 1)
MAX_TUPLE_ARITY = 32


def plog(n):
    return F.plog(n)


def row_logs(rows):
    return [max(1, plog(r)) for r in rows]


def facts(rows):
    logs = row_logs(rows)
    return sum(l << logs[i] for i, l in enumerate(LOOKUPS) if GKR_BOUND[i]) + (XOR12_LOOKUPS << XOR12_LOG)


def layers(rows):
    """Max (row_log + lane_log) over the instances: lane groups are the binary decomposition of the lookups."""
    logs = row_logs(rows)
    out = XOR12_LOG + 4
    for i, l in enumerate(LOOKUPS):
        if GKR_BOUND[i]:
            out = max(out, logs[i] + (l.bit_length() - 1))
    return out


def cells(rows, hybrid):
    w = WIDTH_HYBRID if hybrid else WIDTH_CLASSIC
    return sum(x * (1 << plog(r)) for x, r in zip(w, rows)) + (FIXED_CELLS_HYBRID if hybrid else F.FIXED_CELLS)


class Gates:
    """In-circuit verifier gate counts per child class [D], from the Zig tool (cached by row logs)."""

    def __init__(self, tool, cache):
        self.tool, self.cache = tool, cache

    def __call__(self, rows):
        key = ",".join(map(str, row_logs(rows)))
        if key not in self.cache:
            if not self.tool:
                raise SystemExit(f"gate counts for row logs {key} not cached; pass --tool")
            env = dict(os.environ, STWO_RV64_M9_OUTER_GKR="1")
            out = subprocess.run([self.tool, "cost-raw", "node", *map(str, rows)], env=env, check=True,
                                 capture_output=True, text=True).stdout
            j = json.loads(out)
            self.cache[key] = {k: j[k] for k in ("layers", "rounds", "instances", "facts", "section_bytes", "blake_g_gate",
                                                 "qm31_ops", "m31_to_u32", "triple_xor", "eq", "draws")}
        g = self.cache[key]
        assert g["facts"] == facts(rows) and g["layers"] == layers(rows), (key, g)
        return g


def base_case(case):
    return "central" if case in ("engineered", "central_after_stream") else case


def ns_per_fact(case):
    return NS_PER_FACT_ENGINEERED if case == "engineered" else NS_PER_FACT[base_case(case)]


def child_delta(gates, case):
    """Extra rows a parent spends to verify ONE hybrid child instead of a classic one [D/E], per variable component."""
    d = [gates["eq"], gates["qm31_ops"] - DEEP_SAVED_QM31[base_case(case)], gates["triple_xor"], gates["m31_to_u32"],
         gates["blake_g_gate"] - HASH_SAVED_G - OODS_MIX_SAVED_G]
    return d


def tree(block, opts, gates, case, cal):
    items, groups, nodes, root = F.plan(block, **opts)
    hyb_rows = []
    out_nodes = []
    for i, n in enumerate(nodes):
        rows = list(n.rows)
        if n.kind == "fold":
            # Classic child rows are already in n.rows (CHILD[log] of the classic child). Add the hybrid child delta
            # at the CHILD's hybrid shape (its own GKR class), bottom-up: children precede parents in `nodes`.
            for c in n.children:
                rows = F.add(rows, child_delta(gates(hyb_rows[c]), case))
        hyb_rows.append(rows)
        cb, ca = cells(n.rows, False), cells(rows, True)
        crossed = [F.COMPONENTS[k] for k in range(5) if plog(rows[k]) > plog(n.rows[k])]
        rk = cal["rk"] * (STREAM_RK_FACTOR if case == "central_after_stream" else 1.0)
        k_before = rk * cb
        w = WITNESS_SHARE[base_case(case)]
        gate_ratio = sum(rows) / sum(n.rows)
        fct = facts(rows)
        gkr_s = fct * ns_per_fact(case) * 1e-9
        k_after = k_before * ((1 - w) * ca / cb + w * gate_ratio) + gkr_s
        out_nodes.append({"kind": n.kind, "children": list(n.children), "rows_classic": list(n.rows), "rows_hybrid": rows,
                          "padded_logs_classic": row_logs(n.rows), "padded_logs_hybrid": row_logs(rows),
                          "crossed_power_of_two": crossed, "cells_classic": cb, "cells_hybrid": ca,
                          "cell_factor": ca / cb, "gkr_facts": fct, "gkr_layers": layers(rows),
                          "gkr_gpu_s": gkr_s, "kernel_gpu_s_hybrid_without_gkr": k_after - gkr_s, "kernel_gpu_s_classic": k_before, "kernel_gpu_s_hybrid": k_after,
                          "wall_s_classic": cal["t0"] + cal["rw"] * cb,
                          "wall_s_hybrid": cal["t0"] + cal["rw"] * cb * ((1 - w) * ca / cb + w * gate_ratio) + gkr_s,
                          "gkr_workspace_gb": fct * WORKSPACE_B_PER_FACT / 1e9})
    return out_nodes, root


def summarize(nodes):
    s = lambda k, kind=None: sum(n[k] for n in nodes if kind is None or n["kind"] == kind)
    out = {"nodes": len(nodes), "leaves": sum(n["kind"] == "leaf" for n in nodes), "folds": sum(n["kind"] == "fold" for n in nodes)}
    for k in ("cells_classic", "cells_hybrid", "kernel_gpu_s_classic", "kernel_gpu_s_hybrid", "gkr_gpu_s", "wall_s_classic", "wall_s_hybrid"):
        out[k] = s(k)
    out["cell_factor"] = out["cells_hybrid"] / out["cells_classic"]
    f = s("gkr_facts")
    out["gkr_facts"] = f
    # GKR prover rate at which hybrid kernel GPU-s equals classic (outer GKR breaks even) [D].
    out["break_even_ns_per_fact"] = (out["kernel_gpu_s_classic"] - s("kernel_gpu_s_hybrid_without_gkr")) / f * 1e9
    out["kernel_factor"] = out["kernel_gpu_s_hybrid"] / out["kernel_gpu_s_classic"]
    out["node_wall_sum_factor"] = out["wall_s_hybrid"] / out["wall_s_classic"]
    for kind in ("leaf", "fold"):
        c = s("kernel_gpu_s_classic", kind)
        out[f"{kind}_kernel_factor"] = (s("kernel_gpu_s_hybrid", kind) / c) if c else None
        cc = s("cells_classic", kind)
        out[f"{kind}_cell_factor"] = (s("cells_hybrid", kind) / cc) if cc else None
    out["folds_crossing_power_of_two"] = sum(1 for n in nodes if n["crossed_power_of_two"])
    out["max_gkr_workspace_gb"] = max(n["gkr_workspace_gb"] for n in nodes)
    out["nodes_over_admission_free"] = sum(1 for n in nodes if n["gkr_workspace_gb"] * 1e9 > ADMISSION_FREE_B)
    out["nodes_over_admission_free_partial_frontier"] = sum(
        1 for n in nodes if n["gkr_facts"] * PARTIAL_FRONTIER_B_PER_FACT > ADMISSION_FREE_B)
    return out


def soundness(n_nodes, max_layers):
    """Union bound per request (ledger of rv64-m5-outer-gkr.md §2 with the actual node count; i = 8 instances)."""
    i, v, d = 8, max_layers, 3
    per = i * d * v * (v + 1) / 2 + (2 * i + 2) * v + 2 * i * v + i * MAX_TUPLE_ARITY * 2 ** v + 2 * i * 2 ** v
    total = n_nodes * per
    return {"outer_proofs": n_nodes, "max_layers": v, "log2_degree_mass": math.log2(total),
            "bits_strict_draws": LOG2_P8 - math.log2(total), "required_bits": 151}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tool")
    ap.add_argument("--gates", type=Path, default=Path("vectors/reports/rv64-m9-prep/m9-outer-gkr/gates.json"))
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--blocks", default="focus", choices=["focus", "basket"])
    a = ap.parse_args()
    cache = json.loads(a.gates.read_text()) if a.gates.exists() else {}
    gates = Gates(a.tool, cache)
    cal = F.calibrate()
    blocks = FOCUS if a.blocks == "focus" else [b[0] for b in F.BASKET]
    res = {}
    for block in blocks:
        res[block] = {}
        for tname, opts in TREES.items():
            per_case = {}
            for case in CASES:
                nodes, root = tree(block, opts, gates, case, cal)
                per_case[case] = summarize(nodes)
                if case == "central":
                    central_nodes = nodes
                    per_case["soundness"] = soundness(len(nodes), max(n["gkr_layers"] for n in nodes))
                    per_case["proof_bytes"] = {
                        "root_section_bytes": gates(central_nodes[root]["rows_hybrid"])["section_bytes"],
                        "root_inter_openings_saved_bytes": DCOLS * 4 * Q,
                        "net_root_proof_bytes": gates(central_nodes[root]["rows_hybrid"])["section_bytes"] - DCOLS * 4 * Q}
                    if block in FOCUS:
                        per_case["nodes"] = [{k: n[k] for k in ("kind", "children", "padded_logs_classic", "padded_logs_hybrid",
                                                             "crossed_power_of_two", "cells_classic", "cells_hybrid", "gkr_facts",
                                                             "gkr_layers", "gkr_gpu_s", "kernel_gpu_s_classic",
                                                                 "kernel_gpu_s_hybrid", "gkr_workspace_gb")} for n in central_nodes]
            res[block][tname] = per_case
    a.gates.parent.mkdir(parents=True, exist_ok=True)
    a.gates.write_text(json.dumps(dict(sorted(cache.items())), indent=1) + "\n")
    out = {
        "schema": "rv64-m9-outer-gkr-factor/v1",
        "labels": {"M": "measured", "D": "derived from measured / counted from code", "E": "estimate"},
        "sources": {
            "trees": "scripts/rv64_m9_leaf_fanin_model.py (codex/rv64-m9-fewer-leaves @ a056cee67, unchanged copy)",
            "gates": "rv64-m9-outer-gkr-tool cost-raw (shape-only CG.measure; equals honest sections, test pinned; "
                     "reproduces M5 [M] leaf/fold counts exactly)",
            "gkr_ns_per_fact": "rv64-m5-outer-gkr.md §6 fused 148.2 ms/257.9 M [M]; production-negative prod3 GPU_GKR_SPANS/"
                               "GPU_GKR native_stage_wall_ns [M]",
            "workspace": "production-negative README 16,573,396,480 B at 257,949,696 facts; refused fold free 15,737,028,608 B [M]",
            "calibration": "fan-in model calibrate(): rk, rw, t0 on bench15 [D]",
        },
        "constants": {"width_classic": WIDTH_CLASSIC, "width_hybrid": WIDTH_HYBRID, "fixed_cells_classic": F.FIXED_CELLS,
                      "fixed_cells_hybrid": FIXED_CELLS_HYBRID, "dcols": DCOLS, "queries": Q,
                      "hash_saved_g_per_child": HASH_SAVED_G, "oods_mix_saved_g_per_child_E": OODS_MIX_SAVED_G,
                      "deep_saved_qm31_per_child_E": DEEP_SAVED_QM31, "ns_per_fact": NS_PER_FACT, "ns_per_fact_engineered_E": NS_PER_FACT_ENGINEERED,
                      "stream_rk_factor_E": STREAM_RK_FACTOR,
                      "witness_share": WITNESS_SHARE, "workspace_b_per_fact": WORKSPACE_B_PER_FACT,
                      "plan_factor_E": PLAN_FACTOR, "calibration": {k: cal[k] for k in ("t0", "rw", "rk")}},
        "blocks": res,
    }
    if a.blocks == "basket":
        out["basket"] = {t: {c: {"sum_kernel_gpu_s_classic": sum(res[b][t][c]["kernel_gpu_s_classic"] for b in blocks),
                                 "sum_kernel_gpu_s_hybrid": sum(res[b][t][c]["kernel_gpu_s_hybrid"] for b in blocks)}
                             for c in CASES} for t in TREES}
        for t in TREES:
            for c in CASES:
                x = out["basket"][t][c]
                x["factor"] = x["sum_kernel_gpu_s_hybrid"] / x["sum_kernel_gpu_s_classic"]
        print(json.dumps({t: {c: round(out["basket"][t][c]["factor"], 3) for c in CASES} for t in TREES}))
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(out, indent=1) + "\n")
    for block in blocks:
        for tname in TREES:
            r = res[block][tname]
            print(block, tname, " ".join(f"{c}: kern x{r[c]['kernel_factor']:.3f} cells x{r[c]['cell_factor']:.3f}"
                                          f" (leaf x{r[c]['leaf_kernel_factor']:.3f} fold x{r[c]['fold_kernel_factor'] or 0:.3f})"
                                          f" GKR {r[c]['gkr_gpu_s']:.2f}s cross {r[c]['folds_crossing_power_of_two']}"
                                          for c in ("pess", "central", "opt", "engineered")),
                  f"| R {r['central']['kernel_gpu_s_classic']:.2f} -> {r['central']['kernel_gpu_s_hybrid']:.2f} GPU-s"
                  f" | ws max {r['central']['max_gkr_workspace_gb']:.1f} GB, over-free {r['central']['nodes_over_admission_free']}"
                  f" | bits {r['soundness']['bits_strict_draws']:.0f} | break-even {r['central']['break_even_ns_per_fact']:.3f} ns/fact"
                  f" (after stream {r['central_after_stream']['break_even_ns_per_fact']:.3f})")


if __name__ == "__main__":
    main()
