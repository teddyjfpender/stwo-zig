#!/usr/bin/env python3
"""Adversarial review of scripts/rv64_m9/outer_gkr_factor.py (stream m9-outer-gkr). CPU only, no GPU, no tool.

Checks the three places where the factor receipt is weakest:

1. r_k identification [D]. `calibrate()` fits kernel_gpu_s = a*Minstr + r_k*cells on 6 bench15 blocks, no
   intercept. Minstr and recursion cells are almost collinear (corr(a, r_k) = -0.995), so r_k carries a large
   standard error. The verdict "outer GKR loses GPU-s" depends on r_k, because every saved cell is priced at r_k
   and the GKR is not. This reports the factor and break-even across the r_k band: leave-one-out range and +-1/2 sigma.
2. Zero-cost floor [D]. Kernel factor with a free GKR prover (0 ns/fact): the plan's x0.57 is unreachable at any
   GKR rate once the witness share (which scales with gate rows) is counted.
3. Critical path [E]. The factor receipt reports a SUM of node walls with the GKR at its kernel rate. The request
   sees the recursion-after-native MAKESPAN on 2 GPUs (fan-in model `schedule`, the bench15 calibration target),
   and the measured all-in GKR stage wall is 1.58 ns/fact [M], not 0.82. This re-schedules the tree with hybrid
   node walls at both GKR wall rates and with the 2^24 composition tax of the model's `node_time`.

  python3 scripts/rv64_m9/outer_gkr_review.py --out vectors/reports/rv64-m9-prep/m9-outer-gkr/review.json
"""
import argparse
import importlib.util
import json
import math
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("ogkr", HERE / "outer_gkr_factor.py")
G = importlib.util.module_from_spec(spec)
spec.loader.exec_module(G)
F = G.F


def rk_fit():
    """Same least squares as F.calibrate (no intercept), plus its standard error and leave-one-out range [D]."""
    proved = [r for r in F.BASKET if r[5]]
    xs = [(r[1], sum(n.cells for n in F.plan(r[0])[2]) / 1e9, r[5][2]) for r in proved]

    def solve(X):
        s11 = sum(a * a for a, _, _ in X); s12 = sum(a * c for a, c, _ in X); s22 = sum(c * c for _, c, _ in X)
        y1 = sum(a * y for a, _, y in X); y2 = sum(c * y for _, c, y in X)
        det = s11 * s22 - s12 * s12
        return (y1 * s22 - y2 * s12) / det, (s11 * y2 - s12 * y1) / det, (s11, s12, s22, det)

    a, rk, (s11, s12, s22, det) = solve(xs)
    res = [y - a * m - rk * c for m, c, y in xs]
    sig2 = sum(e * e for e in res) / (len(xs) - 2)
    se = math.sqrt(sig2 * s11 / det)
    loo = [solve(xs[:i] + xs[i + 1:])[1] for i in range(len(xs))]
    return {"rk_ns": rk, "se_ns": se, "corr_a_rk": -s12 / math.sqrt(s11 * s22), "loo_min_ns": min(loo),
            "loo_max_ns": max(loo), "n_blocks": len(xs), "dof": len(xs) - 2}


def run_tree(block, opts, gates, cal, ns, case="central"):
    old = G.NS_PER_FACT_ENGINEERED
    G.NS_PER_FACT_ENGINEERED = ns
    try:
        nodes, root = G.tree(block, opts, gates, "engineered", cal)  # "engineered" = central constants, custom ns
    finally:
        G.NS_PER_FACT_ENGINEERED = old
    return nodes, root


class Shim:
    """A node for F.schedule with an effective wall expressed in cells (node_time = t0 + rw*(cells + tax))."""
    __slots__ = ("kind", "children", "natives", "cells", "log")

    def __init__(self, kind, children, natives, cells, log):
        self.kind, self.children, self.natives, self.cells, self.log = kind, children, natives, cells, log


def makespans(block, opts, nodes, root, cal, gkr_wall_ns):
    _, _, fnodes, froot = F.plan(block, **opts)
    assert froot == root and len(fnodes) == len(nodes)
    t0, rw = cal["t0"], cal["rw"]
    classic, hybrid = [], []
    for fn, n in zip(fnodes, nodes):
        classic.append(Shim(fn.kind, fn.children, fn.natives, fn.cells, fn.log))
        w = G.WITNESS_SHARE["central"]
        gate_ratio = sum(n["rows_hybrid"]) / sum(n["rows_classic"])
        eff = fn.cells * ((1 - w) * n["cells_hybrid"] / n["cells_classic"] + w * gate_ratio)
        eff += n["gkr_facts"] * gkr_wall_ns * 1e-9 / rw
        hybrid.append(Shim(fn.kind, fn.children, fn.natives, eff, max(G.row_logs(n["rows_hybrid"]))))
    mc = F.schedule(classic, root, 2, t0, rw)
    mh = F.schedule(hybrid, root, 2, t0, rw)
    sum_c = sum(F.node_time(x, t0, rw) for x in classic)
    sum_h = sum(F.node_time(x, t0, rw) for x in hybrid)
    return {"makespan_classic_s": mc, "makespan_hybrid_s": mh, "makespan_factor": mh / mc,
            "node_wall_sum_factor_with_comp_tax": sum_h / sum_c}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--gates", type=Path, default=Path("vectors/reports/rv64-m9-prep/m9-outer-gkr/gates.json"))
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    gates = G.Gates(None, json.loads(a.gates.read_text()))
    cal = F.calibrate()
    fit = rk_fit()
    assert abs(fit["rk_ns"] * 1e-9 - cal["rk"]) < 1e-15
    t95 = 2.776  # Student t, 4 dof, two-sided 95%
    rk_band = {"loo_min": fit["loo_min_ns"], "fit": fit["rk_ns"], "loo_max": fit["loo_max_ns"],
               "plus_1sigma": fit["rk_ns"] + fit["se_ns"], "plus_2sigma": fit["rk_ns"] + 2 * fit["se_ns"],
               "ci95_low": fit["rk_ns"] - t95 * fit["se_ns"], "ci95_high": fit["rk_ns"] + t95 * fit["se_ns"]}
    central_ns = G.NS_PER_FACT["central"]
    out = {"schema": "rv64-m9-outer-gkr-review/v1",
           "labels": {"M": "measured", "D": "derived", "E": "estimate"},
           "rk_fit_D": fit, "rk_band_ns_D": rk_band,
           "gkr_ns_per_fact": {"central_kernel_D": central_ns, "stage_wall_all_in_M": G.NS_PER_FACT["pess"]},
           "blocks": {}}
    for block in G.FOCUS:
        out["blocks"][block] = {}
        for tname, opts in G.TREES.items():
            r = {"rk_sensitivity_central": {}, "critical_path_E": {}}
            for name, rk in rk_band.items():
                c = dict(cal, rk=rk * 1e-9)
                nodes, _ = run_tree(block, opts, gates, c, central_ns)
                s = G.summarize(nodes)
                r["rk_sensitivity_central"][name] = {"rk_ns": rk, "kernel_factor": s["kernel_factor"],
                                                     "break_even_ns_per_fact": s["break_even_ns_per_fact"]}
            nodes, root = run_tree(block, opts, gates, cal, central_ns)
            s = G.summarize(nodes)
            # r_k at which the central GKR rate breaks even: break-even scales linearly with r_k.
            r["rk_needed_for_break_even_at_central_ns"] = cal["rk"] * 1e9 * central_ns / s["break_even_ns_per_fact"]
            # [E] v2 binding columns (anchored Eq + cyclic prefix) re-read every fact once more (n + gamma*d per lane,
            # no inversion): priced like one more projection pass, which the central 0.82 ns/fact does not contain.
            nb, _ = run_tree(block, opts, gates, cal, central_ns + G.NS_PER_FACT_PROJECTION)
            r["kernel_factor_central_plus_binding_pass_E"] = G.summarize(nb)["kernel_factor"]
            n0, _ = run_tree(block, opts, gates, cal, 0.0)
            r["kernel_factor_free_gkr_central_witness_D"] = G.summarize(n0)["kernel_factor"]
            for label, ns in (("gkr_wall_0.82", central_ns), ("gkr_wall_1.58_M", G.NS_PER_FACT["pess"])):
                r["critical_path_E"][label] = makespans(block, opts, nodes, root, cal, ns)
            out["blocks"][block][tname] = r
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps({"rk_fit": fit, "band": rk_band}, indent=1))
    for block in G.FOCUS:
        for tname in G.TREES:
            r = out["blocks"][block][tname]
            sens = " ".join(f"{k} {v['kernel_factor']:.3f}" for k, v in r["rk_sensitivity_central"].items())
            cp = " | ".join(f"{k}: makespan x{v['makespan_factor']:.3f} sum x{v['node_wall_sum_factor_with_comp_tax']:.3f}"
                            f" ({v['makespan_classic_s']:.2f}->{v['makespan_hybrid_s']:.2f}s)"
                            for k, v in r["critical_path_E"].items())
            print(block, tname, "| kern:", sens, f"| rk for BE {r['rk_needed_for_break_even_at_central_ns']:.3f}",
                  f"| +binding pass x{r['kernel_factor_central_plus_binding_pass_E']:.3f}"
                  f" | free-GKR x{r['kernel_factor_free_gkr_central_witness_D']:.3f} |", cp)


if __name__ == "__main__":
    main()
