#!/usr/bin/env python3
"""M9 Poseidon2-leaves lever model: measured kernels [M] + code-derived in-circuit
costs [D] -> projected per-request GPU-s for p50/p95 mainnet blocks [E].

Usage: python3 -I scripts/rv64_m9/poseidon2_leaves_model.py [REPORT_DIR]
Reads REPORT_DIR/{bench-single,chain-24628607-trees}.jsonl, writes REPORT_DIR/model.json.
Every constant below cites its source; nothing is fitted here.
"""
import json
import math
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT = os.path.join(HERE, "..", "..", "vectors", "reports", "rv64-m9-prep", "m9-poseidon2-leaves")

# ---- [D] in-circuit costs from code / accepted census logs -------------------
# src/integrations/riscv_cpu/poseidon2_outer/layout.zig: MAIN_COLUMNS 476,
# FIXED_COLUMNS 73, CLASSIC_INTERACTION_COLUMNS 192 (GKR mode 16), one row/permutation.
P2_CELLS_PER_PERM = 476 + 73 + 192
P2_CELLS_PER_PERM_GKR = 476 + 73 + 16
# vectors/reports/rv64-m7-20261105/poseidon2/matched-blake-cpu-census/matched-blake-cpu-census.log
BLAKE_CENSUS = dict(total_cells=554_830_848, blake_g_gate=1_339_680)  # 80 G-gates/compression
# .../full-pure-cpu-matched-p20/pure-cpu-candidate-census.log (b4-q54-P20-f4, same source geometry)
P2_CENSUS = dict(total_cells=106_332_160, p2_calls=30_655, p2_rows=32_768)
# rv64-4gpu-realtime.md section 2.1: in-circuit Blake2s is 74-85% of real leaf cells;
# section 7.1: ~22.7k committed cells per compression [M/D].
BLAKE_HASH_SHARE = (0.74, 0.80, 0.85)
BLAKE_CELLS_PER_COMP_DOC = 22_700

# ---- [M] request context (task CONTEXT + receipts) --------------------------
REQ_24628607 = dict(minstr=26.9, kernel_gpu_s=8.48, merkle_share=0.14)  # integrate @95e3d7e15
# vectors/reports/rv64-m8-20261106/p3p5/NATIVE-REGRESSION-AUDIT.md: recursion-node kernels
# 5.992 GPU-s, native-stream 4.456 GPU-s of the same request -> recursion share 0.573.
RECURSION_SHARE = (0.50, 0.573, 0.60)
# bench15-1 (codex/rv64-m8-gpu): kernel GPU-s ~ 1.8 + 0.28 x Minstr per block.
KERNEL_FIT = (1.8, 0.28)
# rv64-4gpu-realtime.md section 1.1: basket instr/gas 2.71-3.89; 26235159 3.548.
INSTR_PER_GAS = (3.13, 3.55, 3.89)
# gas_sample.json (2,901 mainnet blocks Sep-Oct 2026): p50 29.11M, p95 55.82M.
GAS = {"p50": 29.11e6, "p95": 55.82e6, "24628607": 7.37e6}


def load(path):
    with open(path) as f:
        return [json.loads(line) for line in f if line.strip()]


def main():
    rd = sys.argv[1] if len(sys.argv) > 1 else DEFAULT
    single = load(os.path.join(rd, "bench-single.jsonl"))
    chain = load(os.path.join(rd, "chain-24628607-trees.jsonl"))
    out = {"schema": "rv64-m9-poseidon2-leaves-model/v1", "labels": "[M] measured, [D] derived from code/census, [E] estimate"}

    # [M] kernel throughput, single-height and real-tree flat (bench-single).
    rows = []
    for r in single:
        leaf_ratio = r["p2v1_leaf_ms"] / r["blake_leaf_ms"]
        tree_ratio = (r["p2v1_leaf_ms"] + r["p2v1_tree_ms"]) / (r["blake_leaf_ms"] + r["blake_tree_ms"])
        rows.append(dict(spec=r["spec"], log=r["log_size"], words=r["leaf_words"],
                         blake_leaf_ms=r["blake_leaf_ms"], p2_leaf_ms=r["p2v1_leaf_ms"], p2v2_leaf_ms=r["p2v2_leaf_ms"],
                         leaf_ratio=round(leaf_ratio, 2), leaf_plus_tree_ratio=round(tree_ratio, 2),
                         p2_leaf_perm_per_s=r["p2_leaf_perms"] / (r["p2v1_leaf_ms"] * 1e-3),
                         p2_node_perm_per_s=r["p2_node_perms"] / (r["p2v1_tree_ms"] * 1e-3),
                         blake_input_TB_s=r["input_cells"] * 4 / (r["blake_leaf_ms"] * 1e-3) / 1e12))
    big = [x for x in rows if x["log"] >= 20]
    out["kernel_M"] = dict(
        rows=rows,
        p2_perm_per_s_at_log_ge_20=[min(x["p2_leaf_perm_per_s"] for x in big), max(x["p2_leaf_perm_per_s"] for x in big)],
        leaf_ratio_log_ge_20=[min(x["leaf_ratio"] for x in big), max(x["leaf_ratio"] for x in big)],
        v2_over_v1_leaf=[round(min(x["p2v2_leaf_ms"] / x["p2_leaf_ms"] for x in big), 3),
                         round(max(x["p2v2_leaf_ms"] / x["p2_leaf_ms"] for x in big), 3)])

    # [M] all 68 native trees of 24628607 at M6 geometry, prefix-bank chain.
    warm = [c for c in chain if not c["tree"].endswith("-t0")]
    def tot(cs, k):
        return sum(c[k] for c in cs)
    node_perms = sum(2 * ((1 << c["log_size"]) - 1) for c in warm)
    p2_perms = tot(warm, "p2_perms_model")
    native = dict(
        trees_cold=len(chain), trees_warm=len(warm),
        cold_blake_ms=tot(chain, "blake_ms"), cold_p2_ms=tot(chain, "p2_ms"),
        warm_blake_ms=tot(warm, "blake_ms"), warm_p2_ms=tot(warm, "p2_ms"),
        warm_p2_perms=p2_perms, warm_blake_compressions=tot(warm, "blake_compressions_model"),
        warm_node_perm_fraction=node_perms / p2_perms)
    native["warm_ratio"] = native["warm_p2_ms"] / native["warm_blake_ms"]
    native["warm_delta_gpu_s_M"] = (native["warm_p2_ms"] - native["warm_blake_ms"]) / 1e3
    # [E] 1-permutation 2-to-1 node (pil2 pattern; needs S0 security note): nodes halve.
    per_perm = native["warm_p2_ms"] / p2_perms
    p2_2to1_ms = (p2_perms - node_perms / 2) * per_perm
    native["warm_delta_gpu_s_2to1_E"] = (p2_2to1_ms - native["warm_blake_ms"]) / 1e3
    native["ratio_2to1_E"] = p2_2to1_ms / native["warm_blake_ms"]
    out["native_24628607"] = native

    # [D] per-decommitment in-circuit cost for one query into one tree.
    comps = BLAKE_CENSUS["blake_g_gate"] // 80
    non_hash = P2_CENSUS["total_cells"] - P2_CENSUS["p2_rows"] * P2_CELLS_PER_PERM
    blake_cells_per_comp_padded = (BLAKE_CENSUS["total_cells"] - non_hash) / comps
    def decommit(width, depth, blake_cells, two_to_one=False):
        b = (max(1, math.ceil(width / 16)) + depth) * blake_cells
        p = (width // 12 + 1 + (1 if two_to_one else 2) * depth) * P2_CELLS_PER_PERM
        return b, p
    trees = [("cpu FIXED", 203), ("cpu MAIN", 3606), ("cpu INTER", 2008), ("composition", 16), ("recursion-like", 300)]
    dec = []
    for name, w in trees:
        for depth in (21, 23):
            b, p = decommit(w, depth, BLAKE_CELLS_PER_COMP_DOC)
            _, p1 = decommit(w, depth, BLAKE_CELLS_PER_COMP_DOC, True)
            dec.append(dict(tree=name, width=w, depth=depth, blake_cells=b, p2_cells=p, p2_2to1_cells=p1,
                            ratio=round(b / p, 1), ratio_2to1=round(b / p1, 1)))
    leaf_ratio_census = P2_CENSUS["total_cells"] / BLAKE_CENSUS["total_cells"]
    hash_ratio = min(d["p2_cells"] / d["blake_cells"] for d in dec), max(d["p2_cells"] / d["blake_cells"] for d in dec)
    leaf_ratio_model = [(1 - h) + h * hash_ratio[1] for h in BLAKE_HASH_SHARE]
    out["in_circuit_D"] = dict(
        p2_cells_per_perm=P2_CELLS_PER_PERM, p2_cells_per_perm_gkr=P2_CELLS_PER_PERM_GKR,
        blake_compressions_in_census=comps, blake_cells_per_comp_doc=BLAKE_CELLS_PER_COMP_DOC,
        blake_cells_per_comp_padded_from_census=round(blake_cells_per_comp_padded),
        p2_cells_per_perm_padded_from_census=round(P2_CENSUS["p2_rows"] * P2_CELLS_PER_PERM / P2_CENSUS["p2_calls"]),
        census_non_hash_cells=non_hash, census_hash_ops=dict(blake_compressions=comps, p2_perms=P2_CENSUS["p2_calls"]),
        per_decommitment=dec, hash_cell_ratio_range=hash_ratio,
        whole_leaf_cell_ratio_census_M=leaf_ratio_census, whole_leaf_cell_ratio_model=leaf_ratio_model)

    # [E] per-request projection.
    def project(minstr, c, m, k_rec, k_nat, rshare):
        kernel = KERNEL_FIT[0] + KERNEL_FIT[1] * minstr
        rec = rshare * kernel
        rec_after = rec * c * ((1 - m) + m * k_rec)
        native_blake = native["warm_blake_ms"] / 1e3 * minstr / REQ_24628607["minstr"]
        native_delta = native_blake * (k_nat - 1)
        return dict(minstr=round(minstr, 1), kernel_gpu_s=round(kernel, 2), recursion_gpu_s=round(rec, 2),
                    recursion_after=round(rec_after, 2), recursion_cut=round(rec - rec_after, 2),
                    native_hash_delta=round(native_delta, 2), net_cut=round(rec - rec_after - native_delta, 2),
                    net_cut_pct_of_kernel=round(100 * (rec - rec_after - native_delta) / kernel, 1))
    mean = lambda xs: sum(xs) / len(xs)
    r_sponge = mean([d["p2_cells"] / d["blake_cells"] for d in dec])
    r_2to1 = mean([d["p2_2to1_cells"] / d["blake_cells"] for d in dec])
    h = BLAKE_HASH_SHARE[1]
    c_central = (1 - h) + h * r_sponge
    c_2to1 = (1 - h) + h * r_2to1
    c_pess = leaf_ratio_model[0]
    c_opt = leaf_ratio_census
    out["in_circuit_D"].update(mean_hash_ratio_sponge=r_sponge, mean_hash_ratio_2to1=r_2to1,
                               c_central=c_central, c_2to1=c_2to1, c_pessimistic=c_pess, c_optimistic=c_opt)
    kn = native["warm_ratio"]
    k2 = native["ratio_2to1_E"]
    scenarios = {
        # c: whole-leaf cell ratio; m: Merkle share of recursion kernel time;
        # k_rec/k_nat: P2/Blake GPU cost of the recursion / native trees.
        "as_measured_sponge_nodes": dict(c=c_central, m=0.18, k_rec=kn, k_nat=kn, rshare=0.573),
        "with_2to1_nodes": dict(c=c_2to1, m=0.18, k_rec=k2, k_nat=k2, rshare=0.573),
        "2to1_plus_kernel_x0.6": dict(c=c_2to1, m=0.18, k_rec=0.6 * k2, k_nat=0.6 * k2, rshare=0.573),
        "pessimistic": dict(c=c_pess, m=0.22, k_rec=11.1, k_nat=kn, rshare=0.50),
        "optimistic": dict(c=c_opt, m=0.14, k_rec=0.6 * k2, k_nat=0.6 * k2, rshare=0.60),
    }
    proj = {}
    for block, gas in GAS.items():
        minstr = gas * INSTR_PER_GAS[1] / 1e6 if block != "24628607" else REQ_24628607["minstr"]
        proj[block] = {name: dict(params={k: round(v, 3) for k, v in s.items()}, **project(minstr, **s))
                       for name, s in scenarios.items()}
    out["projection_E"] = proj
    out["notes"] = [
        "native delta is measured at M6 geometry (log blowup 1, 17 proofs); D2 b4 roughly doubles native LDE hashing [E]",
        "recursion GPU-s assumed proportional to committed cells; recursion-prover trees switch to P2 too (they are verified in-circuit by the next layer)",
        "c_central/c_2to1: hash share 0.80 x mean per-decommitment P2/Blake cell ratio; pessimistic: share 0.74 x max ratio; optimistic: accepted whole-leaf census ratio 0.192 [M/D]",
        "m=0.18 Merkle share of recursion kernel time [E] (request-wide Merkle share 0.14 [M]); k_rec/k_nat = measured P2/Blake tree cost 9.95 (8.55 with 2-to-1 [E]); x0.6 = a kernel-tuning target, not measured",
    ]
    with open(os.path.join(rd, "model.json"), "w") as f:
        json.dump(out, f, indent=1)
    print(json.dumps({k: out[k] for k in ("native_24628607",)}, indent=1))
    print(json.dumps({b: {n: {k: v for k, v in s.items() if k != "params"} for n, s in p.items()} for b, p in proj.items()}, indent=1))
    print(json.dumps({k: v for k, v in out["in_circuit_D"].items() if k != "per_decommitment"}, indent=1))
    print(json.dumps({k: v for k, v in out["kernel_M"].items() if k != "rows"}, indent=1))


if __name__ == "__main__":
    main()
