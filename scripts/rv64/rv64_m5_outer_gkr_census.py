#!/usr/bin/env python3
"""Committed-cell census for the outer LogUp-GKR profile (outer_gkr_om31_strict_v1), 24628607.

Inputs (all committed next to the receipt):
  - census-v2 row logs of the 33 recursion nodes (vectors/reports/rv64-m3-20261104/topo/census-v2.json) [M]
  - per-node preprocessed coefficient words from the M4.0 counters run (GPU_TRACE_OWNERSHIP tree=0) [M]
  - component widths (profile.zig FACTS = component_list.zig component_facts); classic outer interaction
    is OM31 = 2x the QM31-counted facts; checked: 304 columns, and main/interaction words per class equal
    the measured GPU_TRACE_OWNERSHIP tree=1/tree=2 words exactly [M]
  - in-circuit GKR verifier gate counts at the production leaf/fold shapes, measured on GPU-proved
    sections (rv64-outer-gkr-tool cost) [M]
  - GPU GKR traversal time per class (outer_gkr_bench, CUDA events) [M]
Everything else is arithmetic on those [D] or a named model [E].
"""
import argparse
import json
from pathlib import Path

COMPONENTS = ["eq", "qm31_ops", "triple_xor", "m_31_to_u_32", "blake_g_gate", "verify_bitwise_xor_8",
              "verify_bitwise_xor_12", "verify_bitwise_xor_4", "verify_bitwise_xor_7", "verify_bitwise_xor_9", "range_check_16"]
MAIN = [4, 12, 20, 4, 52, 2, 16, 1, 1, 1, 1]
INTER_QM31 = [4, 8, 24, 12, 52, 4, 32, 4, 4, 4, 4]
LOOKUPS = [2, 3, 12, 5, 26, 2, 16, 1, 1, 1, 1]
PP_PER_ROW = {"triple_xor": 5, "m_31_to_u_32": 3, "blake_g_gate": 11}
BINDING = 16  # eq + weighted prefix, OM31
CLASSIC = [2 * x for x in INTER_QM31]
GKR = [c > BINDING for c in CLASSIC]
GATE_COMPONENT = {"blake_g_gate": "blake_g_gate", "qm31_ops": "qm31_ops", "m31_to_u32": "m_31_to_u_32", "triple_xor": "triple_xor", "eq": "eq"}
Q_OUTER = 108          # queries of the verified child (outer r1 profile, conjectured128_b2_q108)
LOG_BLOWUP_OUTER = 1   # r1 outer profile b2
NS_PER_LDE_CELL = 0.235  # M4.0 item 8 all-in recursion kernel rate [M]
WORDS_PER_COMPRESSION = 16
G_PER_COMPRESSION = 80


def row_cells(c, hybrid):
    i = COMPONENTS.index(c)
    inter = (BINDING if GKR[i] else CLASSIC[i]) if hybrid else CLASSIC[i]
    return MAIN[i] + inter + PP_PER_ROW.get(c, 0)


def node_cells(row_logs, pp):
    rows = [1 << r for r in row_logs]
    main = sum(m * n for m, n in zip(MAIN, rows))
    classic = sum(c * n for c, n in zip(CLASSIC, rows))
    hybrid = sum((BINDING if g else c) * n for c, g, n in zip(CLASSIC, GKR, rows))
    return {"pp": pp, "main": main, "interaction_classic": classic, "interaction_hybrid": hybrid,
            "total_classic": pp + main + classic, "total_hybrid": pp + main + hybrid}


def verifier_cells(gates, hybrid):
    return sum(gates[g] * row_cells(c, hybrid) for g, c in GATE_COMPONENT.items())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--census", type=Path, required=True)
    ap.add_argument("--pp", type=Path, required=True)
    ap.add_argument("--leaf-cost", type=Path, required=True)
    ap.add_argument("--fold-cost", type=Path, required=True)
    ap.add_argument("--leaf-bench", type=Path, required=True)
    ap.add_argument("--fold-bench", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    a = ap.parse_args()
    census = json.loads(a.census.read_text())["nodes"]
    pp = {int(k): v for k, v in json.loads(a.pp.read_text())["pp_words_by_node"].items()}
    cost = {"leaf": json.loads(a.leaf_cost.read_text()), "fold": json.loads(a.fold_cost.read_text())}
    bench = {"leaf": json.loads(a.leaf_bench.read_text()), "fold": json.loads(a.fold_bench.read_text())}
    nodes = []
    for k in sorted(census, key=int):
        logs = [int(x) for x in census[k]["row_logs"].strip("{} ").split(",")]
        n = node_cells(logs, pp[int(k)])
        n.update({"node": int(k), "kind": "leaf" if int(k) < 17 else "fold", "row_logs": logs})
        nodes.append(n)
    check_classic = sum(n["interaction_classic"] for n in nodes)
    # Parent side: a fold verifies 2 children; each child verification adds the in-circuit GKR verifier and
    # saves query-scaled hashing + DEEP work on the 176 fewer committed child columns.
    dcols = sum(CLASSIC) - sum(BINDING if g else c for c, g in zip(CLASSIC, GKR))
    comp_saved = Q_OUTER * dcols / WORDS_PER_COMPRESSION
    child = {}
    for widths in ("classic_widths", "hybrid_widths"):
        hybrid = widths == "hybrid_widths"
        g = cost["fold"]
        add = verifier_cells(g, hybrid)
        save_hash = comp_saved * G_PER_COMPRESSION * row_cells("blake_g_gate", hybrid)
        save_deep = 2 * dcols * Q_OUTER * row_cells("qm31_ops", hybrid)  # [E] 2 qm31 rows per column per query
        child[widths] = {"gkr_verifier_cells_M": add, "query_hash_cells_saved_D": save_hash, "deep_cells_saved_E": save_deep,
                         "net_per_child": add - save_hash - save_deep}
    child_verifications = 2 * sum(1 for n in nodes if n["kind"] == "fold")
    tree = {}
    for widths in ("classic_widths", "hybrid_widths"):
        before = sum(n["total_classic"] for n in nodes)
        own = sum(n["total_hybrid"] for n in nodes)
        parent = child_verifications * child[widths]["net_per_child"]
        tree[widths] = {"before": before, "own_after": own, "parent_delta": parent, "after": own + parent, "factor": (own + parent) / before}

    def cls(node_id, kind):
        n = next(x for x in nodes if x["node"] == node_id)
        b = bench[kind]
        saved = n["total_classic"] - n["total_hybrid"]
        gkr_ms = b["total_ms_median"]
        lde_saved_s = saved * (1 << LOG_BLOWUP_OUTER) * NS_PER_LDE_CELL * 1e-9
        return {"node": node_id, "row_logs": n["row_logs"], "cells_before": n["total_classic"], "cells_after_own": n["total_hybrid"],
                "own_factor": n["total_hybrid"] / n["total_classic"], "pp": n["pp"], "main": n["main"],
                "interaction_before": n["interaction_classic"], "interaction_after": n["interaction_hybrid"],
                "interaction_share_before": n["interaction_classic"] / n["total_classic"],
                "gpu_gkr_ms_M": gkr_ms, "gpu_gkr_tree_ms_M": b["tree_ms_median"], "gpu_gkr_traversal_ms_M": b["traversal_ms_median"],
                "gpu_gkr_device_bytes_M": b["device_allocated_bytes"], "fractions": b["fractions"], "kernel_calls": b["kernel_calls_per_rep"],
                "gpu_s_saved_on_committed_cells_D": lde_saved_s, "gpu_s_net_D": lde_saved_s - gkr_ms / 1e3,
                "in_circuit_verifier_gates_M": {k: cost[kind][k] for k in ("blake_g_gate", "qm31_ops", "m31_to_u32", "triple_xor", "eq", "draws")},
                "in_circuit_verifier_cells_classic_widths_D": verifier_cells(cost[kind], False),
                "in_circuit_verifier_cells_hybrid_widths_D": verifier_cells(cost[kind], True),
                "verifier_share_of_node_D": verifier_cells(cost[kind], False) / n["total_classic"]}

    leaf, fold = cls(0, "leaf"), cls(20, "fold")
    total_before = sum(n["total_classic"] for n in nodes)
    inter_share = check_classic / total_before
    gkr_tree_gpu_s = sum(bench["leaf" if n["kind"] == "leaf" else "fold"]["total_ms_median"] for n in nodes) / 1e3
    saved_tree_cells = sum(n["total_classic"] - n["total_hybrid"] for n in nodes)
    section_bytes = 69812
    proof = {"gkr_section_bytes_M": section_bytes,
             "interaction_openings_saved_bytes_E": dcols * 4 * Q_OUTER,
             "net_final_proof_bytes_E": section_bytes - dcols * 4 * Q_OUTER,
             "model": "final (root) proof carries one GKR section; each of q=108 queries opens 1 value of each of 176 fewer interaction columns; Merkle path count unchanged; no dedup modelled"}
    out = {"schema": "rv64-m5-outer-gkr-census/v1", "block": 24628607, "profile": "outer_gkr_om31_strict_v1",
           "labels": {"M": "measured", "D": "arithmetic on measured", "E": "model/estimate"},
           "checks": {"tree_interaction_classic_cells": check_classic, "measured_tree_interaction_cells": 32617000000,
                      "tree_total_classic_cells": total_before, "measured_tree_total_cells": 53391000000,
                      "interaction_share": inter_share, "committed_columns_classic": sum(CLASSIC), "committed_columns_hybrid": sum(BINDING if g else c for c, g in zip(CLASSIC, GKR))},
           "hybrid_rule": "GKR for components whose classic OM31 interaction width exceeds the 16 binding columns: " + ", ".join(c for c, g in zip(COMPONENTS, GKR) if g),
           "leaf_class": leaf, "fold_class": fold,
           "per_child_verification": child, "child_verifications": child_verifications, "tree": tree,
           "tree_gpu": {"gkr_gpu_s_D": gkr_tree_gpu_s, "committed_cells_saved": saved_tree_cells,
                        "lde_cell_gpu_s_saved_D": saved_tree_cells * (1 << LOG_BLOWUP_OUTER) * NS_PER_LDE_CELL * 1e-9},
           "proof_size": proof, "nodes": nodes}
    a.out.write_text(json.dumps(out, indent=1) + "\n")
    s = {k: out[k] for k in ("checks",)}
    s["leaf"] = {k: leaf[k] for k in ("cells_before", "cells_after_own", "own_factor", "gpu_gkr_ms_M", "gpu_s_net_D", "in_circuit_verifier_cells_classic_widths_D", "verifier_share_of_node_D")}
    s["fold"] = {k: fold[k] for k in ("cells_before", "cells_after_own", "own_factor", "gpu_gkr_ms_M", "gpu_s_net_D")}
    s["tree"] = tree
    s["child"] = child
    s["tree_gpu"] = out["tree_gpu"]
    s["proof"] = proof
    print(json.dumps(s, indent=1))


if __name__ == "__main__":
    main()
