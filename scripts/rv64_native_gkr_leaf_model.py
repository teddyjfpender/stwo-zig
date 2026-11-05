#!/usr/bin/env python3
"""Leaf-cell delta model [E] for rv64-m5-native-gkr/v1 (stream native-gkr). Python 3 stdlib only.

A recursion leaf verifies one native proof. v1 removes committed native INTER columns (fewer opened
columns: Merkle leaf hashing + DEEP per query) and adds GKR instances (more in-circuit GKR mask work;
truth proofs gain a GKR they do not have today). Calibration: the outer-gkr census model
(scripts/rv64_m5_outer_gkr_census.py): 80 G rows per Blake compression, 16 words per compression,
2 qm31 rows per column per query for DEEP, row widths of today's leaf (blake_g_gate 167, qm31_ops 28 cells
per row incl. classic interaction), native queries q = 108.
Per added instance-layer: 4 mask felts mixed (32 words = 2 compressions) + ~10 qm31 ops. Per added round
(truth proofs only): 4 coefficients mixed + 1 draw ~ 3 compressions + ~8 qm31 ops.
"""
import json, math, sys
Q, WPC, GPC, G_ROW, QM_ROW = 108, 16, 80, 167, 28
def lanes(t): return 0 if t <= 1 else math.ceil(math.log2(t))
def main(path, out):
    c = json.load(open(path))
    rows = []
    for kind, items in (("cpu", c["cpus"]), ("truth", c["truths"])):
        for i, p in enumerate(items):
            if kind == "cpu":
                today = sum(s["binding_cols"] + s["ram_cols"] + s["other_cols"] for s in p["slots"])
                v1 = 16 * sum(1 for s in p["slots"] if s["local_terms"] or s["ram_cols"] or s["other_cols"])
                # added instances: one per global group (ram, kio/wire); its masks = row_log + lane_log layers
                added_layers = 0; added_rounds = 0
                for s in p["slots"]:
                    for cols in (s["ram_cols"], s["other_cols"]):
                        if cols:
                            q = 2 * (cols // 8 - 1)
                            added_layers += s["log"] + lanes(q)
                    if s["local_terms"] == 0 and (s["ram_cols"] or s["other_cols"]):
                        pass  # initial/terminal: new binding pair counted in v1 columns
            else:
                today = sum(x["local_cols"] + x["global_cols"] for x in p["parts"])
                v1 = 16 * sum(1 for x in p["parts"] if x["local_cols"] or x["global_cols"])
                added_layers = 0; L = 0
                for x in p["parts"]:
                    for cols in (x["local_cols"], x["global_cols"]):
                        if cols:
                            q = 3 * (cols // 8 - 1) if x["kind"] == "keccak" else 2 * (cols // 8 - 1)
                            v = x["log"] + lanes(max(q, 1)); added_layers += v; L = max(L, v)
                added_rounds = L * (L - 1) // 2
            dcols = today - v1
            save = Q * dcols / WPC * GPC * G_ROW + 2 * dcols * Q * QM_ROW
            add = added_layers * (2 * GPC * G_ROW + 10 * QM_ROW) + added_rounds * (3 * GPC * G_ROW + 8 * QM_ROW)
            rows.append({"proof": f"{kind}-{i}", "inter_cols_today": today, "inter_cols_v1": v1, "delta_cols": dcols,
                         "leaf_cells_saved_E": round(save), "leaf_cells_added_E": round(add), "leaf_cells_net_E": round(add - save)})
    tot = {k: sum(r[k] for r in rows) for k in ("delta_cols", "leaf_cells_saved_E", "leaf_cells_added_E", "leaf_cells_net_E")}
    json.dump({"schema": "rv64-native-gkr-leaf-model/v1", "label": "E", "calibration": __doc__.strip().splitlines()[3:8], "proofs": rows, "totals": tot}, open(out, "w"), indent=1)
    print(json.dumps(tot))
if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
