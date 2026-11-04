#!/usr/bin/env python3
"""M7 cell-diet census (stream diet, 2026-11-04).

Committed main+interaction cells per recursion node of 24628607 (17 leaves,
16 folds, census-v2 row logs [M]) today and under each M7 lever:

  F  fused Blake2s compression AIR (src/frontends/circuit/diet/fused_blake2s.zig)
  G  outer LogUp-GKR replacing classic interaction columns
     (src/integrations/riscv_cpu/logup_gkr/outer_gkr_diet_test.zig)

Inputs are read, not retyped: component widths from component_list.zig, the
fused row shape from fused_blake2s.zig, row logs from census-v2.json, and the
in-circuit GKR verifier counts from the test log (OUTER_GKR_* lines).

Labels: [M] measured, [D] derived from measured inputs by the stated formula,
[E] estimate with a named assumption.
"""
import argparse, json, math, re, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMPONENTS = ["eq", "qm31_ops", "triple_xor", "m_31_to_u_32", "blake_g_gate", "verify_bitwise_xor_8",
              "verify_bitwise_xor_12", "verify_bitwise_xor_4", "verify_bitwise_xor_7", "verify_bitwise_xor_9", "range_check_16"]
# Preprocessed columns per row (common/preprocessed.zig *_COLUMN_IDS).
PP = {"triple_xor": 5, "m_31_to_u_32": 3, "blake_g_gate": 11}
BLAKE_COMPONENTS = {"blake_g_gate", "triple_xor", "verify_bitwise_xor_8", "verify_bitwise_xor_12",
                    "verify_bitwise_xor_4", "verify_bitwise_xor_7", "verify_bitwise_xor_9"}


def facts():
    src = (ROOT / "src/frontends/circuit/common/component_list.zig").read_text()
    body = src[src.index("pub const component_facts"):]
    out = {}
    for name in COMPONENTS:
        m = re.search(r"\." + name + r" = \.\{\s*\.trace_columns = (\d+),\s*\.interaction_columns = (\d+)", body)
        out[name] = (int(m.group(1)), int(m.group(2)))
    return out


def fused_shape():
    src = (ROOT / "src/frontends/circuit/diet/fused_blake2s.zig").read_text()
    # The Zig test pins these values ("row shape" test); keep the script honest.
    assert "expectEqual(@as(usize, 3328), N_COLUMNS)" in src and "expectEqual(@as(usize, 1376), N_LOOKUPS)" in src
    return {"main": 3328, "lookups": 1376, "pp": 45, "main_per_g": 40, "lookups_per_g": 16}


def padded(n, max_instances=3, min_log=4):
    """fused_blake2s.paddedRows: <= max_instances power-of-two instances."""
    if n <= 0:
        return 0
    total, rem, used = 0, n, 0
    while rem > 0:
        fl = rem.bit_length() - 1
        if used + 1 == max_instances or fl < min_log:
            return total + max(1 << min_log, 1 << (rem - 1).bit_length())
        total += 1 << fl
        rem -= 1 << fl
        used += 1
    return total


def fused_per_compression(k):
    """Committed (main, inter, columns) per compression for k rows per compression.
    k=1 is the implemented layout [M]; k>1 adds per-row msg(32)+state-in(64)+h-carry(32) [D]."""
    g_per_row = 80 // k
    if k == 1:
        main, lookups = 3328, 1376
    else:
        main = 32 + 64 + 32 + 64 + 40 * g_per_row
        lookups = 16 * g_per_row + 64 + 32
    inter = 4 * math.ceil(lookups / 2)
    return {"k": k, "rows": k, "main_row": main, "inter_row": inter, "cells": k * (main + inter), "columns": main + inter + (45 if k == 1 else 45 + 3)}


def node_cells(logs, f):
    return {c: (f[c][0] + f[c][1]) * (1 << l) for c, l in zip(COMPONENTS, logs)}


def compression_bounds(logs):
    g, t = logs[4], logs[2]
    lo = max((1 << (g - 1)) // 80, (1 << (t - 1)) // 8) + 1
    hi = min((1 << g) // 80, (1 << t) // 8)
    return lo, hi


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--census", default=str(ROOT / "vectors/reports/rv64-m3-20261104/topo/census-v2.json"))
    ap.add_argument("--gkr-log", required=True)
    ap.add_argument("--g-fill", type=float, default=5.98 / 8.39, help="[D] real/padded G rows (plan 2.3)")
    ap.add_argument("--queries", type=int, default=108, help="outer FRI queries of the verified child (r1 q108; m3 q51)")
    ap.add_argument("--deep-ops-per-column", type=float, default=2.0, help="[E] qm31 rows per opened column per query")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    f = facts()
    fs = fused_shape()
    census = json.loads(Path(a.census).read_text())
    nodes = {int(k): [int(x) for x in v["row_logs"].strip("{} ").split(",")] for k, v in census["nodes"].items()}

    # --- measured GKR verifier counts
    gkr_fit, binding = None, None
    for line in Path(a.gkr_log).read_text(errors="replace").splitlines():
        if "OUTER_GKR_COST" in line and "fit_at_production_shape" in line:
            gkr_fit = json.loads(line.split("OUTER_GKR_COST", 1)[1])
        if "OUTER_GKR_BINDING" in line and '"all"' in line:
            binding = json.loads(line.split("OUTER_GKR_BINDING", 1)[1])["counts"]
    measured_rows = [json.loads(l.split("OUTER_GKR_COST", 1)[1]) for l in Path(a.gkr_log).read_text(errors="replace").splitlines() if "OUTER_GKR_COST" in l and '"measured"' in l]
    if gkr_fit is None or binding is None:
        sys.exit("missing OUTER_GKR lines in the GKR log")
    width = {c: f[c][0] + f[c][1] for c in COMPONENTS}
    g_cell = width["blake_g_gate"]          # 104 cells per G gate
    q_cell = width["qm31_ops"]              # 20 per qm31 row
    gkr_verify_cells = (gkr_fit["blake_g_gate"] * g_cell + gkr_fit["qm31_ops"] * q_cell + gkr_fit["m31_to_u32"] * width["m_31_to_u_32"]
                        + gkr_fit["triple_xor"] * width["triple_xor"] + gkr_fit["eq"] * width["eq"])
    binding_cells = (binding["blake_g_gate"] * g_cell + binding["qm31_ops"] * q_cell + binding["m31_to_u32"] * width["m_31_to_u_32"]
                     + binding["triple_xor"] * width["triple_xor"] + binding["eq"] * width["eq"])

    # --- per compression
    today_pc = 80 * width["blake_g_gate"] + 8 * width["triple_xor"]
    today_pp = 80 * PP["blake_g_gate"] + 8 * PP["triple_xor"]
    per_comp = {"today": {"cells": today_pc, "main": 80 * f["blake_g_gate"][0] + 8 * f["triple_xor"][0],
                          "inter": 80 * f["blake_g_gate"][1] + 8 * f["triple_xor"][1], "pp": today_pp, "columns_per_row": width["blake_g_gate"]},
                "fused": [fused_per_compression(k) for k in (1, 2, 5, 10)]}

    # --- per node
    rows = []
    for nid in sorted(nodes):
        logs = nodes[nid]
        kind = "leaf" if nid < census["leaves"] else "fold"
        cells = node_cells(logs, f)
        today = sum(cells.values())
        inter_today = sum(f[c][1] * (1 << l) for c, l in zip(COMPONENTS, logs))
        main_today = today - inter_today
        lo, hi = compression_bounds(logs)
        point = round(a.g_fill * (1 << logs[4]) / 80)
        point = min(max(point, lo), hi)
        nonblake = sum(v for c, v in cells.items() if c not in BLAKE_COMPONENTS)
        tables = 3 * (1 << 16) * (1 + 4)
        fused = {}
        for k in (1, 2, 5, 10):
            pc = fused_per_compression(k)
            fused[k] = {"point": nonblake + tables + (pc["main_row"] + pc["inter_row"]) * padded(point * k),
                        "lo": nonblake + tables + (pc["main_row"] + pc["inter_row"]) * padded(lo * k),
                        "hi": nonblake + tables + (pc["main_row"] + pc["inter_row"]) * padded(hi * k)}
        # GKR: interaction columns -> binding columns (eq + weighted prefix, 2 secure columns).
        log_classes = sorted(set(logs))
        gkr_bind = {"per_log_class_8": main_today + sum(8 * (1 << l) for l in log_classes),
                    "per_component_8": main_today + sum(8 * (1 << l) for l in logs),
                    "per_component_12": main_today + sum(12 * (1 << l) for l in logs)}
        # Combined F(k=1) + G(per_log_class): fused main only + binding per class.
        pc1 = fused_per_compression(1)
        fused_main = sum(f[c][0] * (1 << l) for c, l in zip(COMPONENTS, logs) if c not in BLAKE_COMPONENTS) + 3 * (1 << 16) + pc1["main_row"] * padded(point)
        fused_logs = sorted(set([l for c, l in zip(COMPONENTS, logs) if c not in BLAKE_COMPONENTS] + [16]))
        fg = fused_main + sum(8 * (1 << l) for l in fused_logs) + 8 * padded(point)
        rows.append({"node": nid, "kind": kind, "row_logs": logs, "today_cells": today, "today_main": main_today, "today_inter": inter_today,
                     "compressions": {"lo": lo, "hi": hi, "point_D": point},
                     "fused_cells": {str(k): v for k, v in fused.items()}, "gkr_cells": gkr_bind, "fused_plus_gkr_cells": fg})

    # --- parent-side verification deltas per verified child (folds verify 2 children today)
    today_cols = sum(width.values()) + 45
    fused_cols = {k: sum(width[c] for c in COMPONENTS if c not in BLAKE_COMPONENTS) + 3 * 5 + fused_per_compression(k)["columns"] for k in (1, 2, 5, 10)}
    gkr_cols = sum(f[c][0] for c in COMPONENTS) + 8 * len(set(nodes[0])) + 45
    def query_cells(dcols, cell_per_compression=today_pc):
        comp = a.queries * dcols / 16.0
        deep = a.queries * dcols * a.deep_ops_per_column * q_cell
        return comp * cell_per_compression + deep
    parent = {"queries": a.queries, "today_columns": today_cols,
              "fused_columns": fused_cols, "gkr_columns": gkr_cols,
              "fused_delta_cells_per_child": {str(k): query_cells(fused_cols[k] - today_cols) for k in fused_cols},
              "gkr_delta_cells_per_child": gkr_verify_cells + binding_cells + query_cells(gkr_cols - today_cols),
              "gkr_verify_cells_per_child": gkr_verify_cells, "gkr_binding_cells_per_child": binding_cells}

    # --- tree totals including what parents pay to verify each child [D]
    n_child_verifications = 2 * sum(1 for r in rows if r["kind"] == "fold")
    gkr_comp = gkr_fit["blake_g_gate"] / 80.0 + binding["blake_g_gate"] / 80.0
    gkr_other = lambda: (gkr_fit["qm31_ops"] + binding["qm31_ops"]) * q_cell + (gkr_fit["eq"] + binding["eq"]) * width["eq"]
    tree = {"child_verifications": n_child_verifications, "today": sum(r["today_cells"] for r in rows)}
    for k in (1, 2, 5, 10):
        pc = fused_per_compression(k)
        own = sum(r["fused_cells"][str(k)]["point"] for r in rows)
        tree[f"fused_k{k}"] = {"own": own, "parent_width_delta": n_child_verifications * query_cells(fused_cols[k] - today_cols, pc["cells"]),
                               "total": own + n_child_verifications * query_cells(fused_cols[k] - today_cols, pc["cells"])}
    own = sum(r["gkr_cells"]["per_log_class_8"] for r in rows)
    pd = parent["gkr_delta_cells_per_child"]
    tree["gkr_per_log_class"] = {"own": own, "parent_verify_delta": n_child_verifications * pd, "total": own + n_child_verifications * pd}
    own = sum(r["gkr_cells"]["per_component_8"] for r in rows)
    tree["gkr_per_component_8"] = {"own": own, "parent_verify_delta": n_child_verifications * pd, "total": own + n_child_verifications * pd}
    # Combined fused(k=1) + GKR: the parent's added work is priced at fused-under-GKR cost per compression.
    fg_pc = 3328 + 8
    fg_cols = sum(f[c][0] for c in COMPONENTS if c not in BLAKE_COMPONENTS) + 3 + 3328 + 8 * 6 + 45
    fg_child = gkr_comp * fg_pc + gkr_other() + query_cells(fg_cols - today_cols, fg_pc)
    own = sum(r["fused_plus_gkr_cells"] for r in rows)
    tree["fused_k1_plus_gkr"] = {"own": own, "columns": fg_cols, "parent_delta_per_child": fg_child, "total": own + n_child_verifications * fg_child}
    for key, v in tree.items():
        if isinstance(v, dict):
            v["factor_vs_today"] = v["total"] / tree["today"]

    leaves = [r for r in rows if r["kind"] == "leaf"]
    folds = [r for r in rows if r["kind"] == "fold"]
    def tot(rs, key, sub=None):
        return sum((r[key][sub] if sub else r[key]) for r in rs)
    summary = {
        "leaf0_today_M": rows[0]["today_cells"] / 1e6,
        "leaves_today_G": tot(leaves, "today_cells") / 1e9, "folds_today_G": tot(folds, "today_cells") / 1e9,
        "leaves_fused_k1_point_G": sum(r["fused_cells"]["1"]["point"] for r in leaves) / 1e9,
        "leaves_fused_k1_hi_G": sum(r["fused_cells"]["1"]["hi"] for r in leaves) / 1e9,
        "leaves_gkr_per_class_G": sum(r["gkr_cells"]["per_log_class_8"] for r in leaves) / 1e9,
        "leaves_gkr_per_component8_G": sum(r["gkr_cells"]["per_component_8"] for r in leaves) / 1e9,
        "leaves_fused_plus_gkr_G": tot(leaves, "fused_plus_gkr_cells") / 1e9,
    }
    out = {"schema": "rv64-m4-diet-census-v1", "block": 24628607, "labels": {
        "today_cells": "[M] census-v2 row logs x component_list widths",
        "fused_cells.k1": "[M] row shape (Zig test) x [D] compressions (point = g_fill x 2^logG / 80, clamped into the bounds implied by measured G and triple_xor logs)",
        "fused_cells.k>1": "[D] analytic multi-row layout from the measured per-G shape (40 main, 16 lookups) + per-row overheads",
        "gkr_cells": "[D] main unchanged + 2 secure binding columns (eq, weighted prefix) per log class or per component",
        "gkr_verify_cells_per_child": "[M] in-circuit GKR verifier counts at the production shape (affine law fitted on 5 scaled shapes, exact on 2 held out) x component widths",
        "parent deltas": "[D] per verified child: queries x delta columns / 16 compressions x cells per compression, + [E] DEEP qm31 rows per column per query"},
        "per_compression": per_comp, "parent_side": parent, "gkr_measured_rows": measured_rows, "gkr_fit_production": gkr_fit, "gkr_binding_all": binding,
        "summary": summary, "tree": tree, "nodes": rows}
    Path(a.out).write_text(json.dumps(out, indent=1))
    print(json.dumps({"per_compression": per_comp, "parent_side": parent, "summary": summary, "tree": tree}, indent=1))


if __name__ == "__main__":
    main()
