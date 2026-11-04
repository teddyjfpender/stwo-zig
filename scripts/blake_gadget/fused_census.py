#!/usr/bin/env python3
"""fused_blake2s_v1 census from STWO_RV64_FUSED_BLAKE=shadow|check producer logs (stream blake-gadget).

  python3 scripts/blake_gadget/fused_census.py LOG [LOG...] --out census.json [--block 24628607]

Reads every `FUSED_BLAKE2S_V1_SHADOW` line (one per outer node MAIN generation). For each node:
  [M] g_rows (padded blake_g_gate rows), compressions the device gather accepted (valid), fused rows of the
      <=3-instance plan, gather/fill/check GPU ns, check violations, component log sizes;
  [D] committed base cells of the node today and with fused_blake2s_v1 replacing blake_g_gate + triple_xor
      + the G-only XOR tables (xor_12/4/7/9), plus the two new split tables.
Committed interaction = 2 x the component-facts interaction columns (OM31 recursion; M4.0 reconciliation,
vectors/reports/rv64-m4-20261104/measure/M40-FINDINGS.md item 8: CPU leaf 304 committed vs 152 facts columns).
Parent-side width (a parent opens every child column at every query) is reported separately [D, first order]:
q x delta_columns / 16 extra compressions per verified child, fused at the v1 per-compression cost; DEEP rows excluded.
Every power-of-two instance is its own component with its own columns, so a child with n instances adds
n x (fused main + committed interaction) columns (review fix: the v1 census counted one instance).
--max-instances N re-plans each node's measured compressions over <= N instances (planInstances, MIN_LOG_ROWS 4);
the default 3 reproduces the logged fused_rows.
"""
import argparse
import json
import re
import statistics

# component_list.zig component_facts, ComponentList order.
COMPONENTS = ["eq", "qm31_ops", "triple_xor", "m_31_to_u_32", "blake_g_gate", "verify_bitwise_xor_8",
              "verify_bitwise_xor_12", "verify_bitwise_xor_4", "verify_bitwise_xor_7", "verify_bitwise_xor_9", "range_check_16"]
MAIN = [4, 12, 20, 4, 52, 2, 16, 1, 1, 1, 1]
INTER = [4, 8, 24, 12, 52, 4, 32, 4, 4, 4, 4]
INTER_COMMIT = 2  # OM31: committed M31 interaction columns per facts column
REMOVED = {"triple_xor", "blake_g_gate", "verify_bitwise_xor_12", "verify_bitwise_xor_4", "verify_bitwise_xor_7", "verify_bitwise_xor_9"}
FUSED_MAIN, FUSED_INTER = 3328, 2752
# Analytic k=2 layout (two rows of 5 rounds per compression), diet README §1 [D]: per compression
# 3,584 main + 2,944 interaction (facts units); per row 1,792 + 1,472.
LAYOUTS = {"k1": (1, FUSED_MAIN, FUSED_INTER), "k2": (2, 3584 // 2, 2944 // 2)}
SPLIT_TABLES = 2 * (1 << 16) * (1 + INTER_COMMIT * 4)
LINE = re.compile(r"FUSED_BLAKE2S_V1_SHADOW (.*)")


def parse(line):
    body = LINE.search(line).group(1)
    logs = re.search(r"logs=\{ ?([0-9, ]+) ?\}", body)
    out = {k: int(v, 0) for k, v in re.findall(r"(\w+)=(0x[0-9a-f]+|-?\d+)(?=\s|$)", body)}
    out["logs"] = [int(x) for x in logs.group(1).split(",")] if logs else None
    return out


def node_cells(logs):
    per = {c: (1 << l) * (m + INTER_COMMIT * i) for c, l, m, i in zip(COMPONENTS, logs, MAIN, INTER)}
    return sum(per.values()), per


def columns_today():
    return sum(MAIN) + INTER_COMMIT * sum(INTER)


def columns_fused(layout="k1", instances=1.0):
    _, main, inter = LAYOUTS[layout]
    kept = sum(m + INTER_COMMIT * i for c, m, i in zip(COMPONENTS, MAIN, INTER) if c not in REMOVED)
    return kept + instances * (main + INTER_COMMIT * inter) + 2 * (1 + INTER_COMMIT * 4)


MIN_LOG_ROWS = 4


def plan_instances(n, max_instances):
    """fused_blake2s_v1.planInstances with MAX_INSTANCES = max_instances: log sizes, largest first."""
    logs, remaining = [], n
    while remaining > 0:
        floor_log = remaining.bit_length() - 1
        if len(logs) + 1 == max_instances or floor_log < MIN_LOG_ROWS:
            logs.append((max(remaining, 1 << MIN_LOG_ROWS) - 1).bit_length())
            return logs
        logs.append(floor_log)
        remaining -= 1 << floor_log
    return logs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("logs", nargs="+")
    ap.add_argument("--out", required=True)
    ap.add_argument("--block")
    ap.add_argument("--queries", type=int, default=108, help="queries per verified child (r1 = 108)")
    ap.add_argument("--layout", choices=sorted(LAYOUTS), default="k1", help="k1 = built v1 [M rows]; k2 = analytic [D]")
    ap.add_argument("--max-instances", type=int, default=3, help="instances per node (v1 MAX_INSTANCES = 3 is what the shadow logged)")
    args = ap.parse_args()
    nodes = []
    for path in args.logs:
        for line in open(path, errors="replace"):
            if "FUSED_BLAKE2S_V1_SHADOW" in line and "logs=" in line:
                nodes.append(parse(line))
    rows = []
    for n in nodes:
        today, per = node_cells(n["logs"])
        k, lmain, linter = LAYOUTS[args.layout]
        plan = plan_instances(n["valid"], args.max_instances)
        fused_rows = sum(1 << l for l in plan)
        if args.max_instances == 3 and fused_rows != n["fused_rows"]:
            raise SystemExit(f"plan mismatch at ordinal {n['ordinal']}: {fused_rows} != logged {n['fused_rows']}")
        fused_own = today - sum(per[c] for c in REMOVED) + k * fused_rows * (lmain + INTER_COMMIT * linter) + SPLIT_TABLES
        g_real = 80 * n["valid"]
        rows.append({
            "ordinal": n["ordinal"], "status": n["status"], "logs": n["logs"],
            "g_rows_padded": n["g_rows"], "compressions": n["valid"], "g_rows_real": g_real,
            "g_padding_share": 1 - g_real / n["g_rows"] if n["g_rows"] else 0,
            "triple_xor_rows_padded": 1 << n["logs"][2], "triple_xor_rows_real_if_blake_only": 8 * n["valid"],
            "fused_rows": fused_rows, "fused_instances": len(plan), "fused_rows_logged": n["fused_rows"],
            "fused_instances_logged": n["instances"],
            "fused_padding_share": 1 - n["valid"] / fused_rows if fused_rows else 0,
            "cells_today": today, "cells_blake_today": sum(per[c] for c in REMOVED),
            "cells_fused_own": fused_own, "own_factor": fused_own / today,
            "gather_ms": n["gather_ns"] / 1e6, "fill_ms": n["fill_ns"] / 1e6, "check_ms": n["check_ns"] / 1e6,
            "check_violations": n["check_violations"], "xor_lookups_counted": n["xor_lookups"],
            "xor_lookups_expected": n["fused_rows"] * (704 + 320 + 320), "wall_ms": n["wall_ns"] / 1e6,
            "parent_extra_cells_as_child": None,
            "scratch_rows": n["scratch_rows"],
        })
    k, lmain, linter = LAYOUTS[args.layout]
    # Each verified child costs the parent q * delta_cols / 16 more compressions (column hashing at each query);
    # delta_cols counts every fused instance of that child. The root (highest ordinal) is verified by nobody.
    root = max(r["ordinal"] for r in rows) if rows else None
    for r in rows:
        if r["ordinal"] == root:
            continue
        delta = columns_fused(args.layout, r["fused_instances"]) - columns_today()
        r["parent_extra_cells_as_child"] = args.queries * delta / 16 * k * (lmain + INTER_COMMIT * linter)
    child_extra = [r["parent_extra_cells_as_child"] for r in rows if r["parent_extra_cells_as_child"] is not None]
    parent_extra_cells = statistics.mean(child_extra) if child_extra else 0
    mean_instances = statistics.mean(r["fused_instances"] for r in rows) if rows else 0
    delta_cols = columns_fused(args.layout, mean_instances) - columns_today()
    total_today = sum(r["cells_today"] for r in rows)
    total_fused = sum(r["cells_fused_own"] for r in rows)
    n_children = len(child_extra)
    summary = {
        "schema": "rv64-m5-blake-gadget-census/v1", "block": args.block, "layout": args.layout, "nodes": len(rows),
        "labels": {"compressions,g_rows,fill_ms,gather_ms,check": "M", "cells": "D (committed base cells from logged log sizes)",
                   "parent_width": "D first order, DEEP rows excluded"},
        "compressions_total": sum(r["compressions"] for r in rows),
        "check_violations_total": sum(r["check_violations"] for r in rows),
        "xor_multiplicity_balance": all(r["xor_lookups_counted"] == r["xor_lookups_expected"] for r in rows),
        "cells_today_total": total_today, "cells_fused_own_total": total_fused,
        "own_factor_tree": total_fused / total_today if total_today else None,
        "max_instances": args.max_instances, "fused_instances_mean": mean_instances,
        "columns_today": columns_today(), "columns_fused": columns_fused(args.layout, mean_instances),
        "columns_fused_delta": delta_cols,
        "parent_queries": args.queries, "parent_extra_cells_per_child": parent_extra_cells, "children": n_children,
        "tree_factor_with_parent_width": (total_fused + sum(child_extra)) / total_today if total_today else None,
        "fill_ms_total": sum(r["fill_ms"] for r in rows), "gather_ms_total": sum(r["gather_ms"] for r in rows),
        "check_ms_total": sum(r["check_ms"] for r in rows), "shadow_wall_ms_total": sum(r["wall_ms"] for r in rows),
        "own_factor_median": statistics.median(r["own_factor"] for r in rows) if rows else None,
        "g_padding_share_mean": statistics.mean(r["g_padding_share"] for r in rows) if rows else None,
        "fused_padding_share_mean": statistics.mean(r["fused_padding_share"] for r in rows) if rows else None,
        "per_node": rows,
    }
    json.dump(summary, open(args.out, "w"), indent=1)
    print(json.dumps({k: v for k, v in summary.items() if k != "per_node"}, indent=1))


if __name__ == "__main__":
    main()
