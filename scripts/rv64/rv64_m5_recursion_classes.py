#!/usr/bin/env python3
"""canon-vk (M5): per-run recursion census from a harness run dir: distinct leaf/fold outer VKs (tree.json authorities),
padded outer shapes (RECURSION_NODE_SHAPE lines), nodes and fold depth, per-kind prep/device medians (pipeline.json).
Usage (pod): python3 scripts/rv64_m5_recursion_classes.py RUN_DIR [RUN_DIR ...]"""
import json, sys, glob, statistics as st
# distinct outer authorities (= circuit VKs) per node kind, from tree.json; shape census lines from producer.stderr
for run in sys.argv[1:]:
    tree = glob.glob(run + "/case/batch/trial-0/*/proof/recursion-om31/tree.json")[0]
    t = json.load(open(tree))
    nodes = t["nodes"]
    def is_leaf(n): return n.get("leaf_count") == 1 and not n.get("children") and n.get("left") is None
    leaves = [n for n in nodes if is_leaf(n)]; folds = [n for n in nodes if not is_leaf(n)]
    out = {"run": run.split("/")[-1], "schema": t.get("schema"), "leaves": len(leaves), "folds": len(folds),
           "distinct_leaf_vks": len({bytes(n["authority"]).hex() if isinstance(n["authority"], list) else n["authority"] for n in leaves}),
           "distinct_fold_vks": len({bytes(n["authority"]).hex() if isinstance(n["authority"], list) else n["authority"] for n in folds})}
    # fold depth: leaf 0, fold 1 + max child depth (binary schema 2: left/right; k-ary schema 3: children)
    depth = {}
    for i, n in enumerate(nodes):
        kids = n.get("children") or [k for k in (n.get("left"), n.get("right")) if k is not None]
        depth[i] = 0 if not kids else 1 + max(depth[k] for k in kids)
    out["nodes"] = len(nodes)
    out["fold_depth"] = depth[t["root"]]
    shapes = {"leaf": set(), "fold": set()}
    try:
        for line in open(run + "/case/producer.stderr", errors="replace"):
            if line.startswith("RECURSION_NODE_SHAPE"):
                kv = dict(x.split("=", 1) for x in line.split()[1:])
                shapes[kv["kind"]].add(kv["padded"])
        out["distinct_padded_shapes"] = {k: len(v) for k, v in shapes.items()}
    except FileNotFoundError:
        pass
    p = glob.glob(run + "/case/batch/trial-0/*/proof/recursion-om31/pipeline.json")
    if p:
        d = json.load(open(p[0]))
        for kind in ("leaf", "fold"):
            ns = [n for n in d["nodes"] if n["kind"] == kind]
            if ns:
                out[kind + "_prep_med_s"] = round(st.median((n["stamps"]["prep_end"] - n["stamps"]["prep_start"]) / 1e9 for n in ns), 3)
                out[kind + "_graph_med_s"] = round(st.median(n["graph_ns"] / 1e9 for n in ns), 3)
                out[kind + "_device_med_s"] = round(st.median((n["stamps"]["device_end"] - n["stamps"]["device_start"]) / 1e9 for n in ns), 3)
                out[kind + "_device_sum_s"] = round(sum((n["stamps"]["device_end"] - n["stamps"]["device_start"]) / 1e9 for n in ns), 2)
        out["dag_wall_s"] = round(d["dag_wall_ns"] / 1e9, 2)
        out["occupancy"] = round(d["lane_device_stage_occupancy"], 3)
    print(json.dumps(out))
