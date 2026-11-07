#!/usr/bin/env python3
"""M9 recursion-arch: padding-aware recursion-tree cost of the per-child verifier levers.

Inputs (all committed):
  * vectors/reports/rv64-m9-prep/m9-recursion-arch/census.jsonl  [M] exact per-child verifier rows by phase and PCS
    variant (zig build test-riscv64-m9-recursion-census; production rows pinned to the unmodified V.verify).
  * scripts/rv64_m9_leaf_fanin_model.py (vendored unchanged from codex/rv64-m9-fewer-leaves a056cee67): native
    verification rows per class [M], fold-child rows per child log [D], the leaf fan-in DP, padded-cell accounting.

Model [D on M]: a fold child's verification rows are CHILD[log] (measured, includes table admission and summary
binding) times the census ratio of the variant to production, per component. A batch of B sibling proofs costs the
census batch-B rows. Padded cells = sum width * 2^ceil(log2 rows) + fixed tables, exactly as the fan-in model. Fold
arity is re-optimised per variant (a cheaper child leaves a 4-ary fold half empty at 2^23): the arity that minimises
the basket's padded cells with every fold inside today's envelope (all components <= 2^23 with 3% margin,
<= 2.2 G cells). Recursion kernel GPU-s are proportional to padded cells (0.262 ns/cell, fan-in calibration) [D].

  python3 -I scripts/rv64_m9/recursion_arch_model.py --out vectors/reports/rv64-m9-prep/m9-recursion-arch/model.json
"""
import argparse
import importlib.util
import json
import math
import os

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_spec = importlib.util.spec_from_file_location("fanin", os.path.join(ROOT, "scripts/rv64_m9_leaf_fanin_model.py"))
FL = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(FL)
CENSUS = os.path.join(ROOT, "vectors/reports/rv64-m9-prep/m9-recursion-arch/census.jsonl")
CHILD_BASE = {k: list(v) for k, v in FL.CHILD.items()}
NATIVE_BASE = {k: list(v) for k, v in FL.NATIVE.items()}
RK = 0.262e-9  # kernel GPU-s per padded recursion cell (fan-in calibration, rv64-m9-fewer-leaves.md s2.3) [D]
P2_CAP_CELLS = 2.2e9  # post-P1 per-job cell cap (~13 GB); a batch job holds all its circuits [E, fewer-leaves s3]


def load(path=CENSUS):
    rows = [json.loads(l) for l in open(path)]
    meta = rows[0]
    by = {(r["child"], r["variant"]): r for r in rows[1:]}
    return meta, by


META, BY = load() if os.path.exists(CENSUS) else (None, {})


def per_child(child, variant):
    r = BY[(child, variant)]
    return [x / r["batch"] for x in r["total"][:5]]


def ratio(variant, child="fold4_log23"):
    """Per-component rows of one child under `variant` / production [M]."""
    base = per_child(child, "prod_b2_q108_p20_f4_cap3")
    got = per_child(child, variant)
    return [g / b for g, b in zip(got, base)]


def ratio_log(variant, log):
    child = "pair_leaf_log24" if log >= 24 and ("pair_leaf_log24", variant) in BY else "fold4_log23"
    return ratio(variant, child)


# Lever sets: name -> (census variant per batch size, batch size B, description). Batch 1 = one proof per circuit.
DIET = "combo_q102_p26_blake3_coset_ll4"
LEVERS = {
    "prod": ({1: "prod_b2_q108_p20_f4_cap3"}, 1, "production outer profile m6 k4 cap3 (b2 q108 p20 fold4)"),
    "pow26": ({1: "b2_q102_p26_f4_cap3"}, 1, "q108/P20 -> q102/P26 (1*102+26 = 128 conjectured)"),
    "pow28": ({1: "b2_q100_p28_f4_cap3"}, 1, "q100/P28"),
    "coset": ({1: "cosetleaf_cap3"}, 1, "FRI leaf = whole 16-value coset"),
    "ll4": ({1: "b2_q108_p20_f4_cap3_ll4"}, 1, "FRI last layer 2^4 coefficients"),
    "ll8": ({1: "b2_q108_p20_f4_cap3_ll8"}, 1, "FRI last layer 2^8 coefficients"),
    "blake3": ({1: "blake3_cap3"}, 1, "Blake3 (7-round) outer commitments, Blake2s channel"),
    "diet": ({1: DIET}, 1, "q102/P26 + Blake3 outer commitments + coset leaves + last layer 2^4"),
    "diet_ll8": ({1: "combo_q102_p26_blake3_coset_ll8"}, 1, "diet with last layer 2^8 (opt)"),
    "diet_noblake3": ({1: "cosetleaf_ll4_cap3"}, 1, "coset leaves + last layer 2^4 (no hash change; pow26 separate)"),
    "batch2": ({1: "prod_b2_q108_p20_f4_cap3", 2: "batch2_cap3"}, 2, "sibling pairs proven as one outer proof"),
    "batch4": ({1: "prod_b2_q108_p20_f4_cap3", 2: "batch2_cap3", 3: "batch3_cap3", 4: "batch4_cap3"}, 4, "sibling quads as one proof"),
    "batch2_diet": ({1: DIET, 2: "batch2_combo_ll4"}, 2, "diet + sibling pairs as one proof"),
    "batch4_diet": ({1: DIET, 2: "batch2_combo_ll4", 3: "batch3_combo_ll4", 4: "batch4_combo_ll4"}, 4, "diet + sibling quads as one proof"),
}


def lever_ratio(lever, b, log):
    vmap = LEVERS[lever][0]
    if b in vmap and (("fold4_log23", vmap[b]) in BY):
        return ratio_log(vmap[b], log)
    # missing batch size: linear in b between measured neighbours [D]
    lo = max(k for k in vmap if k < b)
    hi = min((k for k in vmap if k > b), default=None)
    rl = ratio_log(vmap[lo], log)
    if hi is None:
        return rl
    rh = ratio_log(vmap[hi], log)
    t = (b - lo) / (hi - lo)
    return [x + t * (y - x) for x, y in zip(rl, rh)]


def child_rows(lever, log, b=1):
    """Rows of verifying one child (of a batch of b) whose largest padded log is `log` [D on M]."""
    log = min(24, max(19, log))
    r = lever_ratio(lever, b, log)
    return [x * y for x, y in zip(CHILD_BASE[log], r)]


def build(block, lever="prod", kmax=1, cap_log="env23", arity=4, batch=None, batch_levels="all", native_scale=None,
          homogeneous="class", margin=0.03):
    """Leaves from the fan-in DP (kmax=1: one native per leaf), then the streaming k-ary carry of ready_dag with
    fold rows = sum over child batches of the batch's verification rows. batch_levels: 'all' or 'leaves' (only
    leaf children are batched; folds keep one proof each)."""
    B = LEVERS[lever][1] if batch is None else batch
    saved_native = FL.NATIVE
    saved_child = FL.CHILD
    try:
        if native_scale:
            FL.NATIVE = {k: [x * s for x, s in zip(v, native_scale)] for k, v in NATIVE_BASE.items()}
        # the grouping DP prices a group's parent cost with CHILD: use this lever's single-proof child rows
        FL.CHILD = {log: child_rows(lever, log, 1) for log in CHILD_BASE}
        items = FL.natives(block)
        if kmax <= 1:
            groups = [(i, 1) for i in range(len(items))]
        else:
            groups = FL.group_leaves(items, kmax, "blake23", margin, homogeneous)
        leaves = []
        for ordinal, (first, count) in enumerate(groups):
            rows = [0] * 5
            for item in items[first:first + count]:
                rows = FL.add(rows, FL.NATIVE[item])
            leaves.append(FL.Node("leaf", ordinal, 1, [], rows, count))
    finally:
        FL.NATIVE = saved_native
        FL.CHILD = saved_child
    nodes = []

    def parent(group):
        kids = [nodes[g] for g in group]
        rows = [0] * 5
        i = 0
        while i < len(kids):
            leafs = kids[i].kind == "leaf"
            take = B if (batch_levels == "all" or leafs) else 1
            batch_kids = [kids[i]]
            while len(batch_kids) < take and i + len(batch_kids) < len(kids) and (kids[i + len(batch_kids)].kind == "leaf") == leafs:
                batch_kids.append(kids[i + len(batch_kids)])
            for k in batch_kids:
                rows = FL.add(rows, child_rows(lever, k.log, len(batch_kids)))
            i += len(batch_kids)
        node = FL.Node("fold", kids[0].first, sum(k.count for k in kids), list(group), rows, sum(k.natives for k in kids))
        nodes.append(node)
        return len(nodes) - 1

    stack = [[None] * arity for _ in range(16)]
    depth = [0] * 16
    for leaf in leaves:
        nodes.append(leaf)
        current = len(nodes) - 1
        level = 0
        while depth[level] + 1 == arity:
            current = parent(stack[level][:arity - 1] + [current])
            depth[level] = 0
            level += 1
        stack[level][depth[level]] = current
        depth[level] += 1
    carry = None
    for level in range(16):
        group = stack[level][:depth[level]] + ([carry] if carry is not None else [])
        if len(group) == 1:
            carry = group[0]
        elif len(group) >= 2:
            carry = parent(group)
    root = carry
    folds = [n for n in nodes if n.kind == "fold"]
    fold_ok = all(FL.fits(n.rows, cap_log, margin) for n in folds)
    d = FL.depths(nodes, root)
    # batch jobs: a fold's children batched together are proven by ONE job holding all of them
    max_job = 0.0
    if B > 1:
        for f in folds:
            kids = [nodes[c] for c in f.children]
            i = 0
            while i < len(kids):
                leafs = kids[i].kind == "leaf"
                take = B if (batch_levels == "all" or leafs) else 1
                grp = [kids[i]]
                while len(grp) < take and i + len(grp) < len(kids) and (kids[i + len(grp)].kind == "leaf") == leafs:
                    grp.append(kids[i + len(grp)])
                max_job = max(max_job, sum(k.cells for k in grp))
                i += len(grp)
    max_job = max(max_job, max(n.cells for n in nodes))
    tax = sum(FL.COMP_TAX_CELLS * ((1 << n.log) - (1 << 23)) / (1 << 23) for n in nodes if n.log > 23)
    return dict(cells=sum(n.cells for n in nodes), log24_tax_cells=tax, log24_nodes=sum(1 for n in nodes if n.log > 23), leaf_cells=sum(n.cells for n in leaves), fold_cells=sum(n.cells for n in folds),
                unpadded=sum(FL.unpadded(n.rows) + FL.FIXED_CELLS for n in nodes),
                leaves=len(leaves), folds=len(folds), nodes=len(nodes), depth=max(d) if d else 0, fold_ok=fold_ok,
                max_fold_shape=FL.shape(max(folds, key=lambda n: n.cells).rows) if folds else None,
                max_job_cells=max_job)


def best_arity(lever, kmax, blocks, batch_levels="all", native_scale=None, arities=range(2, 17), fold_cap="env23"):
    """One profile-constant fold arity for the basket: min total padded cells with every fold inside the envelope."""
    best = None
    for a in arities:
        res = {b: build(b, lever, kmax, cap_log=fold_cap, arity=a, batch_levels=batch_levels, native_scale=native_scale) for b in blocks}
        if not all(r["fold_ok"] for r in res.values()):
            continue
        tot = sum(r["cells"] for r in res.values())
        if best is None or tot < best[1]:
            best = (a, tot, res)
    return best


SCENARIOS = {
    # name: (lever, kmax, batch_levels, native_scale_key, re-arity)
    "post_m8": ("prod", 1, "all", None, False),
    "fanin": ("prod", 4, "all", None, False),
}


def native_blake3_scale():
    """[E] natives committed with Blake3 too (a NATIVE proof-format change): scale native-verification rows by the
    measured per-component Blake3 ratio of the outer child's Merkle/FRI phases; the native channel stays Blake2s."""
    return ratio("blake3_cap3")


def run(out=None):
    blocks = [r[0] for r in FL.BASKET]
    focus = (26235168, 26235159, 24628607)
    res = dict(labels="M measured (census.jsonl), D derived (this model on M), E estimate", census_meta=META,
               per_child={}, trees={}, factors={})
    for lever in LEVERS:
        r = ratio(LEVERS[lever][0][max(LEVERS[lever][0])])
        base = per_child("fold4_log23", "prod_b2_q108_p20_f4_cap3")
        v = LEVERS[lever][0][max(LEVERS[lever][0])]
        res["per_child"][lever] = dict(variant=v, batch=LEVERS[lever][1], description=LEVERS[lever][2],
                                       unpadded_cells_per_child=sum(w * x for w, x in zip(FL.WIDTH, per_child("fold4_log23", v))),
                                       ratio_unpadded=sum(w * x for w, x in zip(FL.WIDTH, per_child("fold4_log23", v))) / sum(w * x for w, x in zip(FL.WIDTH, base)),
                                       component_ratio=r)
    configs = []
    for tree, kmax in (("post_m8", 1), ("fanin", 4)):
        configs.append((tree, "prod", kmax, "all", None, [4]))
        for lever in ("pow26", "pow28", "coset", "ll4", "ll8", "blake3", "diet_noblake3", "diet", "diet_ll8"):
            configs.append((tree, lever, kmax, "all", None, None))
        for lever in ("batch2", "batch4", "batch2_diet", "batch4_diet"):
            configs.append((tree, lever, kmax, "leaves", None, None))
            configs.append((tree, lever, kmax, "all", None, None))
        configs.append((tree, "diet+native_blake3", kmax, "all", "nb3", None))
    for (tree, lever, kmax, levels, nat, arities), fold_cap in [(c, f) for c in configs for f in ("env23", "blake23")]:
        lv = "diet" if lever == "diet+native_blake3" else lever
        ns = native_blake3_scale() if nat == "nb3" else None
        best = best_arity(lv, kmax, blocks, levels, ns, arities or range(2, 17), fold_cap)
        if best is None:
            continue
        a, tot, per = best
        key = "%s/%s/%s%s" % (tree, fold_cap, lever, "" if LEVERS[lv][1] == 1 else "/" + levels)
        res["trees"][key] = dict(arity=a, basket_cells=tot,
                                 blocks={str(b): {k: (round(v, 0) if isinstance(v, float) else v) for k, v in per[b].items()} for b in blocks})
    for key, t in res["trees"].items():
        tree = key.split("/")[0]
        base = res["trees"]["%s/env23/prod" % tree]
        t["factor_basket"] = t["basket_cells"] / base["basket_cells"]
        t["factor"] = {b: t["blocks"][b]["cells"] / base["blocks"][b]["cells"] for b in t["blocks"]}
        # with the unvalidated log-24 composition/FRI tax of fewer-leaves review r1 on both sides [E]
        t["factor_taxed"] = {b: (t["blocks"][b]["cells"] + t["blocks"][b]["log24_tax_cells"]) / (base["blocks"][b]["cells"] + base["blocks"][b]["log24_tax_cells"]) for b in t["blocks"]}
        t["delta_rec_gpu_s"] = {str(b): RK * (t["blocks"][str(b)]["cells"] - base["blocks"][str(b)]["cells"]) for b in focus}
        t["max_job_post_p1_ok"] = max(v["max_job_cells"] for v in t["blocks"].values()) <= P2_CAP_CELLS * 1.0001
    res["factors"] = {k: dict(arity=v["arity"], basket=round(v["factor_basket"], 4),
                              p50_26235168=round(v["factor"]["26235168"], 4), p95_26235159=round(v["factor"]["26235159"], 4),
                              k607=round(v["factor"]["24628607"], 4),
                              p50_taxed=round(v["factor_taxed"]["26235168"], 4), p95_taxed=round(v["factor_taxed"]["26235159"], 4),
                              basket_taxed=round(sum(b["cells"] + b["log24_tax_cells"] for b in v["blocks"].values()) / sum(b["cells"] + b["log24_tax_cells"] for b in res["trees"][k.split("/")[0] + "/env23/prod"]["blocks"].values()), 4),
                              log24_nodes_26235168=v["blocks"]["26235168"]["log24_nodes"], max_job_g=round(max(b["max_job_cells"] for b in v["blocks"].values()) / 1e9, 2),
                              job_fits_post_p1=v["max_job_post_p1_ok"],
                              nodes_26235168=v["blocks"]["26235168"]["nodes"], depth_26235168=v["blocks"]["26235168"]["depth"])
                      for k, v in res["trees"].items()}
    if out:
        os.makedirs(os.path.dirname(out), exist_ok=True)
        json.dump(res, open(out, "w"), indent=1, sort_keys=True)
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    a = ap.parse_args()
    res = run(a.out)
    print("per-child verifier cost of a log-23 recursion child [M]:")
    for k, v in res["per_child"].items():
        print("  %-14s %-34s B=%d  %6.1f M cells/child  x%.3f" % (k, v["variant"], v["batch"], v["unpadded_cells_per_child"] / 1e6, v["ratio_unpadded"]))
    print("\npadded recursion cells vs the same tree at production [D] (arity re-optimised; job = cells of one prover job):")
    for k, v in res["factors"].items():
        print("  %-40s arity %2d  basket x%.3f (taxed %.3f)  168 x%.3f (%.3f)  159 x%.3f (%.3f)  607 x%.3f  nodes168 %3d depth %d log24 %2d  max job %.2f G %s"
              % (k, v["arity"], v["basket"], v["basket_taxed"], v["p50_26235168"], v["p50_taxed"], v["p95_26235159"], v["p95_taxed"], v["k607"],
                 v["nodes_26235168"], v["depth_26235168"], v["log24_nodes_26235168"], v["max_job_g"], "" if v["job_fits_post_p1"] else "(> post-P1 cap)"))


if __name__ == "__main__":
    main()
