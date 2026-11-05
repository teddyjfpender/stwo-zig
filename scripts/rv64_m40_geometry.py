#!/usr/bin/env python3
"""M4.0 item 5: native geometry distribution over the 15 M3 receipts + canonical-rung padding-tax model.

Reads (read-only) the bundle.json of every M3 scale-up run on the pod and writes one JSON:
  - per block: proofs, distinct geometry classes, per-component log histograms;
  - basket-wide: distinct classes per family, log histograms;
  - rung tax: for R in {1,2,3,4} canonical heights per (family, component), chosen optimally over the
    basket (exact DP over the observed logs, minimising padded rows), the padded-row tax vs today's
    per-proof power-of-two heights.  Width-agnostic per component (rows), and an aggregate weighted by
    a per-component width vector when given (--widths JSON), else by rows only.

  python3 scripts/rv64_m40_geometry.py --runs /workspace/m3/runs/integrate --out geometry.json
"""
import argparse
import json
from pathlib import Path

CPU_FIELDS = ["cpu_log", "alu_log", "alu_tail_log", "binary_log", "binary_tail_log", "shift_log", "shift_tail_log", "jalr_log",
              "division_log", "multiplication_log", "ls_log", "ls_tail_log", "boundary_log", "initial_log", "terminal_log"]


def flatten_bridges(bridges, prefix="bridge."):
    out = {}
    for k, v in (bridges or {}).items():
        if isinstance(v, dict):
            out.update(flatten_bridges(v, prefix + k + "."))
        elif v is not None:
            out[prefix + k] = v
    return out


SPLIT_BOUNDARY = False


def proofs_of(bundle):
    rows = []
    for i, cpu in enumerate(bundle["cpus"]):
        g = cpu["declaration"]["geometry"]
        comps = {k: g[k] for k in CPU_FIELDS if g.get(k) is not None}
        comps.update(flatten_bridges(cpu["declaration"].get("bridges")))
        family = "cpu"
        if SPLIT_BOUNDARY:
            family = "cpu:first" if i == 0 else "cpu:last" if i == len(bundle["cpus"]) - 1 else "cpu:middle"
        rows.append({"family": family, "index": i, "components": comps, "steps": cpu["request"]["cpu"]["steps"]})
    for i, t in enumerate(bundle["truths"]):
        d = t["declaration"]
        rows.append({"family": "truth:" + d["family"], "index": i, "components": {"main": d["logs"][0]}, "calls": d["calls"], "aux": d["logs"][1:]})
    return rows


def best_rungs(logs_with_counts, r):
    """Choose <= r rung heights (subset of observed logs, must include the max) minimising padded rows.

    Each proof's log is padded up to the smallest rung >= it. Exact DP over sorted distinct logs."""
    items = sorted(logs_with_counts.items())  # [(log, count)]
    n = len(items)
    if n == 0:
        return [], 0, 0
    real = sum(c * 2**l for l, c in items)
    inf = float("inf")
    # cost(i, j): all items i..j padded to items[j].log
    def cost(i, j):
        return sum(c for _, c in items[i:j + 1]) * 2**items[j][0]
    dp = [[inf] * (r + 1) for _ in range(n + 1)]
    choice = [[None] * (r + 1) for _ in range(n + 1)]
    dp[0] = [0] * (r + 1)
    for j in range(1, n + 1):
        for k in range(1, r + 1):
            for i in range(1, j + 1):
                v = dp[i - 1][k - 1] + cost(i - 1, j - 1)
                if v < dp[j][k]:
                    dp[j][k] = v
                    choice[j][k] = i - 1
    k = min(r, n)
    padded = min(dp[n][kk] for kk in range(1, k + 1))
    kk = min(range(1, k + 1), key=lambda x: dp[n][x])
    rungs, j = [], n
    while j > 0 and kk > 0:
        i = choice[j][kk]
        rungs.append(items[j - 1][0])
        j, kk = i, kk - 1
    return sorted(rungs), real, padded


def vector_rungs(vectors, r):
    """Canonical *class* rungs (what a constant-log-size canonical leaf needs): each proof of a family is
    padded to one of <= r component-wise log vectors. Proofs sorted by today's rows; contiguous groups
    (exact DP over that order) are padded to the group's component-wise max. Rows-weighted."""
    keys = sorted({k for v in vectors for k in v})
    rows = lambda v: sum(2**v.get(k, 0) for k in keys if k in v)
    vs = sorted(vectors, key=rows)
    n = len(vs)
    real = sum(rows(v) for v in vs)
    def group_cost(i, j):
        m = {k: max(v[k] for v in vs[i:j + 1] if k in v) for k in keys if any(k in v for v in vs[i:j + 1])}
        return (j - i + 1) * sum(2**l for l in m.values()), m
    inf = float("inf")
    dp = [[inf] * (r + 1) for _ in range(n + 1)]
    back = [[None] * (r + 1) for _ in range(n + 1)]
    dp[0] = [0] * (r + 1)
    for j in range(1, n + 1):
        for k in range(1, r + 1):
            for i in range(1, j + 1):
                c, _ = group_cost(i - 1, j - 1)
                if dp[i - 1][k - 1] + c < dp[j][k]:
                    dp[j][k] = dp[i - 1][k - 1] + c
                    back[j][k] = i - 1
    kk = min(range(1, min(r, n) + 1), key=lambda x: dp[n][x])
    padded = dp[n][kk]
    groups, j = [], n
    while j > 0 and kk > 0:
        i = back[j][kk]
        _, m = group_cost(i, j - 1)
        groups.append({"proofs": j - i, "rung": m})
        j, kk = i, kk - 1
    return {"rows_real_pow2": real, "rows_padded": padded, "tax": round(padded / real - 1, 4) if real else 0, "classes": groups[::-1]}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--runs", default="/workspace/m3/runs/integrate")
    parser.add_argument("--out", required=True)
    parser.add_argument("--summary", help="M3 summary.json: use its accepted run per block (25229951 is a diag-idle0 run)")
    parser.add_argument("--split-boundary", action="store_true", help="CPU first/middle/last segments as separate families")
    args = parser.parse_args()
    global SPLIT_BOUNDARY
    SPLIT_BOUNDARY = args.split_boundary
    runs = Path(args.runs)
    blocks = {}
    found = sorted(runs.glob("*-2gpu-scale"))
    if args.summary:
        found = [Path(r["run"]) for r in json.load(open(args.summary))["rows"]]
    for run in found:
        block = run.name.split("-")[0]
        bundle = run / "case/batch/trial-0" / block / "proof/bundle.json"
        if bundle.is_file():
            blocks[int(block)] = proofs_of(json.load(open(bundle)))
    per_block = {}
    basket_hist = {}
    classes_all = {}
    for block, proofs in sorted(blocks.items()):
        classes = {}
        for p in proofs:
            key = (p["family"], tuple(sorted(p["components"].items())))
            classes[key] = classes.get(key, 0) + 1
            classes_all[key] = classes_all.get(key, 0) + 1
            for comp, log in p["components"].items():
                h = basket_hist.setdefault(p["family"], {}).setdefault(comp, {})
                h[log] = h.get(log, 0) + 1
        per_block[block] = {"proofs": len(proofs), "cpu": sum(p["family"] == "cpu" for p in proofs), "truth": sum(p["family"] != "cpu" for p in proofs),
                            "distinct_geometry_classes": len(classes),
                            "families": sorted({p["family"] for p in proofs})}
    tax = {}
    for r in (1, 2, 3, 4):
        fam_rows = {}
        comps = {}
        for family, hist in basket_hist.items():
            for comp, h in hist.items():
                rungs, real, padded = best_rungs(h, r)
                comps[f"{family}/{comp}"] = {"rungs": rungs, "rows_real_pow2": real, "rows_padded": padded, "tax": round(padded / real - 1, 4) if real else 0}
                f = fam_rows.setdefault(family, [0, 0])
                f[0] += real
                f[1] += padded
        rung_of = {}
        for key, c in comps.items():
            rung_of[key] = c["rungs"]
        padded_classes = {}
        for proofs in blocks.values():
            for p in proofs:
                vecp = []
                for comp, log in sorted(p["components"].items()):
                    rs = rung_of[f"{p['family']}/{comp}"]
                    vecp.append((comp, min(x for x in rs if x >= log)))
                padded_classes.setdefault(p["family"], set()).add(tuple(vecp))
        tax[str(r)] = {"distinct_padded_classes": {f: len(v) for f, v in padded_classes.items()},
                       "distinct_padded_classes_total": sum(len(v) for v in padded_classes.values()),
                       "per_family_rows_tax": {f: round(p / q - 1, 4) for f, (q, p) in fam_rows.items()},
                       "all_rows_tax": round(sum(p for _, p in fam_rows.values()) / sum(q for q, _ in fam_rows.values()) - 1, 4),
                       "components": comps}
    vec = {}
    by_family = {}
    for proofs in blocks.values():
        for p in proofs:
            by_family.setdefault(p["family"], []).append(p["components"])
    for r in (1, 2, 3, 4):
        fams = {f: vector_rungs(v, r) for f, v in by_family.items()}
        real = sum(x["rows_real_pow2"] for x in fams.values())
        vec[str(r)] = {"all_rows_tax": round(sum(x["rows_padded"] for x in fams.values()) / real - 1, 4), "per_family": fams,
                       "native_classes": sum(len(x["classes"]) for x in fams.values())}
    out = {"schema": "rv64-m40-geometry/v1", "label": "D (arithmetic on measured M3 bundles)",
           "scope": "native proofs of the 15 M3 scale-up runs (bundle.json declarations). Rows = 2^log per component per proof; "
                    "today every component is already padded to its own power of two, so 'tax' is the extra padded rows a canonical rung set "
                    "would add on top of today's pow2 padding. Width-agnostic (each component's tax is width-independent within a family; "
                    "family/all aggregates weight components by rows, NOT cells).",
           "blocks": per_block, "basket": {"proofs": sum(len(v) for v in blocks.values()), "distinct_geometry_classes": len(classes_all),
                                            "distinct_classes_per_family": {}, "log_histograms": basket_hist},
           "rung_tax_per_component": tax, "rung_tax_class_vectors": vec}
    for (family, _), _ in classes_all.items():
        out["basket"]["distinct_classes_per_family"][family] = out["basket"]["distinct_classes_per_family"].get(family, 0) + 1
    Path(args.out).write_text(json.dumps(out, indent=1, default=str))
    print(json.dumps({"blocks": len(blocks), "proofs": out["basket"]["proofs"], "classes": len(classes_all),
                      "tax_rows_per_component": {r: (tax[r]["all_rows_tax"], tax[r]["distinct_padded_classes_total"]) for r in tax},
                      "tax_rows_class_vectors": {r: (vec[r]["all_rows_tax"], vec[r]["native_classes"]) for r in vec},
                      "class_vectors_r3_per_family": {f: x["tax"] for f, x in vec["3"]["per_family"].items()}}, indent=1))


if __name__ == "__main__":
    main()
