#!/usr/bin/env python3
"""[D/E] fold-class recurrence under the default EXACT outer shape: a fold's class = f(its children's classes).
Tree model [E]: leaves in bundle order (CPU ordinals, then truths), 4-ary folds over consecutive nodes, a short tail group kept."""
import importlib.util, json, sys
from pathlib import Path
root = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("cat", root / "scripts/rv64_m9_canon_leaf_catalog.py")
R = int(sys.argv[1]) if len(sys.argv) > 1 else 4
cat = importlib.util.module_from_spec(spec); sys.argv = [sys.argv[0]]; spec.loader.exec_module(cat)
shapes = json.load(open(root / "vectors/reports/rv64-m9-prep/canon-leaf/segment-shapes-15.json"))
widths = cat.rungs_mod.Widths(json.load(open(root / "vectors/reports/rv64-m5-20261104/canon-native/widths-gkr-v3.json")))
segs = cat.segments(shapes)
ct, tt = cat.build_catalog(segs, widths, R)
cat.classify(segs, ct, tt)
def folds(leaves, k=4):
    out, level = [], leaves
    while len(level) > 1:
        nxt = [("F",) + tuple(level[i:i + k]) for i in range(0, len(level), k)]
        out += nxt; level = nxt
    return out
rows = []; seen_leaf = {"exact": set(), "canon": set()}; seen_fold = {"exact": set(), "canon": set()}
for b in cat.BASKET_ORDER:
    mine = sorted([s for s in segs if s["block"] == b], key=lambda s: s["ordinal"])
    r = {"block": b, "leaves": len(mine)}
    for mode, key in (("exact", lambda s: s["exact"]), ("canon", lambda s: s["class"])):
        ls = [key(s) for s in mine]; fs = folds(ls)
        r[mode + "_new_leaf"] = sum(1 for x in set(ls) if x not in seen_leaf[mode]); seen_leaf[mode] |= set(ls)
        r[mode + "_new_fold"] = sum(1 for x in set(fs) if x not in seen_fold[mode]); seen_fold[mode] |= set(fs)
        r["folds"] = len(fs)
    rows.append(r)
tot = lambda k: sum(r[k] for r in rows[1:])
print(json.dumps({"schema": "rv64-m9-canon-leaf-fold-classes/v1", "label": "D on the basket declarations; tree model E (bundle order, 4-ary consecutive folds)",
                  "rungs": R, "per_block": rows, "after_first_block": {k: tot(k) for k in ("folds", "exact_new_fold", "canon_new_fold", "exact_new_leaf", "canon_new_leaf")}}, indent=1))
