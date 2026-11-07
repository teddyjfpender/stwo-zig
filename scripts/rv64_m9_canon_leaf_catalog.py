#!/usr/bin/env python3
"""M9 canon-leaf: canonical leaf classes (shape catalog) for the 15-block basket.

Reads the per-segment declarations of the 15 basket blocks (vectors/reports/rv64-m9-prep/canon-leaf/segment-shapes-15.json,
copied from the M3 accepted bundles) and answers, with arithmetic only [D]:

  1. exact     : how many leaf classes exist today (a leaf circuit is a function of its declaration, rootverify leafKey premise);
  2. v1 table  : does the frozen canon-native v1 rung table (ethereum/canon_native_rungs.zig, R=4, derived from 14 blocks; 25229951
                 was not in it) cover every segment under the STRICT roster rule (plan.zig canonFitStrict, with the pair counts
                 bounded from the declaration's own capacity, i.e. conservative);
  3. catalog   : the catalog this stream proposes (per (family, cpu_log) contiguous DP rungs on cells, strict roster, plus one
                 envelope rung per family), for R = 1..8: number of classes, padding tax, and leave-one-block-out coverage;
  4. service   : a different-blocks warm service (each block once, basket order) - leaf class misses per block, exact vs canonical.

Reuses scripts/rv64_m5_canon_rungs.py (proofs_of, Widths, cost, group_memo, group_rungs) and rv64_m5_canon_native_ref.py.
Writes the receipt JSON (--out) and optionally the Zig catalog table (--zig) consumed by rv64_recursion/canon_leaf.zig.

  python3 scripts/rv64_m9_canon_leaf_catalog.py --shapes vectors/reports/rv64-m9-prep/canon-leaf/segment-shapes-15.json \
      --widths vectors/reports/rv64-m5-20261104/canon-native/widths-gkr-v3.json --out catalog.json [--zig canon_leaf_catalog.zig] [--rungs 4]
"""
import argparse
import importlib.util
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent


def _load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


rungs_mod = _load("rungs", "rv64_m5_canon_rungs.py")
ref = rungs_mod.ref
COMP = ref.CPU_COMPONENTS  # 41 frozen component ids
IDX = {c: i for i, c in enumerate(COMP)}
# plan.zig PAIRS (head, tail, reserve): alu, binary, shift, ls, ls_dword.
PAIRS = [(1, 2, 0), (3, 4, 0), (5, 6, 0), (10, 11, 1), (38, 39, 1)]
PAIRED = {h for h, _, _ in PAIRS} | {t for _, t, _ in PAIRS}
BASKET_ORDER = [26235156, 24647140, 24628607, 25229957, 24628608, 24626900, 24697073, 24697070, 26235168, 25229955,
                25229951, 24628590, 24628595, 24628611, 26235159]  # bench15 order (ascending segments)


def vec_of(comps):
    return [comps.get(c, 0) for c in COMP]


def segments(shapes):
    """Every leaf of the basket: CPU (family by position, 41-vector, flags) and truth (family, aux, log)."""
    out = []
    for block, v in shapes["blocks"].items():
        bundle = {"cpus": [{"declaration": d} for d in v["cpus"]], "truths": [{"declaration": d} for d in v["truths"]]}
        proofs = rungs_mod.proofs_of(bundle)
        n = len(v["cpus"])
        for i, p in enumerate(proofs):
            p["block"] = int(block)
            if i < n:
                d = v["cpus"][i]
                p["kind"] = "cpu"
                p["ordinal"] = i
                p["vec"] = vec_of(p["comps"])
                p["omit_div"] = bool(d["geometry"].get("omit_empty_division"))
                p["exact"] = json.dumps(d, sort_keys=True)
                p["dword_layout"] = any(c["bridges"].get("ls_dword") is not None for c in v["cpus"])
            else:
                d = v["truths"][i - n]
                p["kind"] = "truth"
                p["ordinal"] = i
                p["log"] = d["logs"][0]
                p["exact"] = json.dumps({"family": d["family"], "logs": d["logs"]}, sort_keys=True)
            out.append(p)
    return out


def pair_capacity(head, tail, reserve):
    if head == 0:
        return 0
    return (1 << head) - reserve + (((1 << tail) - reserve) if tail else 0)


def strict_fit(seg, rung):
    """plan.zig canonFitStrict on a declaration (pair counts bounded by the declaration's own capacity: conservative)."""
    a = seg["vec"]
    for c, (x, r) in enumerate(zip(a, rung)):
        if c in PAIRED:
            continue
        if c in (0, 12):
            if r != x:
                return "cpu_log" if c == 0 else "boundary_log"
            continue
        if c == 8 and seg["omit_div"]:
            if r == 0:
                return "division_absent"
            continue
        if x != 0 and (r == 0 or r < x):
            return COMP[c]
    for h, t, res in PAIRS:
        if rung[h] == 0:
            if a[h] != 0:
                return COMP[h]
            continue
        if h == 38 and not seg["dword_layout"]:
            return "ls_dword_layout"
        if pair_capacity(a[h], a[t], res) > pair_capacity(rung[h], rung[t], res):
            return COMP[h]
    return None


def cpu_class(seg, table):
    """First (smallest) strict-fitting rung of the segment's family, or (None, reasons)."""
    reasons = []
    for r, rung in enumerate(table.get(seg["family"], [])):
        why = strict_fit(seg, rung)
        if why is None:
            return r, None
        reasons.append(why)
    return None, reasons or ["family_missing"]


def truth_class(seg, table):
    for r, log in enumerate(table.get((seg["family"], seg["aux"]), [])):
        if log >= seg["log"]:
            return r, None
    return None, ["truth_log"]


def parse_v1(path):
    """ethereum/canon_native_rungs.zig -> ({family: [vector]}, {(family, aux): [log]})."""
    text = Path(path).read_text()
    cpu, truth = {}, {}
    names = {v: k for k, v in ref.FAMILY_NAMES.items()}
    names.update({"truth_" + n: ref.TRUTH_BASE + i for i, n in enumerate(ref.TRUTH_NAMES)})
    for m in re.finditer(r"\.family = \.(\w+), \.rungs = &\[_\]C\.CpuVector\{(.*?)\n    \} \}", text, re.S):
        cpu[names[m.group(1)]] = [[int(x) for x in v.split(",") if x.strip()] for v in re.findall(r"\.\{ ([0-9, ]+) \}", m.group(2))]
    for m in re.finditer(r"\.family = \.(\w+), \.aux = (\d+), \.logs = &\.\{ ([0-9, ]+) \}", text):
        truth[(names[m.group(1)], int(m.group(2)))] = [int(x) for x in m.group(3).split(",")]
    return cpu, truth


def classify(segs, cpu_table, truth_table):
    classes, misses = {}, []
    for s in segs:
        r, why = cpu_class(s, cpu_table) if s["kind"] == "cpu" else truth_class(s, truth_table)
        if r is None:
            misses.append({"block": s["block"], "ordinal": s["ordinal"], "family": ref.FAMILY_NAMES.get(s["family"], s["family"]),
                           "cpu_log": s["vec"][0] if s["kind"] == "cpu" else None, "reasons": why})
            s["class"] = None
        else:
            key = (s["family"], s["aux"], s["vec"][0] if s["kind"] == "cpu" else 0, r)
            s["class"] = key
            classes[key] = classes.get(key, 0) + 1
    return classes, misses


ENVELOPE_CAP = 23      # largest component log admitted anywhere in the basket (initial_log 23); never exceeded by the envelope
# Receiver source-bounds caps (om31_security_candidate.zig MAX_TRACE_LOG / MAX_PUBLIC_BOUNDARY_LOG, enforced by
# gkr_local/source_bounds.zig includeRole): only initial/terminal may reach 23; every other component is refused above 22.
MAX_TRACE_LOG = 22
BOUNDARY_COMPONENTS = (13, 14)  # initial_log, terminal_log
UNSEEN_LOG = 12        # [E] log given to a component no training segment uses (so an unseen bridge still has a class)
LAST_CPU_LOGS = range(16, 23)  # cpu_last envelope ladder; capture pads a shorter final segment up to 2^16 rows (design sec. 3.2)


def envelope_vector(cpu_segs, all_segs):
    """Roster-complete envelope of one CPU family: every component present, at max(family max + 1, max over every CPU family),
    capped at ENVELOPE_CAP; a component no CPU segment uses gets UNSEEN_LOG. boundary_log stays the roster constant 5 (strict fit needs equality);
    zbb stays absent (a layout feature the basket client does not use; adding it is a layout decision, not a rung)."""
    env = [0] * len(COMP)
    for c in range(len(COMP)):
        mine = [s["vec"][c] + 1 for s in cpu_segs if s["vec"][c]]
        every = [s["vec"][c] for s in all_segs if s["vec"][c]]
        cap = ENVELOPE_CAP if c in BOUNDARY_COMPONENTS else min(ENVELOPE_CAP, MAX_TRACE_LOG)
        env[c] = min(max(mine + every), cap) if every else UNSEEN_LOG
    env[12] = 5
    env[40] = 0
    return env


def build_catalog(segs, widths, R, envelope=True):
    """Proposed catalog: CPU rungs per (family, cpu_log) (cpu_log is a class constant: capture fixes it), DP on strict-roster cells;
    truth rungs per (family, aux) DP on rows; plus envelope rungs (completeness for unseen blocks): per CPU (family, cpu_log) one
    roster-complete envelope (envelope_vector), cpu_last additionally one envelope per cpu_log in LAST_CPU_LOGS; per truth group
    one rung at max + 1."""
    cpu_groups, truth_groups = {}, {}
    for s in segs:
        if s["kind"] == "cpu":
            cpu_groups.setdefault((s["family"], s["vec"][0]), []).append(s)
        else:
            truth_groups.setdefault((s["family"], s["aux"]), []).append(s)
    cpu_table, truth_table = {}, {}
    for (fam, cpu_log), ps in sorted(cpu_groups.items()):
        res = rungs_mod.group_rungs(rungs_mod.group_memo(ps, widths, "cells", "roster"), R)
        rungs = []
        for rv in res["rungs"]:
            # The group max vector dominates every member component-wise, so it also dominates every member's pair
            # capacity (monotone in head and tail); classify() re-checks this (0 misses on the training set).
            v = vec_of(rv)
            if any(p["omit_div"] for p in ps) and v[8] == 0:
                v[8] = 5
            rungs.append(v)
        cpu_table.setdefault(fam, []).extend(rungs)
    if envelope:
        for fam in sorted({f for f, _ in cpu_groups}):
            logs = {l for f, l in cpu_groups if f == fam}
            if fam == ref.CPU_LAST:
                logs |= set(LAST_CPU_LOGS)
            env = envelope_vector([s for s in segs if s["kind"] == "cpu" and s["family"] == fam], [s for s in segs if s["kind"] == "cpu"])
            for l in sorted(logs):
                v = list(env)
                v[0] = l
                cpu_table[fam].append(v)
    for (fam, aux), ps in sorted(truth_groups.items()):
        res = rungs_mod.group_rungs(rungs_mod.group_memo(ps, widths, "cells", "roster"), R)
        logs = sorted({rv["main"] for rv in res["rungs"]})
        if envelope:
            logs.append(logs[-1] + 1)
        truth_table[(fam, aux)] = logs
    # Strict fit keys CPU rungs by cpu_log, so a family's rung list is ordered by (cpu_log, cells); envelopes sort last per log.
    for fam in cpu_table:
        cpu_table[fam].sort(key=lambda v: (v[0], rungs_mod.cost(dict(zip(COMP, v)), [c for c, x in zip(COMP, v) if x], widths, "cells", "present")))
    return cpu_table, truth_table


def tax(segs, cpu_table, truth_table, widths, which="cells"):
    """Strict-roster committed cells of the catalog vs today's exact cells (CPU; which = cells = main + interaction, or main only,
    the GKR-route weight) and rows (truth); also per block (CPU + truth rows x 1, as canon-native's dev-block figures)."""
    real = pad = treal = tpad = 0
    per = {}
    for s in segs:
        if s.get("class") is None:
            continue
        if s["kind"] == "cpu":
            rung = cpu_table[s["family"]][s["class"][3]]
            r = rungs_mod.cost(s["comps"], s["comps"].keys(), widths, which, "present")
            q = rungs_mod.cost(dict(zip(COMP, rung)), [c for c, x in zip(COMP, rung) if x], widths, which, "present")
            real += r
            pad += q
        else:
            r = 2 ** s["log"]
            q = 2 ** truth_table[(s["family"], s["aux"])][s["class"][3]]
            treal += r
            tpad += q
        e = per.setdefault(str(s["block"]), [0, 0])
        e[0] += r
        e[1] += q
    return {f"cpu_{which}_tax": round(pad / real - 1, 4) if real else 0.0, "truth_rows_tax": round(tpad / treal - 1, 4) if treal else 0.0,
            f"cpu_{which}_real": real, f"cpu_{which}_padded": pad, "truth_rows_real": treal, "truth_rows_padded": tpad, f"block_{which}_tax": {k: round(v[1] / v[0] - 1, 4) for k, v in sorted(per.items())}}


def is_envelope(v, family_rungs):
    """Envelope rungs share every component but cpu_log (envelope_vector); DP rungs are group maxima. An envelope is a rung
    whose non-cpu_log part equals the family's componentwise-largest rung."""
    top = [max(r[c] for r in family_rungs) for c in range(len(COMP))]
    return list(v[1:]) == top[1:]


def presence_classes(segs):
    """Classes if presence stayed a circuit constant (presence-preserving mode): (class, present-component mask)."""
    return len({(s["class"], tuple(x != 0 for x in s["vec"])) if s["kind"] == "cpu" else s["class"] for s in segs if s.get("class")})


def catalog_size(cpu_table, truth_table):
    return sum(len(v) for v in cpu_table.values()) + sum(len(v) for v in truth_table.values())


def service(segs, key):
    """Different-blocks warm: one service, basket order, unbounded host class store. Misses per block."""
    seen, rows = set(), []
    for b in BASKET_ORDER:
        mine = [s for s in segs if s["block"] == b]
        miss = 0
        for s in mine:
            k = key(s)
            if k not in seen:
                miss += 1
                seen.add(k)
        rows.append({"block": b, "leaves": len(mine), "new_classes": miss})
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--shapes", required=True)
    ap.add_argument("--widths", required=True)
    ap.add_argument("--v1", default=str(HERE.parent / "src/integrations/riscv_cpu/word16_global_execution/ethereum/canon_native_rungs.zig"))
    ap.add_argument("--out", required=True)
    ap.add_argument("--zig")
    ap.add_argument("--rungs", type=int, default=4, help="R of the emitted catalog (DP rungs per group, before the envelope rung)")
    a = ap.parse_args()
    shapes = json.load(open(a.shapes))
    widths = rungs_mod.Widths(json.load(open(a.widths)))
    segs = segments(shapes)
    n_cpu = sum(1 for s in segs if s["kind"] == "cpu")
    out = {"schema": "rv64-m9-canon-leaf-catalog/v1", "label": "D (arithmetic on the 15 M3 basket declarations + exported widths)",
           "blocks": len(shapes["blocks"]), "leaves": len(segs), "cpu_leaves": n_cpu, "truth_leaves": len(segs) - n_cpu}
    # 1. exact (today)
    exact = {s["exact"] for s in segs}
    out["exact"] = {"classes": len(exact), "cpu_classes": len({s["exact"] for s in segs if s["kind"] == "cpu"}),
                    "truth_classes": len({s["exact"] for s in segs if s["kind"] == "truth"}),
                    "service": service(segs, lambda s: s["exact"])}
    # 2. frozen v1 rung table, strict roster
    v1_cpu, v1_truth = parse_v1(a.v1)
    classes, misses = classify(segs, v1_cpu, v1_truth)
    out["v1_strict"] = {"catalog_classes": catalog_size(v1_cpu, v1_truth), "classes_used": len(classes), "misses": len(misses),
                        "miss_blocks": sorted({m["block"] for m in misses}), "miss_detail": misses[:40],
                        "miss_reasons": _count(r for m in misses for r in m["reasons"][:1])}
    # 3. proposed catalog, R sweep, all 15 blocks + leave-one-block-out
    sweep = {}
    for R in range(1, 9):
        ct, tt = build_catalog(segs, widths, R)
        classes, misses = classify(segs, ct, tt)
        row = {"catalog_classes": catalog_size(ct, tt), "classes_used": len(classes), "misses": len(misses)}
        row.update(tax(segs, ct, tt, widths))
        row["cpu_main_tax"] = tax(segs, ct, tt, widths, "main")["cpu_main_tax"]
        row["presence_preserving_classes"] = presence_classes(segs)
        del row["block_cells_tax"]
        lobo_miss, lobo_blocks = 0, []
        # Held-out (out-of-sample) padding tax: the in-sample tax above is fitted on the very blocks it is measured on (many
        # leaves sit on a DP rung equal to their own max vector); a production block is unseen, so this is the honest tax.
        lo = {"cpu_real": 0, "cpu_pad": 0, "truth_real": 0, "truth_pad": 0, "block_cells_tax": {}, "envelope_leaves": 0}
        for b in BASKET_ORDER:
            train = [s for s in segs if s["block"] != b]
            test = [dict(s) for s in segs if s["block"] == b]
            ct2, tt2 = build_catalog(train, widths, R)
            _, m2 = classify(test, ct2, tt2)
            if m2:
                lobo_blocks.append({"block": b, "misses": len(m2), "first": m2[0]})
            lobo_miss += len(m2)
            t2 = tax(test, ct2, tt2, widths)
            lo["cpu_real"] += t2["cpu_cells_real"]
            lo["cpu_pad"] += t2["cpu_cells_padded"]
            lo["truth_real"] += t2["truth_rows_real"]
            lo["truth_pad"] += t2["truth_rows_padded"]
            lo["block_cells_tax"][str(b)] = t2["block_cells_tax"].get(str(b))
            env = {fam: {tuple(v) for v in vs[-len(vs):] if is_envelope(v, vs)} for fam, vs in ct2.items()}
            lo["envelope_leaves"] += sum(1 for s in test if s["kind"] == "cpu" and s.get("class") is not None and tuple(ct2[s["family"]][s["class"][3]]) in env[s["family"]])
        row["leave_one_block_out"] = {"misses": lobo_miss, "of": len(segs), "blocks_with_misses": lobo_blocks[:15],
                                      "blocks_refused": len(lobo_blocks), "blocks": len(BASKET_ORDER),
                                      "heldout_cpu_cells_tax": round(lo["cpu_pad"] / lo["cpu_real"] - 1, 4),
                                      "heldout_truth_rows_tax": round(lo["truth_pad"] / lo["truth_real"] - 1, 4),
                                      "heldout_envelope_cpu_leaves": lo["envelope_leaves"], "heldout_block_cells_tax": lo["block_cells_tax"]}
        sweep[str(R)] = row
    out["catalog_sweep"] = sweep
    ct, tt = build_catalog(segs, widths, a.rungs)
    classes, misses = classify(segs, ct, tt)
    out["catalog"] = {"rungs": a.rungs, "envelope": True, "classes": catalog_size(ct, tt), "classes_used": len(classes), "misses": len(misses),
                      "cpu_groups": {f"{ref.FAMILY_NAMES[f]}": len(v) for f, v in ct.items()},
                      "truth_groups": {f"{ref.TRUTH_NAMES[f - ref.TRUTH_BASE]}@{aux}": v for (f, aux), v in tt.items()},
                      "service": service(segs, lambda s: s["class"])}
    out["catalog"].update(tax(segs, ct, tt, widths))
    out["catalog"].update(tax(segs, ct, tt, widths, "main"))
    out["catalog"]["presence_preserving_classes"] = presence_classes(segs)
    Path(a.out).write_text(json.dumps(out, indent=1))
    brief = {k: out[k] for k in ("leaves", "cpu_leaves", "truth_leaves")}
    brief["exact_classes"] = out["exact"]["classes"]
    brief["v1_strict"] = {k: out["v1_strict"][k] for k in ("catalog_classes", "classes_used", "misses", "miss_blocks", "miss_reasons")}
    brief["sweep"] = {R: {k: v[k] for k in ("catalog_classes", "classes_used", "misses", "cpu_cells_tax", "cpu_main_tax", "truth_rows_tax", "presence_preserving_classes")}
                      | {"lobo_" + k: v["leave_one_block_out"][k] for k in ("misses", "blocks_refused", "heldout_cpu_cells_tax", "heldout_truth_rows_tax", "heldout_envelope_cpu_leaves")}
                      for R, v in sweep.items()}
    print(json.dumps(brief, indent=1))
    if a.zig:
        write_zig(a.zig, ct, tt, a.rungs)


def _count(it):
    out = {}
    for x in it:
        out[x] = out.get(x, 0) + 1
    return out


def write_zig(path, ct, tt, R):
    names = dict(ref.FAMILY_NAMES)
    lines = ["//! GENERATED by scripts/rv64_m9_canon_leaf_catalog.py from the 15 basket declarations; do not edit.",
             f"//! M9 canonical leaf catalog: per CPU family, rungs ordered by (cpu_log, cells); DP R={R} per (family, cpu_log) + one",
             "//! envelope rung per group. Truth: per (family, profile word) ascending main logs + envelope. Component ids = canon_native.",
             "const C = @import(\"../word16_global_execution/ethereum/canon_native.zig\");",
             f"pub const R: u32 = {R};",
             "pub const Entry = struct { family: C.Family, rungs: []const C.CpuVector };",
             "pub const TruthEntry = struct { family: C.Family, aux: u32, logs: []const u32 };"]
    cpu = []
    for fam in sorted(ct):
        vecs = "\n".join("        .{ " + ", ".join(map(str, v)) + " }," for v in ct[fam])
        cpu.append(f"    .{{ .family = .{names[fam]}, .rungs = &[_]C.CpuVector{{\n{vecs}\n    }} }},")
    truth = [f"    .{{ .family = .truth_{ref.TRUTH_NAMES[f - ref.TRUTH_BASE]}, .aux = {aux}, .logs = &.{{ {', '.join(map(str, v))} }} }},"
             for (f, aux), v in sorted(tt.items())]
    lines.append("pub const CPU = [_]Entry{\n" + "\n".join(cpu) + "\n};")
    lines.append("pub const TRUTH = [_]TruthEntry{\n" + "\n".join(truth) + "\n};")
    Path(path).write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
