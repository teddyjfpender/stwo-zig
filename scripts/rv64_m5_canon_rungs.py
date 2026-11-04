#!/usr/bin/env python3
"""M5 canon-native: cells-weighted canonical-rung tax and the v1 rung table (stream canon-native).

Inputs (read-only): the 15 M3 scale-up bundles (bundle.json declarations, as scripts/rv64_m40_geometry.py) and the per-component
widths exported by the canon_native_widths.zig test (`RV64_M5_WIDTHS {json}` line).  CPU segments are split into the families
cpu_first / cpu_middle / cpu_last / cpu_single (rv64_m5_canon_native_ref.py ids).

Per family and R in {2,3,4}: proofs sorted by today's committed cells, contiguous groups (exact DP) padded to the group's
component-wise max log vector, minimising padded CELLS (width x 2^log summed over the proof's components).  Two padding models:
  - present  : v1 admissible mode -- every PRESENT component is raised to the rung log, absent components stay absent
               (today's admission ties presence to non-zero counts: InvalidCombinedBridgePresence, ls/provider tails);
  - roster   : strict canonical roster -- every component of the rung is committed, empty ones all padding
               (needs the presence relaxation of the m5 native version; binding note 3.1).
Weights: cells = main + interaction widths (classic layout widths; GKR-route CPU interaction is GKR-proved, so `main` is also
reported).  Truth proofs have one sized component, so their tax is width-independent; family totals use rows x 1.
Kill rule (plan M5): cells-weighted tax > 40 % with 3 rungs => 4 rungs.

  python3 scripts/rv64_m5_canon_rungs.py --widths widths.json --out rungs.json [--zig canon_native_rungs.zig]
"""
import argparse
import json
from pathlib import Path

import importlib.util
_ref_spec = importlib.util.spec_from_file_location("ref", Path(__file__).with_name("rv64_m5_canon_native_ref.py"))
ref = importlib.util.module_from_spec(_ref_spec)
_ref_spec.loader.exec_module(ref)

GEOM = ref.CPU_COMPONENTS[:15]
ROLE_OF = {"cpu_log": "cpu", "alu_log": "alu", "alu_tail_log": "alu_tail", "binary_log": "binary", "binary_tail_log": "binary_tail",
           "shift_log": "shift", "shift_tail_log": "shift_tail", "jalr_log": "jalr", "division_log": "division",
           "multiplication_log": "multiplication", "ls_log": "ls", "ls_tail_log": "ls_tail", "boundary_log": "boundary",
           "initial_log": "initial", "terminal_log": "terminal"}
DEV = (26235156, 24628607)


def flatten(bridges, prefix="bridge."):
    out = {}
    for k, v in (bridges or {}).items():
        if isinstance(v, dict):
            out.update(flatten(v, prefix + k + "."))
        elif v is not None:
            out[prefix + k] = v
    return out


def cpu_family(i, n):
    return ref.CPU_SINGLE if n == 1 else ref.CPU_FIRST if i == 0 else ref.CPU_LAST if i == n - 1 else ref.CPU_MIDDLE


def proofs_of(bundle):
    out = []
    n = len(bundle["cpus"])
    for i, cpu in enumerate(bundle["cpus"]):
        g = cpu["declaration"]["geometry"]
        comps = {k: g[k] for k in GEOM if g.get(k) is not None}
        if "initial_log" not in comps:
            comps["initial_log"] = g["boundary_log"]
        if "terminal_log" not in comps:
            comps["terminal_log"] = g["boundary_log"]
        comps.update(flatten(cpu["declaration"].get("bridges")))
        flags = tuple(sorted(k for k, v in g.items() if isinstance(v, bool) and v))
        out.append({"family": cpu_family(i, n), "comps": comps, "flags": flags})
    for t in bundle["truths"]:
        d = t["declaration"]
        out.append({"family": ref.TRUTH_BASE + ref.TRUTH_NAMES.index(d["family"]), "comps": {"main": d["logs"][0]}, "aux": d["logs"][1]})
    return out


class Widths:
    def __init__(self, w):
        self.w = w

    def of(self, comp, which):
        """which: 'main' or 'cells' (main + interaction)."""
        if comp.startswith("bridge."):
            name = comp[len("bridge."):]
            if name.startswith("bulk."):
                v = self.w["bulk"][name[5:]]
            elif name.startswith("sponge."):
                v = self.w["sponge"][name[7:]]
            elif name in ("ls_dword", "ls_dword_tail"):
                v = self.w["other"]["ls_dword"]
            elif name == "zbb":
                v = self.w["other"]["zbb"]
            else:
                v = self.w["bridges"][name]
        elif comp == "main":
            return 1
        else:
            v = self.w["roles"][ROLE_OF[comp]]
        return v[1] if which == "main" else v[1] + v[2]


def cost(vec, comps_present, widths, which, model):
    """Committed cells of a proof padded to `vec` (model 'present': only comps_present are committed)."""
    keys = comps_present if model == "present" else vec.keys()
    return sum(widths.of(k, which) * 2 ** vec[k] for k in keys)


def group_rungs(proofs, r, widths, which, model):
    vs = sorted(proofs, key=lambda p: cost(p["comps"], p["comps"].keys(), widths, which, "present"))
    n = len(vs)
    real = sum(cost(p["comps"], p["comps"].keys(), widths, which, "present") for p in vs)

    def gmax(i, j):
        m = {}
        for p in vs[i:j + 1]:
            for k, l in p["comps"].items():
                m[k] = max(m.get(k, 0), l)
        return m

    def gcost(i, j):
        m = gmax(i, j)
        return sum(cost(m, p["comps"].keys(), widths, which, model) for p in vs[i:j + 1]), m
    inf = float("inf")
    dp = [[inf] * (r + 1) for _ in range(n + 1)]
    back = [[None] * (r + 1) for _ in range(n + 1)]
    dp[0] = [0] * (r + 1)
    memo = {}
    for j in range(1, n + 1):
        for i in range(1, j + 1):
            memo[(i - 1, j - 1)] = gcost(i - 1, j - 1)
        for k in range(1, r + 1):
            for i in range(1, j + 1):
                c = dp[i - 1][k - 1] + memo[(i - 1, j - 1)][0]
                if c < dp[j][k]:
                    dp[j][k], back[j][k] = c, i - 1
    kk = min(range(1, min(r, n) + 1), key=lambda x: dp[n][x])
    groups, j = [], n
    while j > 0 and kk > 0:
        i = back[j][kk]
        groups.append({"proofs": j - i, "rung": memo[(i, j - 1)][1]})
        j, kk = i, kk - 1
    groups = groups[::-1]
    # rungs ascending by roster cells
    return {"real": real, "padded": dp[n][min(range(1, min(r, n) + 1), key=lambda x: dp[n][x])], "rungs": [g["rung"] for g in groups],
            "proofs_per_rung": [g["proofs"] for g in groups]}


def select(rungs, comps):
    for i, v in enumerate(rungs):
        if all(k in v and v[k] >= l for k, l in comps.items()):
            return i
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--runs", default="/workspace/m3/runs/integrate")
    ap.add_argument("--widths", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--zig")
    a = ap.parse_args()
    widths = Widths(json.load(open(a.widths)))
    blocks = {}
    for run in sorted(Path(a.runs).glob("*-2gpu-scale")):
        block = int(run.name.split("-")[0])
        b = run / "case/batch/trial-0" / str(block) / "proof/bundle.json"
        if b.is_file():
            blocks[block] = proofs_of(json.load(open(b)))
    fams = {}
    for block, ps in blocks.items():
        for p in ps:
            p["block"] = block
            fams.setdefault(p["family"], []).append(p)
    out = {"schema": "rv64-m5-canon-rungs/v1", "label": "D (arithmetic on measured M3 bundles + exported widths)",
           "blocks": sorted(blocks), "proofs": sum(len(v) for v in blocks.values()), "families": {}, "summary": {}}
    for which in ("cells", "main"):
        for model in ("present", "roster"):
            for r in (1, 2, 3, 4):
                tot_real = tot_pad = cpu_real = cpu_pad = 0
                dev = {b: [0, 0] for b in DEV}
                classes = 0
                for fam, ps in fams.items():
                    res = group_rungs(ps, r, widths, which, model)
                    classes += len(res["rungs"])
                    tot_real += res["real"]
                    tot_pad += res["padded"]
                    if fam < ref.TRUTH_BASE:
                        cpu_real += res["real"]
                        cpu_pad += res["padded"]
                    for p in ps:
                        if p["block"] in dev:
                            i = select(res["rungs"], p["comps"])
                            dev[p["block"]][0] += cost(p["comps"], p["comps"].keys(), widths, which, "present")
                            dev[p["block"]][1] += cost(res["rungs"][i], p["comps"].keys(), widths, which, model)
                    if which == "cells" and model == "present":
                        fe = out["families"].setdefault(ref.FAMILY_NAMES[fam], {})
                        fe[str(r)] = {"tax": round(res["padded"] / res["real"] - 1, 4), "proofs": len(ps), "proofs_per_rung": res["proofs_per_rung"],
                                      "rungs": res["rungs"]}
                key = f"{which}/{model}/R{r}"
                out["summary"][key] = {"tax_all": round(tot_pad / tot_real - 1, 4), "tax_cpu": round(cpu_pad / cpu_real - 1, 4) if cpu_real else 0,
                                       "classes": classes, "dev_blocks": {str(b): round(v[1] / v[0] - 1, 4) for b, v in dev.items() if v[0]}}
    s = out["summary"]
    tax3 = s["cells/roster/R3"]["tax_all"]
    out["decision"] = {"rungs": 3 if tax3 <= 0.40 else 4, "rule": "plan M5 kill rule on cells-weighted strict-roster tax, 3 rungs",
                       "cells_roster_R3": tax3, "cells_present_R3": s["cells/present/R3"]["tax_all"]}
    Path(a.out).write_text(json.dumps(out, indent=1))
    print(json.dumps({"summary": s, "decision": out["decision"]}, indent=1))
    if a.zig:
        write_zig(a.zig, out, out["decision"]["rungs"])


def write_zig(path, out, R):
    lines = ["//! GENERATED by scripts/rv64_m5_canon_rungs.py from the 15 M3 bundles; do not edit.",
             "//! v1 canonical rung table: per family, R class rung vectors ascending (component logs, 0 = absent).",
             "const C = @import(\"canon_native.zig\");", f"pub const R: u32 = {R};",
             "pub const Entry = struct { family: C.Family, rungs: []const C.CpuVector };",
             "pub const TruthEntry = struct { family: C.Family, logs: []const u32 };"]
    cpu, truth = [], []
    for name, fe in sorted(out["families"].items(), key=lambda kv: [k for k, v in ref.FAMILY_NAMES.items() if v == kv[0]][0]):
        rungs = fe[str(R)]["rungs"]
        if name.startswith("cpu"):
            vecs = []
            for v in rungs:
                vec = [v.get(c, 0) for c in ref.CPU_COMPONENTS]
                vecs.append("        .{ " + ", ".join(map(str, vec)) + " },")
            cpu.append(f"    .{{ .family = .{name}, .rungs = &[_]C.CpuVector{{\n" + "\n".join(vecs) + "\n    } },")
        else:
            truth.append(f"    .{{ .family = .{name}, .logs = &.{{ " + ", ".join(str(v["main"]) for v in rungs) + " } },")
    lines.append("pub const CPU = [_]Entry{\n" + "\n".join(cpu) + "\n};")
    lines.append("pub const TRUTH = [_]TruthEntry{\n" + "\n".join(truth) + "\n};")
    Path(path).write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    main()
