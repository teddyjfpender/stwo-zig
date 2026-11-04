#!/usr/bin/env python3
"""M4.0 items 3, 6, 7, 8: models computed from one measured M3-baseline run (logs + receipt v2).

  python3 scripts/rv64_m40_models.py RUN_DIR [--nsys-receipt RUN_WITH_NSYS] --out models.json

  8  reconciled committed cells: sum of GPU_TRACE_OWNERSHIP coefficient words per tree (base cells the PCS
     LDEs and hashes), native vs recursion [M]; LDE cells = base x 2 (b2); kernel ns per LDE cell [D].
  7  device-memory model for 2^22/2^23/2^24 segments at b2/b4 from the measured 2^22 CPU-segment numbers,
     plus the composition-arena breakdown (native and recursion) [D].
  6  D2 paper model: native b4_q54_p20 vs b2_q108_p20 [D/E, assumptions stated in the output].
  3  analytic per-origin Blake2s compression census for one CPU leaf (verifying a 2^22 CPU segment) [D],
     from logged column counts and the q108/b2/fold4 profile. NOT an in-circuit count.
Labels: M measured, D arithmetic on measured numbers, E estimate.
"""
import argparse
import json
import math
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
import rv64_measure as M  # noqa: E402


def kv(line):
    out = {}
    for k, v in re.findall(r"(\w+)=(\{[^}]*\}|\S+)", line):
        out[k] = int(v) if v.lstrip("-").isdigit() else v
    return out


def split_log(run):
    lines = M.producer_log(run).splitlines()
    start = next(i for i, l in enumerate(lines) if "pipelined recursion: nodes" in l)
    return lines[:start], lines[start:]


def cells(native, recursion):
    def tally(seg):
        t = {}
        for l in seg:
            if l.startswith("GPU_TRACE_OWNERSHIP"):
                d = kv(l)
                a = t.setdefault(d["tree"], [0, 0])
                a[0] += 1
                a[1] += d["coefficient_words"]
        return t
    n, r = tally(native), tally(recursion)
    names = {0: "preprocessed", 1: "main", 2: "interaction"}
    out = {"label": "M", "scope": "GPU_TRACE_OWNERSHIP coefficient_words = base (pre-LDE) M31 cells committed per tree; composition/quotient and FRI trees not included",
           "native": {names[k]: {"commits": v[0], "base_cells_g": round(v[1] / 1e9, 3)} for k, v in sorted(n.items())},
           "recursion": {names[k]: {"commits": v[0], "base_cells_g": round(v[1] / 1e9, 3)} for k, v in sorted(r.items())}}
    out["native_total_g"] = round(sum(v[1] for v in n.values()) / 1e9, 3)
    out["recursion_total_g"] = round(sum(v[1] for v in r.values()) / 1e9, 3)
    out["recursion_main_plus_interaction_g"] = round((r.get(1, [0, 0])[1] + r.get(2, [0, 0])[1]) / 1e9, 3)
    out["recursion_interaction_share_of_total"] = round(r.get(2, [0, 0])[1] / sum(v[1] for v in r.values()), 3)
    out["reconciliation"] = ("53.39 G (construction-cost) == preprocessed + main + interaction base cells over the 33 nodes (this run: "
                             f"{out['recursion_total_g']} G). The '~37 G main+interaction' census-v2 figure counted the interaction tree at half "
                             f"its committed M31 columns (measured main+interaction = {out['recursion_main_plus_interaction_g']} G; main + interaction/2 = "
                             f"{round((r.get(1, [0, 0])[1] + r.get(2, [0, 0])[1] / 2) / 1e9, 2)} G per this run).")
    return out


def device_model(native, recursion, cpu_proofs):
    cpu = []
    for i, l in enumerate(native):
        if l.startswith("GPU_TRACE_STREAM") and "leaves=8388608" in l:
            d = kv(l)
            cpu.append(d)
    owners, last_leaves = [], {}
    for l in native:
        if l.startswith("GPU_TRACE_STREAM"):
            d = kv(l)
            last_leaves[d["tree"]] = d["leaves"]
        elif l.startswith("GPU_TRACE_OWNERSHIP"):
            d = kv(l)
            if last_leaves.get(d["tree"]) == 8388608:  # 2^22 CPU segments at b2 (truth proofs here are 2^21 LDE)
                owners.append(d)
    main_words = max(o["coefficient_words"] for o in owners if o["tree"] == 1)
    inter_words = max(o["coefficient_words"] for o in owners if o["tree"] == 2)
    arena = {}
    for phase, seg in (("native", native), ("recursion", recursion)):
        per = {}
        for l in seg:
            if l.startswith("GPU_COMPOSITION_ARENA"):
                d = kv(l)
                a = per.setdefault(d["ordinal"], {"roles": 0, "words": 0, "legacy": 0, "max_role": 0, "max_eval_log": 0})
                a["roles"] += 1
                a["words"] += d["arena_words"]
                a["legacy"] += d["legacy_arena_words"]
                a["max_role"] = max(a["max_role"], d["arena_words"])
                a["max_eval_log"] = max(a["max_eval_log"], d["eval_log"])
        if phase == "native" and per:
            cpu_per = {o: v for o, v in per.items() if o < cpu_proofs}
            topc = max(cpu_per.values(), key=lambda v: v["words"])
            arena["native_cpu_segments"] = {"ordinals": len(cpu_per), "max_sum_of_roles_gb": round(topc["words"] * 4 / 1e9, 2),
                                            "max_single_role_gb": round(max(v["max_role"] for v in cpu_per.values()) * 4 / 1e9, 2), "eval_log_at_max": topc["max_eval_log"]}
            tr = {o: v for o, v in per.items() if o >= cpu_proofs}
            if tr:
                o, topt = max(tr.items(), key=lambda kv: kv[1]["max_role"])
                arena["native_truth_largest"] = {"ordinal": o, "single_role_gb": round(topt["max_role"] * 4 / 1e9, 2), "eval_log": topt["max_eval_log"], "roles": topt["roles"]}
        if per:
            top = max(per.values(), key=lambda v: v["words"])
            arena[phase] = {"ordinals": len(per), "max_sum_of_roles_gb": round(top["words"] * 4 / 1e9, 2), "max_single_role_gb": round(max(v["max_role"] for v in per.values()) * 4 / 1e9, 2),
                            "legacy_max_sum_gb": round(max(v["legacy"] for v in per.values()) * 4 / 1e9, 2), "roles_at_max": top["roles"], "eval_log_at_max": top["max_eval_log"]}
    peaks = {}
    for phase, seg in (("native", native), ("recursion", recursion)):
        ds = [kv(l) for l in seg if l.startswith("GPU_DEVICE_PEAK")]
        if ds:
            peaks[phase] = {"max_pool_used_gb": round(max(d.get("pool_used_bytes", 0) for d in ds) / 1e9, 2), "max_live_lease_gb": round(max(d.get("live_lease_bytes", 0) for d in ds) / 1e9, 2)}
    pcs = [kv(l) for l in native + recursion if l.startswith("GPU_PCS_NATIVE")]
    base22 = (main_words + inter_words) * 4
    cpu_arena = arena["native_cpu_segments"]["max_sum_of_roles_gb"] * 1e9
    rows = []
    for log in (22, 23, 24):
        for b, lb in (("b2", 1), ("b4", 2)):
            s = 2 ** (log - 22)
            base = base22 * s
            lde = base * 2 ** lb
            comp = cpu_arena * s
            rows.append({"segment_log": log, "blowup": b, "base_main_plus_interaction_gb": round(base / 1e9, 2), "lde_if_materialised_gb": round(lde / 1e9, 2),
                         "composition_arena_gb": round(comp / 1e9, 2), "peak_naive_gb": round((base + lde + comp) / 1e9, 2),
                         "peak_streamed_commit_gb": round((base + comp + 3.8e9 * s * 2 ** (lb - 1)) / 1e9, 2),
                         "fits_32gb_with_3gb_runtime": (base + comp + 3.8e9 * s * 2 ** (lb - 1)) / 1e9 + 3 <= 32})
    return {"label": "D", "measured_inputs": {"cpu_segment_2^22_main_words_max": main_words, "cpu_segment_2^22_interaction_words_max": inter_words,
                                              "composition_arena": arena, "pool_peaks": peaks,
                                              "pcs_max_device_gb": round(max(p["device_bytes"] for p in pcs) / 1e9, 2),
                                              "pcs_max_retained_gb": round(max(p["retained_bytes"] for p in pcs) / 1e9, 2)},
            "assumptions": ["base cells, LDE and composition arena scale linearly with segment rows (all components grow with the segment)",
                            "composition arena is evaluated on 2x the trace domain (eval_log = trace_log + 1, measured) and does not grow with FRI blowup",
                            "streamed commit working set measured 3.8 GB (bank + scratch) at 2^23 LDE leaves; scales with LDE leaves",
                            "3 GB runtime reserve: context, ~1.9 GB kernel stack reservation, setup cache 2.1 GB is extra when resident"],
            "model": rows}


def d2_model(nsys_view, cells_out):
    rec = nsys_view["recursion"]
    rec_kernel = rec["reconciled_kernel_gpu_s"]
    dev_kernel = sum(v["kernel_sum_s"] for v in nsys_view["devices"].values())
    native_kernel = dev_kernel - rec_kernel
    leaf = rec["per_kind"]["leaf"]
    leaf_kernel = leaf["kernel_busy_s_total"]
    leaf_cells = 1.94e9  # measured CPU leaf base cells (PP 0.18 + main 0.58 + interaction 1.18 G)
    # Leaf work that scales with queries: Merkle decommit (leaf values + paths) and FRI query folding.
    q_share_low, q_share_high = 0.55, 0.80
    return {"label": "D/E",
            "inputs_measured": {"native_kernel_gpu_s": round(native_kernel, 2), "recursion_kernel_gpu_s": rec_kernel, "leaf_kernel_gpu_s_17": leaf_kernel,
                                "fold_kernel_gpu_s_16": rec["per_kind"]["fold"]["kernel_busy_s_total"]},
            "assumptions": ["native b4 doubles LDE + Merkle + quotient-commit work; those are 50-70% of native kernel time [E]",
                            f"leaf cells that scale with the query count are {int(q_share_low*100)}-{int(q_share_high*100)}% of a leaf [E: hashing is ~85% of leaf cells, decommit dominates hashing]",
                            "folds verify outer (q108) proofs, unchanged by D2; only leaves shrink",
                            "D2 also changes the native profile -> new named profile + soundness note (profiles stream)"],
            "native_delta_gpu_s": [round(native_kernel * 0.5, 2), round(native_kernel * 0.7, 2)],
            "leaf_delta_gpu_s": [round(-leaf_kernel * q_share_high * 0.5, 2), round(-leaf_kernel * q_share_low * 0.5, 2)],
            "net_gpu_s": [round(native_kernel * 0.5 - leaf_kernel * q_share_high * 0.5, 2), round(native_kernel * 0.7 - leaf_kernel * q_share_low * 0.5, 2)],
            "leaf_base_cells_g_after": [round(leaf_cells * (1 - q_share_high * 0.5) / 1e9, 2), round(leaf_cells * (1 - q_share_low * 0.5) / 1e9, 2)],
            "recommendation": ("net saving in GPU-s on 24628607 across the whole assumption band, but SMALL (0.1-2.8 GPU-s of ~30: native kernels are ~5 GPU-s, leaves ~13). "
                               "Recommend D2 = YES as an M7 candidate, gated on: (a) an in-circuit per-origin Blake count confirming the query-scaled share >= 55%, "
                               "(b) the device-memory model (b4 doubles native LDE: 2^22 b4 fits, 2^23 b4 only with streamed commit), "
                               "(c) a named profile + soundness note. Native wall rises; it is not on the M6 critical path if stage-2 overlaps leaves.")}


def blake_census(native):
    cols = {}
    for l in native:
        if l.startswith("GPU_TRACE_STREAM") and "leaves=8388608" in l:
            d = kv(l)
            cols.setdefault(d["tree"], []).append(d["columns"])
    main_c, inter_c = max(cols.get(1, [3606])), max(cols.get(2, [2008]))
    q, depth, fold = 108, 23, 4
    pp_c, comp_c = 45, 16  # E: native preprocessed and composition-quotient columns per CPU proof (not logged per tree)
    trees = {"preprocessed": pp_c, "main": main_c, "interaction": inter_c, "composition": comp_c}

    def distinct_path_nodes(qn, d):
        return sum(min(2 ** j, qn) for j in range(1, d + 1))
    out = {}
    path_nodes = distinct_path_nodes(q, depth)
    for name, c in trees.items():
        out[f"merkle_leaf_values:{name}"] = q * math.ceil(c / 16)
        out[f"merkle_path:{name}"] = path_nodes
    layers = math.ceil(depth / fold)
    fri_leaf = fri_path = 0
    for i in range(layers):
        d = depth - fold * (i + 1)
        if d <= 0:
            break
        fri_leaf += q * math.ceil((2 ** fold) * 4 / 16)
        fri_path += distinct_path_nodes(q, d)
    out["fri_layer_leaves"] = fri_leaf
    out["fri_layer_paths"] = fri_path
    total_cols = sum(trees.values())
    out["channel_oods_values"] = math.ceil(total_cols * 1.3 * 4 / 16)
    out["channel_other"] = 64
    total = sum(out.values())
    groups = {"merkle_leaf_values": 0, "merkle_path": 0, "fri": 0, "channel": 0}
    for k, v in out.items():
        g = "fri" if k.startswith("fri") else "channel" if k.startswith("channel") else k.split(":")[0]
        groups[g] += v
    return {"label": "D (analytic; not an in-circuit count)", "profile": "q108 b2 fold4, 2^22 CPU segment, LDE depth 23",
            "columns": trees, "compressions": out, "total_compressions": total,
            "share_by_origin": {g: round(v / total, 3) for g, v in groups.items()},
            "query_scaled_share": round((groups["merkle_leaf_values"] + groups["merkle_path"] + groups["fri"]) / total, 3),
            "caveat": "stwo mixed-size Merkle hashes column values at their own layer; this model charges ceil(C/16) per query per tree plus deduplicated "
                      "2-to-1 path nodes. PP/composition column counts are estimates. The exit gate (origins >= 95% of in-circuit Blake rows) needs a "
                      "per-origin counter in the leaf graph builder (owned by canon-vk/hint-tape); spec in M40-FINDINGS.md."}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("run")
    parser.add_argument("--nsys-receipt", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    native, recursion = split_log(args.run)
    nsys = M.load(args.nsys_receipt)["gpu"]["nsys"]
    c = cells(native, recursion)
    rec = nsys["recursion"]
    lde = c["recursion_total_g"] * 2 * 1e9
    c["recursion_kernel_ns_per_lde_cell"] = round(rec["reconciled_kernel_gpu_s"] * 1e9 / lde, 3)
    native_kernel = sum(v["kernel_sum_s"] for v in nsys["devices"].values()) - rec["reconciled_kernel_gpu_s"]
    c["native_kernel_ns_per_lde_cell_upper_bound"] = round(native_kernel * 1e9 / (c["native_total_g"] * 2 * 1e9), 3)
    out = {"schema": "rv64-m40-models/v1", "run": args.run, "nsys_run": args.nsys_receipt,
           "item8_cells": c, "item7_device_memory": device_model(native, recursion, M.load(Path(args.run) / "receipt.json")["native"]["cpu_proofs"]), "item6_d2": d2_model(nsys, c), "item3_blake": blake_census(native)}
    Path(args.out).write_text(json.dumps(out, indent=1))
    print(json.dumps({"cells": {k: c[k] for k in ("native_total_g", "recursion_total_g", "recursion_kernel_ns_per_lde_cell", "native_kernel_ns_per_lde_cell_upper_bound")},
                      "d2_net_gpu_s": out["item6_d2"]["net_gpu_s"], "blake_shares": out["item3_blake"]["share_by_origin"],
                      "device_model": [(r["segment_log"], r["blowup"], r["peak_streamed_commit_gb"], r["fits_32gb_with_3gb_runtime"]) for r in out["item7_device_memory"]["model"]]}, indent=1))


if __name__ == "__main__":
    main()
