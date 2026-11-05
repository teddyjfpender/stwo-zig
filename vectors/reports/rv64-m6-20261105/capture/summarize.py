#!/usr/bin/env python3
"""summarize.py RUNDIR OUTDIR COMMIT TAG=LABEL...  M6 capture receipts from cap.py run records.

Groups cap-<block>-<tag>-r<k>.json by (block, tag); writes OUTDIR/<block>-capture-m6.json (every run + medians)
and prints one progress row per run (append to vectors/reports/progress/capture.jsonl).
"""
import glob, json, os, re, statistics, sys
rundir, outdir, commit = sys.argv[1:4]
labels = dict(kv.split("=", 1) for kv in sys.argv[4:])
DIGEST = {24628607: "e5f5e7606c584ca6f9a68f6e6eefef86908d7011ad2a98ad75e82eb8f5a4bb77", 26235156: "c9f3d40fa8c9e3b724f2153c2fa23168335bff8882f5b71cd31b02d99ec8a932"}
def s(ns): return None if ns is None else round(ns / 1e9, 4)
def row(rec):
    c = rec.get("capture", {}); ci = c.get("capture_inputs", {}); dc = c.get("direct_capture") or {}; sg = dc.get("segments") or {}
    walk_mips = round(sg["walk_retired"] / sg["walk_ns_total"] * 1e3, 1) if sg.get("walk_ns_total") else None
    traced_mips = round(sg["walk_retired"] / sg["walk_traced_ns"] * 1e3, 1) if sg.get("walk_traced_ns") else None
    ready = [s(x) for x in dc.get("segment_ready_ns", []) if x]
    return {"tag": rec["tag"], "rc": rec["rc"], "env": rec["env"], "loadavg_1m": round(rec["loadavg_before"][0], 2),
            "capture_s": s(c.get("image_and_import_ns")), "init_s": s(ci.get("init_ns")), "first_inputs_s": s(ci.get("first_inputs_ns")),
            "last_inputs_s": s(ci.get("last_inputs_ns")), "ledger_s": s(ci.get("ledger_ns")), "ledger_finish_s": s(ci.get("ledger_finish_ns")),
            "breakdown_s": {k: s(v) for k, v in (c.get("capture_breakdown") or {}).items()},
            "start_boot_s": s(dc.get("start_boot_ns")), "start_join_s": s(dc.get("start_join_ns")),
            "first_batch_ready_s": s(dc.get("first_batch_ready_ns")), "first_batch_capture_s": s(dc.get("first_batch_capture_ns")),
            "segment_ready_s": ready, "first_pass_s": s(sg.get("first_pass_ns")), "traced_engine": sg.get("traced_engine"),
            "traced_program_s": s(sg.get("traced_program_ns")), "walk_retired": sg.get("walk_retired"), "walk_fast_retired": sg.get("walk_fast_retired"),
            "walk_s_total": s(sg.get("walk_ns_total")), "walk_s_max": s(sg.get("walk_ns_max")), "walk_traced_s": s(sg.get("walk_traced_ns")),
            "walk_finish_s": s(sg.get("walk_finish_ns")), "walk_mips_per_worker": walk_mips, "traced_mips_per_worker": traced_mips,
            "process_wall_s": rec["process_wall_s"], "avg_busy_cores": rec["avg_busy_cores"], "max_rss_gib": rec["max_rss_gib"],
            "captured_values_sha256": c.get("captured_values_sha256"), "binary_sha256": rec["binary_sha256"]}
out = {}
for path in sorted(glob.glob(f"{rundir}/cap-*-*.json")):
    rec = json.load(open(path)); b = rec["block"]
    m = re.match(r"(.*)-r\d+$", rec["tag"]); group = m.group(1) if m else rec["tag"]
    if group not in labels: continue
    out.setdefault(b, {}).setdefault(group, []).append(row(rec))
for b, groups in out.items():
    rec = {"schema": "rv64-m6-capture-receipt/v1", "block": b, "commit": commit, "reference_digest": DIGEST.get(b), "groups": {}}
    for g, runs in groups.items():
        ok = [r for r in runs if r["rc"] == 0]
        med = lambda k: round(statistics.median([r[k] for r in ok if r[k] is not None]), 4) if ok else None
        rec["groups"][g] = {"label": labels[g], "runs": runs, "median": {k: med(k) for k in ("capture_s", "init_s", "first_inputs_s", "last_inputs_s", "walk_s_max", "walk_mips_per_worker", "loadavg_1m")},
                            "byte_identical": all(r["captured_values_sha256"] == DIGEST.get(b) for r in runs)}
        for r in runs:
            print(json.dumps({"date": "2026-11-05", "commit": commit, "stream": "capture", "milestone": "M6", "block": b, "gpus": 0, "request_s": None,
                "capture_s": r["capture_s"], "setup_s": None, "native_s": None, "recursion_s": None, "verifier_s": None, "rss_peak_gib": r["max_rss_gib"],
                "device_peak_gb": None, "proof_bytes": None, "byte_identical_to": "captured_values_sha256 " + (r["captured_values_sha256"] or "?")[:16] + (" (= M5)" if r["captured_values_sha256"] == DIGEST.get(b) else " (MISMATCH)"),
                "receiver_accepted": None, "label": "M", "loadavg_1m": r["loadavg_1m"], "config": f"cpu capture bench {g} {labels[g]}",
                "receipt": f"vectors/reports/rv64-m6-20261105/capture/{b}-capture-m6.json",
                "notes": f"{r['tag']}: init={r['init_s']} first_inputs={r['first_inputs_s']} walk_max={r['walk_s_max']} walk_mips/worker={r['walk_mips_per_worker']} fast={r['walk_fast_retired']}/{r['walk_retired']}"}))
    json.dump(rec, open(f"{outdir}/{b}-capture-m6.json", "w"), indent=1)
