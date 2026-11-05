#!/usr/bin/env python3
"""Summarize raw/cap-*.json (CPU capture diagnostic, `capture REQ - 0 RES`) into per-block receipts
and progress rows. Usage: summarize.py [--ledger]   (--ledger appends rows to vectors/reports/progress/capture.jsonl)"""
import glob, json, os, statistics, sys
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "../../../.."))
CODE = "043923ff9"   # code commit the v6 binary was built from (base = 78c3bd5d2, M4 integrate)
BIN = {"base": "78c3bd5d2 (M4 integrate)", "basex": "78c3bd5d2", "basey": "78c3bd5d2", "basez": "78c3bd5d2",
       "v1": "dev (chunked capture + grouping + THP gate)", "v2": "v1 + profile counters", "v3": "v2 + page-cached first touch",
       "v4": "v3 + 16-thread budget", "v5": "v4 + job-nice option", "v6": CODE + " (final: 8-thread budget)", "v6b": CODE + " (v6, control for v7)", "v6c": CODE + " (v6, control for v8)",
       "v7": "candidate: execution-only walk authority (candidates/exec-only-walk-authority.diff), NOT shipped",
       "v8": "candidate: partitioned ALU/BINARY dedup + reserved word census, NOT shipped (no gain)",
       "probe": "v6 + authority timing probe", "probe2": "v6 + prepared phase probe"}
def one(path):
    d = json.load(open(path)); c = d.get("capture") or {}
    ci, dc = c.get("capture_inputs") or {}, c.get("direct_capture") or {}
    sg = dc.get("segments") or {}
    inflight = d["resources"]["capture_options"]["max_inflight_packets"]
    s = lambda ns: None if ns is None else round(ns / 1e9, 4)
    walk = sg.get("walk_ns_total") or 0
    row = {"tag": d["tag"], "binary": d["tag"].split("-")[0], "inflight": inflight, "env": d.get("env", {}), "rc": d["rc"],
           "load1": round(d["loadavg_before"][0], 1), "capture_s": s(c.get("image_and_import_ns")), "init_s": s(ci.get("init_ns")),
           "first_inputs_s": s(ci.get("first_inputs_ns")), "last_inputs_s": s(ci.get("last_inputs_ns")), "ledger_s": s(ci.get("ledger_ns")),
           "ledger_finish_s": s(ci.get("ledger_finish_ns")), "first_batch_captured_s": s(dc.get("first_batch_capture_ns")),
           "segment_ready_s": [s(x) for x in (dc.get("segment_ready_ns") or [])[: dc.get("segments_ready", 0)]] or None,
           "fast_pass_mips": round(sg["first_pass_retired"] / sg["first_pass_ns"] * 1e3, 1) if sg.get("first_pass_ns") else None,
           "traced_walk_mips_per_worker": round(sg["walk_retired"] / walk * 1e3, 2) if walk else None,
           "walk_max_s": s(sg.get("walk_ns_max")), "compact_stall": d.get("vmstat_delta", {}).get("compact_stall"),
           "max_rss_gib": d["max_rss_gib"], "captured_values_sha256": c.get("captured_values_sha256")}
    if walk and sg.get("walk_traced_ns", 0) < 10 * walk:   # v1 had an uninitialised split counter
        row["walk_traced_s"], row["walk_finish_s"] = s(sg.get("walk_traced_ns")), s(sg.get("walk_finish_ns"))
    return d["block"], row
def main():
    blocks = {}
    for p in sorted(glob.glob(os.path.join(HERE, "raw/cap-*.json"))):
        b, r = one(p); blocks.setdefault(b, []).append(r)
    ledger = []
    for b, rows in blocks.items():
        groups = {}
        for r in rows:
            if r["rc"] == 0 and not r["env"]:
                groups.setdefault(f'{r["binary"]}-i{r["inflight"]}', []).append(r)
        med = {k: {"runs": len(v), "median_capture_s": round(statistics.median(x["capture_s"] for x in v), 3),
                   "median_first_inputs_s": round(statistics.median(x["first_inputs_s"] for x in v), 3),
                   "median_ledger_s": round(statistics.median(x["ledger_s"] for x in v), 3),
                   "load1": [x["load1"] for x in v]} for k, v in sorted(groups.items())}
        digests = sorted({r["captured_values_sha256"] for r in rows if r["captured_values_sha256"]})
        out = {"schema": "rv64-m5-capture-cpu-diagnostic/v1", "block": b, "date": "2026-11-04", "code_commit": CODE,
               "binaries": BIN, "measurement": "CPU-only `rv64-word16-ethereum-gkr capture REQ - 0 RES` on the shared 2x5090 pod (48 vCPU quota 40.8); "
               "load1 recorded per run, all >= 8 (not quiet): compare interleaved pairs, not absolute values.",
               "captured_values_sha256": digests, "byte_identical_capture": len(digests) == 1, "groups": med, "runs": rows}
        json.dump(out, open(os.path.join(HERE, f"{b}-capture-m5.json"), "w"), indent=1)
        for r in rows:
            if r["rc"] != 0 or not r["binary"].startswith("v6"):
                continue
            ledger.append({"date": "2026-11-04", "commit": CODE, "stream": "capture", "milestone": "M5", "block": b, "gpus": 0,
                           "request_s": None, "capture_s": r["capture_s"], "setup_s": None, "native_s": None, "recursion_s": None,
                           "verifier_s": None, "rss_peak_gib": r["max_rss_gib"], "device_peak_gb": None, "proof_bytes": None,
                           "byte_identical_to": "captured_values_sha256 " + (r["captured_values_sha256"] or "")[:16], "receiver_accepted": None,
                           "label": "M", "loadavg_1m": r["load1"], "config": f"cpu capture diag inflight={r['inflight']} workers=8",
                           "receipt": f"vectors/reports/rv64-m5-20261104/capture/{b}-capture-m5.json",
                           "notes": f"{r['tag']}: first_inputs={r['first_inputs_s']} ledger={r['ledger_s']} stalls={r['compact_stall']}"})
        print(b, json.dumps(med, indent=0), digests)
    if "--ledger" in sys.argv:
        with open(os.path.join(ROOT, "vectors/reports/progress/capture.jsonl"), "a") as f:
            for row in ledger: f.write(json.dumps(row) + "\n")
        print("appended", len(ledger))
main()
