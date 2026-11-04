#!/usr/bin/env python3
"""sched M6: append progress rows (vectors/reports/progress/sched.jsonl) from rv64-m6-sched-run/v1 receipts.
  python3 scripts/rv64_m6_sched_rows.py --commit SHA --config TEXT --notes TEXT RECEIPT.json [...]"""
import argparse, json
from pathlib import Path
ap = argparse.ArgumentParser()
ap.add_argument("receipts", nargs="+")
ap.add_argument("--commit", required=True)
ap.add_argument("--config", required=True)
ap.add_argument("--notes", default="")
ap.add_argument("--date", default="2026-11-05")
ap.add_argument("--receiver-accepted", choices=("true", "false", "none"), default="none")
args = ap.parse_args()
out = Path("vectors/reports/progress/sched.jsonl")
rows = []
for path in args.receipts:
    r = json.load(open(path))
    for q in r["requests"]:
        s, rec = q["stages"], q["recursion"]
        after = rec.get("recursion_after_native_ns")
        row = {"date": args.date, "commit": args.commit, "stream": "sched", "milestone": "M6", "block": q["block"], "gpus": 2, "label": "M",
               "config": args.config, "request_s": s["request_wall_s"], "capture_s": s["capture_s"], "setup_s": s["setup_s"],
               "native_s": s["native_prove_s"],
               "recursion_s": round(after / 1e9, 3) if after else s["recursion_s"],
               "native_verify_s": 0.0, "fold_tail_s": rec["tail_after_last_leaf_s"],
               "rss_peak_gib": r["service_rss_peak_gib"], "device_peak_gb": max(r["device_peak_gb"].values()),
               "proof_bytes": q["proof_bytes_root"], "nodes": 2 * len(rec.get("leaf_ready_s") or []) - 1 if rec.get("leaf_ready_s") else None,
               "loadavg_1m": r["load_avg_before"][0],
               "byte_identical_to": "M5 default receipts (M3 accepted-v7 parity, all %d proofs)" % q["proof_count"] if q["byte_identical_to_m3"] else None,
               "receipt": str(path), "run": r["run"],
               "notes": (args.notes + "; " if args.notes else "") + "recursion_s = %s; streamed=%s overlap_s=%s" % ("wall after native prove end" if after else "harness recursion_ns (after native publication)", rec["streaming"], rec["native_overlap_s"])}
        acc = [x["accepted"] for x in r.get("receivers", []) if x["block"] == q["block"]]
        if acc: row["receiver_accepted"] = acc[0]
        rows.append({k: v for k, v in row.items() if v is not None})
with out.open("a") as handle:
    for row in rows: handle.write(json.dumps(row) + "\n")
print(len(rows), "rows ->", out)
