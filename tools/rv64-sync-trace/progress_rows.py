#!/usr/bin/env python3
"""Append enqueue progress rows (rv64-progress-row/v1) from a daemon receipt + optional sync-trace windows.

  python3 progress_rows.py DAEMON_RECEIPT.json --commit SHA --receipt-path vectors/... [--windows W.json]
         [--config "..."] [--notes "..."] [--trial-index-from N]

One row per request (block, trial). `syncs` / `launches` are the RECURSION-WINDOW blocking calls / kernel launches
from the tracer when --windows is given (per request, not per process), and `nodes` the recursion node count.
"""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
LEDGER = ROOT / "vectors/reports/progress/enqueue.jsonl"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("receipt")
    ap.add_argument("--commit", required=True)
    ap.add_argument("--receipt-path", required=True)
    ap.add_argument("--windows")
    ap.add_argument("--config", default="resident service (combined-serve), DEFAULT_PRODUCER_ENV")
    ap.add_argument("--notes", default="")
    ap.add_argument("--date", default="2026-11-05")
    ap.add_argument("--skip-first", action="store_true", help="drop each block's first (seed) request")
    args = ap.parse_args()
    d = json.loads(Path(args.receipt).read_text())
    windows = json.loads(Path(args.windows).read_text())["requests"] if args.windows else []
    load = (d.get("load_avg_before") or [None])[0]
    peak = d.get("physical_gpu_memory", {}).get("peak_used_bytes", {})
    device_peak = round(max(peak.values()) / 1e9, 3) if peak else None
    rss = round(d["producer_process"]["peak_rss_bytes"] / 2**30, 3)
    accepted = {}
    for r in d.get("receivers") or []:
        accepted[(r.get("block"), r.get("trial", r.get("ordinal")))] = r.get("accepted")
    seen = set()
    rows = []
    for i, r in enumerate(d["requests"]):
        first = r["block"] not in seen
        seen.add(r["block"])
        if args.skip_first and first:
            continue
        st = r["stages"]
        parity = r.get("parity_vs_m3", {})
        row = {"date": args.date, "commit": args.commit, "stream": "enqueue", "milestone": "M6", "block": r["block"], "gpus": 2,
               "label": "M", "request_s": st["request_wall_s"], "capture_s": st["capture_s"], "setup_s": st["setup_s"],
               "native_s": st["native_prove_s"], "recursion_s": st["recursion_s"], "rss_peak_gib": rss, "device_peak_gb": device_peak,
               "proof_bytes": r.get("proof_bytes_root"), "loadavg_1m": round(load, 1) if load is not None else None,
               "byte_identical_to": "M5 default = rv64-m3-20261104/integrate/scale (all hashes)" if parity.get("byte_identical") else "NOT byte-identical",
               "config": args.config + f"; request {i} ({'seed' if first else 'warm'})", "receipt": args.receipt_path, "run": d["run"]}
        # window.py emits one row per request in receipt order
        w = windows[i] if len(windows) == len(d["requests"]) and windows[i]["block"] == r["block"] else None
        if w:
            row["syncs"] = w["recursion"]["blocking_total"]
            row["launches"] = w["recursion"]["kinds"].get("launch", 0)
            row["nodes"] = w["nodes"]
        acc = accepted.get((r["block"], r.get("trial")))
        if acc is not None:
            row["receiver_accepted"] = acc
        row["notes"] = args.notes + ("" if not w else f" Recursion window (tracer): {w['recursion']['blocking_per_node']} blocking/node, {w['recursion']['launches_per_node']} launches/node.")
        rows.append({k: v for k, v in row.items() if v is not None})
    with LEDGER.open("a") as f:
        for row in rows:
            f.write(json.dumps(row, separators=(",", ":")) + "\n")
    print(f"appended {len(rows)} rows to {LEDGER.relative_to(ROOT)}")


if __name__ == "__main__":
    main()
