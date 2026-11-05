#!/usr/bin/env python3
"""Progress-ledger rows (rv64-progress-row/v1) from M6 integrate receipts (local copies under this directory).

usage: make_rows.py COMMIT CONFIG_NOTE RECEIPT.json [...] >> vectors/reports/progress/integrate.jsonl
Daemon receipts give one row per request; bench receipts one row.
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import table  # noqa: E402


def bench_row(path, d):
    st = d["stages"]
    rv = d.get("receiver", {})
    proc = rv.get("process", {})
    return {
        "block": d["block"], "request_s": st.get("request_wall_s"), "capture_s": st.get("capture_s"), "setup_s": st.get("setup_s"),
        "native_s": st.get("native_prove_s"), "native_verify_s": st.get("native_verify_s"), "recursion_s": st.get("recursion_s"),
        "verifier_s": round(proc["wall_ns"] / 1e9, 2) if proc.get("wall_ns") else None, "receiver_accepted": rv.get("accepted"),
        "config": "one-shot bench (cold setup)",
    }


def main():
    commit, note, paths = sys.argv[1], sys.argv[2], sys.argv[3:]
    for p in paths:
        d = json.load(open(p))
        rel = str(Path(p).resolve().relative_to(HERE.parents[3])) if str(Path(p).resolve()).startswith(str(HERE.parents[3])) else p
        if d.get("schema", "").startswith("rv64-m4-resident-daemon"):
            recv = {(r.get("block"), r.get("trial")): r for r in d.get("receivers") or []}
            for r in table.rows(p):
                rv = recv.get((r["block"], r["trial"]), {})
                row = {
                    "date": "2026-11-05", "commit": commit, "stream": "integrate", "milestone": "M6", "block": r["block"], "gpus": 2,
                    "request_s": r["request_s"], "capture_s": r["capture_s"], "setup_s": r["setup_s"], "native_s": r["native_s"],
                    "native_verify_s": r["native_verify_s"], "recursion_s": r["recursion_s"],
                    "fold_tail_s": round(r["tail_s"], 3) if r["tail_s"] is not None else None,
                    "verifier_s": r["receiver_wall_s"], "receiver_accepted": (rv.get("status") == "accepted") if rv else None,
                    "rss_peak_gib": r["rss_peak_gib"], "device_peak_gb": r["device_peak_gb"], "proof_bytes": r["proof_bytes_root"],
                    "byte_identical_to": "M3 integrate scale receipts (= M5 default)" if r["byte_identical"] else None,
                    "loadavg_1m": round(r["load_before"], 1) if r["load_before"] is not None else None,
                    "config": f"resident daemon store=none trial={r['trial']} ({'cold setup' if r['trial'] == 0 else 'warm'})",
                    "label": "M", "receipt": rel, "notes": note,
                }
                print(json.dumps({k: v for k, v in row.items() if v is not None}, sort_keys=True))
        else:
            b = bench_row(p, d)
            row = dict(date="2026-11-05", commit=commit, stream="integrate", milestone="M6", gpus=2, label="M", receipt=rel, notes=note, **b)
            print(json.dumps({k: v for k, v in row.items() if v is not None}, sort_keys=True))


if __name__ == "__main__":
    main()
