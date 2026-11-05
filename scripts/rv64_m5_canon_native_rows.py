#!/usr/bin/env python3
"""Progress-ledger rows (rv64-progress-row/v1, vectors/reports/progress/SCHEMA.md) for canon-native daemon receipts.

  python3 scripts/rv64_m5_canon_native_rows.py RECEIPT --commit SHA --config NAME --notes TEXT >> vectors/reports/progress/canon-native.jsonl
"""
import argparse
import json
import time
from pathlib import Path


def rows(receipt, commit, config, notes):
    out = []
    rss = round(receipt["producer_process"].get("peak_rss_bytes", 0) / 2**30, 2)
    peaks = (receipt.get("physical_gpu_memory") or {}).get("peak_used_bytes") or {}
    verdicts = {(v["block"], v.get("trial")): v for v in receipt.get("receivers", [])}
    for r in receipt["requests"]:
        s = r.get("stages") or {}
        v = verdicts.get((r["block"], r["trial"]))
        out.append({"date": time.strftime("%Y-%m-%d"), "commit": commit, "stream": "canon-native", "milestone": "M5",
                    "block": r["block"], "gpus": 2, "request_s": s.get("request_wall_s"), "capture_s": s.get("capture_s"),
                    "setup_s": s.get("setup_s"), "native_s": s.get("native_prove_s"), "recursion_s": s.get("recursion_s"),
                    "verifier_s": round(v["process"]["wall_ns"] / 1e9, 2) if v else None, "rss_peak_gib": rss,
                    "device_peak_gb": round(max(peaks.values()) / 1e9, 2) if peaks else None, "proof_bytes": r.get("proof_bytes_root"),
                    "byte_identical_to": None, "receiver_accepted": v["accepted"] if v else None, "label": "M",
                    "native_verify_s": s.get("native_verify_s"), "loadavg_1m": round(receipt["load_avg_before"][0], 2),
                    "config": f"{config}; service position {r['ordinal']}; store {receipt['store']['mode']}", "run": Path(receipt["run"]).name, "notes": notes})
    return out


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("receipt")
    p.add_argument("--commit", required=True)
    p.add_argument("--config", required=True)
    p.add_argument("--notes", default="")
    a = p.parse_args()
    for row in rows(json.load(open(a.receipt)), a.commit, a.config, a.notes):
        print(json.dumps(row, sort_keys=True))


if __name__ == "__main__":
    main()
