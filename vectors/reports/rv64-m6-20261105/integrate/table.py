#!/usr/bin/env python3
"""Per-request table from rv64_m4_resident daemon receipts (and bench receipts).

usage: table.py RECEIPT.json [...]   -> one line per request + a JSON dump of the rows on stdout (--json)
"""
import json
import sys
from pathlib import Path


def tail_after_last_leaf(req):
    for key in ("pipeline", "recursion_pipeline"):
        p = req.get(key)
        if isinstance(p, dict) and "tail_after_last_leaf_ns" in p:
            return p["tail_after_last_leaf_ns"] / 1e9
    run = req.get("proof")
    if run:
        for cand in Path(run).parent.rglob("pipeline.json") if Path(run).exists() else []:
            try:
                d = json.load(open(cand))
                if "tail_after_last_leaf_ns" in d:
                    return d["tail_after_last_leaf_ns"] / 1e9
            except Exception:
                pass
    return None


def sidecar(path):
    """<receipt>.tails.json: {"<block>/<trial>": tail_s} saved on the pod (pipeline.json lives in the run spool)."""
    p = Path(str(path).replace(".json", ".tails.json"))
    return json.load(open(p)) if p.exists() else {}


def rows(path):
    d = json.load(open(path))
    tails = sidecar(path)
    out = []
    peak = d.get("physical_gpu_memory", {}).get("peak_used_bytes", {})
    busy = d.get("physical_gpu_memory", {}).get("kernel_activity", {})
    proc = d.get("producer_process", {})
    recv = {}
    for r in d.get("receivers", []) or []:
        recv[(r.get("block"), r.get("trial"))] = r
    for q in d.get("requests", []):
        st = q.get("stages", {})
        par = q.get("parity_vs_m3", {}) or {}
        rv = recv.get((q.get("block"), q.get("trial")), {})
        out.append({
            "receipt": str(path), "tag": d.get("run", "").rsplit("-", 1)[-1], "block": q.get("block"), "trial": q.get("trial"),
            "request_s": st.get("request_wall_s"), "capture_s": st.get("capture_s"), "setup_s": st.get("setup_s"),
            "native_s": st.get("native_prove_s"), "native_verify_s": st.get("native_verify_s"),
            "recursion_s": st.get("recursion_s"), "tail_s": tails.get(f"{q.get('block')}/{q.get('trial')}", tail_after_last_leaf(q)),
            "proof_bytes_root": q.get("proof_bytes_root"), "byte_identical": par.get("byte_identical"),
            "receiver": rv.get("status") or rv.get("accepted"), "receiver_wall_s": round(rv["process"]["wall_ns"] / 1e9, 1) if rv.get("process") else None,
            "leaves": q.get("leaves"),
            "rss_peak_gib": round(proc.get("peak_rss_bytes", 0) / 2**30, 2) if proc else None,
            "device_peak_gb": round(max(peak.values()) / 1e9, 2) if peak else None,
            "gpu_busy_nvml_pct": round(sum(v.get("mean_percent", 0) for v in busy.values()) / max(len(busy), 1), 1) if busy else None,
            "load_before": (d.get("load_avg_before") or [None])[0], "load_after": (d.get("load_avg_after") or [None])[0],
        })
    return out


def main():
    as_json = "--json" in sys.argv
    allrows = []
    for p in [a for a in sys.argv[1:] if not a.startswith("--")]:
        allrows += rows(p)
    if as_json:
        print(json.dumps(allrows, indent=1))
        return
    cols = ["tag", "block", "trial", "request_s", "capture_s", "setup_s", "native_s", "recursion_s", "tail_s",
            "proof_bytes_root", "byte_identical", "receiver", "rss_peak_gib", "device_peak_gb", "gpu_busy_nvml_pct", "load_before"]
    print("\t".join(cols))
    for r in allrows:
        print("\t".join(str(r.get(c)) for c in cols))


if __name__ == "__main__":
    main()


def write_sidecar(receipt_on_pod, out):
    json.dump({f"{r['block']}/{r['trial']}": r["tail_s"] for r in rows(receipt_on_pod)}, open(out, "w"), indent=1)
