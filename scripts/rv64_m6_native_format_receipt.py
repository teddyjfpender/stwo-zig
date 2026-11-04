#!/usr/bin/env python3
"""Stream native-format (M6) receipt: one compact JSON + .md per harness run.

  python3 scripts/rv64_m6_native_format_receipt.py RUN_DIR --what WHAT --out DIR [--control RUN_DIR] [--notes TEXT]

Reads the harness run (receipt.json, receipt-v2.json when present, case/producer.stderr, the newest
receiver-*/ verdict) and writes <out>/<block>-<what>.json/.md with: stages, native committed cells per
tree (FIXED/MAIN/INTER words of the first n_native GPU_TRACE_OWNERSHIP lines per tree = the native
proofs, which commit before any recursion node), the RV64_NATIVE_CHAIN class lines, proof bytes,
device/RSS peaks, receiver verdict, load average. With --control it adds the same numbers of a control
run (e.g. the M5 default flat run on the same binaries) and the deltas. Standard library only.
"""
import argparse
import json
import re
from pathlib import Path


def load(p):
    return json.loads(Path(p).read_text())


def tree_words(stderr, n_native):
    by_tree = {0: [], 1: [], 2: []}
    for line in stderr.splitlines():
        m = re.match(r"GPU_TRACE_OWNERSHIP tree=(\d) coefficient_words=(\d+)", line)
        if m and int(m.group(1)) in by_tree:
            by_tree[int(m.group(1))].append(int(m.group(2)))
    return {f"tree{t}": sum(v[:n_native]) for t, v in by_tree.items()}, {f"tree{t}_count": len(v) for t, v in by_tree.items()}


def chain_lines(stderr):
    out, seen = [], set()
    for line in stderr.splitlines():
        m = re.match(r"RV64_NATIVE_CHAIN version=(\S+) ordinal=(\d+) family=(\d+) rung=(\d+) vkhash=([0-9a-f]+)", line)
        if m and m.group(2) not in seen:
            seen.add(m.group(2))
            out.append({"version": m.group(1), "ordinal": int(m.group(2)), "family": int(m.group(3)), "rung": int(m.group(4)), "vkhash": m.group(5)})
    return out


def summarize(run):
    run = Path(run)
    r = load(run / "receipt.json")
    v2 = load(run / "receipt-v2.json") if (run / "receipt-v2.json").is_file() else {}
    stderr = (run / "case/producer.stderr").read_text(errors="replace")
    native = r.get("recursion", {}).get("counters", {}).get("recursive_report", {})
    n_native = native.get("leaf_proofs") or 0
    words, counts = tree_words(stderr, n_native)
    receivers = sorted(run.glob("receiver-*/verdict.json")) or sorted(run.glob("receiver-*/receiver.json"))
    verdict = r.get("receiver")
    out = {
        "run": str(run), "block": r["block"], "gpus": r["gpus"], "source_commit": r.get("source_commit"),
        "environment_overrides": r.get("environment_overrides"), "assets": r.get("assets"),
        "loadavg_1m_start": r.get("loadavg", {}).get("start", {}).get("1m"), "loadavg_1m_end": r.get("loadavg", {}).get("end", {}).get("1m"),
        "stages": r.get("stages"),
        "native_proofs": n_native,
        "native_committed_words": words, "trace_ownership_lines": counts,
        "proof_bytes_root": native.get("root_proof_bytes"),
        "root_digest": bytes(native.get("root_digest", [])).hex(), "manifest": bytes(native.get("manifest", [])).hex(),
        "root_sha256": (r.get("parity_vs_accepted_v7") or {}).get("root_sha256"),
        "producer_peak_rss_gib": round((r.get("producer_process") or {}).get("peak_rss_bytes", 0) / 2**30, 3) if r.get("producer_process") else (v2.get("ram") or {}).get("rss_peak_daemon_gib"),
        "device_peak_gb": (v2.get("device_memory") or {}).get("device_peak_gb"),
        "verifier": v2.get("verifier"),
        "receiver": {k: verdict.get(k) for k in ("status", "accepted", "error", "receiver_sha256")} if isinstance(verdict, dict) else verdict,
        "chain": chain_lines(stderr),
    }
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run")
    ap.add_argument("--what", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--control")
    ap.add_argument("--notes", default="")
    a = ap.parse_args()
    s = summarize(a.run)
    rec = {"schema": "rv64-m6-native-format-receipt/v1", "label": "M (single observation)", "notes": a.notes, "run": s}
    if a.control:
        c = summarize(a.control)
        rec["control"] = c
        d = {}
        for k in ("tree0", "tree1", "tree2"):
            x, y = s["native_committed_words"][k], c["native_committed_words"][k]
            d[f"native_{k}_words"] = {"v2": x, "control": y, "ratio": round(x / y, 4) if y else None}
        for k in ("request_wall_s", "native_prove_s", "recursion_s", "setup_s", "capture_s"):
            x, y = (s["stages"] or {}).get(k), (c["stages"] or {}).get(k)
            d[k] = {"v2": x, "control": y}
        d["proof_bytes_root"] = {"v2": s["proof_bytes_root"], "control": c["proof_bytes_root"]}
        rec["delta"] = d
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    stem = f"{s['block']}-{a.what}"
    (out / f"{stem}.json").write_text(json.dumps(rec, indent=1) + "\n")
    st = s["stages"] or {}
    lines = [f"# {stem}", "", f"run `{s['run']}` @ {s['source_commit']}, load {s['loadavg_1m_start']}->{s['loadavg_1m_end']} (single observation [M])", "",
             f"- request {st.get('request_wall_s')} s; capture {st.get('capture_s')}; setup {st.get('setup_s')}; native {st.get('native_prove_s')} (verify {st.get('native_verify_s')}); recursion {st.get('recursion_s')}",
             f"- native committed words FIXED/MAIN/INTER: {s['native_committed_words']}",
             f"- root proof bytes {s['proof_bytes_root']}; receiver {s['receiver']}"]
    if a.control:
        lines.append(f"- vs control: {json.dumps(rec['delta'])}")
    if a.notes:
        lines += ["", a.notes]
    (out / f"{stem}.md").write_text("\n".join(lines) + "\n")
    print(json.dumps({"written": str(out / f"{stem}.json"), "delta": rec.get("delta")}, indent=1))


if __name__ == "__main__":
    main()
