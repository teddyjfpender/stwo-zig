#!/usr/bin/env python3
"""M6 hint-tape: per-node host-prep census from recursion pipeline timelines.

usage: rv64_m6_hint_tape_prep.py RUN_DIR [--log producer.stderr] [--out receipt.json]
       rv64_m6_hint_tape_prep.py ledger DAEMON_RECEIPT PREP_JSON --commit C --notes N [--trials 1] >> vectors/reports/progress/hint-tape.jsonl

RUN_DIR is a resident-daemon run (spool/out/<n>-<block>/<block>/proof/recursion-om31/pipeline.json)
or a bench run (case/batch/trial-0/<block>/proof/recursion-om31/pipeline.json). For every request it
reports, per node kind: prep (prep_start -> prep_end), the prep sub-phases, device stage, the lane wait
before device start, and the fold TAIL (nodes taken after the last leaf finished its device stage):
how much of the tail is host prep vs device. Optional producer.stderr adds the FOLD_SEED_TAPE and
GPU_OUTER_ASSIGNMENT_TIMING lines (tape use, fallbacks, device assignment stream ms per node).
"""
import argparse, json, re, statistics, sys, time
from pathlib import Path


def med(xs):
    return round(statistics.median(xs), 4) if xs else None


def node_rows(pipeline):
    rows = []
    for n in pipeline["nodes"]:
        s = n["stamps"]
        rows.append({
            "id": n["id"], "kind": n["kind"], "lane": n["lane"], "leaf_count": n["leaf_count"],
            "taken_s": s["taken"] / 1e9, "prep_s": (s["prep_end"] - s["prep_start"]) / 1e9,
            "wait_s": (s["device_start"] - s["prep_end"]) / 1e9, "device_s": (s["device_end"] - s["device_start"]) / 1e9,
            "device_end_s": s["device_end"] / 1e9, "finish_s": (s["finish_end"] - s["finish_start"]) / 1e9,
            "graph_s": n["graph_ns"] / 1e9, "finalize_s": n["finalize_ns"] / 1e9, "columns_s": n["columns_ns"] / 1e9,
            "host_plan_s": n["host_plan_ns"] / 1e9, "variables": n["variables"]})
    return rows


def summarize(pipeline):
    rows = node_rows(pipeline)
    out = {"dag_wall_s": round(pipeline["dag_wall_ns"] / 1e9, 3), "nodes": len(rows)}
    for kind in ("leaf", "fold"):
        k = [r for r in rows if r["kind"] == kind]
        out[kind] = {f"{key}_median": med([r[key] for r in k]) for key in ("prep_s", "graph_s", "finalize_s", "columns_s", "host_plan_s", "device_s", "wait_s", "finish_s")}
        out[kind]["prep_max"] = round(max(r["prep_s"] for r in k), 4) if k else None
        out[kind]["prep_sum_s"] = round(sum(r["prep_s"] for r in k), 3)
        out[kind]["count"] = len(k)
    last_leaf = max(r["device_end_s"] for r in rows if r["kind"] == "leaf")
    tail = sorted((r for r in rows if r["kind"] == "fold" and r["taken_s"] >= last_leaf), key=lambda r: r["taken_s"])
    out["tail"] = {"after_last_leaf_s": round(pipeline["dag_wall_ns"] / 1e9 - last_leaf, 3), "folds": len(tail),
                   "prep_sum_s": round(sum(r["prep_s"] for r in tail), 3), "device_sum_s": round(sum(r["device_s"] for r in tail), 3),
                   "finish_sum_s": round(sum(r["finish_s"] for r in tail), 3), "ids": [r["id"] for r in tail]}
    out["first_device_start_s"] = round(min(r["taken_s"] + r["prep_s"] + r["wait_s"] for r in rows), 3)
    return out


def log_census(path):
    text = Path(path).read_text(errors="replace")
    used = [dict(kv.split("=", 1) for kv in line.split()[2:]) for line in text.splitlines() if line.startswith("FOLD_SEED_TAPE used")]
    timing = [dict(kv.split("=", 1) for kv in line.split()[1:] if "=" in kv) for line in text.splitlines() if line.startswith("GPU_OUTER_ASSIGNMENT_TIMING")]
    return {"tape_used": len(used), "tape_fallbacks": text.count("FOLD_SEED_TAPE fallback"),
            "tape_check_ok": text.count("FOLD_SEED_TAPE check_ok"), "tape_check_mismatch": text.count("FOLD_SEED_TAPE check_mismatch"),
            "tape_refused": re.findall(r"GPU_OUTER_SEED_TAPE refused=(\S+)", text), "constants_unstable": text.count("constants_unstable"),
            "tape_prep_ms_median": med([int(u["prep_ns"]) / 1e6 for u in used]),
            "tape_record_ms_median": med([int(u["record_ns"]) / 1e6 for u in used]),
            "tape_authority_ms_median": med([int(u["authority_ns"]) / 1e6 for u in used]),
            "tape_plan_ms_median": med([int(u["plan_ns"]) / 1e6 for u in used]),
            "assignment_levels_stream_ms": {"fold_like_median": med([float(t["levels_stream_ms"]) for t in timing if int(t["launches"]) < 2500]),
                                             "leaf_like_median": med([float(t["levels_stream_ms"]) for t in timing if int(t["launches"]) >= 2500]),
                                             "count": len(timing)}}


def ledger(argv):
    """Progress rows (SCHEMA.md v1 keys) for the requests of a resident-daemon receipt + its prep census."""
    p = argparse.ArgumentParser()
    p.add_argument("receipt")
    p.add_argument("prep")
    p.add_argument("--commit", required=True)
    p.add_argument("--notes", default="")
    p.add_argument("--trials", type=int, nargs="*", help="only these service trials (default: all)")
    p.add_argument("--byte-identical-to", default="M3 integrate scale receipts (= M5 default)")
    args = p.parse_args(argv)
    receipt = json.loads(Path(args.receipt).read_text())
    prep = json.loads(Path(args.prep).read_text())
    census = {r["request"]: r for r in prep["requests"]}
    verdicts = {(v["block"], v.get("trial")): v for v in receipt.get("receivers", [])}
    peaks = (receipt.get("physical_gpu_memory") or {}).get("peak_used_bytes") or {}
    for r in receipt["requests"]:
        if args.trials and r["trial"] not in args.trials:
            continue
        s = r.get("stages") or {}
        v = verdicts.get((r["block"], r["trial"]))
        c = census.get(f"{r['ordinal']:04d}-{r['block']}", {})
        row = {"date": time.strftime("%Y-%m-%d"), "commit": args.commit, "stream": "hint-tape", "milestone": "M6",
               "block": r["block"], "gpus": 2, "request_s": s.get("request_wall_s"), "capture_s": s.get("capture_s"),
               "setup_s": s.get("setup_s"), "native_s": s.get("native_prove_s"), "recursion_s": s.get("recursion_s"),
               "verifier_s": round(v["process"]["wall_ns"] / 1e9, 2) if v else None,
               "rss_peak_gib": round(receipt["producer_process"].get("peak_rss_bytes", 0) / 2**30, 2),
               "device_peak_gb": round(max(peaks.values()) / 1e9, 2) if peaks else None,
               "proof_bytes": r.get("proof_bytes_root"),
               "byte_identical_to": args.byte_identical_to if (r.get("parity_vs_m3") or {}).get("byte_identical") else None,
               "receiver_accepted": v["accepted"] if v else None, "label": "M",
               "loadavg_1m": round(receipt["load_avg_before"][0], 1), "fold_tail_s": (c.get("tail") or {}).get("after_last_leaf_s"),
               "config": f"resident daemon warm={r['trial'] > 0} trial={r['trial']} store={receipt['store'].get('mode')}",
               "host_prep_fold_median_s": (c.get("fold") or {}).get("prep_s_median"),
               "host_prep_fold_max_s": (c.get("fold") or {}).get("prep_max"),
               "host_prep_leaf_median_s": (c.get("leaf") or {}).get("prep_s_median"),
               "fold_tail_host_prep_s": (c.get("tail") or {}).get("prep_sum_s"),
               "run": Path(receipt["run"]).name, "receipt": str(args.receipt), "notes": args.notes}
        print(json.dumps(row, sort_keys=True))


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "ledger":
        return ledger(sys.argv[2:])
    p = argparse.ArgumentParser()
    p.add_argument("run")
    p.add_argument("--log")
    p.add_argument("--out")
    args = p.parse_args()
    run = Path(args.run)
    files = sorted(run.glob("spool/out/*/*/proof/recursion-om31/pipeline.json")) or sorted(run.glob("case/batch/trial-*/*/proof/recursion-om31/pipeline.json"))
    if not files:
        sys.exit(f"no pipeline.json under {run}")
    result = {"schema": "rv64-m6-hint-tape-prep/v1", "run": str(run), "requests": []}
    for f in files:
        result["requests"].append({"request": f.parts[-5] if "spool" in f.parts else f.parts[-4], "block": int(f.parts[-4]),
                                   **summarize(json.loads(f.read_text()))})
    log = Path(args.log) if args.log else run / "producer.stderr"
    if log.is_file():
        result["log"] = log_census(log)
    text = json.dumps(result, indent=1)
    if args.out:
        Path(args.out).write_text(text + "\n")
    print(text)


if __name__ == "__main__":
    main()
