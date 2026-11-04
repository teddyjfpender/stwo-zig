#!/usr/bin/env python3
"""M6 hint-tape: per-node host-prep census from recursion pipeline timelines.

usage: rv64_m6_hint_tape_prep.py RUN_DIR [--log producer.stderr] [--out receipt.json]

RUN_DIR is a resident-daemon run (spool/out/<n>-<block>/<block>/proof/recursion-om31/pipeline.json)
or a bench run (case/batch/trial-0/<block>/proof/recursion-om31/pipeline.json). For every request it
reports, per node kind: prep (prep_start -> prep_end), the prep sub-phases, device stage, the lane wait
before device start, and the fold TAIL (nodes taken after the last leaf finished its device stage):
how much of the tail is host prep vs device. Optional producer.stderr adds the FOLD_SEED_TAPE and
GPU_OUTER_ASSIGNMENT_TIMING lines (tape use, fallbacks, device assignment stream ms per node).
"""
import argparse, json, re, statistics, sys
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


def main():
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
