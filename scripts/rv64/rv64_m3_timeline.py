#!/usr/bin/env python3
"""Summarise where request wall time goes for one rv64_m3_pod.py run.

Inputs (all optional except the run directory):
  case/producer.stderr   RECURSION_NODE_TIMELINE lines (per node, per lane, CLOCK_REALTIME ns)
                         plus the per-node phase records already emitted by the driver
  case/batch/.../proof/{report,combined-report}.json   request stage walls
  nsys/timeline.sqlite   Nsight Systems export: per-device kernel/memcpy busy and idle gaps

  python3 rv64_m3_timeline.py RUN_DIR [--out timeline.json]
"""
import argparse
import json
from pathlib import Path
import re
import sqlite3
import statistics

NODE = re.compile(r"RECURSION_NODE_TIMELINE (.*)")
KV = re.compile(r"(\w+)=([^\s]+)")
PHASES = {  # record prefix -> fields summed across all nodes (ns unless *_ms)
    "CUDA_OUTER_PREPROCESS": ("finalize_ns", "columns_ns", "authority_ns", "total_ns"),
    "GPU_OUTER_ASSIGNMENT_PLAN": ("plan_ns", "seeds_ns", "tasks_ns", "dependency_walk_ns", "ordering_ns", "task_pack_ns", "seed_pack_ns", "hash_ns"),
    "GPU_OUTER_ASSIGNMENT_TIMING": ("total_ns", "static_ingress_ns", "levels_enqueue_ns", "levels_join_ns", "launches"),
    "GPU_PCS_NATIVE": ("prepare_ns", "device_ns", "total_ns"),
    "GPU_COMPOSITION_TIMING": ("domain_fft_ms", "rows_ms", "finalize_ms", "commit_fft_ms", "commit_hash_ms", "gpu_enqueued_kernel_spans_ms"),
}


def parse_value(value):
    try:
        return int(value)
    except ValueError:
        try:
            return float(value)
        except ValueError:
            return {"true": True, "false": False}.get(value, value)


def records(text):
    nodes, phases = [], {k: {f: 0 for f in v} | {"count": 0} for k, v in PHASES.items()}
    for line in text.splitlines():
        m = NODE.search(line)
        if m:
            nodes.append({k: parse_value(v) for k, v in KV.findall(m[1])})
            continue
        body = line[6:] if line.startswith("info: ") else line
        for prefix, fields in PHASES.items():
            if body.startswith(prefix + " "):
                values = dict(KV.findall(body))
                phases[prefix]["count"] += 1
                for f in fields:
                    if f in values:
                        phases[prefix][f] += parse_value(values[f])
    return nodes, phases


def lane_view(nodes):
    if not nodes:
        return None
    t0 = min(n["taken_unix_ns"] for n in nodes)
    t1 = max(n["published_unix_ns"] for n in nodes)
    lanes = {}
    for n in sorted(nodes, key=lambda n: n["taken_unix_ns"]):
        n["start_s"] = round((n["taken_unix_ns"] - t0) / 1e9, 3)
        n["end_s"] = round((n["published_unix_ns"] - t0) / 1e9, 3)
        n["span_s"] = round(n["end_s"] - n["start_s"], 3)
        lanes.setdefault(n["lane"], []).append(n)
    summary = {}
    for lane, items in sorted(lanes.items()):
        busy = sum(n["published_unix_ns"] - n["taken_unix_ns"] for n in items)
        gaps = [b["taken_unix_ns"] - a["published_unix_ns"] for a, b in zip(items, items[1:])]
        summary[lane] = {"device": items[0]["device"], "nodes": len(items), "busy_s": round(busy / 1e9, 3),
                         "idle_between_nodes_s": round(sum(gaps) / 1e9, 3), "max_gap_s": round(max(gaps, default=0) / 1e9, 3),
                         "tail_idle_s": round((t1 - items[-1]["published_unix_ns"]) / 1e9, 3),
                         "graph_s": round(sum(n["graph_ns"] for n in items) / 1e9, 3),
                         "wrap_s": round(sum(n["wrap_ns"] for n in items) / 1e9, 3),
                         "serialize_s": round(sum(n["serialize_ns"] for n in items) / 1e9, 3),
                         "write_s": round(sum(n["write_ns"] for n in items) / 1e9, 3)}
    kinds = {}
    for kind in ("leaf", "fold"):
        spans = [n["span_s"] for n in nodes if n["kind"] == kind]
        if spans:
            kinds[kind] = {"count": len(spans), "mean_s": round(statistics.mean(spans), 3), "max_s": max(spans), "min_s": min(spans),
                           "graph_mean_s": round(statistics.mean(n["graph_ns"] for n in nodes if n["kind"] == kind) / 1e9, 3),
                           "wrap_mean_s": round(statistics.mean(n["wrap_ns"] for n in nodes if n["kind"] == kind) / 1e9, 3)}
    # Fold-tail: time from the last leaf's completion to the root publication.
    last_leaf = max(n["published_unix_ns"] for n in nodes if n["kind"] == "leaf")
    return {"recursion_span_s": round((t1 - t0) / 1e9, 3), "fold_tail_after_last_leaf_s": round((t1 - last_leaf) / 1e9, 3),
            "t0_unix_ns": t0, "lanes": summary, "kinds": kinds,
            "nodes": [{k: n[k] for k in ("node", "kind", "first_leaf", "leaf_count", "lane", "device", "start_s", "end_s", "span_s")}
                      | {"graph_s": round(n["graph_ns"] / 1e9, 3), "wrap_s": round(n["wrap_ns"] / 1e9, 3)} for n in sorted(nodes, key=lambda n: n["node"])]}


def union(intervals):
    total, end = 0, None
    for s, e in sorted(intervals):
        if end is None or s > end:
            total += e - s
            end = e
        elif e > end:
            total += e - end
            end = e
    return total


def merged(intervals):
    out = []
    for s, e in sorted(intervals):
        if out and s <= out[-1][1]:
            out[-1][1] = max(out[-1][1], e)
        else:
            out.append([s, e])
    return out


def busy_within(merged_list, lo, hi):
    import bisect
    starts = [s for s, _ in merged_list]
    i = max(bisect.bisect_right(starts, lo) - 1, 0)
    total = 0
    while i < len(merged_list) and merged_list[i][0] < hi:
        s, e = merged_list[i]
        total += max(0, min(e, hi) - max(s, lo))
        i += 1
    return total


def node_gpu_busy(path, nodes):
    """Per recursive node: device-busy seconds (kernels+memcpy) inside [taken, published]."""
    db = sqlite3.connect(str(path))
    cur = db.cursor()
    base = cur.execute("select utcEpochNs from TARGET_INFO_SESSION_START_TIME").fetchone()[0]
    per = {}
    for d, s, e in cur.execute("select deviceId,start,end from CUPTI_ACTIVITY_KIND_KERNEL"):
        per.setdefault(d, []).append((s + base, e + base))
    for d, s, e in cur.execute("select deviceId,start,end from CUPTI_ACTIVITY_KIND_MEMCPY"):
        per.setdefault(d, []).append((s + base, e + base))
    lists = {d: merged(v) for d, v in per.items()}
    out = []
    for n in nodes:
        busy = busy_within(lists.get(n["device"], []), n["taken_unix_ns"], n["published_unix_ns"])
        span = n["published_unix_ns"] - n["taken_unix_ns"]
        out.append({"node": n["node"], "kind": n["kind"], "device": n["device"], "span_s": round(span / 1e9, 3),
                    "gpu_busy_s": round(busy / 1e9, 3), "host_only_s": round((span - busy) / 1e9, 3)})
    return out


def nsys_view(path, windows):
    db = sqlite3.connect(str(path))
    cur = db.cursor()
    tables = {r[0] for r in cur.execute("select name from sqlite_master where type='table'")}
    base = 0
    if "TARGET_INFO_SESSION_START_TIME" in tables:
        base = cur.execute("select utcEpochNs from TARGET_INFO_SESSION_START_TIME").fetchone()[0]
    out = {"session_epoch_ns": base, "devices": {}}
    kernels = cur.execute("select deviceId,start,end,shortName from CUPTI_ACTIVITY_KIND_KERNEL").fetchall() if "CUPTI_ACTIVITY_KIND_KERNEL" in tables else []
    copies = cur.execute("select deviceId,start,end,bytes,copyKind from CUPTI_ACTIVITY_KIND_MEMCPY").fetchall() if "CUPTI_ACTIVITY_KIND_MEMCPY" in tables else []
    names = dict(cur.execute("select id,value from StringIds").fetchall()) if "StringIds" in tables else {}
    for device in sorted({k[0] for k in kernels}):
        ks = [(s + base, e + base) for d, s, e, _ in kernels if d == device]
        cs = [(s + base, e + base) for d, s, e, _, _ in copies if d == device]
        info = {"kernels": len(ks), "kernel_sum_s": round(sum(e - s for s, e in ks) / 1e9, 3),
                "kernel_busy_union_s": round(union(ks) / 1e9, 3), "memcpy_busy_union_s": round(union(cs) / 1e9, 3),
                "any_busy_union_s": round(union(ks + cs) / 1e9, 3), "first_s": None, "windows": {}}
        if ks:
            info["first_unix_ns"], info["last_unix_ns"] = min(s for s, _ in ks), max(e for _, e in ks)
        for name, (lo, hi) in windows.items():
            clip = [(max(s, lo), min(e, hi)) for s, e in ks + cs if e > lo and s < hi]
            span = hi - lo
            busy = union(clip)
            info["windows"][name] = {"span_s": round(span / 1e9, 3), "gpu_busy_s": round(busy / 1e9, 3),
                                     "gpu_busy_fraction": round(busy / span, 3) if span > 0 else None}
        out["devices"][device] = info
    totals = {}
    for _, s, e, n in kernels:
        name = names.get(n, str(n))
        t = totals.setdefault(name, [0, 0])
        t[0] += e - s
        t[1] += 1
    out["top_kernels"] = [{"name": k[:120], "total_s": round(v[0] / 1e9, 3), "calls": v[1]} for k, v in sorted(totals.items(), key=lambda kv: -kv[1][0])[:25]]
    if "CUPTI_ACTIVITY_KIND_RUNTIME" in tables:
        rows = cur.execute("select r.nameId, sum(r.end-r.start), count(*) from CUPTI_ACTIVITY_KIND_RUNTIME r group by r.nameId order by 2 desc limit 15").fetchall()
        out["top_runtime_api"] = [{"name": names.get(n, str(n)), "total_s": round(t / 1e9, 3), "calls": c} for n, t, c in rows]
    return out


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("run", type=Path)
    parser.add_argument("--out", type=Path)
    args = parser.parse_args()
    case = args.run / "case"
    text = (case / "producer.stderr").read_text(errors="replace") + (case / "producer.stdout").read_text(errors="replace")
    nodes, phases = records(text)
    result = {"schema": "rv64-m3-timeline/v1", "label": "measured", "run": str(args.run)}
    receipt = args.run / "receipt.json"
    if receipt.is_file():
        r = json.loads(receipt.read_text())
        result.update(block=r.get("block"), gpus=r.get("gpus"), stages=r.get("stages"), nsys_overhead_present=r.get("nsys"))
    result["recursion_lanes"] = lane_view(nodes)
    result["phase_sums"] = phases
    sqlite = args.run / "nsys/timeline.sqlite"
    if sqlite.is_file():
        windows = {}
        lanes = result["recursion_lanes"]
        if lanes:
            t0 = lanes["t0_unix_ns"]
            windows["recursion"] = (t0, t0 + int(lanes["recursion_span_s"] * 1e9))
        result["nsys"] = nsys_view(sqlite, windows)
        if nodes:
            per_node = node_gpu_busy(sqlite, nodes)
            result["nsys"]["per_node"] = per_node
            for kind in ("leaf", "fold"):
                items = [x for x in per_node if x["kind"] == kind]
                if items:
                    result["nsys"][kind + "_mean"] = {k: round(sum(x[k] for x in items) / len(items), 3) for k in ("span_s", "gpu_busy_s", "host_only_s")}
    out = args.out or args.run / "timeline.json"
    out.write_text(json.dumps(result, indent=1) + "\n")
    brief = {k: result.get(k) for k in ("block", "gpus", "stages")}
    if result["recursion_lanes"]:
        brief["recursion"] = {k: result["recursion_lanes"][k] for k in ("recursion_span_s", "fold_tail_after_last_leaf_s", "lanes", "kinds")}
    if "nsys" in result:
        brief["gpu"] = {d: {k: v[k] for k in ("kernels", "kernel_busy_union_s", "any_busy_union_s", "windows")} for d, v in result["nsys"]["devices"].items()}
        brief["gpu"]["leaf_mean"] = result["nsys"].get("leaf_mean")
        brief["gpu"]["fold_mean"] = result["nsys"].get("fold_mean")
    print(json.dumps(brief, indent=1))


if __name__ == "__main__":
    main()
