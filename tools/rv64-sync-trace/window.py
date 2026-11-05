#!/usr/bin/env python3
"""Cut a symbolized rv64_sync_trace into per-request recursion windows (stream enqueue, M6).

  python3 window.py TRACE.json REPORT.json DAEMON_RUN_DIR [--out windows.json]

The daemon writes spool/done/<name>.json when a request finishes; recursion is the request tail
(M5: recursion starts after the last native proof), so the recursion window of a request is
[done_mtime - recursion_s, done_mtime]. Within it: blocking calls per host call site, kernel launches
per kernel, and per-node rates using the receipt's leaf count (nodes = 2 * leaves - 1, binary folds).
"""
import argparse
import collections
import json
import os
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("trace")
    ap.add_argument("report")
    ap.add_argument("run")
    ap.add_argument("--out")
    ap.add_argument("--top", type=int, default=25)
    args = ap.parse_args()
    trace = json.load(open(args.trace))
    report = json.load(open(args.report))
    receipt = json.load(open(Path(args.run) / "receipt.json"))
    origin_real = trace["origin_realtime_ns"]
    site_frame = {s["id"]: (s["kind"], s["driver_frame"]) for s in report["sites"]}
    funcs = {f[2]: f[0] for f in trace["functions"]}
    done = sorted((Path(args.run) / "spool" / "done").glob("*.json"))
    out = {"schema": "rv64-sync-trace-windows/v1", "run": args.run, "requests": []}
    for request, path in zip(receipt["requests"], done):
        end = os.stat(path).st_mtime_ns - origin_real
        rec = request["stages"]["recursion_s"]
        start = end - int(rec * 1e9)
        req_start = end - int(request["stages"]["request_wall_s"] * 1e9)
        # M6 switched the default to k4 folds. Count the actual authenticated
        # tree topology; 2*leaves-1 silently understates per-node rates for k4.
        tree = json.loads((Path(request["proof"]) / "recursion-om31/tree.json").read_text())
        nodes = len(tree["nodes"])
        if nodes == 0:
            raise ValueError("empty recursive tree in trace window")
        windows = {"recursion": (start, end), "pre_recursion": (req_start, start)}
        row = {"block": request["block"], "nodes": nodes, "recursion_s": rec}
        for wname, (lo, hi) in windows.items():
            syncs = collections.Counter()
            sync_ns = collections.Counter()
            launches = collections.Counter()
            kinds = collections.Counter()
            for t0, ns, site, tid in trace["events"]:
                if not lo <= t0 < hi:
                    continue
                if site & 0x80000000:
                    launches[funcs.get(site & 0x7FFFFFFF, "?")] += 1
                    kinds["launch"] += 1
                    continue
                kind, frame = site_frame.get(site, ("?", None))
                syncs[f"{kind} | {frame}"] += 1
                sync_ns[f"{kind} | {frame}"] += ns
                kinds[kind] += 1
            blocking = sum(v for k, v in kinds.items() if k in ("cuStreamSynchronize", "cuEventSynchronize", "cuCtxSynchronize", "cuMemcpyDtoH", "cuMemcpyHtoD"))
            row[wname] = {
                "kinds": dict(kinds),
                "blocking_total": blocking,
                "blocking_per_node": round(blocking / nodes, 1) if wname == "recursion" else None,
                "launches_per_node": round(kinds["launch"] / nodes, 1) if wname == "recursion" else None,
                "blocked_s": round(sum(sync_ns.values()) / 1e9, 3),
                "sites": [{"site": k, "count": v, "blocked_s": round(sync_ns[k] / 1e9, 3)} for k, v in syncs.most_common(args.top)],
                "kernels": launches.most_common(args.top),
            }
        out["requests"].append(row)
        r = row["recursion"]
        print(f"== {row['block']} nodes={nodes} recursion={rec}s blocking={r['blocking_total']} ({r['blocking_per_node']}/node, {r['blocked_s']} s) launches={r['kinds'].get('launch', 0)} ({r['launches_per_node']}/node)")
        for s in r["sites"][:15]:
            print(f"   {s['count']:>6} {s['blocked_s']:7.3f}s {s['site']}")
        for k, v in r["kernels"][:15]:
            print(f"   {v:>6} launches {k[:110]}")
    if args.out:
        Path(args.out).write_text(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
