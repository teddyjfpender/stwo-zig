#!/usr/bin/env python3
"""Symbolize an rv64_sync_trace dump and aggregate it by call site (stream enqueue, M6).

  python3 symbolize.py sync-trace-<pid>.json [--out report.json] [--top 40]

Per site: the kind (cuStreamSynchronize, cuLaunchKernel, ...), count, blocked ns and the symbolized
stack. Aggregates: by the innermost libstwo frame (the CUDA-side call site) and by the innermost
driver (Zig) frame (the host-side caller), and a phase split (recursion = any frame of the outer OM31
prover; native = everything else). Symbols come from `nm` (function granularity); this needs only an
unstripped binary, not DWARF.
"""
import argparse
import bisect
import collections
import json
import re
import subprocess
import sys

CUDART = re.compile(r"libcudart_static|cuda[A-Z]|__cuda|cudaError|__device_stub|\?$")
RECURSION = re.compile(r"om31|outer_|Outer|recursion|fold_|leaf_|composition_codegen|circuit_")


class Module:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            head = f.read(18)
        self.pie = head[16] == 3  # ET_DYN: addresses are offsets
        out = subprocess.run(["nm", "--defined-only", "-C", path], capture_output=True, text=True).stdout
        rows = []
        for line in out.splitlines():
            parts = line.split(" ", 2)
            if len(parts) != 3 or parts[1] not in "tTwW":
                continue
            try:
                rows.append((int(parts[0], 16), parts[2]))
            except ValueError:
                pass
        rows.sort()
        self.addrs = [r[0] for r in rows]
        self.names = [r[1] for r in rows]

    def name(self, absolute, offset):
        key = offset if self.pie else absolute
        i = bisect.bisect_right(self.addrs, key) - 1
        return self.names[i] if i >= 0 else "?"


def short(name):
    name = re.sub(r"\(.*", "", name)
    return name[-110:]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("trace")
    ap.add_argument("--out")
    ap.add_argument("--top", type=int, default=40)
    args = ap.parse_args()
    d = json.load(open(args.trace))
    modules = {}

    def sym(frame):
        absolute, path, offset = int(frame[0], 16), frame[1], int(frame[2], 16)
        if path == "?" or "libcuda" in path or "rv64_sync_trace" in path:
            return path.rsplit("/", 1)[-1], "?"
        if path not in modules:
            try:
                modules[path] = Module(path)
            except OSError:
                modules[path] = None
        m = modules[path]
        return path.rsplit("/", 1)[-1], (short(m.name(absolute, offset)) if m else "?")

    sites = []
    for s in d["sites"]:
        frames = [sym(f) for f in s["frames"]]
        own = [(m, n) for m, n in frames if not CUDART.match(n)]
        lib = next((n for m, n in own if m.startswith("libstwo")), None)
        drv = next((n for m, n in own if not m.startswith("lib") and m != "?" and n != "?"), None)
        phase = "recursion" if any(RECURSION.search(n) for _, n in frames) else "native/other"
        sites.append({"id": s["id"], "kind": s["kind"], "count": s["count"], "ns": s["ns"], "phase": phase,
                      "libstwo_frame": lib, "driver_frame": drv, "stack": [f"{m}:{n}" for m, n in frames]})
    by = lambda key: collections.defaultdict(lambda: {"count": 0, "ns": 0, "sites": 0})
    agg = {"by_libstwo": by(None), "by_driver": by(None), "by_phase": by(None)}
    for s in sites:
        for name, k in (("by_libstwo", (s["kind"], s["phase"], s["libstwo_frame"])), ("by_driver", (s["kind"], s["phase"], s["driver_frame"])),
                        ("by_phase", (s["kind"], s["phase"]))):
            a = agg[name][" | ".join(str(x) for x in k)]
            a["count"] += s["count"]; a["ns"] += s["ns"]; a["sites"] += 1
    report = {"schema": "rv64-sync-trace-report/v1", "trace": args.trace, "totals": d["totals"],
              "functions_top": sorted(d["functions"], key=lambda x: -x[1])[: args.top * 3],
              **{k: dict(sorted(v.items(), key=lambda kv: -kv[1]["count"])) for k, v in agg.items()},
              "sites": sorted(sites, key=lambda s: -s["count"])}
    text = json.dumps(report, indent=1)
    if args.out:
        open(args.out, "w").write(text)
    else:
        sys.stdout.write(text)
    # compact console view
    print("== by phase", file=sys.stderr)
    for k, v in report["by_phase"].items():
        print(f"{v['count']:>9} {v['ns'] / 1e9:8.3f}s  {k}", file=sys.stderr)
    for name in ("by_driver", "by_libstwo"):
        print(f"== {name} (syncs/copies only)", file=sys.stderr)
        n = 0
        for k, v in report[name].items():
            if "Launch" in k or "Graph" in k or "HostFunc" in k:
                continue
            print(f"{v['count']:>9} {v['ns'] / 1e9:8.3f}s  {k}", file=sys.stderr)
            n += 1
            if n >= args.top:
                break


if __name__ == "__main__":
    main()
