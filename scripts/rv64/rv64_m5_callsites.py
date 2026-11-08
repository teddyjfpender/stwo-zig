#!/usr/bin/env python3
"""Symbolize and rank a cuda-callsites-<pid>.json census (tools/rv64-cuda-callsites).

    python3 scripts/rv64_m5_callsites.py RUN_DIR_OR_JSON [--out summary.json] [--top 40]

Run it on the pod (needs the same binaries the census ran against and binutils
addr2line). Groups every host-blocking CUDA call (stream/event/ctx syncs,
H2D/D2H copies, optionally launches) by its first frame in the Zig driver,
i.e. the producer call site, and prints count / bytes / pageable share / ns.
"""
import argparse
import collections
import glob
import json
import os
import subprocess
import sys


def load(path):
    if os.path.isdir(path):
        files = sorted(glob.glob(os.path.join(path, "**", "cuda-callsites-*.json"), recursive=True))
        if not files:
            sys.exit(f"no cuda-callsites-*.json under {path}")
        path = max(files, key=os.path.getsize)
    with open(path) as f:
        return path, json.load(f)


def parse_maps(text):
    maps = []
    for line in text.splitlines():
        parts = line.split(None, 5)
        if len(parts) < 6:
            continue
        lo, hi = (int(x, 16) for x in parts[0].split("-"))
        maps.append((lo, hi, int(parts[2], 16), parts[5].strip()))
    return maps


def is_exec(path):
    try:
        with open(path, "rb") as f:
            head = f.read(18)
        return head[16] == 2  # ET_EXEC: absolute addresses
    except OSError:
        return False


def symbolize(module, addrs):
    out = {}
    if not addrs or not os.path.exists(module):
        return out
    addrs = sorted(set(addrs))
    for i in range(0, len(addrs), 2000):
        chunk = addrs[i:i + 2000]
        res = subprocess.run(["addr2line", "-a", "-f", "-C", "-i", "-e", module] + [hex(a) for a in chunk],
                             capture_output=True, text=True)
        cur = None
        lines = res.stdout.splitlines()
        j = 0
        while j < len(lines):
            line = lines[j]
            if line.startswith("0x") and len(line) >= 3:
                try:
                    cur = int(line, 16)
                    out[cur] = []
                    j += 1
                    continue
                except ValueError:
                    pass
            if cur is not None and j + 1 < len(lines):
                func, loc = line, lines[j + 1]
                loc = "/".join(loc.split("/")[-3:])
                out[cur].append(f"{func} @ {loc}")
                j += 2
            else:
                j += 1
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("path")
    ap.add_argument("--out")
    ap.add_argument("--top", type=int, default=40)
    ap.add_argument("--driver-substr", default="ethereum-gpu-combined")
    a = ap.parse_args()
    path, d = load(a.path)
    maps = parse_maps(d["maps"])
    exec_cache = {}

    def locate(addr):
        for lo, hi, off, mod in maps:
            if lo <= addr < hi:
                if mod not in exec_cache:
                    exec_cache[mod] = is_exec(mod)
                return mod, (addr if exec_cache[mod] else addr - lo + off)
        return "?", addr

    per_mod = collections.defaultdict(set)
    sites = d["sites"]
    for s in sites:
        s["loc"] = []
        for fr in s["frames"]:
            mod, rel = locate(int(fr, 16))
            rel = max(rel - 1, 0)  # return address -> call instruction
            s["loc"].append((mod, rel))
            per_mod[mod].add(rel)
    names = {}
    for mod, addrs in per_mod.items():
        if mod == "?":
            continue
        for k, v in symbolize(mod, addrs).items():
            names[(mod, k)] = v

    def driver_chain(s, n=3):
        chain = []
        for mod, rel in s["loc"]:
            if a.driver_substr in mod:
                fns = names.get((mod, rel)) or [hex(rel)]
                # innermost inline frame first; keep the innermost non-runtime one
                chain.append(fns[0] if fns else hex(rel))
                if len(chain) >= n:
                    break
        return chain

    def skip_runtime(fn):
        return any(t in fn for t in ("runtime/context.zig", "runtime_error", "abi/runtime.zig"))

    groups = collections.OrderedDict()
    for s in sites:
        chain = driver_chain(s, 6)
        key_frames = [f for f in chain if not skip_runtime(f)][:2] or chain[:2] or ["(no driver frame)"]
        if not chain:
            lib = [(names.get(l) or [hex(l[1])])[0] for l in s["loc"][:3]]
            key_frames = ["lib: " + " <- ".join(lib)]
        key = (s["sym"], " <- ".join(key_frames))
        g = groups.setdefault(key, collections.Counter())
        for f in ("count", "bytes", "pageable", "pageable_bytes", "ns"):
            g[f] += s[f]
        g["sites"] += 1
    rows = [dict(sym=k[0], site=k[1], **v) for k, v in groups.items()]
    totals = collections.defaultdict(collections.Counter)
    for r in rows:
        t = totals[r["sym"]]
        for f in ("count", "bytes", "pageable", "pageable_bytes", "ns"):
            t[f] += r[f]
    print(f"# census {path}")
    for sym, t in sorted(totals.items()):
        print(f"{sym:22s} count={t['count']:>8d} bytes={t['bytes']/1e9:8.2f}GB pageable={t['pageable']:>7d} "
              f"({t['pageable_bytes']/1e9:.2f}GB) ns={t['ns']/1e9:.2f}s")
    for sym in sorted(totals):
        sub = sorted((r for r in rows if r["sym"] == sym), key=lambda r: (-r["count"], -r["bytes"]))
        print(f"\n## {sym} by count (top {a.top})")
        for r in sub[:a.top]:
            print(f"{r['count']:>7d} {r['bytes']/1e9:7.2f}GB pg={r['pageable']:>6d} {r['ns']/1e9:6.2f}s  {r['site']}")
        if any(r["bytes"] for r in sub):
            print(f"\n## {sym} by bytes (top {a.top // 2})")
            for r in sorted(sub, key=lambda r: -r["bytes"])[:a.top // 2]:
                print(f"{r['count']:>7d} {r['bytes']/1e9:7.2f}GB pg={r['pageable']:>6d} {r['ns']/1e9:6.2f}s  {r['site']}")
    if a.out:
        with open(a.out, "w") as f:
            json.dump({"schema": "rv64-m5-callsites-summary/v1", "source": path,
                       "totals": {k: dict(v) for k, v in totals.items()}, "rows": rows}, f, indent=1)


if __name__ == "__main__":
    main()
