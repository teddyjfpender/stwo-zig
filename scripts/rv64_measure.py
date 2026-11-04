#!/usr/bin/env python3
"""RV64 M4 measurement toolkit (stream measure; plan M4.0 items 2 and 9).

Library used by scripts/rv64_m3_pod.py (--counters / --smaps hooks) plus a CLI:

  python3 rv64_measure.py receipt-v2  RUN_DIR [--reference RECEIPT] [--out PATH]
      Build receipt schema v2 (fixed stage boundaries, plan section 8.1) from a harness run
      directory: receipt.json (v1) + producer logs + proof dir + optional counter-shim JSON,
      smaps peak census and nsys sqlite.  Works on old M3 runs (fields it cannot derive are null).
  python3 rv64_measure.py fingerprint A B
      Proof-fingerprint diff: compare every proof hash in two receipts (v1 or v2) or run dirs.
  python3 rv64_measure.py nsys RUN_DIR [--out PATH]
      nsys per-phase / per-node extractor: kernel-busy GPU-s vs span GPU-s, per device and per
      recursion node kind, API totals.
  python3 rv64_measure.py smaps PID [--out PATH]
      One-shot smaps census of a live process.

Everything here only reads producer outputs; nothing changes proving.
"""
import argparse
import bisect
import glob
import json
import os
from pathlib import Path
import re
import sqlite3
import threading
import time

SCHEMA_V2 = "rv64-m4-receipt/v2"
HERE = Path(__file__).resolve().parent
SHIM_DEFAULT = Path("/workspace/m3/build/m4-measure/shim/librv64_cuda_counters.so")


def load(path):
    with open(path) as handle:
        return json.load(handle)


def loadavg():
    try:
        one, five, fifteen = Path("/proc/loadavg").read_text().split()[:3]
        return {"1m": float(one), "5m": float(five), "15m": float(fifteen), "unix": time.time()}
    except OSError:
        return None


def host_info():
    info = {"nodename": os.uname().nodename, "nproc": os.cpu_count()}
    try:
        quota = Path("/sys/fs/cgroup/cpu.max").read_text().split()
        if quota[0] != "max":
            info["cgroup_cpus"] = round(int(quota[0]) / int(quota[1]), 2)
    except (OSError, ValueError, IndexError):
        pass
    return info


# ----------------------------------------------------------------------------- counter shim

def shim_environment(out_dir, shim=SHIM_DEFAULT):
    """Producer env additions for the LD_PRELOAD CUDA driver-API counter shim."""
    if not Path(shim).is_file():
        raise SystemExit(f"counter shim missing: {shim} (build tools/rv64-cuda-counters, see README)")
    Path(out_dir).mkdir(parents=True, exist_ok=True)
    return {"LD_PRELOAD": str(shim), "RV64_CUDA_COUNTERS_OUT": str(out_dir), "RV64_CUDA_COUNTERS_BIN_MS": "10"}


def shim_files(run):
    return sorted(Path(run).glob("counters/cuda-counters-*.json"), key=lambda p: p.stat().st_size, reverse=True)


# ----------------------------------------------------------------------------- smaps

def classify(name, flags):
    if name.startswith("/dev/nvidia"):
        return "nvidia_device_mapping"
    if name == "[heap]":
        return "heap_brk"
    if name.startswith("[stack"):
        return "stack"
    if name.startswith("["):
        return "special"
    if name.startswith("/memfd:") or "(deleted)" in name:
        return "memfd_or_deleted"
    if name.startswith("/"):
        if "libstwo" in name:
            return "file:libstwo-native"
        if "libcuda" in name or "libnvidia" in name:
            return "file:libcuda-driver"
        if name.endswith((".so", ".so.1", ".so.6")) or ".so." in name:
            return "file:other-shared-lib"
        if "/bin/" in name:
            return "file:driver-binary"
        return "file:data"
    return "anon"


def parse_smaps(pid):
    """Per-mapping Rss/Pss/Private/Anonymous (bytes) from /proc/PID/smaps."""
    maps, current = [], None
    with open(f"/proc/{pid}/smaps") as handle:
        for line in handle:
            first = line.split(None, 1)[0]
            if "-" in first and not first.endswith(":"):
                parts = line.split(None, 5)
                lo, hi = (int(x, 16) for x in parts[0].split("-"))
                current = {"lo": lo, "size": hi - lo, "perms": parts[1], "name": parts[5].strip() if len(parts) > 5 else ""}
                maps.append(current)
            elif first.endswith(":") and current is not None:
                key = first[:-1]
                if key == "VmFlags":
                    current["flags"] = line.split(None, 1)[1].split() if " " in line.strip() else []
                elif key in ("Rss", "Pss", "Private_Clean", "Private_Dirty", "Shared_Clean", "Shared_Dirty", "Anonymous", "Locked", "AnonHugePages", "Swap"):
                    current[key] = int(line.split()[1]) * 1024
    return maps


def census(maps, pinned=None):
    """Aggregate an smaps snapshot by category and by size class; pinned = [(addr,size)] from the shim."""
    pinned = sorted(pinned or [])
    starts = [p[0] for p in pinned]
    cats, sizes = {}, {}
    total = 0
    pinned_rss = 0
    for m in maps:
        rss = m.get("Rss", 0)
        total += rss
        cat = classify(m["name"], m.get("flags", []))
        if cat == "anon" and pinned:
            i = bisect.bisect_right(starts, m["lo"] + m["size"] - 1) - 1
            if i >= 0 and pinned[i][0] + pinned[i][1] > m["lo"]:
                cat = "anon:cuda_pinned_host"
                pinned_rss += rss
        c = cats.setdefault(cat, {"mappings": 0, "rss": 0, "private": 0, "anonymous": 0, "vsize": 0})
        c["mappings"] += 1
        c["rss"] += rss
        c["private"] += m.get("Private_Clean", 0) + m.get("Private_Dirty", 0)
        c["anonymous"] += m.get("Anonymous", 0)
        c["vsize"] += m["size"]
        if cat.startswith("anon"):
            size = m["size"]
            klass = "<=128KiB" if size <= 128 << 10 else "<=2MiB" if size <= 2 << 20 else "<=64MiB" if size <= 64 << 20 else "<=1GiB" if size <= 1 << 30 else ">1GiB"
            s = sizes.setdefault(klass, {"mappings": 0, "rss": 0})
            s["mappings"] += 1
            s["rss"] += rss
    top = sorted(maps, key=lambda m: m.get("Rss", 0), reverse=True)[:40]
    return {"rss_total_bytes": total, "categories": cats, "anon_size_classes": sizes, "pinned_rss_bytes": pinned_rss,
            "top_mappings": [{"lo": hex(m["lo"]), "size": m["size"], "rss": m.get("Rss", 0), "anon": m.get("Anonymous", 0),
                              "perms": m["perms"], "name": m["name"], "flags": " ".join(m.get("flags", []))} for m in top]}


def rollup(pid):
    out = {}
    with open(f"/proc/{pid}/smaps_rollup") as handle:
        for line in handle:
            parts = line.split()
            if len(parts) >= 3 and parts[0].endswith(":") and parts[2] == "kB":
                out[parts[0][:-1]] = int(parts[1]) * 1024
    return out


class SmapsSampler:
    """Polls the producer (found by a marker in its argv) and keeps the smaps snapshot at peak RSS.

    smaps_rollup every `interval` s (cheap); a full smaps parse when RSS grows >1% past the last
    full snapshot, so the kept snapshot is within ~1% + one interval of the true peak."""

    def __init__(self, marker, out, interval=0.25):
        self.marker, self.out, self.interval = marker, Path(out), interval
        self.stop_event = threading.Event()
        self.series, self.peak, self.peak_maps, self.pid, self.error = [], 0, None, None, None
        self.thread = threading.Thread(target=self.run, daemon=True)

    def find(self):
        for path in glob.glob("/proc/[0-9]*/cmdline"):
            try:
                argv = Path(path).read_bytes().split(b"\0")
            except OSError:
                continue
            if argv and self.marker.encode() in b" ".join(argv) and b"combined-batch" in argv:
                return int(path.split("/")[2])
        return None

    def run(self):
        start = time.monotonic()
        try:
            while not self.stop_event.is_set() and self.pid is None:
                self.pid = self.find()
                if self.pid is None:
                    time.sleep(0.1)
            snap_rss = 0
            while not self.stop_event.is_set():
                try:
                    r = rollup(self.pid)
                except OSError:
                    break
                t = round(time.monotonic() - start, 3)
                rss = r.get("Rss", 0)
                self.series.append([t, rss, r.get("Anonymous", 0), r.get("Pss_File", 0), r.get("Pss_Anon", 0)])
                if rss > self.peak:
                    self.peak = rss
                    if rss > snap_rss * 1.01:
                        try:
                            self.peak_maps = (t, parse_smaps(self.pid))
                            snap_rss = rss
                        except OSError:
                            break
                time.sleep(self.interval)
        except Exception as error:  # never break a proving run
            self.error = repr(error)

    def start(self):
        self.thread.start()
        return self

    def finish(self, pinned=None):
        self.stop_event.set()
        self.thread.join(timeout=30)
        result = {"schema": "rv64-smaps-census/v1", "label": "measured", "pid": self.pid, "interval_s": self.interval,
                  "peak_rss_bytes_sampled": self.peak, "error": self.error,
                  "series_columns": ["t_s", "rss", "anonymous", "pss_file", "pss_anon"], "series": self.series}
        if self.peak_maps:
            result["peak_t_s"] = self.peak_maps[0]
            result["peak_census"] = census(self.peak_maps[1], pinned)
        self.out.parent.mkdir(parents=True, exist_ok=True)
        with open(self.out, "w") as handle:
            json.dump(result, handle)
        return result


# ----------------------------------------------------------------------------- logs

KV = re.compile(r"(\w+)=(\{[^}]*\}|\S+)")


def kv_lines(text, prefix):
    rows = []
    for line in text.splitlines():
        if line.startswith(prefix + " ") or line.startswith("info: " + prefix + " "):
            row = {}
            for k, v in KV.findall(line):
                if v.startswith("{"):
                    row[k] = [int(x) for x in re.findall(r"-?\d+", v)]
                else:
                    try:
                        row[k] = int(v)
                    except ValueError:
                        try:
                            row[k] = float(v)
                        except ValueError:
                            row[k] = v
            rows.append(row)
    return rows


def producer_log(run):
    case = Path(run) / "case"
    return (case / "producer.stdout").read_text(errors="replace") + (case / "producer.stderr").read_text(errors="replace")


def proof_dir(run):
    plan = load(Path(run) / "plan.json")
    job = plan["jobs"][0]
    return Path(job["target"]) / "batch/trial-0" / str(job["block"]) / "proof"


# ----------------------------------------------------------------------------- per-node alignment

def pipeline_nodes(proof):
    path = Path(proof) / "recursion-om31/pipeline.json"
    if not path.is_file():
        return None
    return load(path)


def lane_threads(counter, nodes, min_launch=1000):
    """Map lane -> shim thread record, and an offset (shim ns - pipeline ns).

    Lane threads are spawned at pipeline start and make their first CUDA call when their first
    node's device stage starts. Threads are matched to lanes by first-call order."""
    lanes = sorted({n["lane"] for n in nodes if n.get("lane") is not None})
    firsts = {lane: min(n["stamps"]["device_start"] for n in nodes if n.get("lane") == lane) for lane in lanes}
    rec_start = min(firsts.values())
    candidates = [t for t in counter["threads"] if t["count"][1] >= min_launch]
    # The lane threads are the latest-starting heavy launchers (native-stage threads start earlier).
    candidates.sort(key=lambda t: t["first_ns"])
    chosen = candidates[-len(lanes):] if len(candidates) >= len(lanes) else []
    if not chosen:
        return None, None
    chosen.sort(key=lambda t: t["first_ns"])
    order = sorted(lanes, key=lambda lane: firsts[lane])
    mapping = dict(zip(order, chosen))
    offsets = [mapping[lane]["first_ns"] - firsts[lane] for lane in order]
    return mapping, {"offsets_ns": offsets, "offset_ns": int(sum(offsets) / len(offsets)), "spread_ns": max(offsets) - min(offsets),
                     "recursion_start_pipeline_ns": rec_start}


def bin_sum(bins, lo_ns, hi_ns, bin_ns):
    lo, hi = lo_ns // bin_ns, hi_ns // bin_ns
    return sum(c for b, c in bins if lo <= b <= hi)


def per_node_counters(counter, pipeline):
    nodes = pipeline["nodes"]
    mapping, align = lane_threads(counter, nodes)
    if not mapping:
        return None
    classes = counter["classes"]
    bin_ns = counter["bin_ns"]
    out = []
    for n in nodes:
        lane = n.get("lane")
        if lane is None:
            continue
        thread = mapping[lane]
        lo = n["stamps"]["device_start"] + align["offset_ns"]
        hi = n["stamps"]["device_end"] + align["offset_ns"]
        row = {"node": n["id"], "kind": n["kind"], "lane": lane, "device_stage_s": round((n["stamps"]["device_end"] - n["stamps"]["device_start"]) / 1e9, 3),
               "span_s": round((n["stamps"]["finish_end"] - n["stamps"]["taken"]) / 1e9, 3)}
        for klass in classes:
            bins = thread["bins"].get(klass)
            row[klass] = bin_sum(bins, lo, hi, bin_ns) if bins else 0
        out.append(row)
    summary = {}
    for kind in ("leaf", "fold"):
        rows = [r for r in out if r["kind"] == kind]
        if rows:
            summary[kind] = {"nodes": len(rows), **{f"{k}_per_node": round(sum(r[k] for r in rows) / len(rows), 1) for k in classes},
                             "device_stage_s_mean": round(sum(r["device_stage_s"] for r in rows) / len(rows), 3),
                             "span_s_mean": round(sum(r["span_s"] for r in rows) / len(rows), 3)}
    return {"alignment": align, "lane_thread_tids": {str(k): v["tid"] for k, v in mapping.items()}, "per_kind": summary, "nodes": out,
            "scope": "device-stage window of each node on its lane thread (10 ms bins); prep/finish threads are reported per thread, not per node"}


def counters_view(counter, pipeline):
    sym = counter["symbols"]
    get = lambda name, f="count": sym.get(name, {}).get(f, 0)
    view = {
        "hook_active": counter["hook"]["wrapped_symbols"] > 0 and sum(s["count"] for s in sym.values()) > 0,
        "stream_synchronize": get("cuStreamSynchronize"), "ctx_synchronize": get("cuCtxSynchronize"), "event_synchronize": get("cuEventSynchronize"),
        "sync_total": get("cuStreamSynchronize") + get("cuCtxSynchronize") + get("cuEventSynchronize"),
        "sync_s": round((get("cuStreamSynchronize", "ns") + get("cuCtxSynchronize", "ns") + get("cuEventSynchronize", "ns")) / 1e9, 3),
        "kernel_launches": get("cuLaunchKernel") + get("cuLaunchKernelEx"), "launch_api_s": round((get("cuLaunchKernel", "ns") + get("cuLaunchKernelEx", "ns")) / 1e9, 3),
        "graph_launches": get("cuGraphLaunch"), "host_func_launches": get("cuLaunchHostFunc"),
        "pool_mallocs": get("cuMemAllocFromPoolAsync") + get("cuMemAllocAsync"),
        "pool_malloc_s": round((get("cuMemAllocFromPoolAsync", "ns") + get("cuMemAllocAsync", "ns")) / 1e9, 3),
        "pool_trims": get("cuMemPoolTrimTo"), "pool_trim_s": round(get("cuMemPoolTrimTo", "ns") / 1e9, 3),
        "library_loads": get("cuLibraryLoadData") + get("cuModuleLoadData") + get("cuModuleLoadFatBinary"),
        "library_load_s": round((get("cuLibraryLoadData", "ns") + get("cuModuleLoadData", "ns") + get("cuModuleLoadFatBinary", "ns")) / 1e9, 3),
        "library_unload_s": round((get("cuLibraryUnload", "ns") + get("cuModuleUnload", "ns")) / 1e9, 3),
        "pageable_copies": counter["copies"]["pageable_count"], "pageable_copy_bytes": counter["copies"]["pageable_bytes"],
        "pageable_copy_s": round(counter["copies"]["pageable_ns"] / 1e9, 3),
        "pinned_or_device_copies": counter["copies"]["pinned_or_device_count"],
        "host_pinned_allocs": get("cuMemHostAlloc") + get("cuMemAllocHost"), "host_pinned_alloc_bytes": get("cuMemHostAlloc", "bytes") + get("cuMemAllocHost", "bytes"),
        "host_register_bytes": get("cuMemHostRegister", "bytes"),
        "cuda_threads": len(counter["threads"]),
        "symbols": sym,
        "per_thread": [{"tid": t["tid"], "first_s": round(t["first_ns"] / 1e9, 3), "last_s": round(t["last_ns"] / 1e9, 3),
                        **{k: t["count"][i] for i, k in enumerate(counter["classes"])}} for t in counter["threads"] if sum(t["count"])],
    }
    if pipeline:
        try:
            view["per_node"] = per_node_counters(counter, pipeline)
        except Exception as error:
            view["per_node_error"] = repr(error)
    return view


# ----------------------------------------------------------------------------- nsys

def merged(intervals):
    out = []
    for s, e in sorted(intervals):
        if out and s <= out[-1][1]:
            out[-1][1] = max(out[-1][1], e)
        else:
            out.append([s, e])
    return out


def busy(merged_list, lo, hi):
    total = 0
    starts = [s for s, _ in merged_list]
    i = max(bisect.bisect_right(starts, lo) - 1, 0)
    while i < len(merged_list) and merged_list[i][0] < hi:
        s, e = merged_list[i]
        total += max(0, min(e, hi) - max(s, lo))
        i += 1
    return total


def nsys_view(sqlite_path, pipeline=None, phases=None):
    """Kernel-busy GPU-s (union of kernel intervals per device) vs kernel-sum and span GPU-s,
    per device, per stage window and per recursion node (aligned through lane-thread first API call)."""
    db = sqlite3.connect(str(sqlite_path))
    cur = db.cursor()
    tables = {r[0] for r in cur.execute("select name from sqlite_master where type='table'")}
    names = dict(cur.execute("select id,value from StringIds").fetchall())
    kernels = cur.execute("select deviceId,start,end,correlationId,globalPid,shortName from CUPTI_ACTIVITY_KIND_KERNEL").fetchall()
    copies = cur.execute("select deviceId,start,end,bytes,copyKind,srcKind,dstKind from CUPTI_ACTIVITY_KIND_MEMCPY").fetchall() if "CUPTI_ACTIVITY_KIND_MEMCPY" in tables else []
    api = []
    for table in ("CUPTI_ACTIVITY_KIND_RUNTIME", "CUPTI_ACTIVITY_KIND_DRIVER"):
        if table in tables:
            api += [(table, *r) for r in cur.execute(f"select start,end,correlationId,globalTid,nameId from {table}")]
    out = {"schema": "rv64-nsys-view/v1", "label": "measured", "devices": {}}
    by_dev = {}
    for d, s, e, *_ in kernels:
        by_dev.setdefault(d, []).append((s, e))
    t_lo = min(s for _, s, *_ in kernels) if kernels else 0
    t_hi = max(e for _, _, e, *_ in kernels) if kernels else 0
    for d, iv in sorted(by_dev.items()):
        m = merged(iv)
        out["devices"][str(d)] = {"kernels": len(iv), "kernel_sum_s": round(sum(e - s for s, e in iv) / 1e9, 3),
                                  "kernel_busy_union_s": round(sum(e - s for s, e in m) / 1e9, 3),
                                  "first_kernel_to_last_s": round((max(e for _, e in iv) - min(s for s, _ in iv)) / 1e9, 3)}
    copy_kinds = {}
    for d, s, e, b, kind, src, dst in copies:
        c = copy_kinds.setdefault(f"dev{d}:kind{kind}:src{src}:dst{dst}", {"count": 0, "bytes": 0, "s": 0})
        c["count"] += 1
        c["bytes"] += b
        c["s"] += (e - s) / 1e9
    out["memcpy"] = {k: {**v, "s": round(v["s"], 3)} for k, v in sorted(copy_kinds.items())}
    out["memcpy_kind_legend"] = "copyKind 1=HtoD 2=DtoH 8=DtoD; src/dst kind 1=pageable 2=device 3=pinned (ENUM_CUDA_MEM_KIND)"
    # API totals
    totals = {}
    for table, s, e, corr, tid, nid in api:
        name = names.get(nid, str(nid))
        t = totals.setdefault(name, [0, 0])
        t[0] += 1
        t[1] += e - s
    out["api_top"] = [{"name": n, "calls": c, "s": round(ns / 1e9, 3)} for n, (c, ns) in sorted(totals.items(), key=lambda kv: -kv[1][1])[:25]]
    # per-kernel-name top
    kt = {}
    for d, s, e, corr, pid, nid in kernels:
        n = names.get(nid, str(nid))
        k = kt.setdefault(n, [0, 0])
        k[0] += 1
        k[1] += e - s
    out["kernel_top"] = [{"name": n[:80], "calls": c, "s": round(ns / 1e9, 3)} for n, (c, ns) in sorted(kt.items(), key=lambda kv: -kv[1][1])[:25]]
    if pipeline:
        # correlation -> launching thread, for attributing kernels to lane threads
        corr_tid = {corr: tid for table, s, e, corr, tid, nid in api}
        launch_ids = {i for i, v in names.items() if v.startswith(("cuLaunchKernel", "cudaLaunchKernel"))}
        firsts = {}
        for table, s, e, corr, tid, nid in api:
            if nid in launch_ids:
                firsts.setdefault(tid, [s, 0])
                firsts[tid][1] += 1
                firsts[tid][0] = min(firsts[tid][0], s)
        nodes = pipeline["nodes"]
        lanes = sorted({n["lane"] for n in nodes if n.get("lane") is not None})
        lane_first = {lane: min(n["stamps"]["device_start"] for n in nodes if n.get("lane") == lane) for lane in lanes}
        heavy = sorted([(f[0], tid) for tid, f in firsts.items() if f[1] >= 1000])
        chosen = sorted(heavy[-len(lanes):])
        order = sorted(lanes, key=lambda lane: lane_first[lane])
        lane_tid = {lane: tid for lane, (_, tid) in zip(order, chosen)}
        offsets = [first - lane_first[lane] for lane, (first, _) in zip(order, chosen)]
        offset = int(sum(offsets) / len(offsets))
        # kernels per launching thread
        per_tid = {}
        for d, s, e, corr, pid, nid in kernels:
            tid = corr_tid.get(corr)
            per_tid.setdefault(tid, []).append((s, e, d))
        rows = []
        for n in nodes:
            lane = n.get("lane")
            if lane is None:
                continue
            lo, hi = n["stamps"]["device_start"] + offset, n["stamps"]["device_end"] + offset
            ks = [(s, e) for s, e, d in per_tid.get(lane_tid[lane], []) if s >= lo and s < hi]
            m = merged(ks)
            rows.append({"node": n["id"], "kind": n["kind"], "lane": lane, "kernels": len(ks),
                         "kernel_busy_s": round(sum(e - s for s, e in m) / 1e9, 4), "kernel_sum_s": round(sum(e - s for s, e in ks) / 1e9, 4),
                         "first_to_last_kernel_s": round((max(e for _, e in ks) - min(s for s, _ in ks)) / 1e9, 4) if ks else 0,
                         "device_stage_s": round((hi - lo) / 1e9, 4), "span_s": round((n["stamps"]["finish_end"] - n["stamps"]["taken"]) / 1e9, 4)})
        kinds = {}
        for kind in ("leaf", "fold"):
            rs = [r for r in rows if r["kind"] == kind]
            if rs:
                kinds[kind] = {"nodes": len(rs), **{f"{k}_total": round(sum(r[k] for r in rs), 3) for k in ("kernel_busy_s", "first_to_last_kernel_s", "device_stage_s", "span_s")},
                               "kernels_per_node": round(sum(r["kernels"] for r in rs) / len(rs))}
        rec_lo = min(n["stamps"]["device_start"] for n in nodes if n.get("lane") is not None) + offset
        rec_hi = max(n["stamps"]["device_end"] for n in nodes if n.get("lane") is not None) + offset
        window = {}
        for d, iv in sorted(by_dev.items()):
            m = merged(iv)
            window[str(d)] = round(busy(m, rec_lo, rec_hi) / 1e9, 3)
        out["recursion"] = {"alignment": {"offsets_ns": offsets, "spread_ns": max(offsets) - min(offsets), "lane_tids": {str(k): v for k, v in lane_tid.items()}},
                            "window_s": round((rec_hi - rec_lo) / 1e9, 3), "device_busy_in_window_s": window,
                            "device_busy_fraction": {d: round(v / ((rec_hi - rec_lo) / 1e9), 3) for d, v in window.items()},
                            "per_kind": kinds, "nodes": rows,
                            "reconciled_kernel_gpu_s": round(sum(r["kernel_busy_s"] for r in rows), 3),
                            "span_gpu_s_first_to_last": round(sum(r["first_to_last_kernel_s"] for r in rows), 3)}
    return out


# ----------------------------------------------------------------------------- fingerprint

def fingerprints(receipt):
    p = receipt.get("proof_sha256") or receipt.get("proofs", {}).get("sha256") or {}
    out = {}
    for name, value in (p.get("native") or {}).items():
        out["native/" + name] = value
    if p.get("bundle"):
        out["bundle.json"] = p["bundle"]
    rec = p.get("recursive") or {}
    for name, value in (rec.get("proof_sha256") or {}).items():
        out["recursive/" + name] = value
    if rec.get("tree_sha256"):
        out["recursive/tree.json"] = rec["tree_sha256"]
    return out


def fingerprint_diff(a, b):
    fa, fb = fingerprints(a), fingerprints(b)
    names = sorted(set(fa) | set(fb))
    diff = [n for n in names if fa.get(n) != fb.get(n)]
    return {"compared": len(names), "identical": not diff and bool(names), "mismatched": diff[:64], "only_in_a": sorted(set(fa) - set(fb))[:16],
            "only_in_b": sorted(set(fb) - set(fa))[:16]}


def receipt_of(path):
    path = Path(path)
    if path.is_dir():
        for name in ("receipt-v2.json", "receipt.json"):
            if (path / name).is_file():
                return load(path / name)
    return load(path)


# ----------------------------------------------------------------------------- receipt v2

def s(ns):
    return None if ns is None else round(ns / 1e9, 3)


def native_phases(proof):
    """stage1/stage2 walls from schedule.json (each phase has its own origin)."""
    path = Path(proof) / "schedule.json"
    if not path.is_file():
        return {}
    sched = load(path)
    out = {}
    for phase in ("stage1", "stage2"):
        rows = sched.get(phase) or []
        if rows:
            out[f"{phase}_s"] = s(max(r["finished_ns"] for r in rows) - min(r["claimed_ns"] for r in rows))
            out[f"{phase}_jobs"] = len(rows)
    return out


def build_v2(run, reference=None):
    run = Path(run)
    v1 = load(run / "receipt.json")
    stages = v1.get("stages", {})
    proof = proof_dir(run)
    report = load(proof / "report.json")
    log = producer_log(run)
    pipeline = pipeline_nodes(proof)
    resident = (kv_lines(log, "GPU_RESIDENT_BLOCK") or [{}])[-1]
    rec = v1.get("recursion", {}).get("counters", {}).get("recursive_report", {})
    setup_cache = resident.get("setup_cache") == "true"
    setup_s = stages.get("setup_s")
    recursion_s = stages.get("recursion_s")
    fold_tail = None
    if pipeline:
        leaves = [n for n in pipeline["nodes"] if n["kind"] == "leaf"]
        if leaves:
            fold_tail = s(pipeline["dag_wall_ns"] - max(n["stamps"]["finish_end"] for n in leaves))
    peak_dev = (v1.get("physical_gpu_memory_peak") or {}).get("peak_used_bytes") or {}
    proc = v1.get("producer_process", {})
    smaps = None
    if (run / "smaps-peak.json").is_file():
        smaps = load(run / "smaps-peak.json")
    rss_private = None
    if smaps and smaps.get("peak_census"):
        cats = smaps["peak_census"]["categories"]
        rss_private = sum(v["private"] for k, v in cats.items() if not k.startswith("file:"))
    v2 = {
        "schema": SCHEMA_V2, "label": v1.get("label", "measured"), "derived_from": "rv64-m3-receipt/v1 + producer logs + proof dir",
        "stream": v1.get("stream"), "block": v1.get("block"), "gpus": v1.get("gpus"), "run": str(run), "source_commit": v1.get("source_commit"),
        "assets": v1.get("assets"), "environment_overrides": v1.get("environment_overrides"), "nsys": v1.get("nsys"),
        "host": v1.get("host") or host_info(), "loadavg": v1.get("loadavg"),
        "stages": {
            "request_s": stages.get("request_wall_s"),
            "capture_s": stages.get("capture_s"),
            "capture_critical_s": stages.get("capture_s"),
            "setup_s": setup_s,
            "setup_cold_service_s": None if setup_cache else setup_s,
            "setup_warm_s": setup_s if setup_cache else None,
            "setup_install_s": None,
            "native_s": stages.get("native_prove_s"),
            **native_phases(proof),
            "native_verify_side_thread_s": stages.get("native_verify_s"),
            "native_verify_on_critical_path_s": 0.0 if report.get("native_verify_overlapped_with_recursion") else stages.get("native_verify_s"),
            "recursion_s": recursion_s,
            "recursion_wall_s": recursion_s,
            "recursion_tail_s": recursion_s,
            "fold_tail_after_last_leaf_s": fold_tail,
            "compress_s": 0.0,
        },
        "stage_boundaries": {
            "request_s": "request accepted -> final proof bytes written (GPU_RESIDENT_BLOCK request_wall_ns)",
            "capture_s": "input -> last segment compact records ready (report.capture_ns); M3: nothing overlaps it, so capture_critical_s == capture_s",
            "setup_s": "report.setup_ns; cold_service when the SetupCache missed, warm when it hit; install is not a separate step yet (null)",
            "native_s": "report.prove_ns: projection/widening/stage1/barrier/stage2 all count here, never under capture",
            "stage1_s/stage2_s": "schedule.json phase walls (first claim -> last finish of each phase)",
            "recursion_s": "combined recursion_ns; recursion starts after the last native proof in M3, so tail == wall",
            "compress_s": "no compress layer before M7 (0)",
        },
        "ram": {"rss_peak_daemon_gib": round(proc.get("peak_rss_bytes", 0) / 2**30, 3) if proc.get("peak_rss_bytes") else None,
                "rss_peak_request_private_gib": round(rss_private / 2**30, 3) if rss_private else None,
                "rss_scope": "one process per request (no daemon yet): daemon == whole-process peak (getrusage); request_private = private non-file-backed pages at the sampled peak",
                "smaps_peak_census": (smaps or {}).get("peak_census"), "smaps_peak_t_s": (smaps or {}).get("peak_t_s")},
        "device_memory": {"device_peak_gb": {k: round(v / 1e9, 3) for k, v in peak_dev.items()},
                          "scope": (v1.get("physical_gpu_memory_peak") or {}).get("scope")},
        "gpu": {"nvml_kernel_activity": (v1.get("physical_gpu_memory_peak") or {}).get("kernel_activity")},
        "proof_size": {"proof_bytes_final": rec.get("root_proof_bytes"), "proof_bytes_root": rec.get("root_proof_bytes")},
        "process": proc,
        "recursion": {"nodes": (rec.get("leaf_proofs") or 0) + (rec.get("fold_proofs") or 0), "leaves": rec.get("leaf_proofs"), "folds": rec.get("fold_proofs"),
                      "pipeline": {k: pipeline.get(k) for k in ("dag_wall_ns", "lane_device_stage_ns", "lane_device_stage_occupancy", "peak_ready")} if pipeline else None},
        "native": {k: v1.get("native", {}).get(k) for k in ("cpu_proofs", "truth_proofs", "profile", "output_matches_pin")},
        "correctness": {"parity_vs_accepted_v7": v1.get("parity_vs_accepted_v7"), "receiver": {k: (v1.get("receiver") or {}).get(k) for k in ("status", "accepted", "receiver_sha256", "restored_leaves", "restored_folds", "producer_strict_checks")},
                        "accepted": v1.get("accepted")},
        "verifier": {"verify_per_block_s": s(((v1.get("receiver") or {}).get("process") or {}).get("wall_ns")), "derive_vk_tables_once_s": None,
                     "verifier_peak_rss_gib": round((((v1.get("receiver") or {}).get("process") or {}).get("peak_rss_bytes") or 0) / 2**30, 3) or None},
        "proof_sha256": v1.get("proof_sha256"),
    }
    files = shim_files(run)
    if files:
        counter = load(files[0])
        v2["counters"] = counters_view(counter, pipeline)
        v2["counters"]["file"] = str(files[0])
    sqlite = run / "nsys/timeline.sqlite"
    if sqlite.is_file():
        try:
            v2["gpu"]["nsys"] = nsys_view(sqlite, pipeline)
        except Exception as error:
            v2["gpu"]["nsys_error"] = repr(error)
    if reference:
        ref = receipt_of(reference)
        v2["correctness"]["fingerprint_vs_reference"] = {"reference": str(reference), **fingerprint_diff(v1, ref)}
    return v2


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    r = sub.add_parser("receipt-v2")
    r.add_argument("run")
    r.add_argument("--reference")
    r.add_argument("--out")
    f = sub.add_parser("fingerprint")
    f.add_argument("a")
    f.add_argument("b")
    n = sub.add_parser("nsys")
    n.add_argument("run")
    n.add_argument("--out")
    m = sub.add_parser("smaps")
    m.add_argument("pid", type=int)
    m.add_argument("--out")
    args = parser.parse_args()
    if args.command == "receipt-v2":
        result = build_v2(args.run, args.reference)
        out = Path(args.out) if args.out else Path(args.run) / "receipt-v2.json"
    elif args.command == "fingerprint":
        result = fingerprint_diff(receipt_of(args.a), receipt_of(args.b))
        out = None
    elif args.command == "nsys":
        run = Path(args.run)
        result = nsys_view(run / "nsys/timeline.sqlite", pipeline_nodes(proof_dir(run)))
        out = Path(args.out) if args.out else None
    else:
        result = census(parse_smaps(args.pid))
        out = Path(args.out) if args.out else None
    text = json.dumps(result, indent=1)
    if out:
        out.write_text(text + "\n")
        print(str(out))
    else:
        print(text)


if __name__ == "__main__":
    main()
