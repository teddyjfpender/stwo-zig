#!/usr/bin/env python3
"""Attribute owner ranges using launch correlations, including delayed kernels.

Range totals are inclusive (nested rows must not be added). GPU-seconds are
interval unions per physical GPU; CUDA API time is host-thread time and is
reported separately. This deliberately does not equate non-kernel time with
CPU overhead: transfers, host waits and concurrent kernels may overlap.
"""
import argparse
import bisect
import collections
import hashlib
import json
from pathlib import Path
import sqlite3


def union_ns(intervals):
    total = 0
    high = None
    for start, end in sorted(intervals):
        if high is None or start > high:
            total += end - start
            high = end
        elif end > high:
            total += end - high
            high = end
    return total


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--phase", choices=("full", "after-native"), default="full")
    args = parser.parse_args()
    receipt = json.loads((args.run / "receipt.json").read_text())
    path = args.run / "nsys/timeline.sqlite"
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    tables = {row[0] for row in db.execute("select name from sqlite_master where type='table'")}
    if "NVTX_EVENTS" not in tables:
        raise SystemExit("No NVTX ranges: attribution gate failed")
    strings = dict(db.execute("select id,value from StringIds"))
    ranges = []
    for row in db.execute("select * from NVTX_EVENTS where end is not null and end>start"):
        item = dict(row)
        label = item.get("text") or strings.get(item.get("textId"), "")
        if not label.startswith(("rv64/", "m7/pcs/")):
            continue
        ranges.append({"start": item["start"], "end": item["end"], "tid": item.get("globalTid"), "label": label})
    if not ranges:
        raise SystemExit("No rv64 owner ranges: attribution gate failed")
    runtime = collections.defaultdict(list)
    correlation = collections.defaultdict(list)
    for row in db.execute("select start,end,globalTid,correlationId,nameId from CUPTI_ACTIVITY_KIND_RUNTIME order by start"):
        item = {"start": row[0], "end": row[1], "tid": row[2], "correlation": row[3], "name": strings[row[4]]}
        runtime[item["tid"]].append(item)
        correlation[item["correlation"]].append(item)
    starts = {tid: [item["start"] for item in values] for tid, values in runtime.items()}
    activity = collections.defaultdict(list)
    unmatched = collections.Counter()
    for table, kind in [("CUPTI_ACTIVITY_KIND_KERNEL", "kernel"), ("CUPTI_ACTIVITY_KIND_MEMCPY", "copy"), ("CUPTI_ACTIVITY_KIND_MEMSET", "set")]:
        if table not in tables:
            continue
        extra = ",bytes,copyKind" if kind == "copy" else ",bytes" if kind == "set" else ""
        for row in db.execute(f"select start,end,deviceId,correlationId{extra} from {table}"):
            candidates = correlation.get(row[3], [])
            if len(candidates) != 1:
                unmatched[kind] += 1
                continue
            call = candidates[0]
            item = {"start": row[0], "end": row[1], "device": row[2], "kind": kind}
            if kind in ("copy", "set"):
                item["bytes"] = row[4]
            if kind == "copy":
                item["copy_kind"] = row[5]
            activity[(call["tid"], call["correlation"])].append(item)

    epoch = db.execute("select utcEpochNs from TARGET_INFO_SESSION_START_TIME").fetchone()[0]
    reports = []
    for request in receipt["requests"]:
        ack = args.run / "spool/done" / f'{request["ordinal"]:04d}-{request["block"]}.json'
        end = ack.stat().st_mtime_ns - epoch
        start = end - request["client_latency_ns"]
        if args.phase == "after-native":
            combined = json.loads((Path(request["proof"]) / "combined-report.json").read_text())
            producer_start = end - request["marker"]["request_wall_ns"]
            entry_path = Path(request["proof"]) / "combined-entry.json"
            entry = json.loads(entry_path.read_text()) if entry_path.is_file() else {}
            start = producer_start + entry.get("phase_transition_ns", 0) + sum(combined[key] for key in ("capture_ns", "native_setup_ns", "native_prove_ns")) + 5_000_000
        selected = [item for item in ranges if item["start"] < end and item["end"] > start]
        # Controller mode encloses PCS and inline callbacks. OFF mode has
        # separate callback/PCS parents. Compare their outermost owner union,
        # rather than adding inclusive child rows to the controller parent.
        owners = [item for item in selected if item["label"].startswith("rv64/owner/")]
        top_owners = [item for item in owners if not any(
            parent is not item and parent["tid"] == item["tid"]
            and parent["start"] <= item["start"] and parent["end"] >= item["end"]
            and (parent["start"] < item["start"] or parent["end"] > item["end"])
            for parent in owners)]
        selected += [dict(item, label="rv64/owner/top_level_union") for item in top_owners]
        groups = {}
        for marker in selected:
            group = groups.setdefault(marker["label"], {"ranges": 0, "host_range_ns": 0, "host_api": collections.defaultdict(lambda: [0, 0]), "gpu": collections.defaultdict(list), "copies_bytes": collections.Counter(), "outside_owner_kernel_ns": 0})
            group["ranges"] += 1
            group["host_range_ns"] += min(marker["end"], end) - max(marker["start"], start)
            tid = marker["tid"]
            values = runtime.get(tid, [])
            first = bisect.bisect_left(starts.get(tid, []), marker["start"])
            for call in values[first:]:
                if call["start"] >= marker["end"]:
                    break
                # Calls crossing a boundary are clipped for host API time;
                # their activities remain assigned to the enqueueing range.
                duration = max(0, min(call["end"], marker["end"], end) - max(call["start"], start))
                if duration:
                    group["host_api"][call["name"]][0] += 1
                    group["host_api"][call["name"]][1] += duration
                for item in activity.get((tid, call["correlation"]), []):
                    gpu_start, gpu_end = max(item["start"], start), min(item["end"], end)
                    if gpu_end <= gpu_start:
                        continue
                    group["gpu"][(item["kind"], item["device"])].append((gpu_start, gpu_end))
                    if item["kind"] == "copy":
                        group["copies_bytes"][str(item["copy_kind"])] += item["bytes"]
                    if item["kind"] == "kernel":
                        inside = max(0, min(gpu_end, marker["end"]) - max(gpu_start, marker["start"]))
                        group["outside_owner_kernel_ns"] += gpu_end - gpu_start - inside
        out = {}
        for label, group in sorted(groups.items()):
            gpu = {}
            for kind in ("kernel", "copy", "set"):
                per = {str(device): union_ns(intervals) / 1e9 for (k, device), intervals in group["gpu"].items() if k == kind}
                gpu[kind] = {"gpu_seconds": sum(per.values()), "by_device_seconds": per}
            api = {name: {"calls": count, "host_seconds": ns / 1e9} for name, (count, ns) in sorted(group["host_api"].items(), key=lambda pair: -pair[1][1])}
            out[label] = {"ranges": group["ranges"], "inclusive_host_range_seconds": group["host_range_ns"] / 1e9, "correlated_gpu_activity": gpu, "cuda_host_api": api, "copy_bytes_by_cupti_kind": dict(group["copies_bytes"]), "kernel_duration_outside_enqueue_range_seconds": group["outside_owner_kernel_ns"] / 1e9}
        phase_kernels = collections.defaultdict(list)
        for values in activity.values():
            for item in values:
                if item["kind"] != "kernel":
                    continue
                lo, hi = max(start, item["start"]), min(end, item["end"])
                if hi > lo:
                    phase_kernels[str(item["device"])].append((lo, hi))
        per_device = {device: union_ns(values) / 1e9 for device, values in phase_kernels.items()}
        reports.append({"block": request["block"], "trial": request["trial"], "ordinal": request["ordinal"], "request_wall_seconds": request["marker"]["request_wall_ns"] / 1e9, "request_window_ns": [start, end], "phase_wall_seconds": (end-start)/1e9, "phase_kernel_gpu_seconds": sum(per_device.values()), "phase_kernel_by_device_seconds": per_device, "ranges": out})
    result = {"schema": "rv64-nvtx-owner-attribution/v1", "label": "M", "phase": args.phase, "scope": "Inclusive host ranges and correlation-owned GPU work. Nested labels overlap; do not add rows. API waits, copies and kernels overlap. Unmatched activities remain unassigned; no attribution is inferred from kernel names. After-native uses the recorded exclusive native-stage end plus a 5ms uncertainty band; UTC request windows derive from spool acknowledgement mtime.", "assets": receipt["assets"], "sqlite_sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "total_marker_ranges": len(ranges), "activities_without_unique_runtime_correlation": dict(unmatched), "requests": reports}
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"markers": len(ranges), "requests": [{"block": item["block"], "trial": item["trial"], "stages": {name: {"host_s": value["inclusive_host_range_seconds"], "kernel_gpu_s": value["correlated_gpu_activity"]["kernel"]["gpu_seconds"]} for name, value in item["ranges"].items()}} for item in reports]}, indent=2))


if __name__ == "__main__":
    main()
