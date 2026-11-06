#!/usr/bin/env python3
"""Native-window timeline and critical chain from an existing nsys SQLite export.

Read-only over a resident-daemon run directory (receipt.json, spool/done acks,
proof/{combined-report,combined-entry,schedule}.json, nsys/timeline.sqlite).

Per request it reports, inside the native prove window only
[capture + setup end, + native_prove_ns]:
  * per physical GPU: busy union of kernel/copy/memset activity, in fixed bins;
  * per GPU idle attribution, sampled every --sample-us: while the device is
    idle, what are the host threads that enqueue onto it doing? Classes are
    exclusive and checked in order: blocked in a synchronising CUDA call
    (event/stream/device sync, synchronous memcpy), inside another CUDA API
    call, inside an rv64/m7 owner NVTX range without a CUDA call (host work
    on the proof path), or no owner range open (scheduler, admission, CPU
    stage, barrier);
  * per enqueuing thread: launches, sync calls and their host seconds;
  * NVTX GPU projection per label (union of the GPU activity launched from
    inside each range, as nsys nvtx_gpu_proj_sum does), next to host range time;
  * the schedule.json lane chains (stage1/stage2 phase origins are distinct,
    so they are reported per phase, never added to absolute times).
Every value is [M] from the trace except where a key says derived.
"""
import argparse
import bisect
import collections
import json
from pathlib import Path
import sqlite3

SYNC_APIS = ("cudaEventSynchronize", "cudaStreamSynchronize", "cudaDeviceSynchronize", "cudaMemcpy_", "cudaMemcpy2D_", "cuStreamSynchronize", "cuEventSynchronize", "cuCtxSynchronize")


def union(intervals):
    out = []
    for start, end in sorted(intervals):
        if out and start <= out[-1][1]:
            out[-1][1] = max(out[-1][1], end)
        else:
            out.append([start, end])
    return out


def length(intervals):
    return sum(end - start for start, end in intervals)


def clip(intervals, lo, hi):
    return [(max(s, lo), min(e, hi)) for s, e in intervals if e > lo and s < hi]


def covered(merged_starts, merged, t):
    i = bisect.bisect_right(merged_starts, t) - 1
    return i >= 0 and merged[i][1] > t


def native_window(run, request, epoch):
    ack = run / "spool/done" / f'{request["ordinal"]:04d}-{request["block"]}.json'
    end = ack.stat().st_mtime_ns - epoch
    producer_start = end - request["marker"]["request_wall_ns"]
    proof = Path(request["proof"])
    combined = json.loads((proof / "combined-report.json").read_text())
    entry_path = proof / "combined-entry.json"
    entry = json.loads(entry_path.read_text()) if entry_path.is_file() else {}
    start = producer_start + entry.get("phase_transition_ns", 0) + combined["capture_ns"] + combined["native_setup_ns"]
    return start, start + combined["native_prove_ns"], combined


def lane_chains(proof):
    path = proof / "schedule.json"
    if not path.is_file():
        return None
    schedule = json.loads(path.read_text())
    result = {}
    for phase in ("stage1", "stage2"):
        rows = schedule.get(phase) or []
        lanes = collections.defaultdict(list)
        for ordinal, row in enumerate(rows):
            lanes[row["lane"]].append({"ordinal": ordinal, "claimed_ms": row["claimed_ns"] / 1e6, "started_ms": row["started_ns"] / 1e6,
                                       "finished_ms": row["finished_ns"] / 1e6, "admission_wait_ms": (row["started_ns"] - row["claimed_ns"]) / 1e6,
                                       "estimate_bytes": row["estimate_bytes"], "in_flight_bytes_at_start": row["in_flight_bytes_at_start"]})
        summary = {}
        for lane, items in sorted(lanes.items()):
            items.sort(key=lambda item: item["started_ms"])
            summary[str(lane)] = {"finish_ms": max(i["finished_ms"] for i in items), "busy_ms": sum(i["finished_ms"] - i["started_ms"] for i in items),
                                  "admission_wait_ms": sum(i["admission_wait_ms"] for i in items), "ordinals": [i["ordinal"] for i in items], "items": items}
        span = max((v["finish_ms"] for v in summary.values()), default=0)
        critical = max(summary, key=lambda lane: summary[lane]["finish_ms"]) if summary else None
        result[phase] = {"span_ms": span, "critical_lane": critical, "lanes": summary}
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--bin-ms", type=float, default=100.0)
    parser.add_argument("--sample-us", type=float, default=50.0)
    args = parser.parse_args()
    receipt = json.loads((args.run / "receipt.json").read_text())
    sqlite_path = args.run / "nsys/timeline.sqlite"
    db = sqlite3.connect(sqlite_path)
    strings = dict(db.execute("select id,value from StringIds"))
    epoch = db.execute("select utcEpochNs from TARGET_INFO_SESSION_START_TIME").fetchone()[0]
    report = {"schema": "rv64-m8-native-timeline/v1", "label": "M", "run": str(args.run), "sqlite": str(sqlite_path),
              "assets": receipt.get("assets"), "sample_us": args.sample_us, "bin_ms": args.bin_ms, "requests": []}
    for request in receipt["requests"]:
        lo, hi, combined = native_window(args.run, request, epoch)
        calls = collections.defaultdict(list)
        by_correlation = {}
        for start, end, tid, corr, name in db.execute("select start,end,globalTid,correlationId,nameId from CUPTI_ACTIVITY_KIND_RUNTIME where end>? and start<?", (lo, hi)):
            label = strings[name]
            calls[tid].append((start, end, label))
            by_correlation[corr] = (tid, start)
        activity = collections.defaultdict(list)
        thread_device = collections.defaultdict(collections.Counter)
        launched = collections.defaultdict(list)
        for table in ("CUPTI_ACTIVITY_KIND_KERNEL", "CUPTI_ACTIVITY_KIND_MEMCPY", "CUPTI_ACTIVITY_KIND_MEMSET"):
            for start, end, device, corr in db.execute(f"select start,end,deviceId,correlationId from {table} where end>? and start<?", (lo, hi)):
                activity[device].append((start, end))
                owner = by_correlation.get(corr)
                if owner:
                    thread_device[owner[0]][device] += 1
                    launched[owner[0]].append((owner[1], start, end, device))
        ranges = collections.defaultdict(list)
        for start, end, tid, text, text_id in db.execute("select start,end,globalTid,text,textId from NVTX_EVENTS where end is not null and end>? and start<?", (lo, hi)):
            label = text or strings.get(text_id, "")
            if label.startswith(("rv64/", "m7/pcs/")):
                ranges[tid].append((start, end, label))
        devices = {}
        sample_ns = int(args.sample_us * 1000)
        for device in sorted(activity):
            busy = union(clip(activity[device], lo, hi))
            starts = [s for s, _ in busy]
            owners = [tid for tid, counts in thread_device.items() if counts.most_common(1)[0][0] == device]
            owner_sync = {tid: union([(s, e) for s, e, n in calls[tid] if n.startswith(SYNC_APIS)]) for tid in owners}
            owner_api = {tid: union([(s, e) for s, e, n in calls[tid] if not n.startswith(SYNC_APIS)]) for tid in owners}
            owner_range = {tid: union([(s, e) for s, e, _ in ranges.get(tid, [])]) for tid in owners}
            classes = [(name, {tid: ([s for s, _ in kind[tid]], kind[tid]) for tid in owners})
                       for name, kind in (("host_blocked_in_sync", owner_sync), ("host_in_other_cuda_api", owner_api), ("host_work_in_owner_range", owner_range))]
            # Innermost open owner label per thread, for host-work idle samples.
            labelled = {tid: sorted(ranges.get(tid, [])) for tid in owners}
            label_starts = {tid: [r[0] for r in labelled[tid]] for tid in owners}
            idle = collections.Counter()
            idle_labels = collections.Counter()
            t = lo
            while t < hi:
                if not covered(starts, busy, t):
                    state = "no_owner_range"
                    for name, table in classes:
                        if any(covered(table[tid][0], table[tid][1], t) for tid in owners):
                            state = name
                            break
                    idle[state] += sample_ns
                    if state == "host_work_in_owner_range":
                        for tid in owners:
                            open_ranges = [r for r in labelled[tid][:bisect.bisect_right(label_starts[tid], t)] if r[1] > t]
                            if open_ranges:
                                idle_labels[max(open_ranges, key=lambda r: r[0])[2]] += sample_ns
                t += sample_ns
            bins = []
            width = int(args.bin_ms * 1e6)
            for b in range(lo, hi, width):
                bins.append(round(length(clip(busy, b, min(b + width, hi))) / min(width, hi - b), 3))
            devices[str(device)] = {"busy_s": length(busy) / 1e9, "busy_fraction": length(busy) / (hi - lo), "idle_attribution_s": {k: v / 1e9 for k, v in sorted(idle.items())},
                                    "host_work_idle_by_innermost_label_s": {k: v / 1e9 for k, v in idle_labels.most_common()},
                                    "enqueue_threads": len(owners), "busy_by_bin": bins}
        threads = []
        for tid, counts in thread_device.items():
            sync = collections.Counter()
            sync_ns = collections.Counter()
            for s, e, n in calls[tid]:
                if n.startswith(SYNC_APIS):
                    key = n.split("_v")[0]
                    sync[key] += 1
                    sync_ns[key] += min(e, hi) - max(s, lo)
            launches = sum(1 for _, _, n in calls[tid] if n.startswith("cudaLaunch") or n.startswith("cuLaunch"))
            first = min(s for s, _, _ in calls[tid]) - lo
            last = max(e for _, e, _ in calls[tid]) - lo
            threads.append({"tid": tid, "device": counts.most_common(1)[0][0], "launches": launches, "sync_calls": dict(sync), "sync_host_s": {k: v / 1e9 for k, v in sync_ns.items()},
                            "first_call_ms": first / 1e6, "last_call_ms": last / 1e6, "owner_range_s": length(clip(union([(s, e) for s, e, _ in ranges.get(tid, [])]), lo, hi)) / 1e9})
        threads.sort(key=lambda row: (row["device"], row["first_call_ms"]))
        projection = collections.defaultdict(lambda: {"ranges": 0, "host_s": 0, "gpu_projection_s": 0, "gpu_busy_s": 0})
        for tid, items in ranges.items():
            work = sorted(launched.get(tid, []))
            api_times = [w[0] for w in work]
            for s, e, label in items:
                row = projection[label]
                row["ranges"] += 1
                row["host_s"] += (min(e, hi) - max(s, lo)) / 1e9
                a, b = bisect.bisect_left(api_times, s), bisect.bisect_right(api_times, e)
                inside = [(w[1], w[2]) for w in work[a:b]]
                if inside:
                    row["gpu_projection_s"] += (max(x for _, x in inside) - min(x for x, _ in inside)) / 1e9
                    row["gpu_busy_s"] += length(union(inside)) / 1e9
        total_sync = sum(sum(t["sync_calls"].values()) for t in threads)
        report["requests"].append({
            "block": request["block"], "ordinal": request["ordinal"], "request_wall_s": request["marker"]["request_wall_ns"] / 1e9,
            "native_window_s": (hi - lo) / 1e9, "capture_s": combined["capture_ns"] / 1e9, "native_prove_s": combined["native_prove_ns"] / 1e9,
            "recursion_after_native_s": combined.get("recursion_after_native_ns", 0) / 1e9, "devices": devices,
            "native_kernel_launches": sum(t["launches"] for t in threads), "native_sync_calls": total_sync, "native_proofs": request.get("leaves"),
            "threads": threads, "nvtx_gpu_projection": dict(sorted(projection.items())),
            "schedule_chains": lane_chains(Path(request["proof"]))})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=1) + "\n")
    for row in report["requests"]:
        print(json.dumps({"ordinal": row["ordinal"], "native_prove_s": row["native_prove_s"], "launches": row["native_kernel_launches"], "syncs": row["native_sync_calls"],
                          "devices": {d: {"busy": round(v["busy_fraction"], 3), "idle": {k: round(x, 3) for k, x in v["idle_attribution_s"].items()}} for d, v in row["devices"].items()},
                          "stage_spans_ms": {p: (round(c["span_ms"]), c["critical_lane"]) for p, c in (row["schedule_chains"] or {}).items()}}))


if __name__ == "__main__":
    main()
