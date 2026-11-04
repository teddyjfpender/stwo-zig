#!/usr/bin/env python3
"""Summarise per-stage device peaks from a producer log (stdout+stderr).

Measured counters (all printed by the producer, no estimation here):
  GPU_DEVICE_PEAK stage=trace_commit ...  live lease bytes and pool used at each
      MAIN/INTER/FIXED commit's peak point (every scratch lease allocated).
  GPU_TRACE_STREAM / GPU_PCS_STREAM       streamed plan geometry.
  GPU_PCS_NATIVE retained_bytes=          owner logical bytes after a PCS call
      (leases + idle cached PCS blocks + domains: the PCS high-water, since idle
      blocks are kept until evicted).
  GPU_OWNER_OOM / GPU_MEMORY_FAILURE      recovered/terminal allocation failures.
usage: peak_summary.py producer.stdout producer.stderr [--json out.json]
"""
import json, re, sys
from collections import defaultdict

def kv(line):
    return dict(re.findall(r"(\w+)=([^\s]+)", line))

def main(paths, out=None):
    text = "".join(open(p, errors="replace").read() for p in paths)
    trees = {"0": "fixed", "1": "main", "2": "inter"}
    commit = defaultdict(lambda: {"count": 0, "max_scratch_bytes": 0, "max_legacy_scratch_bytes": 0,
                                  "max_live_lease_bytes": 0, "max_pool_used_bytes": 0, "max_pool_reserved_bytes": 0, "modes": set()})
    pcs = {"count": 0, "max_retained_bytes": 0, "max_device_bytes": 0}
    oom = {"owner_oom": 0, "memory_failure": 0, "logical_cap": 0, "max_requested_bytes": 0}
    streams = {"trace": 0, "pcs": 0, "max_pcs_scratch_words": 0, "max_pcs_legacy_rebuild_words": 0}
    for line in text.splitlines():
        try:
            parse(line, commit, trees, pcs, oom, streams)
        except (KeyError, ValueError):
            streams["unparsed_lines"] = streams.get("unparsed_lines", 0) + 1  # interleaved lane output
    for c in commit.values():
        c["modes"] = sorted(c["modes"])
        c["max_predicted_peak_bytes"] = c["max_live_lease_bytes"]  # live leases include this commit's scratch
    result = {"label": "measured", "trace_commit": dict(commit), "pcs": pcs, "streams": streams, "allocation_failures": oom}
    print(json.dumps(result, indent=1))
    if out:
        json.dump(result, open(out, "w"), indent=1)

def parse(line, commit, trees, pcs, oom, streams):
    if True:
        if line.startswith("GPU_DEVICE_PEAK stage=trace_commit"):
            v = kv(line); c = commit[trees.get(v["tree"], v["tree"])]
            c["count"] += 1; c["modes"].add(v["mode"])
            for k, key in (("scratch_bytes", "max_scratch_bytes"), ("legacy_scratch_bytes", "max_legacy_scratch_bytes"),
                           ("live_lease_bytes", "max_live_lease_bytes"), ("pool_used_bytes", "max_pool_used_bytes"),
                           ("pool_reserved_bytes", "max_pool_reserved_bytes")):
                c[key] = max(c[key], int(v[k]))
        elif line.startswith("GPU_PCS_NATIVE prepare_ns"):
            v = kv(line); pcs["count"] += 1
            pcs["max_retained_bytes"] = max(pcs["max_retained_bytes"], int(v["retained_bytes"]))
            pcs["max_device_bytes"] = max(pcs["max_device_bytes"], int(v["device_bytes"]))
        elif line.startswith("GPU_TRACE_STREAM"):
            streams["trace"] += 1
        elif line.startswith("GPU_PCS_STREAM"):
            v = kv(line); streams["pcs"] += 1
            streams["max_pcs_scratch_words"] = max(streams["max_pcs_scratch_words"], int(v["scratch_words"]))
            streams["max_pcs_legacy_rebuild_words"] = max(streams["max_pcs_legacy_rebuild_words"], int(v["legacy_rebuild_words"]))
        elif line.startswith("GPU_OWNER_OOM"):
            oom["owner_oom"] += 1; oom["max_requested_bytes"] = max(oom["max_requested_bytes"], int(kv(line)["requested_bytes"]))
        elif line.startswith("GPU_MEMORY_FAILURE"):
            oom["memory_failure"] += 1
        elif line.startswith("GPU_OWNER_LOGICAL_CAP"):
            oom["logical_cap"] += 1

if __name__ == "__main__":
    args = sys.argv[1:]
    out = None
    if "--json" in args:
        i = args.index("--json"); out = args[i + 1]; del args[i:i + 2]
    main(args, out)
