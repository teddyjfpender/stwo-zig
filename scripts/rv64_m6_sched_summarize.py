#!/usr/bin/env python3
"""sched M6 (pod-side): summarize a resident daemon run (receipt.json + every request's recursion
pipeline.json and combined-report.json) into one compact receipt:
  python3 scripts/rv64_m6_sched_summarize.py RUN_DIR OUT.json
`device_stage_*` are lane device-stage walls (precommit+authority+device prove), an UPPER bound on
kernel-busy time; `gpu_kernel_activity_mean_percent` is the harness NVML sample mean over the whole
service process (boot + idle included)."""
import json, sys, os
from pathlib import Path
run = Path(sys.argv[1]); out = Path(sys.argv[2])
r = json.load(open(run / "receipt.json"))
reqs = []
for q in r["requests"]:
    proof = Path(q["proof"])
    p = json.load(open(proof / "recursion-om31/pipeline.json"))
    c = json.load(open(proof / "combined-report.json"))
    ns = p["nodes"]
    first_dev = min(n["stamps"]["device_start"] for n in ns)
    last_leaf = max(n["stamps"]["finish_end"] for n in ns if n["kind"] == "leaf")
    lanes = p["lanes"]
    # device busy union per physical lane-device (lane-stage wall; upper bound on kernel busy)
    busy = sum(n["stamps"]["device_end"] - n["stamps"]["device_start"] for n in ns)
    post_native_wall = p["dag_wall_ns"] - (p.get("device_wait_for_native_ns") or 0)
    stream = p.get("stream")
    reqs.append({
        "block": q["block"], "stages": q["stages"], "byte_identical_to_m3": q["parity_vs_m3"]["byte_identical"],
        "root_sha256": q["parity_vs_m3"]["root_sha256"], "proof_count": q["parity_vs_m3"]["proof_count"],
        "proof_bytes_root": q["proof_bytes_root"],
        "recursion": {"policy": p.get("policy"), "lanes": lanes, "options": p["options"], "dag_wall_s": round(p["dag_wall_ns"] / 1e9, 3),
                      "streaming": stream is not None,
                      "native_overlap_s": round((p.get("device_wait_for_native_ns") or 0) / 1e9, 3),
                      "first_device_start_s": round(first_dev / 1e9, 3), "last_leaf_finish_s": round(last_leaf / 1e9, 3),
                      "tail_after_last_leaf_s": round((p["dag_wall_ns"] - last_leaf) / 1e9, 3),
                      "lane_device_stage_occupancy": round(p["lane_device_stage_occupancy"], 4),
                      "device_stage_sum_s": round(busy / 1e9, 3),
                      "device_stage_busy_per_gpu_after_native": round(busy / max(1, (p["dag_wall_ns"] - first_dev)) / 2, 4),
                      "leaf_ready_s": [round(x / 1e9, 3) for x in (stream or {}).get("leaf_ready_ns", [])],
                      "native_done_s": round((stream or {}).get("native_done_ns", 0) / 1e9, 3),
                      "combined_recursion_ns": c["recursion_ns"], "recursion_after_native_ns": c.get("recursion_after_native_ns"), "native_verify_join_wait_ns": c.get("native_verify_join_wait_ns")}})
summary = {"schema": "rv64-m6-sched-run/v1", "label": "M", "run": str(run), "source_commit": r.get("source_commit"),
           "assets": r["assets"], "environment": r["environment"], "store_mode": r["store"]["mode"],
           "load_avg_before": r["load_avg_before"], "load_avg_after": r["load_avg_after"],
           "service_start_s": r["service_start_s"], "service_rss_peak_gib": round(r["producer_process"]["peak_rss_bytes"] / 2**30, 2),
           "device_peak_gb": {k: round(v / 1e9, 2) for k, v in r["physical_gpu_memory"]["peak_used_bytes"].items()},
           "gpu_kernel_activity_mean_percent": {k: round(v["mean_percent"], 1) for k, v in r["physical_gpu_memory"]["kernel_activity"].items()},
           "requests": reqs, "receivers": [{"block": x["block"], "accepted": x["accepted"], "wall_s": round(x["process"]["wall_ns"] / 1e9, 2)} for x in r.get("receivers", [])]}
out.write_text(json.dumps(summary, indent=1) + "\n")
print(json.dumps({"run": run.name, "rss": summary["service_rss_peak_gib"], "dev": summary["device_peak_gb"], "act": summary["gpu_kernel_activity_mean_percent"],
                  "req": [(x["block"], x["stages"]["request_wall_s"], x["stages"]["native_prove_s"], x["stages"]["recursion_s"], x["recursion"]["tail_after_last_leaf_s"], x["recursion"]["native_overlap_s"], x["byte_identical_to_m3"]) for x in reqs]}))
