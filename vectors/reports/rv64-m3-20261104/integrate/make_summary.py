#!/usr/bin/env python3
"""Build summary.json + the per-block table from the integrate scale-up receipts (scale/*.json)."""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ORDER = [26235156, 24647140, 24628607, 25229957, 24628608, 24626900, 24697070, 24697073,
         26235168, 25229955, 24628590, 25229951, 24628595, 24628611, 26235159]
BASE = {}
for line in (HERE / "baseline-v7.txt").read_text().splitlines()[1:]:
    f = line.split()
    BASE[int(f[0])] = dict(instructions=int(f[1]), cpu_segments=int(f[2]), truths=int(f[3]), wall_s=float(f[4]),
                           recursion_s=float(f[5]), setup_s=float(f[6]), native_prove_s=float(f[7]),
                           capture_s=float(f[8]), native_verify_s=float(f[9]))
V7_2GPU_24628607 = 98.924

rows = []
for block in ORDER:
    path = HERE / "scale" / f"{block}.json"
    b = BASE[block]
    row = {"block": block, "instructions": b["instructions"], "cpu_segments": b["cpu_segments"], "truth_proofs": b["truths"],
           "v7_1gpu_request_s": b["wall_s"], "status": "not_run"}
    if path.is_file():
        r = json.loads(path.read_text())
        s = r.get("stages", {})
        rc = r.get("receiver", {})
        p = r.get("parity_vs_accepted_v7", {})
        row.update(status="accepted" if r.get("accepted") else ("rejected" if rc.get("status") == "rejected" else rc.get("status", "produced")),
                   label="measured", request_s=s.get("request_wall_s"), capture_s=s.get("capture_s"), setup_s=s.get("setup_s"),
                   native_prove_s=s.get("native_prove_s"), native_verify_side_thread_s=s.get("native_verify_s"),
                   native_verify_on_critical_path_s=0.0, recursion_s=s.get("recursion_s"),
                   speedup_vs_v7_1gpu=round(b["wall_s"] / s["request_wall_s"], 2) if s.get("request_wall_s") else None,
                   native_and_bundle_identical_to_v7=bool(p.get("native_bins") and p.get("bundle")),
                   recursive_mismatched_vs_v7=len(p.get("recursive_mismatched", [])),
                   receiver_accepted=r.get("accepted"), receiver_wall_s=round(rc["process"]["wall_ns"] / 1e9, 1) if rc.get("process", {}).get("wall_ns") else None,
                   receiver_restored_leaves=rc.get("restored_leaves"), receiver_restored_folds=rc.get("restored_folds"),
                   producer_peak_rss_gib=round(r["producer_process"]["peak_rss_bytes"] / 2**30, 1),
                   run=r.get("run"))
    rows.append(row)
summary = {"schema": "rv64-m3-summary/v1", "label": "measured unless noted", "rows": rows,
           "reference": {"accepted_2gpu_v7_24628607_request_s": V7_2GPU_24628607, "m3_target_24628607_request_s": 10.0}}
json.dump(summary, open(HERE.parent / "summary.json", "w"), indent=1)
print("| block | instr (M) | CPU+truth | request s | capture | setup | native prove | recursion | v7 1-GPU s | speedup | receiver |")
print("|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|")
for r in rows:
    if r["status"] == "not_run":
        print(f"| {r['block']} | {r['instructions']/1e6:.1f} | {r['cpu_segments']}+{r['truth_proofs']} | not run | | | | | {r['v7_1gpu_request_s']} | | |")
        continue
    print(f"| {r['block']} | {r['instructions']/1e6:.1f} | {r['cpu_segments']}+{r['truth_proofs']} | {r['request_s']} | {r['capture_s']} | {r['setup_s']} | {r['native_prove_s']} | {r['recursion_s']} | {r['v7_1gpu_request_s']} | {r['speedup_vs_v7_1gpu']}x | {r['status']} |")
