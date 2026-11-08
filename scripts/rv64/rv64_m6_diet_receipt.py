#!/usr/bin/env python3
"""diet-wire (M6) receipt: recursion cell/time/memory census of one rv64_m3_pod.py run directory.

Everything is read from the run directory (all [M] except `committed_cells`, which is [D] = measured per-node row logs
(`GPU_OUTER ... logs={...}`, component_list order) x the component widths of component_list.zig component_facts,
the same widths scripts/rv64_m5_outer_gkr_census.py checked against GPU_TRACE_OWNERSHIP words):
  - node count / leaves / folds / fold arity / outer profile (tree.json, report.json)
  - recursion stage wall (receipt stages.recursion_s), DAG wall, per-lane device-stage seconds (pipeline.json)
  - device peak (receipt physical_gpu_memory_peak, NVML sampled, whole device) and the arena overruns (producer.stderr)
  - proof bytes: root proof, every recursive proof (sum), tree.json
  - receiver verdict (fresh process, cache-disabled; receipt.receiver)

  python3 scripts/rv64_m6_diet_receipt.py RUN_DIR [--out receipt.json] [--progress progress.jsonl --commit SHA --notes TEXT]
"""
import argparse
import datetime
import json
import re
from pathlib import Path

COMPONENTS = ["eq", "qm31_ops", "triple_xor", "m_31_to_u_32", "blake_g_gate", "verify_bitwise_xor_8",
              "verify_bitwise_xor_12", "verify_bitwise_xor_4", "verify_bitwise_xor_7", "verify_bitwise_xor_9", "range_check_16"]
MAIN = [4, 12, 20, 4, 52, 2, 16, 1, 1, 1, 1]
INTER = [2 * x for x in [4, 8, 24, 12, 52, 4, 32, 4, 4, 4, 4]]  # OM31 interaction = 2x the QM31-counted facts
PP_PER_ROW = [0, 0, 5, 3, 11, 0, 0, 0, 0, 0, 0]


def cells(logs):
    rows = [1 << r for r in logs]
    main = sum(m * n for m, n in zip(MAIN, rows))
    inter = sum(c * n for c, n in zip(INTER, rows))
    pp = sum(p * n for p, n in zip(PP_PER_ROW, rows))
    return {"main": main, "interaction": inter, "pp_gate_columns": pp, "total": main + inter + pp}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run", type=Path)
    ap.add_argument("--out", type=Path)
    ap.add_argument("--progress", type=Path)
    ap.add_argument("--commit", default="")
    ap.add_argument("--notes", default="")
    ap.add_argument("--byte-identical-to", default=None)
    args = ap.parse_args()
    run = args.run
    receipt = json.loads((run / "receipt.json").read_text())
    block = str(receipt["block"])
    rec_dir = next((run / "case/batch").glob(f"trial-0/{block}/proof/recursion-om31"))
    tree = json.loads((rec_dir / "tree.json").read_text())
    report = json.loads((rec_dir / "report.json").read_text())
    pipeline = json.loads((rec_dir / "pipeline.json").read_text())
    log = (run / "case/producer.stderr").read_text(errors="replace")
    # GPU_OUTER lines are emitted once per recursion node prove (native proofs do not emit them).
    node_logs = [[int(x) for x in m.group(1).split(",")] for m in re.finditer(r"^GPU_OUTER .*?logs=\{([^}]*)\}", log, re.M)]
    raw_shapes = re.findall(r"^RECURSION_NODE_SHAPE node=(\d+) kind=(\w+) .*?padded=\[([^\]]*)\]", log, re.M)
    n_nodes = len(tree["nodes"])
    if len(node_logs) != n_nodes or len(raw_shapes) != n_nodes:
        raise SystemExit(f"node census mismatch: tree {n_nodes}, GPU_OUTER {len(node_logs)}, shapes {len(raw_shapes)}")
    # The two records of one node are not adjacent under the pipelined executor: pair them by the padded row
    # counts of the five gate components (equal shapes have equal cells, so any pairing of equals is exact).
    unused = [(int(i), k, [int(x).bit_length() - 1 for x in pad.split(",")]) for i, k, pad in raw_shapes]
    shapes = []
    for logs in node_logs:
        at = next((j for j, (_, _, pad) in enumerate(unused) if pad == logs[:5]), None)
        if at is None:
            raise SystemExit(f"GPU_OUTER logs {logs} match no RECURSION_NODE_SHAPE")
        i, k, _ = unused.pop(at)
        shapes.append((i, k))
    per = [cells(l) for l in node_logs]
    kinds = [k for _, k in shapes]
    leaf_cells = sum(p["total"] for p, k in zip(per, kinds) if k == "leaf")
    fold_cells = sum(p["total"] for p, k in zip(per, kinds) if k == "fold")
    proofs = sorted(rec_dir.glob("*.proof"))
    node_proof_bytes = sum(p.stat().st_size for p in proofs if p.name != "root.proof")
    overruns = [int(x) for x in re.findall(r"^GPU_ARENA_OVERRUN .*?requested_bytes=(\d+)", log, re.M)]
    lane_dev = pipeline.get("lane_device_stage_ns") or []
    peak = receipt.get("physical_gpu_memory_peak", {}).get("peak_used_bytes", {})
    stages = receipt["stages"]
    recv = receipt.get("receiver", {})
    out = {
        "schema": "rv64-m6-diet-receipt/v1",
        "stream": "diet-wire",
        "milestone": "M6",
        "run": str(run),
        "block": int(block),
        "source_commit": receipt.get("source_commit"),
        "assets": receipt.get("assets"),
        "environment_overrides": receipt.get("environment_overrides"),
        "loadavg": receipt.get("loadavg"),
        "label": "M (one observation) except committed_cells = D (measured row logs x component_facts widths)",
        "outer_profile": tree.get("outer_profile", "r1_b2_q108_p20_fold4"),
        "fold_arity": report.get("fold_arity", 2),
        "outer_shape": report.get("outer_shape"),
        "nodes": n_nodes, "leaves": report["leaf_proofs"], "folds": report["fold_proofs"],
        "stages_s": stages,
        "recursion_total_s": report["total_ns"] / 1e9,
        "dag_wall_s": pipeline.get("dag_wall_ns", 0) / 1e9,
        "lane_device_stage_s": [x / 1e9 for x in lane_dev],
        "device_stage_gpu_s": sum(lane_dev) / 1e9,
        "lane_device_stage_occupancy": pipeline.get("lane_device_stage_occupancy"),
        "device_peak_gb": max(peak.values()) / 1e9 if peak else None,
        "arena_overruns": len(overruns), "largest_overrun_gb": max(overruns) / 1e9 if overruns else 0,
        "committed_cells": {"total": leaf_cells + fold_cells, "leaves": leaf_cells, "folds": fold_cells,
                            "per_node": [{"node": int(i), "kind": k, "logs": l, **p} for (i, k), l, p in zip(shapes, node_logs, per)]},
        "proof_bytes": {"root": report["root_proof_bytes"], "all_node_proofs": node_proof_bytes,
                        "tree_json": (rec_dir / "tree.json").stat().st_size},
        "receiver": {"accepted": recv.get("accepted"), "status": recv.get("status"), "receiver_sha256": recv.get("receiver_sha256"),
                     "gpu_disabled": recv.get("gpu_disabled"), "wall_s": (recv.get("process") or {}).get("wall_ns", 0) / 1e9},
    }
    if args.out:
        args.out.write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps({k: v for k, v in out.items() if k not in ("committed_cells", "assets", "environment_overrides")}, indent=1))
    print("committed_cells", {k: out["committed_cells"][k] for k in ("total", "leaves", "folds")})
    if args.progress:
        row = {"date": datetime.date.today().isoformat(), "commit": args.commit, "stream": "diet-wire", "milestone": "M6",
               "block": int(block), "gpus": receipt.get("gpus"), "request_s": stages.get("request_wall_s"),
               "capture_s": stages.get("capture_s"), "setup_s": stages.get("setup_s"), "native_s": stages.get("native_prove_s"),
               "recursion_s": stages.get("recursion_s"), "verifier_s": out["receiver"]["wall_s"],
               "rss_peak_gib": (receipt.get("producer_process") or {}).get("peak_rss_bytes", 0) / 2**30,
               "device_peak_gb": out["device_peak_gb"], "proof_bytes": report["root_proof_bytes"],
               "byte_identical_to": args.byte_identical_to, "receiver_accepted": out["receiver"]["accepted"], "label": "M",
               "notes": f"{args.notes} | arity {out['fold_arity']} nodes {n_nodes} committed cells {out['committed_cells']['total']/1e9:.2f} G [D] "
                        f"device-stage {out['device_stage_gpu_s']:.2f} GPU-s load1 {(receipt.get('loadavg') or {}).get('start', {}).get('1m')}"}
        with args.progress.open("a") as f:
            f.write(json.dumps(row) + "\n")


if __name__ == "__main__":
    main()
