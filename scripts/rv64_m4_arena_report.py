#!/usr/bin/env python3
"""M4 arena stream: turn a harness run directory into an arena receipt.

  python3 rv64_m4_arena_report.py RUN_DIR --block B --label NAME --out OUT.json
      [--baseline vectors/reports/rv64-m3-20261104/integrate/scale/<B>.json]
      [--progress vectors/reports/progress/arena.jsonl --commit C --milestone M4]

Reads RUN_DIR/receipt.json (rv64_m3_pod.py) and the producer logs. Extracts:
  - GPU_ARENA_INIT / GPU_ARENA_HW / GPU_ARENA_OVERRUN / GPU_ARENA_SUMMARY
  - GPU_POOL_SUMMARY (pool mallocs, trims, OOM recoveries) and
    GPU_STAGING_SUMMARY (pageable vs pinned vs staged copies)
  - per-stage device live peaks from GPU_DEVICE_PEAK pool_used_bytes (in arena
    mode that is the device-wide live arena bytes) and GPU_COMPOSITION_ARENA
  - arena high-water attribution: each GPU_ARENA_HW line is tagged with the
    closest preceding stage line in producer.stderr (log order, both lanes
    interleave, so the tag is approximate and labelled as such)
  - byte identity against the M3 baseline receipt: native bins, bundle,
    recursive tree and every recursive proof (strongest scheduling check).
"""
import argparse
import json
import re
import sys
from pathlib import Path

KV = re.compile(r"(\w+)=([^\s{]+|\{[^}]*\})")
STAGE_PREFIXES = ("GPU_DEVICE_PEAK", "GPU_COMPOSITION_ARENA", "GPU_PCS_NATIVE", "GPU_OUTER_ASSIGNMENT ",
                  "GPU_OUTER ", "GPU_GKR ", "GPU_CPU_PROJECTION", "GPU_CORE_INGRESS", "GPU_TRUTH_COMPOSITION_RESIDENT",
                  "GPU_COMPOSITION_RESIDENT", "GPU_RESIDENT_SETUP", "GPU_TRACE_STREAM")


def kv(line):
    out = {}
    for k, v in KV.findall(line):
        try:
            out[k] = int(v)
        except ValueError:
            try:
                out[k] = float(v)
            except ValueError:
                out[k] = v
    return out


def stage_tag(line):
    head = line.split(" ", 1)[0]
    d = kv(line)
    if head == "GPU_DEVICE_PEAK":
        return f"{head}:{d.get('stage')}:tree{d.get('tree')}"
    if head == "GPU_COMPOSITION_ARENA":
        return f"{head}:eval_log{d.get('eval_log')}"
    return head


def parse_logs(case):
    err = (case / "producer.stderr").read_text(errors="replace").splitlines()
    out = (case / "producer.stdout").read_text(errors="replace").splitlines()
    result = {"arena_init": [], "arena_hw": [], "arena_overrun": [], "arena_summary": [],
              "pool_summary": None, "staging_summary": None}
    last_stage = "start"
    peaks = {}
    comp = {}
    for line in err + out:
        if line.startswith(STAGE_PREFIXES):
            last_stage = stage_tag(line)
        if line.startswith("GPU_ARENA_INIT"):
            result["arena_init"].append(kv(line))
        elif line.startswith("GPU_ARENA_HW"):
            d = kv(line)
            d["after_stage_line"] = last_stage
            result["arena_hw"].append(d)
        elif line.startswith("GPU_ARENA_OVERRUN"):
            result["arena_overrun"].append(kv(line))
        elif line.startswith("GPU_ARENA_SUMMARY"):
            result["arena_summary"].append(kv(line))
        elif line.startswith("GPU_POOL_SUMMARY"):
            result["pool_summary"] = kv(line)
        elif line.startswith("GPU_STAGING_SUMMARY"):
            result["staging_summary"] = kv(line)
        elif line.startswith("GPU_DEVICE_PEAK"):
            d = kv(line)
            key = f"{d.get('stage')}:tree{d.get('tree')}"
            for field in ("pool_used_bytes", "live_lease_bytes", "scratch_bytes"):
                if isinstance(d.get(field), int):
                    peaks.setdefault(key, {}).setdefault(field, 0)
                    peaks[key][field] = max(peaks[key][field], d[field])
        elif line.startswith("GPU_COMPOSITION_ARENA"):
            d = kv(line)
            key = f"eval_log{d.get('eval_log')}"
            if isinstance(d.get("arena_words"), int):
                comp[key] = max(comp.get(key, 0), d["arena_words"] * 4)
    result["device_peak_by_stage_line"] = peaks
    result["composition_arena_bytes_max"] = comp
    result["owner_oom_lines"] = sum(1 for l in err if l.startswith("GPU_OWNER_OOM"))
    return result


def flat_proofs(ps):
    flat = {}
    for name, digest in (ps.get("native") or {}).items():
        flat["native/" + name] = digest
    flat["bundle"] = ps.get("bundle")
    rec = ps.get("recursive") or {}
    flat["recursive/tree"] = rec.get("tree_sha256")
    for name, digest in (rec.get("proof_sha256") or {}).items():
        flat["recursive/" + name] = digest
    return flat


def compare(receipt, baseline):
    mine, base = flat_proofs(receipt.get("proof_sha256") or {}), flat_proofs(baseline.get("proof_sha256") or {})
    mismatched = sorted(k for k in set(mine) | set(base) if mine.get(k) != base.get(k))
    return {"artifacts_compared": len(set(mine) | set(base)), "mismatched": mismatched[:40],
            "byte_identical": not mismatched and len(base) > 2,
            "baseline_root_sha256": base.get("recursive/root.proof"), "root_sha256": mine.get("recursive/root.proof")}


def main():
    p = argparse.ArgumentParser()
    p.add_argument("run")
    p.add_argument("--block", type=int, required=True)
    p.add_argument("--label", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--baseline")
    p.add_argument("--progress")
    p.add_argument("--commit", default="")
    p.add_argument("--milestone", default="M4")
    p.add_argument("--load1", type=float)
    p.add_argument("--notes", default="")
    a = p.parse_args()
    run = Path(a.run)
    receipt = json.loads((run / "receipt.json").read_text())
    logs = parse_logs(run / "case")
    out = {"schema": "rv64-m4-arena/v1", "label": a.label, "block": a.block, "run": str(run),
           "source_commit": receipt.get("source_commit"), "assets": receipt.get("assets"),
           "environment_overrides": receipt.get("environment_overrides"), "stages": receipt.get("stages"),
           "producer_process": receipt.get("producer_process"), "physical_gpu_memory_peak": receipt.get("physical_gpu_memory_peak"),
           "load1_at_start": a.load1, "arena": logs,
           "receiver": {k: (receipt.get("receiver") or {}).get(k) for k in ("status", "accepted", "process")},
           "accepted": receipt.get("accepted"),
           "parity_vs_accepted_v7": receipt.get("parity_vs_accepted_v7")}
    if a.baseline:
        out["parity_vs_m3_baseline"] = compare(receipt, json.loads(Path(a.baseline).read_text()))
        out["parity_vs_m3_baseline"]["baseline"] = a.baseline
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    Path(a.out).write_text(json.dumps(out, indent=1) + "\n")
    st = receipt.get("stages") or {}
    pp = receipt.get("producer_process") or {}
    summaries = logs["arena_summary"]
    if summaries:
        device_peak = {str(s["device"]): round(s["high_water_bytes"] / 1e9, 3) for s in summaries}
    else:
        device_peak = {k: round(v / 1e9, 3) for k, v in ((receipt.get("physical_gpu_memory_peak") or {}).get("peak_used_bytes") or {}).items()}
    row = {"date": receipt.get("started_unix"), "commit": a.commit, "stream": "arena", "milestone": a.milestone,
           "block": a.block, "gpus": receipt.get("gpus"), "request_s": st.get("request_wall_s"),
           "capture_s": st.get("capture_s"), "setup_s": st.get("setup_s"), "native_s": st.get("native_prove_s"),
           "recursion_s": st.get("recursion_s"), "verifier_s": ((receipt.get("receiver") or {}).get("process") or {}).get("wall_ns", 0) / 1e9 or None,
           "rss_peak_gib": round(pp.get("peak_rss_bytes", 0) / 2**30, 2) or None,
           "device_peak_gb": device_peak,
           "device_peak_kind": "arena_live_high_water" if summaries else "nvml_sampled_whole_device",
           "proof_bytes": (lambda f: f.stat().st_size if f.is_file() else None)(run / "case/batch/trial-0" / str(a.block) / "proof/recursion-om31/root.proof"),
           "byte_identical_to": ("m3-baseline" if out.get("parity_vs_m3_baseline", {}).get("byte_identical") else None),
           "receiver_accepted": receipt.get("accepted"), "label": "M",
           "pool_mallocs": (logs["pool_summary"] or {}).get("pool_mallocs"),
           "pageable_copies": ((logs["staging_summary"] or {}).get("pageable_h2d", 0) + (logs["staging_summary"] or {}).get("pageable_d2h", 0)) if logs["staging_summary"] else None,
           "load1": a.load1, "notes": (a.label + (" " + a.notes if a.notes else ""))}
    if a.progress:
        with open(a.progress, "a") as f:
            f.write(json.dumps(row) + "\n")
    print(json.dumps(row))
    return 0


if __name__ == "__main__":
    sys.exit(main())
