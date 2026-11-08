#!/usr/bin/env python3
"""M4 arena stream: offline memory-preset sweep with a proof-fingerprint gate.

Runs one block under each preset (sequentially, each run takes the GPU lock via
the m3 harness), then selects the preset with the lowest device peak among the
presets whose proofs are byte-identical to the M3 baseline and whose native
prove is within --max-native-slowdown of the reference preset.

  python3 scripts/rv64/rv64_m4_arena_sweep.py BLOCK --lib LIB --presets presets.json --out sweep.json [--reuse]

presets.json: [{"name": "auto", "env": {"STWO_RV64_DEVICE_ARENA": "1"}}, ...]; the
first preset is the reference for the slowdown gate. --reuse skips presets whose
report already exists (resumable). Only dev blocks are accepted (owner rule).
A memory preset is scheduling-only: every knob it may set (arena capacity, PCS
idle-cache bytes, stream chunk words, composition direct path) is proven
proof-invariant elsewhere, and the gate re-checks that on every run.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
REPORTS = Path("/workspace/m3/runs/m4-arena/reports")
DEV_BLOCKS = {26235156, 24628607}
ALLOWED = ("STWO_RV64_DEVICE_ARENA", "STWO_RV64_DEVICE_ARENA_RESERVE", "STWO_RV64_DEVICE_ARENA_STACK",
           "STWO_RV64_PINNED_STAGING", "STWO_RV64_PINNED_STAGING_SLOT", "STWO_RV64_PCS_IDLE_CACHE_BYTES",
           "STWO_RV64_TRACE_STREAM_CHUNK_WORDS", "STWO_RV64_PCS_STREAM_CHUNK_WORDS", "STWO_RV64_COMPOSITION_DIRECT")


def peak_gb(report):
    s = report["arena"]["arena_summary"]
    if s:
        inits = {d["device"]: d for d in report["arena"]["arena_init"]}
        return max(d.get("physical_high_water_bytes", 0) + inits.get(d["device"], {}).get("total_bytes", 0)
                   - inits.get(d["device"], {}).get("free_after_stack_bytes", 0) for d in s) / 1e9
    phys = (report.get("physical_gpu_memory_peak") or {}).get("peak_used_bytes") or {}
    return max(phys.values()) / 1e9 if phys else None


def main():
    p = argparse.ArgumentParser()
    p.add_argument("block", type=int)
    p.add_argument("--lib", required=True)
    p.add_argument("--presets", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--prefix", default="sweep")
    p.add_argument("--mode", default="prove", choices=("prove", "bench"))
    p.add_argument("--reuse", action="store_true")
    p.add_argument("--max-native-slowdown", type=float, default=0.15)
    a = p.parse_args()
    if a.block not in DEV_BLOCKS:
        raise SystemExit("owner rule: dev blocks only")
    presets = json.loads(Path(a.presets).read_text())
    rows = []
    for preset in presets:
        bad = [k for k in preset["env"] if k not in ALLOWED]
        if bad:
            raise SystemExit(f"preset {preset['name']}: non-memory knob(s) {bad}")
        tag = f"{str(a.block)[-3:]}-{a.prefix}-{preset['name']}"
        report_path = REPORTS / f"{tag}.json"
        if not (a.reuse and report_path.is_file()):
            argv = [str(HERE / "rv64/rv64_m4_arena_job.sh"), a.mode, str(a.block), tag, a.lib] + [f"{k}={v}" for k, v in preset["env"].items()]
            subprocess.run(argv, check=False)
        if not report_path.is_file():
            rows.append({"preset": preset["name"], "env": preset["env"], "status": "no_report"})
            continue
        r = json.loads(report_path.read_text())
        parity = (r.get("parity_vs_m3_baseline") or {}).get("byte_identical")
        st = r.get("stages") or {}
        rows.append({"preset": preset["name"], "env": preset["env"], "tag": tag, "byte_identical": parity,
                     "device_peak_gb": peak_gb(r), "native_prove_s": st.get("native_prove_s"),
                     "request_s": st.get("request_wall_s"), "recursion_s": st.get("recursion_s"),
                     "overruns": sum(d.get("overruns", 0) for d in r["arena"]["arena_summary"]),
                     "owner_oom_lines": r["arena"].get("owner_oom_lines"), "load1": r.get("load1_at_start")})
    ref = next((row for row in rows if row.get("native_prove_s")), None)
    for row in rows:
        ok = row.get("byte_identical") is True and row.get("device_peak_gb") is not None
        if ok and ref and row.get("native_prove_s"):
            row["native_slowdown"] = row["native_prove_s"] / ref["native_prove_s"] - 1
            ok = row["native_slowdown"] <= a.max_native_slowdown
        row["admitted"] = ok
    admitted = [row for row in rows if row["admitted"]]
    chosen = min(admitted, key=lambda row: row["device_peak_gb"]) if admitted else None
    out = {"schema": "rv64-m4-arena-sweep/v1", "block": a.block, "library": a.lib, "rows": rows,
           "gate": {"fingerprint": "byte-identical to M3 baseline (native bins, bundle, tree, every recursive proof)",
                    "max_native_slowdown": a.max_native_slowdown, "reference": ref and ref["preset"]},
           "chosen": chosen}
    Path(a.out).write_text(json.dumps(out, indent=1) + "\n")
    print(json.dumps(out, indent=1))
    return 0 if chosen else 1


if __name__ == "__main__":
    sys.exit(main())
