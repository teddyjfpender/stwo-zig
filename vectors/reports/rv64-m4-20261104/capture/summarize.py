#!/usr/bin/env python3
"""Build the capture-stream receipts from raw/ (pod outputs) - run from this directory.

Writes <block>-capture-ledger.json per dev block and appends progress rows to
vectors/reports/progress/capture.jsonl. All numbers are copied from raw receipts [M];
nothing is estimated here.
"""
import json, sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
RAW = HERE / "raw"
COMMIT = sys.argv[1] if len(sys.argv) > 1 else "capture-v3@bcd401ce4"
MANIFEST = sys.argv[2] if len(sys.argv) > 2 else None

# Producer report.json breakdowns (block_to_inputs.capture + capture_breakdown) of the GPU runs,
# extracted on the pod from <run>/case/batch/trial-0/<block>/proof/report.json [M].
GPU_PRODUCER = {
    "24628607": {
        "m3_scale": {"run": "integrate/24628607-2gpu-scale", "breakdown": {"image_load_ns": 500437030, "program_ns": 110419062, "pre_import_ns": 84629967, "import_ns": 2579105878},
                     "inputs": {"init_ns": 695486059, "first_inputs_ns": 2103045789, "last_inputs_ns": 3093788898, "all_inputs_ns": 3274592087, "ledger_ns": 1166652973, "ledger_finish_ns": 150413377}},
        "v3": {"run": "m4-capture/24628607-2gpu-v3", "breakdown": {"image_load_ns": 535370203, "program_ns": 117232486, "pre_import_ns": 89054047, "import_ns": 2308562054},
               "inputs": {"init_ns": 741656736, "first_inputs_ns": 2098627396, "last_inputs_ns": 2951656576, "all_inputs_ns": 3050218980, "ledger_ns": 550636190, "ledger_finish_ns": 65147073}},
    },
    "26235156": {
        "m3_scale": {"run": "integrate/26235156-2gpu-scale", "breakdown": {"image_load_ns": 528149854, "program_ns": 116490383, "pre_import_ns": 82277678, "import_ns": 1816141991},
                     "inputs": {"init_ns": 726917915, "first_inputs_ns": 1908641691, "last_inputs_ns": 2424598539, "all_inputs_ns": 2543060196, "ledger_ns": 718434109, "ledger_finish_ns": 72790305}},
        "v3": {"run": "m4-capture/26235156-2gpu-v3", "breakdown": {"image_load_ns": 612820018, "program_ns": 144433705, "pre_import_ns": 144852244, "import_ns": 1633397959},
               "inputs": {"init_ns": 902105967, "first_inputs_ns": 1970568277, "last_inputs_ns": 2449725083, "all_inputs_ns": 2535504086, "ledger_ns": 280150754, "ledger_finish_ns": 44093374}},
    },
}
M3_SCALE = {  # integrate/<block>-2gpu-scale receipt stages [M] (vectors/reports/rv64-m3-20261104/integrate/scale)
    "24628607": {"request_wall_s": 51.114, "capture_s": 3.275, "setup_s": 12.553, "native_prove_s": 7.83, "recursion_s": 27.275},
    "26235156": {"request_wall_s": 34.281, "capture_s": 2.543, "setup_s": 8.33, "native_prove_s": 5.156, "recursion_s": 18.068},
}
PARITY = {"24628607": {"reference": "integrate/24628607-2gpu-scale", "compared": 55, "byte_identical": True, "mismatched": []},
          "26235156": {"reference": "integrate/26235156-2gpu-scale", "compared": 37, "byte_identical": True, "mismatched": []}}
PARITY_V2 = {"26235156": {"reference": "integrate/26235156-2gpu-scale", "compared": 37, "byte_identical": True, "mismatched": []}}
BUILDS = {
    "base": "bcd401ce4 unmodified (M3 baseline source)",
    "v1": "paged ledger table + pdq boundary sort + no capacity rehash + ready hook",
    "v2": "v1 + env-gated ledger profile + traced-walk stats (report-only)",
    "v3": "v2 + LS event arrays allocated, THP-advised and prefaulted on the parallel capture jobs (= this commit's code)",
}


def cpu_rows(block):
    rows = []
    for path in sorted(RAW.glob(f"cap-{block}-*.json")):
        d = json.loads(path.read_text())
        c = d.get("capture") or {}
        ci, cb, dc = c.get("capture_inputs", {}), c.get("capture_breakdown", {}), c.get("direct_capture") or {}
        build = d["tag"].split("-")[0]
        rows.append({
            "file": f"raw/{path.name}", "build": build, "build_meaning": BUILDS.get(build), "tag": d["tag"], "rc": d["rc"],
            "capture_options": d["resources"]["capture_options"],
            "capture_s": c.get("image_and_import_ns", 0) / 1e9, "init_s": ci.get("init_ns", 0) / 1e9,
            "first_inputs_s": ci.get("first_inputs_ns", 0) / 1e9, "last_inputs_s": ci.get("last_inputs_ns", 0) / 1e9,
            "ledger_s": ci.get("ledger_ns", 0) / 1e9, "ledger_finish_s": ci.get("ledger_finish_ns", 0) / 1e9,
            "image_load_s": cb.get("image_load_ns", 0) / 1e9, "import_s": cb.get("import_ns", 0) / 1e9,
            "first_batch_capture_s": dc.get("first_batch_capture_ns", 0) / 1e9, "join_wait_s": dc.get("join_wait_ns", 0) / 1e9,
            "segments": dc.get("segments"), "memory_words": c.get("memory_words"), "total_steps": c.get("total_steps"),
            "captured_values_sha256": c.get("captured_values_sha256"),
            "process_wall_s": d["process_wall_s"], "process_avg_busy_cores": d["avg_busy_cores"], "max_rss_gib": d["max_rss_gib"],
            "minor_faults": d["minor_faults"], "loadavg_1m_before": d["loadavg_before"][0],
            "ledger_profile": [l for l in d.get("stderr_tail", "").splitlines() if l.startswith("CAPTURE_LEDGER_PROFILE")] or None,
        })
    return rows


def main():
    progress = []
    for block in ("26235156", "24628607"):
        rows = cpu_rows(block)
        digests = {r["captured_values_sha256"] for r in rows}
        gpu = json.loads((RAW / f"{block}-gpu-v3-receipt.json").read_text())
        out = {
            "schema": "rv64-m4-capture-receipt/v1", "stream": "capture", "milestone": "M4", "block": int(block),
            "label": "MEASURED, single observation per row; shared pod (1-min load 30-95, recorded per row); 2x RTX 5090",
            "commit": COMMIT, "parent": "bcd401ce447af9f34b7461c11fd92a7b52e104f5",
            "code_identity": "v3 binaries were built on the pod from source files byte-identical (sha256) to the commit adding this receipt",
            "code_manifest_sha256": MANIFEST,
            "builds": BUILDS,
            "metric": "capture_s = image_and_import_ns of the producer (process timer start to the last segment's inputs ready + ledger finish); same quantity as the harness stage capture_s",
            "cpu_capture_diagnostic": {
                "binary": "rv64-word16-ethereum-gkr (CPU product, ReleaseFast x86_64_v4+sha), mode `capture REQ - 0 RES`, in-process segment execution",
                "captured_values_sha256_all_equal": len(digests) == 1, "captured_values_sha256": sorted(digests),
                "runs": rows,
            },
            "gpu_production_path": {
                "driver": "rv64-word16-ethereum-gpu-combined built from this commit (harness `build --only zig`)",
                "driver_sha256": gpu["assets"]["driver"], "library_sha256": gpu["assets"]["library"], "receiver_sha256": gpu["assets"]["receiver"],
                "environment_overrides": gpu["environment_overrides"],
                "m3_baseline_stages": M3_SCALE[block], "v3_stages": gpu["stages"],
                "producer_capture_breakdown": GPU_PRODUCER[block],
                "proof_parity_vs_m3_scale": PARITY[block],
                "proof_parity_v2_vs_m3_scale": PARITY_V2.get(block),
                "parity_vs_accepted_v7": gpu["parity_vs_accepted_v7"],
                "receiver": {k: gpu["receiver"].get(k) for k in ("status", "accepted", "receiver_sha256")},
                "accepted": gpu["accepted"],
                "producer_process": {k: gpu["producer_process"].get(k) for k in ("wall_ns", "user_seconds", "system_seconds", "peak_rss_bytes", "minor_faults")},
                "receipt": f"raw/{block}-gpu-v3-receipt.json",
            },
        }
        (HERE / f"{block}-capture-ledger.json").write_text(json.dumps(out, indent=1) + "\n")
        s = gpu["stages"]
        pp = gpu["producer_process"]
        progress.append({"date": "2026-11-04", "commit": COMMIT, "stream": "capture", "milestone": "M4", "block": int(block), "gpus": 2,
                         "request_s": s["request_wall_s"], "capture_s": s["capture_s"], "setup_s": s["setup_s"], "native_s": s["native_prove_s"],
                         "recursion_s": s["recursion_s"], "verifier_s": None, "rss_peak_gib": round(pp["peak_rss_bytes"] / 2**30, 2),
                         "device_peak_gb": None, "proof_bytes": None, "byte_identical_to": PARITY[block]["reference"] if PARITY[block]["byte_identical"] else None,
                         "receiver_accepted": gpu["accepted"], "label": "M",
                         "notes": "production GPU path, M3 scale env; ledger %.3f->%.3f s, capture inputs %.3f->%.3f s (producer report); single obs, shared pod" % (
                             GPU_PRODUCER[block]["m3_scale"]["inputs"]["ledger_ns"] / 1e9, GPU_PRODUCER[block]["v3"]["inputs"]["ledger_ns"] / 1e9,
                             GPU_PRODUCER[block]["m3_scale"]["inputs"]["all_inputs_ns"] / 1e9, GPU_PRODUCER[block]["v3"]["inputs"]["all_inputs_ns"] / 1e9)})
        for r in rows:
            if r["build"] not in ("v3", "base"):
                continue
            progress.append({"date": "2026-11-04", "commit": COMMIT if r["build"] == "v3" else "bcd401ce4", "stream": "capture", "milestone": "M4",
                             "block": int(block), "gpus": 0, "request_s": None, "capture_s": round(r["capture_s"], 3), "setup_s": None, "native_s": None,
                             "recursion_s": None, "verifier_s": None, "rss_peak_gib": r["max_rss_gib"], "device_peak_gb": None, "proof_bytes": None,
                             "byte_identical_to": "captured_values_sha256 " + r["captured_values_sha256"][:16], "receiver_accepted": None, "label": "M",
                             "notes": "CPU capture diagnostic %s inflight=%d workers=%d ledger=%.3f s load=%.0f" % (r["tag"], r["capture_options"]["max_inflight_packets"], r["capture_options"]["execution_workers"], r["ledger_s"], r["loadavg_1m_before"])})
    prog = HERE.parent.parent / "progress" / "capture.jsonl"
    prog.parent.mkdir(parents=True, exist_ok=True)
    with prog.open("a") as f:
        for row in progress:
            f.write(json.dumps(row) + "\n")
    print(f"wrote {len(progress)} progress rows")


if __name__ == "__main__":
    main()
