#!/usr/bin/env python3
"""M4 integrate: build summary.json (+ the table data used by SUMMARY.md) and, with --ledger, append
progress rows to vectors/reports/progress/integrate.jsonl (run --ledger exactly once per data set).

Inputs are the receipts in this directory (copied back from /workspace/m3/runs/m4-integrate) and the M3
baseline summary (vectors/reports/rv64-m3-20261104/summary.json)."""
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
M3 = json.load(open(REPO / "vectors/reports/rv64-m3-20261104/summary.json"))
COMMIT = "cbe06a3f3"
DATE = "2026-11-04"

# Plan section 5, cumulative trajectory row "M4" (24628607) and the M4 exit-gate table.
PLAN_M4_607 = {"request_s": "33-36", "capture_s": "1.5", "setup_s": "<=1", "native_s": "7", "recursion_s": "22",
               "verifier_s": "77", "rss_gib": "15-18", "proof_bytes": "708 KB"}


def load(name):
    return json.load(open(HERE / name))


def m3_row(block):
    return next(r for r in M3["rows"] if r["block"] == block)


def gib(b):
    return round(b / 2**30, 2) if b else None


def daemon_rows(name, config):
    r = load(name)
    verdicts = {(v["block"], v.get("trial")): v for v in r.get("receivers", [])}
    peaks = (r.get("physical_gpu_memory") or {}).get("peak_used_bytes") or {}
    out = []
    for q in r["requests"]:
        s = q["stages"]
        v = verdicts.get((q["block"], q["trial"]))
        out.append({"receipt": name, "config": config, "block": q["block"], "position": q["ordinal"], "trial": q["trial"],
                    "request_s": s["request_wall_s"], "capture_s": s["capture_s"], "setup_s": s["setup_s"],
                    "native_s": s["native_prove_s"], "native_verify_side_s": s.get("native_verify_s"),
                    "recursion_s": s["recursion_s"],
                    "verifier_s": round(v["process"]["wall_ns"] / 1e9, 1) if v else None,
                    "receiver_accepted": v["accepted"] if v else None,
                    "service_rss_peak_gib": gib(r["producer_process"].get("peak_rss_bytes")),
                    "device_peak_gb": round(max(peaks.values()) / 1e9, 2) if peaks else None,
                    "proof_bytes": q.get("proof_bytes_root"),
                    "byte_identical_to_m3": bool((q.get("parity_vs_m3") or {}).get("byte_identical")),
                    "service_start_s": r.get("service_start_s"), "loadavg_1m": round(r["load_avg_before"][0], 1)})
    return out


def oneshot_row(name, config):
    v = load(name)
    s = v["stages"]
    c = v.get("counters") or {}
    corr = v["correctness"]
    fp = corr.get("fingerprint_vs_reference") or {}
    rec = corr.get("receiver") or {}
    return {"receipt": name, "config": config, "block": v["block"], "request_s": s["request_s"], "capture_s": s["capture_s"],
            "setup_s": s["setup_s"], "native_s": s["native_s"], "recursion_s": s["recursion_s"],
            "fold_tail_after_last_leaf_s": s.get("fold_tail_after_last_leaf_s"),
            "verifier_s": (v.get("verifier") or {}).get("verify_per_block_s"),
            "receiver_accepted": rec.get("accepted"),
            "rss_peak_gib": (v.get("ram") or {}).get("rss_peak_daemon_gib"),
            "rss_request_private_gib": (v.get("ram") or {}).get("rss_peak_request_private_gib"),
            "device_peak_gb": max((v.get("device_memory") or {}).get("device_peak_gb", {}).values() or [None]),
            "proof_bytes": (v.get("proof_size") or {}).get("proof_bytes_root"),
            "byte_identical_to_m3": bool(fp.get("identical")), "hashes_compared": fp.get("compared"),
            "syncs": c.get("sync_total"), "launches": c.get("kernel_launches"), "pool_mallocs": c.get("pool_mallocs"),
            "library_loads": c.get("library_loads"), "pageable_copies": c.get("pageable_copies"),
            "pageable_copy_gb": round(c["pageable_copy_bytes"] / 1e9, 1) if c.get("pageable_copy_bytes") else None,
            "loadavg_1m": v["loadavg"]["start"]["1m"]}


def main():
    rows = {
        "seed_fresh_store": daemon_rows("daemon-g1-seed.json", "service, empty store (cold setup), arena on"),
        "cold_service": daemon_rows("daemon-g2-coldservice.json", "service, store reuse, lazy (no --warm), arena on"),
        "warm_boot": daemon_rows("daemon-g3-warmboot.json", "service, store reuse, --warm boot, arena on"),
        "nsys": daemon_rows("daemon-g4-nsys.json", "service, --warm, under nsys (timing not quotable)"),
        "counters": [oneshot_row(f"{b}-g5-counters-v2.json", "one-shot combined-batch, no store, counter shim + smaps, arena on")
                     for b in (26235156, 24628607)],
        "scale_probe": [oneshot_row("24697070-g6-scale-probe-v2.json", "one-shot combined-batch, no store, arena on (cold)")],
    }
    per_request_nsys = load("daemon-g4-nsys-per-request.json")
    head = {}
    for block in (26235156, 24628607):
        m3 = m3_row(block)
        w = [r for r in rows["warm_boot"] if r["block"] == block]
        first, second = w[0], w[1]
        cs = [r for r in rows["cold_service"] if r["block"] == block]
        cnt = next(r for r in rows["counters"] if r["block"] == block)
        ns = next(r for r in per_request_nsys if r["block"] == block)
        head[str(block)] = {
            "m3": {k: m3[k] for k in ("request_s", "capture_s", "setup_s", "native_prove_s", "recursion_s", "receiver_wall_s",
                                       "producer_peak_rss_gib")},
            "m4_warm_first": first, "m4_warm_second": second,
            "second_vs_first_pct": round(100 * (second["request_s"] / first["request_s"] - 1), 1),
            "m4_cold_service_first": cs[0], "m4_cold_service_second": cs[1],
            "speedup_request_vs_m3": round(m3["request_s"] / first["request_s"], 2),
            "speedup_recursion_vs_m3": round(m3["recursion_s"] / first["recursion_s"], 2),
            "counters_per_request": {k: cnt[k] for k in ("syncs", "launches", "pool_mallocs", "library_loads", "pageable_copies",
                                                          "pageable_copy_gb")},
            "nsys_per_request_in_service": ns,
            "rss_one_shot_gib": cnt["rss_peak_gib"], "rss_request_private_gib": cnt["rss_request_private_gib"],
        }
    m3s = m3_row(24697070)
    sp = rows["scale_probe"][0]
    summary = {
        "schema": "rv64-m4-summary/v1", "date": DATE, "source_commit": COMMIT, "branch": "codex/rv64-m4-integrate",
        "assets": load("build.json") and {k: load("build.json").get(k) for k in ("driver_sha256", "library_sha256", "receiver_sha256")},
        "label": "measured single observations [M] unless noted; pod 1-min load 6.7-26 (protocol quiet bar is 8)",
        "merged_streams": {"measure": "6f398efa0", "arena": "d3835ed12", "kernels": "c8f9ee76b", "resident": "0fee57fe7",
                           "capture": "ed09c445c", "profiles": "6fb652849", "diet": "abf1c48cf (prototypes/tests only)"},
        "not_merged": {"recsize-port": "d4cdf05fa: proof-format change (k-ary/m3 profile), modifies canon-vk files; M5/M7"},
        "environment": {"STWO_RV64_OUTER_ASSIGNMENT_NARROW_RUNS": "1", "STWO_RV64_GPU_CPU_REPLAY": "1",
                        "STWO_RV64_CORE_SINGLE_STREAM": "1", "STWO_RV64_DEVICE_ARENA": "1"},
        "headline": head,
        "scale_probe_24697070": {"m4": sp, "m3": {k: m3s[k] for k in ("request_s", "capture_s", "setup_s", "native_prove_s",
                                                                        "recursion_s", "receiver_wall_s", "producer_peak_rss_gib")}},
        "plan_m4_targets_24628607": PLAN_M4_607,
        "rows": rows,
    }
    json.dump(summary, open(HERE.parent / "summary.json", "w"), indent=1)
    print(json.dumps({b: {"first": h["m4_warm_first"]["request_s"], "second": h["m4_warm_second"]["request_s"],
                          "x": h["speedup_request_vs_m3"]} for b, h in head.items()}))
    if "--ledger" in sys.argv:
        out = REPO / "vectors/reports/progress/integrate.jsonl"
        with open(out, "a") as f:
            for key, rs in rows.items():
                for r in rs:
                    row = {"date": DATE, "commit": COMMIT, "stream": "integrate", "milestone": "M4", "block": r["block"],
                           "gpus": 2, "label": "M", "config": f"{key}: {r['config']}",
                           "receipt": f"vectors/reports/rv64-m4-20261104/integrate/{r['receipt']}",
                           "loadavg_1m": r["loadavg_1m"],
                           "byte_identical_to": "M3 integrate scale receipt" if r["byte_identical_to_m3"] else None}
                    for k in ("request_s", "capture_s", "setup_s", "native_s", "recursion_s", "verifier_s", "receiver_accepted",
                              "device_peak_gb", "proof_bytes", "syncs", "launches", "pool_mallocs", "library_loads",
                              "pageable_copies", "rss_request_private_gib", "fold_tail_s"):
                        if r.get(k) is not None:
                            row[k] = r[k]
                    rss = r.get("rss_peak_gib", r.get("service_rss_peak_gib"))
                    if rss is not None:
                        row["rss_peak_gib"] = rss
                    if key == "nsys":
                        ns = next(x for x in per_request_nsys if x["block"] == r["block"])
                        api = ns["api"]
                        row["syncs"] = api.get("cudaStreamSynchronize_v3020", 0) + api.get("cudaEventSynchronize_v3020", 0)
                        row["launches"] = api.get("cudaLaunchKernel_v7000")
                        row["pool_mallocs"] = sum(v for k, v in api.items() if "Malloc" in k)
                        row["library_loads"] = sum(v for k, v in api.items() if "Library" in k)
                        row["notes"] = (f"nsys per-request window: kernel-busy GPU-s {ns['gpu0_kernel_busy_s']}+{ns['gpu1_kernel_busy_s']}, "
                                        f"recursion busy {ns['recursion_busy_frac_avg']:.0%}; timings under nsys not quotable")
                    if key == "nsys" or key == "counters":
                        row.pop("rss_peak_gib", None) if key == "nsys" else None
                    f.write(json.dumps(row, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
