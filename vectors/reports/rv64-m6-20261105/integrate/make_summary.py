#!/usr/bin/env python3
"""Build vectors/reports/rv64-m6-20261105/summary.json from the integrate receipts in this directory."""
import json
import statistics
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import table  # noqa: E402

BLOCKS = (26235156, 24628607)


def load(name):
    return json.load(open(HERE / name))


def warm(receipt):
    """Per block: warm rows (trial >= 1) + the cold-setup first row of the service."""
    out = {}
    for r in table.rows(HERE / receipt):
        b = out.setdefault(r["block"], {"warm": [], "first": None})
        if r["trial"] == 0:
            b["first"] = r
        else:
            b["warm"].append(r)
    return out


def med(rows, key):
    vals = [r[key] for r in rows if r.get(key) is not None]
    return round(statistics.median(vals), 3) if vals else None


def config(receipt, label, verifier=None):
    w = warm(receipt)
    d = load(receipt)
    res = {"receipt": f"integrate/{receipt}", "label": label, "driver_sha256": d["assets"]["driver"][:16],
           "load_avg_1m_before": round(d["load_avg_before"][0], 1), "blocks": {}}
    recv = {r["block"]: r for r in d.get("receivers") or []}
    for b in BLOCKS:
        rows = w[b]["warm"]
        res["blocks"][str(b)] = {
            "warm_requests": len(rows),
            "request_s": [r["request_s"] for r in rows], "request_s_median": med(rows, "request_s"),
            "capture_s": med(rows, "capture_s"), "setup_s": med(rows, "setup_s"), "native_s": med(rows, "native_s"),
            "recursion_s": med(rows, "recursion_s"), "tail_after_last_leaf_s": med(rows, "tail_s"),
            "first_request_cold_setup_s": w[b]["first"]["request_s"] if w[b]["first"] else None,
            "proof_bytes_root": rows[0]["proof_bytes_root"], "byte_identical_to_m5_default": rows[0]["byte_identical"],
            "full_tree_receiver": {"status": recv[b]["status"], "wall_s": round(recv[b]["process"]["wall_ns"] / 1e9, 1), "sha256": recv[b]["receiver_sha256"][:16]} if b in recv else None,
            "service_rss_peak_gib": rows[0]["rss_peak_gib"], "device_peak_gb": rows[0]["device_peak_gb"],
        }
    return res


def rootonly(directory):
    p = HERE / directory
    out = {}
    for f in sorted(p.glob("*.json")):
        d = json.load(open(f))
        if f.name.startswith("derive"):
            out[f.stem] = {"derive_once_s": round(d["derive_once_ns"] / 1e9, 2), "table_root": d.get("table_root"),
                           "audit_accepted": d.get("audit_accepted"), "self_check": d.get("root_only_self_check"),
                           "leaves": d.get("block_leaves"), "folds": d.get("block_folds")}
        elif f.name.startswith("verify-pinned") or f.name.startswith("audit"):
            out[f.stem] = {"accepted": d.get("accepted"), "in_process_s": round(d["verify_per_block_ns"] / 1e9, 3),
                           "root_digest": d.get("root_digest", "")[:16], "native_audit": d.get("native_audit")}
        elif "corpus" in f.name:
            out[f.stem] = {k: d.get(k) for k in ("ran", "passed", "unexpected_accepts", "crashes")}
    return out


def main():
    summary = {
        "schema": "rv64-m6-summary/v1", "date": "2026-11-05", "branch": "codex/rv64-m6-integrate",
        "label": "measured single observations [M] unless noted; pod 1-min load 5-30 at run start (protocol quiet bar 8): not quiet-host quotable; same-session A/B against M5 binaries (m5-ab) is the comparison",
        "configs": {
            "m5_same_session": config("daemon-m5-ab.json", "M5 integrate binaries (37f94901), same harness, --store none, RV64_NATIVE_SCHEDULE='{}'"),
            "a_pipeline_old_format": config("daemon-a1-warm.json", "(a) M6 pipeline, old format (r1 binary folds, flat native): driver a883de47 (30650ee7c)"),
            "a_pipeline_old_format_final_driver": config("daemon-a5-final.json", "(a) on the final driver b7a4615f (1345c6eb9), STWO_RV64_OUTER_PROFILE=r1; run while CPU gates ran"),
            "a22_arena_carve": config("daemon-a4-warm22.json", "(a) + STWO_RV64_DEVICE_ARENA=22G (device-peak target)"),
            "b_v2strict_k4cap3": config("daemon-b2-warm.json", "(b) native v2-strict + diet k4-cap3 outer profile + fold-v3 root-only receiver"),
            "c_k4cap3_flat_native": config("daemon-c2-warm.json", "(c) diet k4-cap3 outer profile on the flat native format (driver 8ce08af7, 57e95fb0a)"),
            "default_final": config("daemon-d1-default.json", "DEFAULT (= (c)) on the final driver b7a4615f (1345c6eb9), harness DEFAULT_PRODUCER_ENV"),
        },
        "root_only": {"b": rootonly("rootonly-b-b1-bench"), "c": rootonly("rootonly-c-c1-bench"), "a": rootonly("rootonly-a-a3-bench")},
    }
    static = HERE / "summary_static.json"
    if static.exists():
        summary.update(json.load(open(static)))
    json.dump(summary, sys.stdout, indent=1)


if __name__ == "__main__":
    main()
