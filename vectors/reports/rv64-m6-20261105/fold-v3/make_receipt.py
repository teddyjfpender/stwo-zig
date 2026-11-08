#!/usr/bin/env python3
"""fold-v3 receipts: summarize one rootonly.sh run directory into per-block receipts + progress rows.

usage: make_receipt.py RUN_DIR LOG STEP COMMIT FORMAT [--progress PATH] [--notes TEXT]
RUN_DIR holds out/*.json (+ .stderr.rss) and tables/; LOG is the rootonly.sh log (walls, loads)."""
import json, re, sys, os, statistics, argparse
ap = argparse.ArgumentParser()
ap.add_argument("run"); ap.add_argument("log"); ap.add_argument("step"); ap.add_argument("commit"); ap.add_argument("format")
ap.add_argument("--progress"); ap.add_argument("--notes", default=""); ap.add_argument("--date", default="2026-11-05")
A = ap.parse_args()
walls, loads = {}, {}
cur = None
for line in open(A.log):
    m = re.match(r"== (\S+) load=([\d.]+)", line)
    if m: cur = m.group(1); loads[cur] = float(m.group(2)); continue
    m = re.match(r"exit=(\d+) wall=([\d.]+) load_end=([\d.]+) maxrss_kb=(\d+)", line)
    if m and cur: walls[cur] = dict(exit=int(m.group(1)), wall_s=float(m.group(2)), load_end=float(m.group(3)), maxrss_gib=round(int(m.group(4)) / 2**20, 3))
recv = re.search(r"^([0-9a-f]{64})\s", open(A.log).read(), re.M)
def J(name):
    p = os.path.join(A.run, "out", name + ".json")
    try: return json.load(open(p))
    except Exception: return None
out = {}
rows = []
for b in ("26235156", "24628607"):
    d = J(f"derive-{b}")
    verifies = [J(f"verify-pinned-{b}-r{i}") for i in (1, 2, 3)]
    verifies = [v for v in verifies if v]
    au = J(f"audit-{b}")
    vw = [walls[f"verify-pinned-{b}-r{i}"]["wall_s"] for i in (1, 2, 3) if f"verify-pinned-{b}-r{i}" in walls and walls[f"verify-pinned-{b}-r{i}"]["exit"] == 0]
    internal = [v["verify_per_block_ns"] / 1e9 for v in verifies]
    r = {
        "schema": "rv64-m6-fold-v3-rootonly/v1", "stream": "fold-v3", "milestone": "M6", "step": A.step, "block": int(b),
        "format": A.format, "source_commit": A.commit, "receiver_sha256": recv.group(1) if recv else None,
        "label": "M (single observations per rep; pod shared, 1-min load recorded per step)",
        "root_only_verify_wall_s": vw, "root_only_verify_internal_s": [round(x, 3) for x in internal],
        "root_only_verify_wall_median_s": statistics.median(vw) if vw else None,
        "root_only_breakdown_r1": verifies[0]["breakdown"] if verifies else None,
        "native_table": verifies[0].get("native_table") if verifies else None,
        "accepted": all(v.get("accepted") for v in verifies) if verifies else False,
        "table_root_pinned": all(v.get("table_root_pinned") for v in verifies) if verifies else False,
        "root_digest": verifies[0]["root_digest"] if verifies else None,
        "root_identity": verifies[0]["root_identity"] if verifies else None,
        "audit": (au or {}).get("audit"), "audit_wall_s": walls.get(f"audit-{b}", {}).get("wall_s"),
        "derive_wall_s": walls.get(f"derive-{b}", {}).get("wall_s"),
        "derive_breakdown": (d or {}).get("breakdown"), "derive_schedule": (d or {}).get("recursion_schedule"),
        "derive_native_build": (d or {}).get("native_build"),
        "derive_merge_wall_s": walls.get("derive-both", {}).get("wall_s"),
        "steps": {k: dict(v, load_start=loads.get(k)) for k, v in walls.items() if b in k or k == "derive-both"},
    }
    out[b] = r
    json.dump(r, open(os.path.join(os.path.dirname(os.path.abspath(__file__)), f"{b}-{A.step}.json"), "w"), indent=1)
    row = {"date": A.date, "commit": A.commit, "stream": "fold-v3", "milestone": "M6", "block": int(b), "gpus": 2,
           "verifier_s": r["root_only_verify_wall_median_s"],
           "rss_peak_gib": max([walls[k]["maxrss_gib"] for k in walls if k.startswith(f"verify-pinned-{b}")] or [0]),
           "loadavg_1m": loads.get(f"verify-pinned-{b}-r1"),
           "byte_identical_to": "proofs untouched (receiver-only change); M5 " + A.format + "-format proofs",
           "receiver_accepted": bool(r["accepted"] and r["audit"] and r["audit"].get("agrees")), "label": "M",
           "config": f"fold-v3 receiver {r['receiver_sha256'][:8] if r['receiver_sha256'] else '?'}: verify-root-candidate --table-root PIN (root-only, fresh CPU-only process; native VK table)",
           "receipt": f"vectors/reports/rv64-m6-20261105/fold-v3/{b}-{A.step}.json",
           "notes": f"{A.step}: verifier_s = median wall of {len(vw)} fresh processes {vw}; derive-vk-tables once {r['derive_wall_s']} s (merge {r['derive_merge_wall_s']} s); --audit agrees; load above quiet bar. " + A.notes}
    rows.append(row)
if A.progress:
    with open(A.progress, "a") as f:
        for row in rows: f.write(json.dumps(row) + "\n")
print(json.dumps({b: {k: out[b][k] for k in ("root_only_verify_wall_s", "derive_wall_s", "accepted", "audit_wall_s")} for b in out}, indent=1))
