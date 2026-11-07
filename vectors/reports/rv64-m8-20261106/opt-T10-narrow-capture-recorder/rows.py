#!/usr/bin/env python3
"""rows.py TAG...: one compact JSON row per rv64-capture-bench run (cap/<block>-<TAG>-*.json), plus per-run T10DIGEST set hash."""
import json, re, sys, glob, hashlib
base = "/workspace/m3/runs/m8-opt-T10-narrow-capture-recorder/cap"
for tag in sys.argv[1:]:
    for f in sorted(glob.glob(f"{base}/*-{tag}-*.json")):
        r = json.load(open(f)); c = r.get("capture", {}); dc = c.get("direct_capture") or {}
        e = f[:-5] + ".err"
        err = open(e).read() if glob.glob(e) else ""
        dig = sorted(re.findall(r"T10DIGEST .*", err))
        print(json.dumps({"run": f.split("/")[-1][:-5], "rc": r["rc"], "binary_sha256": r["binary_sha256"][:16], "env": r["env"], "inflight": r["inflight"], "workers": r["workers"],
            "capture_s": round(c.get("image_and_import_ns", 0) / 1e9, 3), "process_wall_s": r["process_wall_s"], "max_rss_gib": r["max_rss_gib"], "user_s": round(r["user_s"], 1), "sys_s": round(r["sys_s"], 1),
            "load_before": round(r["loadavg_before"][0], 1), "join_wait_s": round(dc.get("join_wait_ns", 0) / 1e9, 3), "ledger_s": round((c.get("capture_inputs") or {}).get("ledger_ns", 0) / 1e9, 3),
            "captured_values_sha256": c.get("captured_values_sha256"), "advice_all_sha256": c.get("advice_all_sha256"),
            "t10digest_segments": len(dig), "t10digest_set_sha256": hashlib.sha256("\n".join(dig).encode()).hexdigest()[:16] if dig else None}))
