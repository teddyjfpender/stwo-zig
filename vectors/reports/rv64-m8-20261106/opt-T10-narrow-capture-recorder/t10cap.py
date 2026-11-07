#!/usr/bin/env python3
"""t10cap.py BIN BLOCK INFLIGHT WORKERS TAG [K=V ...]: CPU-only capture diagnostic (rv64-capture-bench CFG - 0 RES).
Writes /workspace/m3/runs/m8-opt-T10-narrow-capture-recorder/cap/<block>-<tag>.json and prints a one-line summary."""
import hashlib, json, os, resource, subprocess, sys, time
binp, block, inflight, workers, tag = sys.argv[1:6]
env_over = dict(kv.split("=", 1) for kv in sys.argv[6:])
run = "/workspace/m3/runs/m8-opt-T10-narrow-capture-recorder/cap"
os.makedirs(run, exist_ok=True)
cfg = json.load(open(f"/workspace/m3/runs/m8-census1/capture/cfg-{block}.json"))
cfg["output_directory"] = f"{run}/out-{block}"
req = f"{run}/cfg-{block}.json"; json.dump(cfg, open(req, "w"), indent=1)
res = {"capture_options": {"max_inflight_packets": int(inflight), "packet_heap_bytes": 1 << 30, "max_inflight_packet_heap_bytes": int(inflight) << 30,
       "max_inflight_wire_bytes": int(inflight) << 30, "execution_workers": int(workers)}}
resp = f"{run}/res-i{inflight}-w{workers}.json"; json.dump(res, open(resp, "w"))
out = f"{run}/{block}-{tag}.json"
env = dict(os.environ); env.update(env_over)
load0 = os.getloadavg(); t0 = time.monotonic()
p = subprocess.Popen([binp, req, "-", "0", resp], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
o, e = p.communicate(); wall = time.monotonic() - t0
ru = resource.getrusage(resource.RUSAGE_CHILDREN)
rec = {"block": int(block), "tag": tag, "binary_sha256": hashlib.sha256(open(binp, "rb").read()).hexdigest(), "inflight": int(inflight), "workers": int(workers),
       "env": env_over, "rc": p.returncode, "process_wall_s": round(wall, 4), "max_rss_gib": round(ru.ru_maxrss / 2**20, 3), "user_s": ru.ru_utime, "sys_s": ru.ru_stime,
       "loadavg_before": load0, "loadavg_after": os.getloadavg()}
try: rec["capture"] = json.loads(o)
except Exception: rec["stdout_tail"] = o[-2000:].decode(errors="replace")
rec["stderr_tail"] = e[-3000:].decode(errors="replace"); open(out[:-5]+".err", "wb").write(e)
json.dump(rec, open(out, "w"), indent=1)
c = rec.get("capture", {}); ci = c.get("capture_inputs", {}); dc = c.get("direct_capture") or {}; sg = dc.get("segments") or {}
print(json.dumps({"tag": tag, "block": block, "i": inflight, "w": workers, "rc": p.returncode, "load": round(load0[0], 1), "rss_gib": rec["max_rss_gib"], "busy": round((ru.ru_utime + ru.ru_stime) / wall, 1),
  "capture_s": round(c.get("image_and_import_ns", 0) / 1e9, 3), "first_s": round(ci.get("first_inputs_ns", 0) / 1e9, 3), "last_s": round(ci.get("last_inputs_ns", 0) / 1e9, 3),
  "ledger_s": round(ci.get("ledger_ns", 0) / 1e9, 3), "join_wait_s": round(dc.get("join_wait_ns", 0) / 1e9, 3), "first_pass_s": round(sg.get("first_pass_ns", 0) / 1e9, 3),
  "local": dc.get("local_ledgers"), "fallbacks": dc.get("local_fallbacks"), "local_s": round((dc.get("local_ledger_ns") or 0) / 1e9, 3), "jadmit_s": round((dc.get("job_admit_ns") or 0) / 1e9, 2), "jcap_s": round((dc.get("job_capture_ns") or 0) / 1e9, 2), "walk_s": round(sg.get("walk_ns_total", 0) / 1e9, 2), "narrow_s": round((dc.get("job_narrow_ns") or 0) / 1e9, 2), "seal_s": round((dc.get("job_seal_ns") or 0) / 1e9, 2), "events_s": round((dc.get("job_events_ns") or 0) / 1e9, 2), "merge_s": round((dc.get("local_merge_ns") or 0) / 1e9, 3), "patch_s": round((dc.get("local_patch_ns") or 0) / 1e9, 3), "touched": dc.get("local_touched"),
  "sha": (c.get("captured_values_sha256") or "")[:16], "all": (c.get("advice_all_sha256") or "")[:16]}), flush=True)
