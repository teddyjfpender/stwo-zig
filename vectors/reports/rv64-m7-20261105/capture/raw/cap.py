#!/usr/bin/env python3
"""cap.py BIN BLOCK RES TAG [K=V ...]: CPU-only capture diagnostic (`capture REQ - 0 RES`).

Records wall, rusage, load, /proc/vmstat compaction + THP deltas, the env overrides and the
capture JSON (stats, digest) to /workspace/m3/runs/m7-capture/cap-<block>-<tag>.json.
"""
import hashlib, json, os, resource, subprocess, sys, time
binp, block, res, tag = sys.argv[1:5]
env_over = dict(kv.split("=", 1) for kv in sys.argv[5:])
run = "/workspace/m3/runs/m7-capture"
req = f"{run}/req-{block}.json"
out = f"{run}/cap-{block}-{tag}.json"
KEYS = ("compact_stall", "compact_fail", "compact_success", "thp_fault_alloc", "thp_fault_fallback", "pgmajfault")
def vmstat():
    d = {}
    for line in open("/proc/vmstat"):
        k, v = line.split()
        if k in KEYS: d[k] = int(v)
    return d
def thp(name):
    try: return open(f"/sys/kernel/mm/transparent_hugepage/{name}").read().strip()
    except OSError: return None
env = dict(os.environ); env.update(env_over)
load0, vm0 = os.getloadavg(), vmstat()
t0 = time.monotonic()
p = subprocess.Popen(([binp] if "capture-bench" in binp else [binp, "capture"]) + [req, "-", "0", res], stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
o, e = p.communicate()
wall = time.monotonic() - t0
vm1 = vmstat()
ru = resource.getrusage(resource.RUSAGE_CHILDREN)
rec = {"block": int(block), "tag": tag, "binary": binp, "binary_sha256": hashlib.sha256(open(binp, "rb").read()).hexdigest(),
       "env": env_over, "resources": json.load(open(res)), "rc": p.returncode, "process_wall_s": round(wall, 4),
       "user_s": ru.ru_utime, "sys_s": ru.ru_stime, "avg_busy_cores": round((ru.ru_utime + ru.ru_stime) / wall, 2),
       "max_rss_gib": round(ru.ru_maxrss / 2**20, 3), "minor_faults": ru.ru_minflt, "major_faults": ru.ru_majflt,
       "loadavg_before": load0, "loadavg_after": os.getloadavg(), "nproc": os.cpu_count(),
       "thp": {"enabled": thp("enabled"), "defrag": thp("defrag")}, "vmstat_delta": {k: vm1.get(k, 0) - vm0.get(k, 0) for k in KEYS}}
try:
    rec["capture"] = json.loads(o)
except Exception:
    rec["stdout_tail"] = o[-2000:].decode(errors="replace")
rec["stderr_tail"] = e[-3000:].decode(errors="replace")
json.dump(rec, open(out, "w"), indent=1)
c = rec.get("capture", {})
ci, dc = c.get("capture_inputs", {}), c.get("direct_capture") or {}
sg = dc.get("segments") or {}
mips = lambda n, ns: round(n / ns * 1e3, 1) if ns else None
print(json.dumps({"tag": tag, "block": block, "rc": p.returncode, "wall": rec["process_wall_s"], "busy": rec["avg_busy_cores"],
  "load": round(load0[0], 1), "stalls": rec["vmstat_delta"]["compact_stall"], "thp_alloc": rec["vmstat_delta"]["thp_fault_alloc"],
  "rss_gib": rec["max_rss_gib"], "capture_s": c.get("image_and_import_ns", 0) / 1e9, "init_s": ci.get("init_ns", 0) / 1e9,
  "first_s": ci.get("first_inputs_ns", 0) / 1e9, "last_s": ci.get("last_inputs_ns", 0) / 1e9, "ledger_s": ci.get("ledger_ns", 0) / 1e9,
  "first_cap_s": dc.get("first_batch_capture_ns", 0) / 1e9, "first_ready_s": dc.get("first_batch_ready_ns", 0) / 1e9,
  "fast_mips": mips(sg.get("first_pass_retired", 0), sg.get("first_pass_ns", 0)),
  "walk_mips_per_worker": mips(sg.get("walk_retired", 0), sg.get("walk_ns_total", 0)), "walk_max_s": sg.get("walk_ns_max", 0) / 1e9,
  "sha": c.get("captured_values_sha256")}))
