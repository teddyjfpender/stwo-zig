#!/usr/bin/env python3
"""cap.py BIN BLOCK RES TAG: run CPU-only capture diagnostic, record wall/rusage/load + capture JSON."""
import json, os, sys, time, subprocess, hashlib
binp, block, res, tag = sys.argv[1:5]
req = f"/workspace/m3/runs/m4-capture/req-{block}.json"
out = f"/workspace/m3/runs/m4-capture/cap-{block}-{tag}.json"
load0 = os.getloadavg()
t0 = time.monotonic()
p = subprocess.Popen([binp, "capture", req, "-", "0", res], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
o, e = p.communicate()
wall = time.monotonic() - t0
ru = __import__("resource").getrusage(__import__("resource").RUSAGE_CHILDREN)
rec = {"block": int(block), "tag": tag, "binary": binp, "binary_sha256": hashlib.sha256(open(binp,"rb").read()).hexdigest(),
       "resources": json.load(open(res)), "rc": p.returncode, "process_wall_s": round(wall, 4),
       "user_s": ru.ru_utime, "sys_s": ru.ru_stime, "avg_busy_cores": round((ru.ru_utime + ru.ru_stime) / wall, 2),
       "max_rss_gib": round(ru.ru_maxrss / 2**20, 3), "minor_faults": ru.ru_minflt, "major_faults": ru.ru_majflt,
       "loadavg_before": load0, "loadavg_after": os.getloadavg(), "nproc": os.cpu_count()}
try:
    rec["capture"] = json.loads(o)
except Exception:
    rec["stdout_tail"] = o[-2000:].decode(errors="replace")
rec["stderr_tail"] = e[-3000:].decode(errors="replace")
json.dump(rec, open(out, "w"), indent=1)
c = rec.get("capture", {})
ci, cb = c.get("capture_inputs", {}), c.get("capture_breakdown", {})
print(json.dumps({"tag": tag, "block": block, "rc": p.returncode, "wall": rec["process_wall_s"], "busy": rec["avg_busy_cores"],
  "minflt": ru.ru_minflt, "rss_gib": rec["max_rss_gib"], "image_and_import_s": c.get("image_and_import_ns", 0)/1e9,
  "init_s": ci.get("init_ns", 0)/1e9, "first_s": ci.get("first_inputs_ns", 0)/1e9, "last_s": ci.get("last_inputs_ns", 0)/1e9,
  "ledger_s": ci.get("ledger_ns", 0)/1e9, "finish_s": ci.get("ledger_finish_ns", 0)/1e9, "sha": c.get("captured_values_sha256"),
  "memory_words": c.get("memory_words"), "load": load0[0]}))
