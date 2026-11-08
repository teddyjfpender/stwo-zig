#!/usr/bin/env python3
"""canon-vk (M5): re-run a harness run's strict receiver argv with STWO_RV64_FOLD_CLASS_CACHE in a list of modes (0, 1, check).
The cache is in-process and receiver-built (never persisted, never producer-fed); the acceptance harness forces 0.
Usage (pod): python3 scripts/rv64_m5_receiver_class_ab.py RUN_DIR 0,1,check   (export the run's outer profile env first)"""
# Re-run a run's strict receiver argv with STWO_RV64_FOLD_CLASS_CACHE in {0, 1, check}; report wall + verdict.
import json, os, subprocess, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import rv64_resident_basket as R
run, modes = sys.argv[1], sys.argv[2].split(",")
rec = json.load(open(run + "/receipt.json"))["receiver"]
argv = rec["argv"]
for mode in modes:
    out = f"{run}/recv-ab-{mode}"
    os.makedirs(out, exist_ok=True)
    env = R.receiver_environment({k: v for k, v in os.environ.items() if k != "STWO_ZIG_RV64_SETUP_CACHE"}, __import__("pathlib").Path(out) / "gpu-disabled")
    env["STWO_RV64_FOLD_CLASS_CACHE"] = mode
    t = time.time()
    p = subprocess.run(argv, env=env, cwd=json.load(open(run + "/plan.json"))["producer_cwd"], capture_output=True, text=True)
    wall = time.time() - t
    ok = False
    try:
        o = json.loads(p.stdout); ok = o.get("accepted") is True and o.get("completed_ethereum_block") is True
        hits = o.get("recursive", {})
    except Exception:
        hits = {}
    open(out + "/stderr", "w").write(p.stderr)
    print(json.dumps({"mode": mode, "exit": p.returncode, "accepted": ok, "wall_s": round(wall, 2), "load1": os.getloadavg()[0],
                      "class_lines": sum(1 for l in p.stderr.splitlines() if "class cache hit" in l)}))
