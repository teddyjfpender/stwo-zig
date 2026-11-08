import json, sqlite3, sys
run = sys.argv[1]
r = json.load(open(run + "/receipt.json"))
db = sqlite3.connect(run + "/nsys/timeline.sqlite")
start = db.execute("select utcEpochNs from TARGET_INFO_SESSION_START_TIME").fetchone()[0]
names = dict(db.execute("select id, value from StringIds"))
def union(iv):
    iv.sort(); tot = 0; cs = ce = None
    for s, e in iv:
        if cs is None or s > ce:
            if cs is not None: tot += ce - cs
            cs, ce = s, e
        else: ce = max(ce, e)
    if cs is not None: tot += ce - cs
    return tot
out = []
tl = r.get("timeline") or r.get("requests")
for q in r["requests"]:
    import os, glob
    done = sorted(glob.glob(run + "/spool/done/*.json"))[q["ordinal"]]
    end_ns = os.stat(done).st_mtime_ns
    w = [end_ns - q["marker"]["request_wall_ns"], end_ns]
    a, b = w[0] - start, w[1] - start
    row = {"block": q["block"], "window_s": (b - a) / 1e9, "request_s": q["stages"]["request_wall_s"],
           "recursion_s": q["stages"]["recursion_s"]}
    for dev in (0, 1):
        iv = db.execute("select max(start,?), min(end,?) from CUPTI_ACTIVITY_KIND_KERNEL where deviceId=? and end>? and start<?", (a, b, dev, a, b)).fetchall()
        row[f"gpu{dev}_kernel_busy_s"] = round(union(list(iv)) / 1e9, 3)
    ra = b - int(q["stages"]["recursion_s"] * 1e9)
    for dev in (0, 1):
        iv = db.execute("select max(start,?), min(end,?) from CUPTI_ACTIVITY_KIND_KERNEL where deviceId=? and end>? and start<?", (ra, b, dev, ra, b)).fetchall()
        row[f"gpu{dev}_recursion_kernel_busy_s"] = round(union(list(iv)) / 1e9, 3)
    row["recursion_busy_frac_avg"] = round((row["gpu0_recursion_kernel_busy_s"] + row["gpu1_recursion_kernel_busy_s"]) / 2 / q["stages"]["recursion_s"], 3)
    api = {}
    for nid, c in db.execute("select nameId, count(*) from CUPTI_ACTIVITY_KIND_RUNTIME where start>=? and start<? group by nameId", (a, b)):
        api[names[nid]] = c
    row["api"] = {k: v for k, v in api.items() if any(s in k for s in ("Synchronize", "Launch", "Malloc", "Library", "Memcpy", "MemMap", "MemCreate"))}
    row["busy_frac_of_request_avg"] = round((row["gpu0_kernel_busy_s"] + row["gpu1_kernel_busy_s"]) / 2 / row["request_s"], 3)
    out.append(row)
print(json.dumps(out, indent=1))
