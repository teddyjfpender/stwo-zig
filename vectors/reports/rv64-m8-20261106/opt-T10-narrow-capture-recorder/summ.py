#!/usr/bin/env python3
"""summ.py TAG: per block/arm medians of capture_s and summed narrow phases from cap/<block>-<TAG>-a<arm>-r<k>.{json,err}"""
import json, re, sys, glob, statistics as st, collections
tag = sys.argv[1]; base = "/workspace/m3/runs/m8-opt-T10-narrow-capture-recorder/cap"
rows = collections.defaultdict(list)
for f in sorted(glob.glob(f"{base}/*-{tag}-a*-r*.json")):
    m = re.search(r"/(\d+)-" + re.escape(tag) + r"-a(\w+?)-r(\d+)\.json$", f)
    if not m: continue
    b, arm, k = m.groups(); r = json.load(open(f)); c = r.get("capture", {})
    err = open(f[:-5] + ".err").read() if glob.glob(f[:-5] + ".err") else ""
    scan = sum(int(x) for x in re.findall(r"T10PROFR? steps=\d+ (?:fn=\d+ mem=\d+ af=\d+ bf=\d+ sf=\d+ df=\d+ )?scan=(\d+)", err)) / 1e9
    rest = 0
    for line in re.findall(r"T10PROF (.*)", err):
        d = dict(kv.split("=") for kv in line.split()); rest += sum(int(d[k]) for k in ("route", "jalr", "group", "shift"))
    rest += sum(int(x) for x in re.findall(r"T10PROFR .*rest=(\d+)", err))
    rows[(b, arm)].append(dict(cap=c.get("image_and_import_ns", 0) / 1e9, scan=scan, rest=rest / 1e9, rss=r["max_rss_gib"], load=r["loadavg_before"][0], sha=(c.get("captured_values_sha256") or "")[:16]))
for (b, arm), v in sorted(rows.items()):
    caps = [x["cap"] for x in v]
    print(f"{b} arm{arm} n={len(v)} capture_s med={st.median(caps):.3f} all={[round(x,3) for x in caps]} scan_sum med={st.median([x['scan'] for x in v]):.2f} rest_sum med={st.median([x['rest'] for x in v]):.2f} rss={max(x['rss'] for x in v)} load={[round(x['load'],1) for x in v]} sha={set(x['sha'] for x in v)}")
