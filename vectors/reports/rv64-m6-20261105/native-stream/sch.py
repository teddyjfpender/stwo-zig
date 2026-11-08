import json,sys,glob,os
p=sys.argv[1]
s=json.load(open(p+"/schedule.json"))
for ph in ("stage1","stage2"):
    rows=s[ph]; 
    if not rows: continue
    end=max(r["finished_ns"] for r in rows)
    print(ph,"span %.3f s"%(end/1e9), "sum %.3f"%(sum(r["finished_ns"]-r["started_ns"] for r in rows)/1e9))
    for i,r in enumerate(rows):
        print("  ord %2d lane %d dev %d start %.3f end %.3f dur %.3f est %.1fG"%(i,r["lane"],i%2,r["started_ns"]/1e9,r["finished_ns"]/1e9,(r["finished_ns"]-r["started_ns"])/1e9,r["estimate_bytes"]/2**30))
print([k for k in s.keys()])
for k in s:
    if k not in ("stage1","stage2"): print(k, json.dumps(s[k])[:600])
