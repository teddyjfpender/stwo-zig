import json, sqlite3, sys, collections
run=sys.argv[1]
db=sqlite3.connect(run+"/nsys/timeline.sqlite")
names=dict(db.execute("select id,value from StringIds"))
tabs=[t for (t,) in db.execute("select name from sqlite_master where type='table'")]
print([t for t in tabs if 'NVTX' in t or 'OSRT' in t or 'SAMPL' in t or 'THREAD' in t])
b=db.execute("select max(end) from CUPTI_ACTIVITY_KIND_KERNEL").fetchone()[0]
a=b-28746452388
na=a+int(3.131e9); nb=a+int(9.728e9)
# per thread: in 200ms bins, time in sync APIs, time in other API, and gap
rows=db.execute("select start,end,globalTid,nameId from CUPTI_ACTIVITY_KIND_RUNTIME where end>? and start<? order by start",(na,nb)).fetchall()
th=collections.defaultdict(list)
for s,e,t,n in rows: th[t].append((s,e,names[n]))
W=int(0.2e9)
for t,ev in th.items():
    print("thread",t%100000,"events",len(ev))
    out=[]
    for x in range(na,nb,W):
        sy=sum(min(e,x+W)-max(s,x) for s,e,n in ev if e>x and s<x+W and 'Synchronize' in n)
        ot=sum(min(e,x+W)-max(s,x) for s,e,n in ev if e>x and s<x+W and 'Synchronize' not in n)
        out.append("%2d/%2d"%(100*sy//W,100*ot//W))
    print("  sync%/api% per 200ms:"," ".join(out))
    # largest host gaps between consecutive API calls
    gaps=sorted(((ev[i+1][0]-ev[i][1],ev[i][1]-na,ev[i][2],ev[i+1][2]) for i in range(len(ev)-1)),reverse=True)[:12]
    for g in gaps: print("   gap %.1f ms at +%.3f s after %s before %s"%(g[0]/1e6,g[1]/1e9,g[2],g[3]))
    tot=sum(max(0,ev[i+1][0]-ev[i][1]) for i in range(len(ev)-1))
    print("   total host gaps %.2f s; gaps>1ms %.2f s"%(tot/1e9, sum(g for g in (ev[i+1][0]-ev[i][1] for i in range(len(ev)-1)) if g>1e6)/1e9))
