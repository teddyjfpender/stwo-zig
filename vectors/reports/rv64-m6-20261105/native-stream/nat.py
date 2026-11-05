import json, sqlite3, sys, os, glob, collections
run = sys.argv[1]; which = int(sys.argv[2])
r = json.load(open(run + "/receipt.json"))
db = sqlite3.connect(run + "/nsys/timeline.sqlite")
start = db.execute("select utcEpochNs from TARGET_INFO_SESSION_START_TIME").fetchone()[0]
names = dict(db.execute("select id, value from StringIds"))
q = r["requests"][which]
done = sorted(glob.glob(run + "/spool/done/*.json"))
end_ns = None
st = q["stages"]; print(q["block"], st)
b = db.execute("select max(end) from CUPTI_ACTIVITY_KIND_KERNEL").fetchone()[0] + int(float(sys.argv[3])*1e9) if len(sys.argv)>3 else db.execute("select max(end) from CUPTI_ACTIVITY_KIND_KERNEL").fetchone()[0]
a = b - q["marker"]["request_wall_ns"]
na = a + int((st["capture_s"] + st["setup_s"]) * 1e9); nb = na + int(st["native_prove_s"] * 1e9); vb = nb + int(st["native_verify_s"]*1e9)
print("window rel s", a/1e9, "native", (na-a)/1e9, (nb-a)/1e9, "verify_end", (vb-a)/1e9, "recursion start", (b-a)/1e9 - st["recursion_s"])
def union(iv):
    iv=sorted(iv); tot=0; cs=ce=None
    for s,e in iv:
        if cs is None or s>ce:
            if cs is not None: tot+=ce-cs
            cs,ce=s,e
        else: ce=max(ce,e)
    if cs is not None: tot+=ce-cs
    return tot
binw = int(0.25e9)
lo = a; hi = a + int((st["capture_s"]+st["setup_s"]+st["native_prove_s"]+st["native_verify_s"]+1.0)*1e9)
for dev in (0,1):
    ks = db.execute("select start,end,shortName from CUPTI_ACTIVITY_KIND_KERNEL where deviceId=? and end>? and start<?", (dev, lo, hi)).fetchall()
    line=[]
    for t in range(lo, hi, binw):
        iv=[(max(s,t),min(e,t+binw)) for s,e,_ in ks if e>t and s<t+binw]
        line.append("%3d"%(100*union(iv)/binw))
    print("gpu%d busy%% per 250ms from request start:"%dev, " ".join(line))
    iv=[(max(s,na),min(e,nb)) for s,e,_ in ks if e>na and s<nb]
    print(" native-window kernel busy s", union(iv)/1e9, "launches", len(iv))
    c=collections.Counter()
    for s,e,n in ks:
        if e>na and s<nb: c[names.get(n,n)]+= min(e,nb)-max(s,na)
    for k,v in c.most_common(25): print("   %8.1f ms %s"%(v/1e6,k[:110]))
    mc = db.execute("select start,end,bytes,copyKind from CUPTI_ACTIVITY_KIND_MEMCPY where deviceId=? and end>? and start<?", (dev, na, nb)).fetchall()
    kinds=collections.defaultdict(lambda:[0,0,0])
    for s,e,by,k in mc: kinds[k][0]+=1; kinds[k][1]+=by; kinds[k][2]+=e-s
    print(" memcpy in native window (kind: n, GB, s):", {k:(v[0],round(v[1]/1e9,3),round(v[2]/1e9,3)) for k,v in kinds.items()})
api=collections.defaultdict(lambda:[0,0])
for s,e,n in db.execute("select start,end,nameId from CUPTI_ACTIVITY_KIND_RUNTIME where start>=? and start<?", (na,nb)):
    api[names[n]][0]+=1; api[names[n]][1]+=e-s
for k,v in sorted(api.items(), key=lambda x:-x[1][1])[:15]: print(" api %-45s n=%6d %.3f s"%(k,v[0],v[1]/1e9))
# threads
th=collections.defaultdict(lambda:[0,0])
for s,e,tid in db.execute("select start,end,globalTid from CUPTI_ACTIVITY_KIND_RUNTIME where start>=? and start<?", (na,nb)):
    th[tid][0]+=1; th[tid][1]+=e-s
print(" api threads:", {k%100000:(v[0],round(v[1]/1e9,2)) for k,v in th.items()})
