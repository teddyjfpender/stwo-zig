import sqlite3,sys,collections
run=sys.argv[1]
db=sqlite3.connect(run+"/nsys/timeline.sqlite")
names=dict(db.execute("select id,value from StringIds"))
b=db.execute("select max(end) from CUPTI_ACTIVITY_KIND_KERNEL").fetchone()[0]
import json
q=json.load(open(run+"/receipt.json"))["requests"][1]; st=q["stages"]
a=b-q["marker"]["request_wall_ns"]
na=a+int((st["capture_s"]+st["setup_s"])*1e9); nb=na+int(st["native_prove_s"]*1e9)
rt=db.execute("select start,globalTid,correlationId from CUPTI_ACTIVITY_KIND_RUNTIME where start>? and start<? order by start",(na,nb)).fetchall()
k=dict((c,names.get(s,s)) for c,s in db.execute("select correlationId,shortName from CUPTI_ACTIVITY_KIND_KERNEL where start>? and start<?",(na,nb+int(1e9))))
mc=dict((c,by) for c,by,kind in db.execute("select correlationId,bytes,copyKind from CUPTI_ACTIVITY_KIND_MEMCPY where copyKind=1 and start>? and start<?",(na,nb+int(1e9))))
th=collections.defaultdict(list)
for s,t,c in rt: th[t].append(c)
attr=collections.Counter(); n=collections.Counter()
for t,cs in th.items():
    pending=[]
    for c in cs:
        if c in mc: pending.append(mc[c])
        elif c in k:
            for by in pending: attr[k[c][:50]]+=by; n[k[c][:50]]+=1
            pending=[]
tot=sum(attr.values())
print("H2D attributed %.2f GB"%(tot/1e9))
for x,v in attr.most_common(25): print("  %7.1f MB n=%4d before %s"%(v/1e6,n[x],x))
