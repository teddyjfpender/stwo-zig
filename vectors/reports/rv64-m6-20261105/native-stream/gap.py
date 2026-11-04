import sqlite3,sys,collections
run=sys.argv[1]
db=sqlite3.connect(run+"/nsys/timeline.sqlite")
names=dict(db.execute("select id,value from StringIds"))
b=db.execute("select max(end) from CUPTI_ACTIVITY_KIND_KERNEL").fetchone()[0]
a=b-28746452388
na=a+int(3.131e9); nb=a+int(9.728e9)
# runtime calls with correlation to kernels
rt=db.execute("select start,end,globalTid,nameId,correlationId from CUPTI_ACTIVITY_KIND_RUNTIME where end>? and start<? order by start",(na,nb)).fetchall()
k=dict((c,(names.get(s,s))) for c,s in db.execute("select correlationId,shortName from CUPTI_ACTIVITY_KIND_KERNEL where end>? and start<?",(na-int(1e9),nb+int(1e9))))
mc=dict((c,(by,kind)) for c,by,kind in db.execute("select correlationId,bytes,copyKind from CUPTI_ACTIVITY_KIND_MEMCPY where end>? and start<?",(na-int(1e9),nb+int(1e9))))
th=collections.defaultdict(list)
for s,e,t,n,c in rt: th[t].append((s,e,names[n],c))
for t,ev in th.items():
    lastk="START"; pend=collections.Counter(); syncs=collections.Counter(); cnt=collections.Counter()
    lastlabel=lambda: lastk
    for i in range(len(ev)-1):
        s,e,n,c=ev[i]
        if c in k: lastk=k[c]
        elif c in mc: lastk="memcpy%d:%dMB"%(mc[c][1],mc[c][0]>>20) if mc[c][0]>(4<<20) else "memcpy%d"%mc[c][1]
        if 'Synchronize' in n: syncs[lastk]+=e-s
        g=ev[i+1][0]-e
        if g>1e6:
            nxt=ev[i+1]; nk=k.get(nxt[3]) or ("memcpy%d"%mc[nxt[3]][1] if nxt[3] in mc else nxt[2])
            pend[(lastk[:40],nk[:40])]+=g; cnt[(lastk[:40],nk[:40])]+=1
    print("THREAD",t%100000,"gap total>1ms %.2f s"%(sum(pend.values())/1e9))
    for (x,y),v in pend.most_common(22): print("   %7.1f ms n=%3d  after %-40s before %s"%(v/1e6,cnt[(x,y)],x,y))
    print("  sync wait by last-launched op:")
    for x,v in syncs.most_common(10): print("   %7.1f ms after %s"%(v/1e6,x[:60]))
