import sys, numpy as np, json
# M6 level census (outer_assignment.levelKindCensus) on a recorded node.
node=np.fromfile(sys.argv[1],dtype=np.uint32); nv,nt,ni,nl,ns=node[2:7]; o=8
ends=node[o:o+nl].astype(np.int64); o+=nl; kinds=node[o:o+nt*8].reshape(nt,8)[:,0]
cls=np.full(16,4); cls[[8,9,10]]=0; cls[7]=1; cls[6]=2; cls[[2,3]]=3
c=cls[kinds]
names=["inverse","permutation","blake_g","mul","other"]
out={"wide_levels":0,"wide_tasks":0,"narrow_width1":0}
for n in names: out[n+"_levels"]=0; out[n+"_tasks"]=0
b=0
for e in ends:
    w=e-b
    if w==0: b=e; continue
    if w>2048: out["wide_levels"]+=1; out["wide_tasks"]+=int(w); b=e; continue
    out["narrow_width1"]+=int(w==1)
    k=int(c[b:e].min()); out[names[k]+"_levels"]+=1; out[names[k]+"_tasks"]+=int(w); b=e
out["levels"]=int(nl); out["tasks"]=int(nt)
print(json.dumps(out))
