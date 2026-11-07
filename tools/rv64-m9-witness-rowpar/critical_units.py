import sys, numpy as np
w=np.fromfile(sys.argv[1],dtype=np.uint32); nlev,nstr,nunit,nb=w[2:6]; o=8
lev=w[o:o+nlev].astype(np.int64); o+=nlev; st=w[o:o+nstr].astype(np.int64); o+=nstr; un=w[o:o+nunit]
lo,hi=int(sys.argv[2]),int(sys.argv[3])
slen=np.diff(np.concatenate([[0],st]))
isb=(un>>31).astype(np.int64); cb=np.concatenate([[0],np.cumsum(isb)])
sstart=np.concatenate([[0],st[:-1]])
sb=cb[st]-cb[sstart]
crit=0; critb=0; tot=0
for l in range(lo,hi):
    a=lev[l-1] if l else 0; b=lev[l]
    i=a+np.argmax(slen[a:b]); crit+=slen[i]; critb+=sb[i]; tot+=slen[a:b].sum()
print(f"levels {hi-lo} crit_units {crit} crit_blake {critb} units {tot}")
