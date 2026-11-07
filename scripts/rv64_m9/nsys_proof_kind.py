#!/usr/bin/env python3
"""Read-only nsys attribution (stream m9-proof-params): split CUPTI kernel GPU-s of a profiled rv64 request into native vs
recursion proofs (NVTX state machine on the launching thread) and into kernel classes / PCS phases.

Usage (on the pod, never on a live run dir you do not own; opens the sqlite read-only):
  python3 nsys_proof_kind.py <timeline.sqlite> <label> > out.json
A proof whose ranges include TC/FIXED, recursion/MAIN-assignment, recursion/INTER-witness or owner/controller is a recursion
node; a TC/MAIN not preceded by those starts a native proof. Kernel classes: lde_eval (n2b*, lde, lift_add), merkle, deep,
interp (b2n*), composition, witness, gkr, samples, pow (search_kernel), fri, other."""
# and into blowup-proportional vs fixed kernel classes. Usage: nvtx_kind.py <timeline.sqlite> [label]
import sqlite3,sys,bisect,collections,json,re
db=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True); c=db.cursor(); c.execute("pragma temp_store=MEMORY")
S={i:v for i,v in c.execute("select id,value from StringIds")}
launch={cid:(tid,st) for cid,tid,st in c.execute("select correlationId,globalTid,start from CUPTI_ACTIVITY_KIND_RUNTIME")}
REC=('TC/FIXED','recursion/MAIN-assignment','recursion/INTER-witness','owner/controller')
ev=collections.defaultdict(list); nproof=collections.Counter()
rows=list(c.execute("select e.start,e.globalTid,coalesce(e.text,s.value) from NVTX_EVENTS e left join StringIds s on e.textId=s.id where e.end is not null order by e.globalTid,e.start"))
last={}; mode={}
for st,tid,txt in rows:
    if txt is None or 'callback' in txt or '/pcs/' in txt and 'final_readback' not in txt: continue
    if any(r in txt for r in REC):
        if mode.get(tid)!='rec' or last.get(tid)=='end': nproof['rec']+= (1 if 'TC/FIXED' in txt else 0)
        mode[tid]='rec'; ev[tid].append((st,'rec'))
    elif 'TC/MAIN' in txt and last.get(tid) not in ('rec',):
        if mode.get(tid)!='nat' or last.get(tid)=='end': nproof['nat']+=1
        mode[tid]='nat'; ev[tid].append((st,'nat'))
    last[tid]='end' if 'final_readback' in txt else ('rec' if any(r in txt for r in REC) else 'x')
keys={t:[e[0] for e in v] for t,v in ev.items()}
PH=collections.defaultdict(list)
for st,en,tid,txt in c.execute("select e.start,e.end,e.globalTid,coalesce(e.text,s.value) from NVTX_EVENTS e left join StringIds s on e.textId=s.id where e.end is not null order by e.globalTid,e.start"):
    if txt and 'callback' not in txt and 'owner/pcs' not in txt and 'controller' not in txt: PH[tid].append((st,en,txt.split('/')[-1]))
PK={t:[x[0] for x in v] for t,v in PH.items()}
def phase(tid,ls):
    if tid not in PK: return 'none'
    i=bisect.bisect_right(PK[tid],ls)-1
    while i>=0 and i>len(PH[tid])-1: i-=1
    if i>=0 and PH[tid][i][0]<=ls<=PH[tid][i][1]: return PH[tid][i][2]
    return 'gap'
ph=collections.defaultdict(float)
def cls(k):
    if k.startswith('n2b') or k.startswith('lde') or 'lde' in k or k in('lift_add',): return 'lde_eval'
    if k in('mixed_leaf_kernel','child_layer_kernel','layer','fri_leaf_kernel','close_layer','begin_layer') or 'merkle' in k: return 'merkle'
    if k.startswith('deep'): return 'deep'
    if k.startswith('b2n') : return 'interp'
    if k.startswith('stwo_rv64_composition') or 'truth_domain' in k or 'joined_domain' in k: return 'composition'
    if k in('chain_flow','chain_run','generate','generate_shared','witness','wide_level','inverse_contribute_sum','cumulative','arithmetic_witness') : return 'witness'
    if k.startswith('oracles') or k.startswith('batch') or 'binding' in k or k.startswith('rv64_projection') or k=='analyze': return 'gkr'
    if k in('sample_first_basis','channel_mix'): return 'samples'
    if k=='search_kernel': return 'pow'
    if 'fold' in k or 'fri' in k: return 'fri'
    return 'other'
agg=collections.defaultdict(float); kern=collections.defaultdict(float)
for name,st,en,cid in c.execute("select shortName,start,end,correlationId from CUPTI_ACTIVITY_KIND_KERNEL"):
    kn=S.get(name,str(name)); d=(en-st)*1e-9; tid,ls=launch.get(cid,(None,None)); m='pre'
    if tid in keys:
        i=bisect.bisect_right(keys[tid],ls)-1
        if i>=0: m=ev[tid][i][1]
    agg[(m,cls(kn))]+=d; kern[(m,kn)]+=d; ph[(m,phase(tid,ls),cls(kn))]+=d
tot=collections.defaultdict(float)
for (m,k),v in agg.items(): tot[m]+=v
out=dict(label=sys.argv[2] if len(sys.argv)>2 else '', proofs=dict(nproof), total={m:round(v,4) for m,v in tot.items()},
         classes={m:{k:round(v,4) for (mm,k),v in sorted(agg.items()) if mm==m} for m in tot},
         phase={m:{'%s|%s'%(p_,k):round(v,4) for (mm,p_,k),v in sorted(ph.items()) if mm==m and v>0.003} for m in tot},
         top={m:{k:round(v,4) for (mm,k),v in sorted(kern.items(),key=lambda x:-x[1]) if mm==m and v>0.02} for m in tot})
print(json.dumps(out))
