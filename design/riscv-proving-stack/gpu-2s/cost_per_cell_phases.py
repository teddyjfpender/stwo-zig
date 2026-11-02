import json,sys,glob,os,collections
PH=['witness','main_lde','main_hash','spill','inter_gen','inter_lde','inter_hash','comp_eval','comp_interp','comp_commit','oods','fri','pow','decommit','other']
def phase(top,leaf):
    if top=='source_construction': return 'witness'
    if top in('main_commit','interaction_commit'):
        p='main' if top=='main_commit' else 'inter'
        if leaf=='streaming_transform': return p+'_lde'
        return p+'_hash'
    if top.startswith('retained_main'): return 'spill'
    if top=='interaction_generation': return 'inter_gen'
    if top=='composition_evaluation': return 'comp_eval'
    if top=='composition_interpolate_and_split': return 'comp_interp'
    if top=='composition_commit': return 'comp_commit'
    if top.startswith('sampled_value') or top.startswith('oods'): return 'oods'
    if top.startswith('fri'): return 'fri'
    if top=='proof_of_work': return 'pow'
    if top=='trace_decommit': return 'decommit'
    return 'other'
def load(f):
    d=json.load(open(f)); w=collections.Counter(); u=collections.Counter()
    def walk(s,top):
        for x in s:
            t=top or x['id']
            if x.get('children'): walk(x['children'],t)
            else:
                p=phase(t,x['id']); w[p]+=x['seconds']; u[p]+=(x.get('process_usage') or {}).get('lane_user_seconds',0)
    walk(d['stages'],None); return w,u
def run(dirn):
    cost=json.load(open(dirn+'/cost.json')); rep=json.load(open(dirn+'/report.json'))
    ents=[('cpu',i,c) for i,c in enumerate(cost['cpu'])]+[('truth',i,c) for i,c in enumerate(cost['truth'])]
    files=sorted(glob.glob(dirn+'/physical-*.stages.json'))
    print(f"\n=== {dirn}  prove_ns={rep['prove_ns']/1e9:.2f}s total={rep['total_before_report_ns']/1e9:.2f}s steps={rep['total_steps']} lanes={rep['coordinator_schedule']['lanes']}x{rep['coordinator_schedule']['workers_per_lane']}")
    assert len(files)==len(ents),(len(files),len(ents))
    TW=collections.Counter();TU=collections.Counter();TC=[0,0,0]
    rows=[]
    for f,(k,i,c) in zip(files,ents):
        w,u=load(f); n=c['native_cells']; TW+=w;TU+=u
        for j in range(3): TC[j]+=n[j]
        rows.append((os.path.basename(f)[9:13],k,i,c['columns'],n,c['max_log'],sum(w.values()),sum(u.values())))
        tot=sum(n)
        print(f"{os.path.basename(f)[9:13]} {k:5}{i} cols={c['columns']} cells(M)={[round(x/1e6,1) for x in n]} log={c['max_log'][0]} wall={sum(w.values()):6.2f}s core={sum(u.values()):6.1f}s  ns/cell(core)={sum(u.values())*1e9/max(tot,1):6.2f}")
    tot=sum(TC)
    print(f"cells: pre={TC[0]/1e6:.0f}M main={TC[1]/1e6:.0f}M inter={TC[2]/1e6:.0f}M total={tot/1e6:.0f}M ; per step {tot/rep['total_steps']:.1f}")
    print(f"sum wall={sum(TW.values()):.2f}s sum core={sum(TU.values()):.1f}s  core-ns/cell={sum(TU.values())*1e9/tot:.2f}  wall(ns)/cell at 14 cores eq={sum(TU.values())*1e9/tot/14:.3f}")
    for p in PH:
        if TW[p]==0 and TU[p]==0: continue
        denom = TC[1] if p.startswith('main') else TC[2] if p.startswith('inter') else tot
        print(f"  {p:12} wall={TW[p]:7.2f}s ({100*TW[p]/sum(TW.values()):4.1f}%) core={TU[p]:7.1f}s ({100*TU[p]/sum(TU.values()):4.1f}%)  core-ns/cell(all)={TU[p]*1e9/tot:6.3f}  core-ns/own-cell={TU[p]*1e9/denom:6.3f}")
    return TW,TU,TC,rep
if __name__=='__main__':
    for d in sys.argv[1:]: run(d)
