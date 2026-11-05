#!/usr/bin/env python3
"""D: source-height hash work + measured-kernel extrapolation, NOT block timing.
Requires source census generated from accepted M6 declarations, and actual
same-hardware P2/Blake rectangular commitment benchmark receipt. No outer
budget, FFT/LDE, FS/PoW, opening, allocation or frontend latency is invented.
"""
import argparse,collections,hashlib,json
from pathlib import Path

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def parts(census):
    proofs=[]
    for i,cpu in enumerate(census['cpus']):
        cs=[dict(name=s['name'],log=s['log'],fixed=s['fixed_cols'],main=s['main_cols'],inter=s['binding_cols']+s['ram_cols']+s['other_cols'],split=1) for s in cpu['slots']]
        assert sum(c['main']*(1<<c['log']) for c in cs)==cpu['main_cells']
        assert sum(c['inter']*(1<<c['log']) for c in cs)==cpu['inter_cells']
        proofs.append(dict(kind='cpu',ordinal=i,components=cs))
    for truth in census['truths']:
        cs=[dict(name=p['kind'],log=p['log'],fixed=p['fixed_cols'],main=p['main_cols'],inter=p['local_cols']+p['global_cols'],split=p['composition_split']) for p in truth['parts']]
        assert sum(c['main']*(1<<c['log']) for c in cs)==truth['main_cells']
        assert sum(c['inter']*(1<<c['log']) for c in cs)==truth['inter_cells']
        proofs.append(dict(kind=truth['family'],ordinal=len(proofs),components=cs))
    return proofs

def group_work(groups):
    if not groups:return dict(columns=0,own_lde_cells=0,lde_cell_log_work_index=0,lifted_cells=0,p2_prefix_permutations=1,blake_prefix_compressions=1,p2_flat_permutations=1,blake_flat_compressions=1,source_height_groups=[])
    height=max(groups);n=1<<height;columns=sum(groups.values());previous=0
    p2=3*n-2 # one mandatory final leaf permutation +2 per interior node
    blake=2*n-1 # final leaf block +one per interior node; prefix IV cached
    stages=[]
    for ordinal,(log,width) in enumerate(sorted(groups.items())):
        new=previous+width
        p2_blocks=new//12-previous//12
        blake_blocks=(new//16 if ordinal+1<len(groups) else max(0,(new-1)//16))-previous//16
        p2+=p2_blocks*(1<<log);blake+=blake_blocks*(1<<log)
        stages.append(dict(log_lde_rows=log,columns=width,cumulative_columns=new,p2_absorb_permutations=p2_blocks*(1<<log),blake_absorb_compressions=blake_blocks*(1<<log)))
        previous=new
    return dict(columns=columns,max_log_lde_rows=height,own_lde_cells=sum(w*(1<<l) for l,w in groups.items()),lde_cell_log_work_index=sum(w*(1<<l)*l for l,w in groups.items()),lifted_cells=columns*n,p2_prefix_permutations=p2,blake_prefix_compressions=blake,p2_flat_permutations=n*(columns//12+1)+2*(n-1),blake_flat_compressions=n*max(1,(columns+15)//16)+(n-1),source_height_groups=stages)

def self_check():
    for width in range(1,65):
        work=group_work({5:width})
        assert work['p2_prefix_permutations']==work['p2_flat_permutations']
        assert work['blake_prefix_compressions']==work['blake_flat_compressions']
    eager=group_work({4:16,6:1})
    assert eager['blake_prefix_compressions']==143
    assert eager['p2_prefix_permutations']==206
    assert group_work({})['p2_prefix_permutations']==1

def main():
    self_check()
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--source-census',type=Path,required=True);p.add_argument('--benchmark',type=Path,required=True);p.add_argument('--log-blowup',type=int,default=1);p.add_argument('--out',type=Path,required=True);args=p.parse_args()
    source=json.loads(args.source_census.read_text());bench=json.loads(args.benchmark.read_text());assert bench['status']=='PASS'
    # Measured rectangular large-shape rates only. This range is a scenario
    # calibration, not a hardware lower/upper bound or statistical CI.
    rates=[]
    for b in bench['benchmarks']:
        if b['log_rows']<17:continue
        n=b['rows'];w=b['columns'];rates.append(dict(columns=w,log_rows=b['log_rows'],p2_permutations_s=(n*(w//12+1)+2*(n-1))/b['p2_median_gpu_s'],blake_compressions_s=(n*((w+15)//16)+n-1)/b['blake_median_gpu_s']))
    assert len(rates)>=3
    total=collections.Counter();warm=collections.Counter();proofs=[]
    for pr in parts(source):
        cs=pr.pop('components');split=max(c['split'] for c in cs);composition_log=max(c['log']+c['split'] for c in cs)-split
        trees=[]
        for name in ('fixed','main','inter','composition'):
            groups=collections.Counter({composition_log+args.log_blowup:8*(1<<split)}) if name=='composition' else collections.Counter()
            if name!='composition':
                for c in cs:
                    if c[name]:groups[c['log']+args.log_blowup]+=c[name]
            work=group_work(groups);work['tree']=name;trees.append(work)
            for field in ('own_lde_cells','lde_cell_log_work_index','lifted_cells','p2_prefix_permutations','blake_prefix_compressions','p2_flat_permutations','blake_flat_compressions'):
                total[field]+=work[field]
                if name!='fixed':warm[field]+=work[field]
        proofs.append(dict(**pr,trees=trees,composition_split=split,composition_coefficient_log=composition_log))
    p2rates=[r['p2_permutations_s'] for r in rates];brates=[r['blake_compressions_s'] for r in rates]
    for totals in (total,warm):
        totals['p2_prefix_gpu_s_scenario_low']=totals['p2_prefix_permutations']/max(p2rates)
        totals['p2_prefix_gpu_s_scenario_high']=totals['p2_prefix_permutations']/min(p2rates)
        totals['blake_prefix_gpu_s_scenario_low']=totals['blake_prefix_compressions']/max(brates)
        totals['blake_prefix_gpu_s_scenario_high']=totals['blake_prefix_compressions']/min(brates)
    result=dict(status='D exact source-height operation counts; E uncalibrated mixed-bank timing scenario',source_census_sha256=sha(args.source_census),benchmark_sha256=sha(args.benchmark),log_blowup=args.log_blowup,proof_count=len(proofs),cold_all_trees=total,warm_omit_FIXED_commits=warm,proofs=proofs,calibration_rectangles=rates,p2_prefix_runtime_implemented=False,outer_commit_budget_available=False,not_measured_block_timing=True,excluded=['FFT/LDE execution; own_lde_cells is work volume only','FS/PoW','openings','memory copy, bank read/write, allocation and launch overhead','outer node commits; candidate shapes not known','host graph/witness, setup/cache, transfer, verification, request latency'],assumptions=['Blake operation count follows existing native_height_leaves eager-prefix full-block convention',
      'P2 incremental source-height prefix bank carries24M31 state and source-owned absorb position; numerical header alone is not this runtime','Composition geometry uses source split bound and8*2^split columns','Warm scenario skips onlyFIXED initialization; allMAIN/INTER/composition charged','Rectangular throughput extrema are scenario calibration, not actual mixed-prefix measurement, confidence interval or bound','Current accepted M6 source geometry; this does not assert P2 native profile validity or compute new full pure-P2 block proof cost'])
    args.out.parent.mkdir(parents=True,exist_ok=True);args.out.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(proofs=len(proofs),cold=total,warm=warm),indent=2))
if __name__=='__main__':main()
