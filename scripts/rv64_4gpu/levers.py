import math, itertools
# Calibrated M6/M7 kernel GPU-s [D]
NAT_PER_MINSTR = 3.93/26.894777   # GPU-s kernel per M instr (M6 nsys native window)
LEAF_K = 0.47; FOLD_K = 0.42       # GPU-s kernel per node (M6 recursion window 10.4 GPU-s split by cells)
BLOCKS = {'24628607':dict(mi=26.894777,seg=7,tru=10,cpu_frac=0.64),
          '26235159':dict(mi=204.825818,seg=49,tru=26,cpu_frac=0.75)}
def folds_levels(L,k=4):
    f=0;lv=0;n=L
    while n>1:
        n=math.ceil(n/k);f+=n;lv+=1
    return f,lv
SC = {  # pess, central, opt
 'nat_eff':   (2.0,3.0,4.0),
 'busy':      (0.75,0.85,0.90),
 'rec_hash':  (0.35,0.27,0.20),
 'leaf_cnt':  (0.40,0.35,0.30),
 'leaf_grow': (1.15,1.10,1.05),  # per-leaf cost growth when a leaf covers more native work
 'd2_leaf':   (0.60,0.55,0.50),  # user: x0.5; M4.0 item 6 put it at x0.60-0.73
 'd2_nat':    (1.50,1.40,1.30),
 'outer_gkr': (0.57,0.57,0.57),
 'nat_gkr_nat':(0.826,0.826,0.826), # native INTER x0.5 -> native cells x0.826 (model.json)
 'nat_gkr_leaf':(0.936,0.936,0.936),
 'precomp':   (0.0,0.20,0.35),   # fraction of CPU instructions removed on heavy blocks
 'precomp_backfill':(0.35,0.25,0.15),# fraction of removed CPU cost reappearing as truth work
 'cap_mips':  (80,120,200),      # parallel capture aggregate MIPS
 'cap_head':  (0.6,0.4,0.3),     # s before first segment is ready
 'busy_tail': (0.7,0.8,0.85),
 'compress':  (2.5,1.5,1.0),
 'overhead':  (0.6,0.4,0.3),
}
OFF = {'nat_eff':1.0,'busy':0.5,'rec_hash':1.0,'leaf_cnt':1.0,'leaf_grow':1.0,'d2_leaf':1.0,'d2_nat':1.0,
       'outer_gkr':1.0,'nat_gkr_nat':1.0,'nat_gkr_leaf':1.0,'precomp':0.0,'precomp_backfill':0.0,'cap_mips':None,'cap_head':None}
LEVERS = {'nat_eff':['nat_eff'],'busy(L3 occupancy)':['busy'],'rec_hash':['rec_hash'],'leaf_cnt':['leaf_cnt','leaf_grow'],
          'D2 b4':['d2_leaf','d2_nat'],'outer_gkr':['outer_gkr'],'native_gkr':['nat_gkr_nat','nat_gkr_leaf'],
          'precompiles':['precomp','precomp_backfill'],'parallel_capture':['cap_mips','cap_head']}
def run(b,p,gpus=4,verbose=False):
    B=BLOCKS[b]; mi=B['mi']
    cf=B['cpu_frac']; x=p['precomp']
    work_scale = (1-cf) + cf*(1-x) + cf*x*p['precomp_backfill']
    nat = NAT_PER_MINSTR*mi*work_scale*p['d2_nat']*p['nat_gkr_nat']/p['nat_eff']
    seg = B['seg']*(1-x) ; L0 = seg + B['tru'] + (B['seg']*x*p['precomp_backfill'] if x else 0)
    L = max(1, math.ceil(L0*p['leaf_cnt']))
    node = p['rec_hash']*p['outer_gkr']
    leaf = LEAF_K*node*p['leaf_grow']*p['d2_leaf']*p['nat_gkr_leaf']
    fold = FOLD_K*node
    F,lv = folds_levels(L)
    window_gpu_s = nat + (L-1)*leaf + max(0,F-lv)*fold
    window = window_gpu_s/(gpus*p['busy'])
    tail = (leaf + lv*fold)/p['busy_tail']
    mi_eff = mi*(1-cf*x)
    if p['cap_mips'] is None:   # today: ~20 MIPS on big blocks, 13.6 on 607 (fixed init)
        cap_total = 1.25 + 0.0524*mi*(1-cf*x) if b=='26235159' else 1.98
        head = 0.6
    else:
        cap_total = p['cap_head'] + mi_eff/p['cap_mips']; head=p['cap_head']
    last_seg_native = nat/max(1,seg+B['tru'])/p['busy']  # one segment's native after capture ends
    body = max(head+window, cap_total+last_seg_native)
    total = p['overhead'] + body + tail + p['compress']
    d=dict(nat_gpu_s=nat,leaves=L,folds=F,levels=lv,leaf_k=leaf,window_gpu_s=window_gpu_s,window=window,cap=cap_total,tail=tail,total=total,
           rec_cells_factor=node)
    return d
names=['pess','central','opt']
for b in BLOCKS:
    for i,n in enumerate(names):
        p={k:v[i] for k,v in SC.items()}
        r=run(b,p)
        print(b,n,{k:(round(v,2) if isinstance(v,float) else v) for k,v in r.items()})
print()
# today-level (no levers)
for b in BLOCKS:
    for g in (2,4):
        p={k:v[1] for k,v in SC.items()}; p.update(OFF); p['busy_tail']=0.6; p['compress']=0.0; p['overhead']=0.4
        r=run(b,p,gpus=g); print('today-level',b,g,'GPUs',{k:(round(v,2) if isinstance(v,float) else v) for k,v in r.items()})
print()
# necessity: remove each lever
for b in BLOCKS:
  for i,n in enumerate(names):
    base={k:v[i] for k,v in SC.items()}
    row=[]
    for lev,keys in LEVERS.items():
        p=dict(base)
        for k in keys: p[k]=OFF[k]
        row.append((lev,round(run(b,p)['total'],2)))
    print(b,n,'all=%.2f'%run(b,base)['total'],row)
print()
# min single-lever sweeps for central on 159: what native eff / busy needed
for b in ['26235159']:
    base={k:v[1] for k,v in SC.items()}
    for ne in (2,3,4,6,8):
        p=dict(base);p['nat_eff']=ne;print('nat_eff',ne,round(run(b,p)['total'],2))
    for x in (0,0.1,0.2,0.35,0.5):
        p=dict(base);p['precomp']=x;print('precomp',x,round(run(b,p)['total'],2))
print('\n--- pessimistic without D2, and overlap-corrected outer GKR (x0.8 after hash change)')
for b in BLOCKS:
  for i,n in enumerate(names):
    p={k:v[i] for k,v in SC.items()}; p['outer_gkr']=0.8
    q=dict(p); q['d2_leaf']=1;q['d2_nat']=1
    print(b,n,'gkr0.8 total=%.2f'%run(b,p)['total'],'gkr0.8 noD2=%.2f'%run(b,q)['total'])
print('\n--- minimal lever sets meeting <10 s on 26235159 (D2 excluded), per scenario')
levs=[l for l in LEVERS if l!='D2 b4']
for i,n in enumerate(names):
    base={k:v[i] for k,v in SC.items()}
    for k in LEVERS['D2 b4']: base[k]=OFF[k]
    ok=[]
    for r in range(len(levs)+1):
        for keep in itertools.combinations(levs,r):
            p=dict(base)
            for l in levs:
                if l not in keep:
                    for k in LEVERS[l]: p[k]=OFF[k]
            t=run('26235159',p)['total']
            if t<10 and not any(set(o)<=set(keep) for o,_ in ok): ok.append((keep,t))
    ok.sort(key=lambda x:len(x[0]))
    print(n,[(k,round(t,2)) for k,t in ok[:8]])
print('\n--- 4-GPU, today kernels, only L3 occupancy+parallel capture (proof-neutral)')
for b in BLOCKS:
    p={k:v[1] for k,v in SC.items()}
    for l in ['nat_eff','rec_hash','leaf_cnt','D2 b4','outer_gkr','native_gkr','precompiles']:
        for k in LEVERS[l]: p[k]=OFF[k]
    print(b,{k:(round(v,2) if isinstance(v,float) else v) for k,v in run(b,p).items()})
