import sys,glob,json
sys.path.insert(0,__import__('os').path.dirname(__file__))
from cost_per_cell_phases import load,PH
d=sys.argv[1]
cost=json.load(open(d+'/cost.json'))
ents=[('cpu',c) for c in cost['cpu']]+[('truth',c) for c in cost['truth']]
files=sorted(glob.glob(d+'/physical-*.stages.json'))
print('proof     '+' '.join(f"{p[:9]:>9}" for p in PH[:-1]))
groups={}
for f,(k,c) in zip(files,ents):
    w,u=load(f); n=c['native_cells']; tot=sum(n)
    g='cpu' if k=='cpu' else ('keccak' if c['max_log'][0]>=21 else 'small')
    G=groups.setdefault(g,[{},0,[0,0,0]])
    for p in PH: G[0][p]=G[0].get(p,0)+u[p]
    G[1]+=tot
    for j in range(3): G[2][j]+=n[j]
for g,(u,tot,n) in groups.items():
    print(f"{g:8}  core-ns/cell: "+' '.join(f"{u[p]*1e9/tot:9.2f}" for p in PH[:-1]), f" total={sum(u.values())*1e9/tot:.1f} cells={tot/1e6:.0f}M split={[round(x/1e6) for x in n]} core-s={sum(u.values()):.1f}")
