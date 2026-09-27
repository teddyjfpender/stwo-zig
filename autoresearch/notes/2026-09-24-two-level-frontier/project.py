from pathlib import Path
import re,json
p=Path(__file__).resolve().parent
s=(p/'profile.log').read_text()
g=[int(x) for x in re.findall(r'BLAKE3_HASH_METADATA g_rows=(\d+)',s)]
costs=[int(x) for x in re.findall(r'BLAKE3_PATH_SHARING_TOTAL .*?node_g_rows=(\d+)',s)]
assert len(costs)==6 and len(set(costs))==1
node_g=costs[0]
cases=[];trees=[]
for line in s.splitlines():
    if line.startswith('BLAKE3_PATH_SHARING kind='):
        d=dict(re.findall(r'(\w+)=(\S+)',line));trees.append({k:int(v) if v.isdigit() else v for k,v in d.items()})
    if line.startswith('BLAKE3_PATH_SHARING_TOTAL '):cases.append(trees);trees=[]
assert len(g)==len(cases)==6
out=[]
for i,(count,trees) in enumerate(zip(g,cases)):
    saved=sum((x['openings']-2)*node_g for x in trees if x['depth']>=2)
    out.append(dict(child=i,current_total_g=count,additional_g_reduction=saved,projected_total_g=count-saved))
def pad(n):return 1<<max(1,(n-1).bit_length())
folds=[]
for i in range(0,6,2):
    cur=g[i]+g[i+1];new=out[i]['projected_total_g']+out[i+1]['projected_total_g']
    folds.append(dict(children=[i,i+1],current_g=cur,projected_g=new,current_padded=pad(cur),projected_padded=pad(new)))
(p/'geometry.json').write_text(json.dumps(dict(children=out,folds=folds,scope='projection before native integration and routing overhead'),indent=2)+'\n')
print(json.dumps(folds))
