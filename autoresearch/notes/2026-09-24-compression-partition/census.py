"""Exact canonical G-DAG partition census; no witness-dependent routing."""
import json
from pathlib import Path
indices=((0,4,8,12),(1,5,9,13),(2,6,10,14),(3,7,11,15),(0,5,10,15),(1,6,11,12),(2,7,8,13),(3,4,9,14))
permutation=(2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8)
state=list(range(16));message=list(range(16,32));calls=[];next_id=32
for _ in range(7):
 for slot,ix in enumerate(indices):
  ins=[state[i] for i in ix]+message[2*slot:2*slot+2]
  outs=list(range(next_id,next_id+4));next_id+=4
  for i,w in zip(ix,outs):state[i]=w
  calls.append((ins,outs))
 message=[message[i] for i in permutation]
xors=[(state[i],state[i+8]) if i<8 else (state[i],i-8) for i in range(16)]
results=[]
for width in (1,2,4,7,8,14,28,56):
 groups=[]
 for start in range(0,56,width):
  selected=calls[start:start+width];produced=set();inputs=[]
  for ins,outs in selected:
   for wire in ins:
    if wire not in produced and wire not in inputs:inputs.append(wire)
   produced.update(outs)
  groups.append(dict(first=start,count=len(selected),inputs=inputs,produced=produced))
 consumers={}
 for g in groups:
  for wire in g['inputs']:consumers[wire]=consumers.get(wire,0)+1
 for pair in xors:
  for wire in pair:consumers[wire]=consumers.get(wire,0)+1
 for g in groups:
  g['outputs']=[w for w in sorted(g.pop('produced')) if consumers.get(w,0)]
  g['output_uses']=[consumers[w] for w in g['outputs']]
  # Existing packed G allocates 24 input bytes and 88 intermediate columns.
  # Input ranges cost two events per external word. Each G has 40 other events.
  g['main_columns']=4*len(g['inputs'])+88*g['count']
  g['lookup_events']=3*len(g['inputs'])+len(g['outputs'])+40*g['count']
  g['interaction_columns']=4*((g['lookup_events']+1)//2)
 results.append(dict(g_calls_per_row=width,groups=groups,rows=len(groups),
                     max_main_columns=max(g['main_columns'] for g in groups),
                     max_interaction_columns=max(g['interaction_columns'] for g in groups),
                     total_main_cells=sum(g['main_columns'] for g in groups),
                     total_lookup_events=sum(g['lookup_events'] for g in groups)))
assert results[0]['total_main_cells']==56*112
assert results[0]['total_lookup_events']==56*62
out=Path(__file__).with_name('census.json');out.write_text(json.dumps(results,indent=2)+'\n')
for r in results:print({k:v for k,v in r.items() if k!='groups'})
