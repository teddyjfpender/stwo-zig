#!/usr/bin/env python3
import json,re,sys
from pathlib import Path
text=Path(sys.argv[1]).read_text()
batches=[]; checkpoints={}; values={}
for line in text.splitlines():
 if line.startswith('NATIVE_COMPOSITION_CONTEXT'): batches.append([])
 if line.startswith('NATIVE_COMPOSITION_CHECKPOINT'):
  fields=dict(re.findall(r'(\w+)=([^ ]+)',line))
  fields['words']=list(map(int,re.findall(r'\.v = (\d+)',line)))
  batches[-1].append(fields)
 if line.startswith('VM_COMPOSITION_CHECKPOINT'):
  fields=dict(re.findall(r'(\w+)=([^ ]+)',line)); checkpoints[(fields['section'],int(fields['index']))]=fields
 if line.startswith('VM_COMPOSITION_HORNER'):
  values[int(re.search(r'node=(\d+)',line)[1])]=list(map(int,re.findall(r'\.v = (\d+)',line)))
selected=int(sys.argv[2]) if len(sys.argv)>2 else 0
if len(batches)<=selected: raise SystemExit('No selected native diagnostic batch yet')
results=[]
for row in batches[selected]:
 key=(row['section'],int(row['index'])+(row['section']=='ethereum'))
 graph=checkpoints.get(key)
 if graph is None: continue
 value=values.get(int(graph['node'])) if 'node' in graph else None
 results.append({'section':key[0],'index':key[1],'name':row['name'],'adapter':row['adapter'],'native_constraints':int(row['constraints']),'graph_constraints':int(graph['constraints']),'node':graph.get('node'),'native':row['words'],'graph':value,'equal':value==row['words'] if value is not None else None})
print(json.dumps({'native_batches':len(batches),'horner_values':len(values),'first_mismatch':next((r for r in results if r['equal'] is False),None),'components':results},indent=2))
