#!/usr/bin/env python3
"""Bounded independent Rust numerical oracle qualification; never execution acceptance."""
import argparse,copy,hashlib,json,subprocess,tempfile,time
from pathlib import Path

def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--oracle',type=Path,required=True);p.add_argument('--fixtures',type=Path,required=True);p.add_argument('--sail',type=Path,required=True);p.add_argument('--output',type=Path,required=True);a=p.parse_args()
 reports=[]
 with tempfile.TemporaryDirectory(prefix='rv64-om-rust-gkr-mutations-') as tmp:
  temp=Path(tmp)/'input.json'
  def run(label,value,honest):
   temp.write_text(json.dumps(value,separators=(',',':')));start=time.monotonic_ns();r=subprocess.run([str(a.oracle),str(temp)],capture_output=True,text=True,timeout=30)
   if bool(r.returncode==0)!=honest:raise RuntimeError(f'{label}: unexpected exit{r.returncode}: {r.stderr[:300]}')
   out=json.loads(r.stdout) if honest else None
   if out and (out['accepting_execution_receiver'] or out['physical_pcs_verified'] or out['whole_protocol_128'] or not out['production_terminal_binding_pending']):raise RuntimeError('unsupported acceptance claim')
   reports.append({'label':label,'numerical_pass':honest,'exit':r.returncode,'elapsed_ns':time.monotonic_ns()-start,'error':r.stderr.strip().splitlines()[0] if r.stderr else None,'report':out})
  examples={name:json.loads((a.fixtures/f'{name}.json').read_text()) for name in ['mixed','zero','constant']}
  for name,value in examples.items():run(name,value,True)
  mixed=examples['mixed']
  def mutate(label,path,fn):
   x=copy.deepcopy(mixed);target=x
   for k in path[:-1]:target=target[k]
   target[path[-1]]=fn(target[path[-1]]);run(label,x,False)
  for coordinate in range(8):
   inc=lambda v:(v+1)%2147483647
   mutate(f'coefficient-coordinate-{coordinate}',['sumchecks',1,0,0,coordinate],inc)
   mutate(f'layer-mask-coordinate-{coordinate}',['masks',0,0,0,0,coordinate],inc)
   mutate(f'expected-terminal-coordinate-{coordinate}',['expected','claims',0,0,coordinate],inc)
   mutate(f'independent-input-coordinate-{coordinate}',['terminal_inputs',0,0,0,coordinate],inc)
  mutate('initial-digest',['initial','digest',0],lambda v:v^1)
  mutate('expected-end-digest',['expected','end','digest',0],lambda v:v^1)
  mutate('expected-end-counter',['expected','end','draws'],lambda v:v+1)
  mutate('root-pole',['outputs',1,1],lambda v:[0]*8)
  mutate('noncanonical-coordinate',['outputs',0,0,7],lambda v:2147483647)
  mutate('malformed-mask-width',['masks',0,0],lambda v:[])
  mutate('malformed-round-shape',['sumchecks',1],lambda v:[])
  # An extra zero coefficient preserves the polynomial function, but changes
  # transcript bytes. Using trimming UnivariatePoly.new() would miss this.
  zero=copy.deepcopy(examples['zero']);zero['sumchecks'][1][0].append([0]*8);run('zero-polynomial-vector-length',zero,False)
  constant=copy.deepcopy(examples['constant']);constant['sumchecks'][1][0].append([0]*8);run('constant-polynomial-trailing-zero',constant,False)
  # The first claims mix resets inherited draw counters in BOTH authorities.
  initial_counter=copy.deepcopy(mixed);initial_counter['initial']['draws']+=1;run('inherited-counter-reset-control',initial_counter,True)
  sail=json.loads(a.sail.read_text());run('actual-sail-child',sail,True)
  bad=copy.deepcopy(sail);bad['expected']['claims'][0][0][7]^=1;run('actual-sail-high-terminal-mutation',bad,False)
 out={'schema':'rv64-independent-rust-om-gkr-numerical-v1','accepting_execution_receiver':False,'whole_protocol_128':False,'oracle_sha256':hashlib.sha256(a.oracle.read_bytes()).hexdigest(),'inputs_sha256':{name:hashlib.sha256((a.fixtures/f'{name}.json').read_bytes()).hexdigest() for name in examples},'sail_sidecar_sha256':hashlib.sha256(a.sail.read_bytes()).hexdigest(),'cases':reports,'scope':'Pinned Rust algorithm mechanically lifted to OM over pinned Rust QM arithmetic; numerical/transcript and tiny independent MLE arrays only. Actual Sail terminals/PCS and starting-state authentication remain outside this oracle.'}
 a.output.write_text(json.dumps(out,indent=2)+'\n');print(json.dumps({'cases':len(reports),'honest_passes':sum(r['numerical_pass'] for r in reports),'rejections':sum(not r['numerical_pass'] for r in reports),'accepting_execution_receiver':False}))
if __name__=='__main__':main()
