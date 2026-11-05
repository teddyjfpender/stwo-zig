from pathlib import Path
import json,subprocess,time,statistics,sys,os
root=Path('/workspace/m3/src/m7-integrate');sys.path.insert(0,str(root/'scripts'));import rv64_m7_integration_stack as S
b=Path('/workspace/m3/runs/m7-integrate');out=b/'p1-outer-chunks-gate-controller-20261106-01';primary=b/'p1-outer-chunks-headline-20261106-01'
while True:
 d=json.loads((primary/'experiment.json').read_text());services=d.get('services',[])
 if any(s.get('exit_code',0) not in (None,0) for s in services):raise RuntimeError('timed service failed; no gate launched')
 if len(services)==6 and all(s.get('exit_code')==0 and s.get('payload_byte_parity') is True for s in services):break
 time.sleep(5)
result={'status':'ALL6_TIMED_SERVICES_EXACT_FRESH_CPU_VALIDATION_PENDING','primary':str(primary),'arms':{},'candidate_complete_gpu_seconds':None,'exact_node_peak':None}
for arm in ['baseline','fullstack']:
 receipts=[json.loads((Path(s['run'])/'receipt.json').read_text()) for s in services if s['arm']==arm]
 requests=[r['requests'][1] for r in receipts]
 walls=[r['marker']['request_wall_ns']/1e9 for r in requests]
 result['arms'][arm]={'warm_s':walls,'median_s':statistics.median(walls),'median_stages':{k:statistics.median(r['stages'][k] for r in requests) for k in requests[0]['stages']},'root_bytes':[r['proof_bytes_root'] for r in requests]}
result['delta_s']=result['arms']['fullstack']['median_s']-result['arms']['baseline']['median_s']
result['finding']='No request-time gain' if result['delta_s']>=0 else 'Lower request median; fresh validation and separate profile remain required'
S.write(out/'matched-primary.json',result)
# Only accepted small-block duplicates; primary payloads stay until all fresh checks finish.
smoke=json.loads((b/'p1-outer-chunks-small-20261106-01/experiment.json').read_text());assert smoke['status']=='SMOKE_BYTE_PARITY_AND_FRESH_ACCEPTED'
all_small=[]
for service in smoke['services']:
 r=json.loads((Path(service['run'])/'receipt.json').read_text());assert len(r['receivers'])==2 and all(x['accepted'] for x in r['receivers'])
 all_small.extend(Path(x['proof']) for x in r['requests'])
ref=all_small[0];pruned=[]
for proof in all_small[1:]:
 for p in proof.rglob('*'):
  if not p.is_file() or p.suffix not in ('.bin','.proof'):continue
  reference=ref/p.relative_to(proof)
  digest=S.sha(p);assert reference.is_file() and S.sha(reference)==digest
  pruned.append({'path':str(p),'bytes':p.stat().st_size,'sha256':digest,'retained_reference':str(reference)});p.unlink()
S.write(out/'small-duplicate-prune.json',{'files':pruned,'bytes_freed':sum(x['bytes'] for x in pruned),'scope':'Only3 already fresh-accepted small proof payload sets; all metadata retained.'})
gate=b/'p1-outer-chunks-gate-20261106-01'
argv=['bash',str(root/'scripts/rv64_gate.sh'),'--source-commit',(root/'.m3-commit').read_text().strip(),'--out',str(gate)]
with (out/'gate.log').open('w') as log:r=subprocess.run(argv,cwd=root,env=S.clean_environment(os.environ),stdout=log,stderr=subprocess.STDOUT)
(out/'exit').write_text(str(r.returncode)+'\n')
