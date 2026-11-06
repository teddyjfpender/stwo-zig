from pathlib import Path
import json,time,sys,os,subprocess,fcntl
root=Path('/workspace/m3/src/m7-integrate');sys.path.insert(0,str(root/'scripts'));import rv64_m7_integration_stack as S
b=Path('/workspace/m3/runs/m7-integrate');out=b/'p1-compact-state-headline-controller-20261106-02';smoke=b/'p1-compact-state-smoke-controller-20261106-02'
while not (smoke/'accepted-reference-parity.json').exists():
 if (smoke/'exit').exists() and (smoke/'exit').read_text().strip()!='0':raise RuntimeError('smoke failed; no headline')
 pre=json.loads((b/'p1-compact-state-preflight-20261106-03/preflight.json').read_text())
 if pre['status']=='FAIL':raise RuntimeError('preflight failed; no headline')
 time.sleep(5)
check=json.loads((smoke/'accepted-reference-parity.json').read_text());assert check['status']=='ALL4_FRESH_ACCEPTED_AND_EXACT_TO_PRIOR_ACCEPTED_V2_REFERENCE'
e=json.loads((b/'p1-compact-state-small-20261106-02/experiment.json').read_text());assert e['status']=='SMOKE_BYTE_PARITY_AND_FRESH_ACCEPTED'
proofs=[]
for s in e['services']:
 r=json.loads((Path(s['run'])/'receipt.json').read_text());assert all(v['accepted'] for v in r['receivers'])
 proofs.extend(Path(r['proof']) for r in r['requests'])
ref=proofs[0];pruned=[]
for proof in proofs[1:]:
 for p in proof.rglob('*'):
  if not p.is_file() or p.suffix not in ('.bin','.proof'):continue
  reference=ref/p.relative_to(proof);digest=S.sha(p);assert reference.is_file() and S.sha(reference)==digest
  pruned.append({'path':str(p),'bytes':p.stat().st_size,'sha256':digest,'retained_reference':str(reference)});p.unlink()
with open('/workspace/m3/locks/build.1.lock','a') as lock:
 fcntl.flock(lock,fcntl.LOCK_EX)
 for folder in [Path('/workspace/m3/build/m7-integrate/tools/bin'),Path('/workspace/m3/build/m7-integrate/p1-outer-chunks-v1/tools/bin')]:
  if not folder.exists():continue
  for p in folder.iterdir():
   if not p.is_file() or not p.name.startswith('rv64-'):continue
   pruned.append({'path':str(p),'bytes':p.stat().st_size,'sha256':S.sha(p),'reason':'Rebuildable owned cold catalogue generator; source/command/generated catalogue receipts retained; no runtime dependency.'});p.unlink()
S.write(out/'storage-prune.json',{'files':pruned,'bytes_freed':sum(x['bytes'] for x in pruned),'scope':'Fresh-accepted small duplicates and owned cold generator binaries only; frozen libraries, driver/receiver and proof reference retained.'})
m=json.loads((smoke/'artifact.json').read_text());S.validate_manifest(m);m['block']=24628607;m['created_utc_ns']=time.time_ns();S.write(out/'artifact.json',m)
assert __import__('shutil').disk_usage('/workspace').free>1_200_000_000,'insufficient headline headroom; no timing started'
argv=[sys.executable,str(root/'scripts/rv64_m7_integration_stack.py'),'run','--manifest',str(out/'artifact.json'),'--out',str(b/'p1-compact-state-headline-20261106-02')]
with (out/'headline.log').open('w') as log:r=subprocess.run(argv,cwd=root,env=S.clean_environment(os.environ),stdout=log,stderr=subprocess.STDOUT)
(out/'exit').write_text(str(r.returncode)+'\n')
if r.returncode:raise RuntimeError('headline failed; preserve receipts and validate completed proofs')
