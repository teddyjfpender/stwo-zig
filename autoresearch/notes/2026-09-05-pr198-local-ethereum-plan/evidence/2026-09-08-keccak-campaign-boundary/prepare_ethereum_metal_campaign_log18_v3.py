from pathlib import Path
import datetime,hashlib,json,shutil
repo=Path.cwd(); base=repo/'.git/local-ethereum/retained-campaign-v2-rw-heap-121x2097152-20260907'
old=base/'metal-field5-block-v1';out=base/'metal-field5-block-v2'
producer=repo/'.git/local-ethereum/prepared-leaf-metal-product-v7'; verifier=repo/'.git/local-ethereum/fixed-program-native-verifier-v6'
trial=base/'metal-field5-segment11-log18-v2';fresh=repo/'.git/local-ethereum/selected-real-metal-leaf11-log18-fresh-v2'
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def ident(p):return {'path':str(p),'bytes':p.stat().st_size,'sha256':sha(p)}
def write(p,value):
 with p.open('x') as f:json.dump(value,f,sort_keys=True,separators=(',',':'));f.write('\n')
if not json.loads((fresh/'receipt.json').read_text())['passed']:raise SystemExit('Real11 independent verification has not passed')
trial_receipt=json.loads((trial/'receipt.json').read_text())
if not trial_receipt['verified_and_published']:raise SystemExit('Real11 producer has not passed')
prod=json.loads((producer/'build-receipt.json').read_text());ver=json.loads((verifier/'build-receipt.json').read_text())
for receipt in (prod,ver):
 if receipt['exit_code']!=0 or ident(Path(receipt['executable']['path']))!=receipt['executable']:raise SystemExit('Product pin changed')
plan=json.loads((old/'prepared-launch-v2.json').read_text());old_snapshot=Path(plan['cwd'])
for entry in plan['controller_sources']:
 if sha(old_snapshot/entry['path'])!=entry['sha256']:raise SystemExit('Controller source changed')
if sha(old_snapshot/'source-manifest.json')!=plan['source_manifest_sha256']:raise SystemExit('Controller source manifest changed')
for entry in plan['aot_files']:
 if ident(Path(entry['path']))!=entry:raise SystemExit('AOT changed')
indices=[int(p.stem.removeprefix('leaf-')) for p in old.glob('leaf-*.json')]
if sorted(indices)!=[*range(11),120]:raise SystemExit('Accepted inventory differs')
imports=[]
for index in sorted(indices):
 path=old/f'leaf-{index:06d}.json';leaf=json.loads(path.read_text());digest=bytes(leaf['proof_sha256']).hex();proof=old/(digest+'.bin')
 if leaf['metadata']['segment_index']!=index or sha(proof)!=digest or proof.stat().st_size!=leaf['proof_bytes']:raise SystemExit('Retained proof differs')
 provenance=[ident(path),ident(old/'prepared-launch-v2.json')]
 for attempt in sorted((old/'attempts').glob(f'*leaf-{index:06d}-*')):
  for name in ('request.json','execution.json','stdout.json','stderr.log'):
   p=attempt/name
   if p.exists():provenance.append(ident(p))
 if index in (9,120):provenance.append(ident(old/'import-accounting-v1.json'))
 imports.append({'segment_index':index,'proof':ident(proof),'metadata':ident(path),'origin':'previous stopped campaign; original producer identity and timing retained','provenance':provenance})
leaf11=Path(trial_receipt['global_metadata']['path']);proof11=Path(trial_receipt['artifact']['path']);leaf=json.loads(leaf11.read_text())
if leaf['metadata']['segment_index']!=11 or bytes(leaf['proof_sha256']).hex()!=sha(proof11):raise SystemExit('Real11 metadata/proof mismatch')
imports.append({'segment_index':11,'proof':ident(proof11),'metadata':ident(leaf11),'origin':'explicit log18 recovery producer and separate-process fresh verifier','provenance':[ident(trial/'plan.json'),ident(trial/'receipt.json'),ident(fresh/'plan.json'),ident(fresh/'receipt.json')]})
out.mkdir();snapshot=out/'controller-source-v1';snapshot.mkdir()
for entry in plan['controller_sources']:
 p=snapshot/entry['path'];p.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(old_snapshot/entry['path'],p)
shutil.copyfile(old_snapshot/'source-manifest.json',snapshot/'source-manifest.json')
# Materialized proof bytes remain identical; canonical metadata is independently
# freshly verified by the controller before each imported leaf is accepted.
for entry in imports:
 shutil.copyfile(entry['proof']['path'],out/(entry['proof']['sha256']+'.bin'))
 write(out/f"leaf-{entry['segment_index']:06d}.json",json.loads(Path(entry['metadata']['path']).read_text()))
write(out/'import-accounting-v1.json',{'version':1,'imports':sorted(imports,key=lambda x:x['segment_index']),'prior_campaign_terminal':ident(old/'controller-terminal-v2.json'),'prior_import_accounting':ident(old/'import-accounting-v1.json'),'timing_note':'All original producer and verification times remain part of campaign accounting; new controller includes fresh revalidation and queue time. Imported artifacts were not produced by the new executable.'})
argv=plan['argv'][:]
for flag,value in [('--prover',prod['executable']['path']),('--verifier',ver['executable']['path']),('--output',str(out))]:argv[argv.index(flag)+1]=value
plan.update({'version':3,'scope':'Explicit migration of accepted native artifacts after real leaf11 log18 proof and independent fresh verification; not a completed block','recorded_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'argv':argv,'cwd':str(snapshot),'prover':prod['executable'],'verifier':ver['executable'],'acceptance_required_before_launch':'All imported hashes validated; controller freshly verifies imports then whole121 coverage','prior_campaign':str(old),'producer_source_manifest':prod['source_manifest'],'verifier_source_manifest':ver['source_manifest']})
write(out/'prepared-launch-v3.json',plan)
print(json.dumps({'prepared_launch':ident(out/'prepared-launch-v3.json'),'imported_indices':sorted(e['segment_index'] for e in imports),'not_launched':True}))
