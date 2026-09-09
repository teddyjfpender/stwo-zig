from pathlib import Path
import datetime,hashlib,json,os,subprocess,time
repo=Path.cwd();out=repo/'.git/local-ethereum/retained-campaign-v2-rw-heap-121x2097152-20260907/metal-field5-block-v2'
planpath=out/'prepared-launch-v3.json';plan=json.loads(planpath.read_text());snapshot=Path(plan['cwd'])
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def ident(p):return {'path':str(p),'bytes':p.stat().st_size,'sha256':sha(p)}
for kind in ('prover','verifier'):
 if ident(Path(plan[kind]['path']))!=plan[kind]:raise SystemExit(kind+' pin differs')
for entry in plan['controller_sources']:
 p=snapshot/entry['path']
 if sha(p)!=entry['sha256'] or p.stat().st_size!=entry['bytes']:raise SystemExit('controller pin differs: '+entry['path'])
if sha(snapshot/'source-manifest.json')!=plan['source_manifest_sha256']:raise SystemExit('controller manifest differs')
for entry in plan['aot_files']:
 if ident(Path(entry['path']))!=entry:raise SystemExit('AOT pin differs')
imports=json.loads((out/'import-accounting-v1.json').read_text())['imports']
if [e['segment_index'] for e in imports]!=[*range(12),120]:raise SystemExit('import inventory differs')
for entry in imports:
 p=out/(entry['proof']['sha256']+'.bin')
 if p.stat().st_size!=entry['proof']['bytes'] or sha(p)!=entry['proof']['sha256']:raise SystemExit('import proof pin differs')
 for origin in entry['provenance']:
  if ident(Path(origin['path']))!=origin:raise SystemExit('import provenance differs')
if not json.loads((repo/'.git/local-ethereum/selected-real-metal-leaf11-log18-fresh-v2/receipt.json').read_text())['passed']:raise SystemExit('real11 fresh verifier did not pass')
env=os.environ.copy();env.update(plan['environment']);started=time.monotonic_ns()
with (out/'controller-stdout-v1.log').open('xb') as stdout,(out/'controller-stderr-v1.log').open('xb') as stderr:
 child=subprocess.Popen(plan['argv'],cwd=snapshot,env=env,stdout=stdout,stderr=stderr)
 launch={'schema':'stwo.ethereum.native-campaign-launch.v1','pid':child.pid,'started_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'plan':ident(planpath),'imports_preserved_without_reproof':list(e['segment_index'] for e in imports),'required':'Fresh verification of imports followed by all121 segments and independent whole bundle coverage/continuation verification'}
 with (out/'controller-launch-v1.json').open('x') as f:json.dump(launch,f,indent=2);f.write('\n')
 print(json.dumps(launch),flush=True);code=child.wait()
terminal={'exit_code':code,'pid':child.pid,'wall_ns_including_child_lock_waits':time.monotonic_ns()-started,'finished_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'stdout':ident(out/'controller-stdout-v1.log'),'stderr':ident(out/'controller-stderr-v1.log'),'accepted_leaf_records':sorted(int(p.stem.removeprefix('leaf-')) for p in out.glob('leaf-*.json'))}
with (out/'controller-terminal-v1.json').open('x') as f:json.dump(terminal,f,indent=2);f.write('\n')
print(json.dumps(terminal),flush=True);raise SystemExit(code)
