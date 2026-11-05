from pathlib import Path
import json,time,os,shutil,hashlib
base=Path('/workspace/m3/runs/m7-integrate');control=base/'p1-outer-chunks-post-abort-20261106-01'
while True:
 d=json.loads((control/'validation.json').read_text())
 if d['status']=='ALL10_COMPLETED_PROOFS_FRESH_CPU_ACCEPTED_HEADLINE_FAILURE_REMAINS':break
 if (control/'exit').exists() and (control/'exit').read_text().strip()!='0':raise RuntimeError('validation failed; no success archive')
 time.sleep(5)
out=base/'p1-outer-chunks-evidence-20261106-01';out.mkdir(exist_ok=False)
names=['p1-outer-chunks-preflight-20261106-01','p1-outer-chunks-smoke-controller-20261106-01','p1-outer-chunks-small-20261106-01','p1-outer-chunks-headline-controller-20261106-01','p1-outer-chunks-headline-20261106-01','p1-outer-chunks-gate-controller-20261106-01','p1-outer-chunks-profile-20261106-01','p1-outer-chunks-post-abort-20261106-01']
services=[]
for name in ['p1-outer-chunks-small-20261106-01','p1-outer-chunks-headline-20261106-01']:
 services.extend(Path(x['run']) for x in json.loads((base/name/'experiment.json').read_text())['services'])
for source in [*(base/name for name in names),*services]:
 for root,dirs,files in os.walk(source,followlinks=False):
  dirs[:]=[n for n in dirs if not (Path(root)/n).is_symlink()]
  for name in files:
   p=Path(root)/name
   if p.is_symlink() or p.suffix in ('.bin','.proof'):continue
   target=out/p.relative_to(base);target.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,target)
source_root=Path('/workspace/m3/src/m7-integrate')
for name in ['rv64/outer_chunks_aot.zig','rv64/outer_chunks_runtime.zig','rv64/outer_source.zig','rv64/resident_composition.zig','rv64_joined_fixture_main.zig']:
 p=source_root/'src/integrations/riscv_cuda'/name;t=out/'source'/name;t.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,t)
files=[{'path':str(p.relative_to(out)),'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for p in out.rglob('*') if p.is_file()]
(out/'index.json').write_text(json.dumps({'status':'ALL14_COMPLETED_SMALL_AND_HEADLINE_PROOFS_FRESH_ACCEPTED_CANONICAL_HEADLINE_FAILED','files':files,'payloads':'Binary proof payloads remain on pod; all logs, source manifests, fingerprints, fresh receiver outputs and failed-request metadata retained.'},indent=2)+'\n')
(control/'export.json').write_text(json.dumps({'status':'EXPORTED','path':str(out),'files':len(files),'bytes':sum(x['bytes'] for x in files)},indent=2)+'\n')
