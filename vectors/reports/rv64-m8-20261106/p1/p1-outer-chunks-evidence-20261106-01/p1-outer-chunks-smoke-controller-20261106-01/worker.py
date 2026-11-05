from pathlib import Path
import os,sys,time,json,subprocess,shutil
root=Path('/workspace/m3/src/m7-integrate');sys.path.insert(0,str(root/'scripts'))
import rv64_m7_integration_stack as S
base=Path('/workspace/m3/runs/m7-integrate')
out=base/'p1-outer-chunks-smoke-controller-20261106-01'
pre=base/'p1-outer-chunks-preflight-20261106-01'
while True:
 d=json.loads((pre/'preflight.json').read_text())
 if d['status']=='UNIT_AND_BUILD_PASS':break
 if d['status']=='FAILED':raise RuntimeError('preflight failed; no GPU request')
 time.sleep(5)
assert S.source_hashes(root)==d['source_sha256']
pinned=Path('/workspace/m3/build/m7-integrate/p1-outer-chunks-v1')
assert S.sha(pinned/'libstwo-outer-chunks.so')=='129959c18fff008a80c5db0459731ca3266b63afff16eb983d94a6d4ef5debab'
for name in ['rv64-word16-ethereum-gpu-combined','rv64-word16-ethereum-recursion-receiver']:
 shutil.copy2(Path('/workspace/m3/build/m7-integrate/zig-out/bin')/name,pinned/name)
old=root/'vectors/reports/rv64-m8-20261106/p1/p1-inter-reuse-v2-smoke-evidence-20261106-02/p1-inter-reuse-preflight-20261106-02/smoke-artifact.json'
m=json.loads(old.read_text());preset=m['preset']
preset['common']['STWO_RV64_RC_OUTER_CHUNKS']='0'
preset['common']['STWO_RV64_RC_OUTER_CHUNKS_LIBRARY']='{outer_chunks}'
preset['arms']['fullstack']['STWO_RV64_RC_OUTER_CHUNKS']='1'
S.write(out/'preset.json',preset)
m.update(source_commit=d['source_commit'],source_sha256=d['source_sha256'],created_utc_ns=time.time_ns(),preset=preset,preset_sha256=S.sha(out/'preset.json'))
m['assets'].update(driver=str(pinned/'rv64-word16-ethereum-gpu-combined'),receiver=str(pinned/'rv64-word16-ethereum-recursion-receiver'),outer_chunks=str(pinned/'libstwo-outer-chunks.so'))
m['asset_sha256']={name:S.sha(path) for name,path in m['assets'].items()}
S.validate_manifest(m);S.write(out/'artifact.json',m)
argv=[sys.executable,str(root/'scripts/rv64_m7_integration_stack.py'),'run','--manifest',str(out/'artifact.json'),'--out',str(base/'p1-outer-chunks-small-20261106-01'),'--smoke','--smoke-seeds','17','--smoke-request-timeout','120']
with (out/'smoke.log').open('w') as log:r=subprocess.run(argv,cwd=root,env=S.clean_environment(os.environ),stdout=log,stderr=subprocess.STDOUT)
(out/'exit').write_text(str(r.returncode)+'\n')
if r.returncode:raise RuntimeError('smoke failed; inspect preserved service')
