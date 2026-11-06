from pathlib import Path
import json,sys,time,subprocess,fcntl,shutil,os,ctypes as C
root=Path('/workspace/m3/src/m7-integrate');sys.path.insert(0,str(root/'scripts'));import rv64_m7_integration_stack as S
b=Path('/workspace/m3/runs/m7-integrate');out=b/'p1-compact-state-smoke-controller-20261106-03';pre=b/'p1-compact-state-preflight-20261106-04'
while True:
 d=json.loads((pre/'preflight.json').read_text())
 if d['status']=='UNIT_ZIG_AND_NATIVE_BUILD_PASS':break
 if d['status']=='FAIL':raise RuntimeError('preflight failed; no GPU work')
 time.sleep(5)
assert S.source_hashes(root)==d['source_sha256']
library=Path(d['library']);pin=library.parent
old=b/'p1-outer-chunks-smoke-controller-20261106-01/artifact.json'
m=json.loads(old.read_text());preset=m['preset'];preset['common']['STWO_RV64_COMPACT_EAGER_STATE']='0';preset['arms']['fullstack']['STWO_RV64_COMPACT_EAGER_STATE']='1'
S.write(out/'preset.json',preset)
m.update(source_commit=d['source_commit'],source_sha256=d['source_sha256'],preset=preset,preset_sha256=S.sha(out/'preset.json'),created_utc_ns=time.time_ns(),native_hooks_commit=d['source_commit'],device_hooks_commit=d['source_commit'])
m['assets'].update(driver=str(pin/'rv64-word16-ethereum-gpu-combined'),receiver=str(pin/'rv64-word16-ethereum-recursion-receiver'),library=str(library))
m['asset_sha256']={k:S.sha(v) for k,v in m['assets'].items()}
S.validate_manifest(m);S.write(out/'artifact.json',m)
run=b/'p1-compact-state-small-20261106-03'
argv=[sys.executable,str(root/'scripts/rv64_m7_integration_stack.py'),'run','--manifest',str(out/'artifact.json'),'--out',str(run),'--smoke','--smoke-seeds','17','--smoke-request-timeout','120']
with (out/'smoke.log').open('w') as log:r=subprocess.run(argv,cwd=root,env=S.clean_environment(os.environ),stdout=log,stderr=subprocess.STDOUT)
assert r.returncode==0,'smoke failure; preserve logs'
e=json.loads((run/'experiment.json').read_text());assert e['status']=='SMOKE_BYTE_PARITY_AND_FRESH_ACCEPTED'
reference=b/'daemon-26235156-r2-p1-outer-chunks-small-20261106-01-one-stack-v5-smoke-00-baseline'
old_receipt=json.loads((reference/'receipt.json').read_text());expected=S.fingerprints(old_receipt['requests'][0],require_capture=True)
for entry in e['services']:
 receipt=json.loads((Path(entry['run'])/'receipt.json').read_text())
 assert all(S.fingerprints(r,require_capture=True)==expected for r in receipt['requests'])
S.write(out/'accepted-reference-parity.json',{'status':'ALL4_FRESH_ACCEPTED_AND_EXACT_TO_PRIOR_ACCEPTED_V2_REFERENCE','reference':str(reference),'whole_smoke':str(run),'scope':'cold/warm native and recursive payloads plus capture SHA256'})
(out/'exit').write_text('0\n')
