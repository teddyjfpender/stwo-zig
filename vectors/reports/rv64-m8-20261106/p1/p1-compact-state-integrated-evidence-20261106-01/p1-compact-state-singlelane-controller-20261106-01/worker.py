from pathlib import Path
import json,sys,os,subprocess,time
root=Path('/workspace/m3/src/m7-integrate');sys.path.insert(0,str(root/'scripts'));import rv64_m7_integration_stack as S
b=Path('/workspace/m3/runs/m7-integrate');out=b/'p1-compact-state-singlelane-controller-20261106-01'
m=json.loads((b/'p1-compact-state-smoke-controller-20261106-04/artifact.json').read_text());S.validate_manifest(m)
m['preset']['arms']['fullstack']['STWO_RV64_RECURSION_LANES_PER_DEVICE']='1'
m['preset']['operational']['fullstack']['recursion_max_pending_authorities']=17
m['scope']='Single-lane correctness diagnostic only. Keep22GiB arena, global admission, sessions, sparse, all4 P1 feature flags and physical guard; change only lane count/pending floor. Does not repair or replace failed intended2-lane small run. No timing or P1 qualification.'
S.write(out/'preset.json',m['preset']);m['preset_sha256']=S.sha(out/'preset.json');m['created_utc_ns']=time.time_ns();S.write(out/'artifact.json',m)
reference=b/'daemon-26235156-r2-p1-compact-state-small-20261106-04-one-stack-v5-smoke-00-baseline'
argv=[sys.executable,str(root/'scripts/rv64_m7_integration_stack.py'),'run','--manifest',str(out/'artifact.json'),'--out',str(b/'p1-compact-state-singlelane-correctness-20261106-01'),'--smoke','--reference-run',str(reference),'--smoke-seeds','17','--smoke-request-timeout','120']
with (out/'smoke.log').open('w') as log:r=subprocess.run(argv,cwd=root,env=S.clean_environment(os.environ),stdout=log,stderr=subprocess.STDOUT)
assert r.returncode==0,'diagnostic failed; preserve and do not retry schedule'
(out/'exit').write_text('0\n')
