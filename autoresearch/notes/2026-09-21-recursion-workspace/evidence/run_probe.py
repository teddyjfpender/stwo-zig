from pathlib import Path
import hashlib,json,os,subprocess,time,re
p=Path('/tmp/stwo-recursion-workspace-probe-20260921')
binary=Path('/tmp/stwo-recursion-workspace-20260921/bin/recursive-segment-v2-detached-parent-prove-metal')
receipt=Path('/tmp/pr198-typed-closure-ladder-20260921-v1/8-metal/parent-3-0-accepted.json')
r=json.loads(receipt.read_bytes());original=r['producer']['argv'];aot=original[1:original.index('--profile')]
sha=lambda x:hashlib.sha256(Path(x).read_bytes()).hexdigest()
args=[str(binary),*aot,'--batch',str(p/'requests.json'),sha(p/'requests.json')]
env={k:v for k,v in os.environ.items() if not k.startswith('STWO_')};env['STWO_RISCV_RECURSIVE_PARENT_PROFILE']='1'
t=time.monotonic_ns()
with (p/'batch.log').open('x') as log:subprocess.run(['/usr/bin/time','-l',*args],env=env,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=240)
elapsed=(time.monotonic_ns()-t)/1e9
report=next(json.loads(line) for line in (p/'batch.log').read_text().splitlines() if line.startswith('{"endpoint":"detached_parent_batch"'))
assert report['requests']==3 and report['plan_builds']==1
expected={f:bytes(r['cases'][0]['receipt'][k]).hex() for f,k in [('key.json','key_sha256'),('claims.json','claims_sha256'),('proof.bin','proof_sha256')]}
for i in range(3):
 bundle=p/f'parent-{i}';verify=r['cases'][0]['argv'].copy();verify[1]=str(bundle)
 result=subprocess.run(verify,env=env,capture_output=True,text=True,check=True,timeout=60)
 v=json.loads(result.stdout);assert v['verified'] and not v['native_inputs_used']
 assert {f:sha(bundle/f) for f in expected}==expected
 (p/f'verified-{i}.json').write_text(result.stdout)
 print('verified identical request',i,flush=True)
summary={'scope':'three sequential identical-parent requests, one persistent runtime/workspace, diagnostic only','process_seconds':elapsed,'batch':report,'producer_sha256':sha(binary),'receipt_sha256':sha(receipt),'argv':args,'expected_artifacts':expected}
(p/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
print('wall_seconds',elapsed,'plans',report['plan_builds'],'request_seconds',[x['request_ns']/1e9 for x in report['reports']],'retained_scratch_bytes',report['retained_scratch_bytes'],flush=True)
