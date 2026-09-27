from pathlib import Path
import hashlib,json,os,subprocess
out=Path('/tmp/stwo-recursion-direct-merkle-20260921')
r=json.loads(Path('/tmp/pr198-typed-closure-ladder-20260921-v1/8-metal/parent-3-0-accepted.json').read_text())
a=r['producer']['argv'];a=a[a.index('--profile'):];a[2]=str(out/'cpu-parent')
binary=Path('/tmp/stwo-recursion-direct-merkle-cpu-20260921/bin/recursive-segment-v2-detached-parent-prove')
a=[str(binary),*a]
env={k:v for k,v in os.environ.items() if not k.startswith('STWO_')}
with (out/'cpu-parent.log').open('wb') as log:subprocess.run(a,env=env,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=120)
v=r['cases'][0]['argv'].copy();v[1]=str(out/'cpu-parent')
result=subprocess.run(v,env=env,capture_output=True,check=True,timeout=30)
accepted=json.loads(result.stdout);assert accepted['verified'] and not accepted['native_inputs_used']
expected={f:bytes(r['cases'][0]['receipt'][k]).hex() for f,k in [('key.json','key_sha256'),('claims.json','claims_sha256'),('proof.bin','proof_sha256')]}
assert {f:hashlib.sha256((out/'cpu-parent'/f).read_bytes()).hexdigest() for f in expected}==expected
(out/'cpu-verified.json').write_bytes(result.stdout)
(out/'cpu-qualification.json').write_text(json.dumps(dict(producer_argv=a,verifier_argv=v,producer_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),verified=True,expected=expected),indent=2)+'\n')
print('CPU parent independently verified; qualified key, claims and proof bytes identical.')
