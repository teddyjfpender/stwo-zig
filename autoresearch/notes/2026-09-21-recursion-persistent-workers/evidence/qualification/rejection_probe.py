import hashlib,json,os,select,subprocess
from pathlib import Path
ROOT=Path('/Users/theodorepender/code/cryptography/stwo-zig')
import sys
sys.path.insert(0,str(ROOT/'scripts'))
from zig_serial_build import build_lock
out=Path('/tmp/stwo-recursion-worker-qualification-20260921/rejections');out.mkdir()
r=json.loads(Path('/tmp/pr198-typed-closure-ladder-20260921-v1/8-metal/parent-3-0-accepted.json').read_text())
a=r['producer']['argv'];pos=a.index('--profile');prefix=a[:pos];prefix[0]='/tmp/stwo-recursion-worker-metal-20260921/bin/recursive-segment-v2-detached-parent-prove-metal'
expected={f:bytes(r['cases'][0]['receipt'][k]).hex() for f,k in [('key.json','key_sha256'),('claims.json','claims_sha256'),('proof.bin','proof_sha256')]}
def sha(data):return hashlib.sha256(data).hexdigest()
def manifest(name,requests,session=64<<20):
 p=out/(name+'.json');p.write_text(json.dumps(dict(version=1,session_byte_budget=session,pcs_plan_byte_budget=256<<20,retained_scratch_byte_limit=256<<20,requests=requests))+'\n');return p,sha(p.read_bytes())
env={k:v for k,v in os.environ.items() if not k.startswith('STWO_')}
results=[]
with build_lock(label='persistent-worker-rejection-qualification'):
 for mode,error in [('limits','ParentWorkerLimitsChanged'),('truncated','TruncatedParentWorkerRequest')]:
  request=a[pos:].copy();request[2]=str(out/mode)
  p,pin=manifest(mode+'-request',[request])
  with (out/(mode+'.log')).open('wb') as log:
   process=subprocess.Popen([*prefix,'--worker',str(p),pin],env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=log,start_new_session=True)
   try:
    assert select.select([process.stdout],[],[],120)[0],'no worker response'
    response=process.stdout.readline(1<<20);candidate=json.loads(response);assert candidate['requests']==1
    (out/(mode+'-candidate.json')).write_bytes(response)
    next_request=request.copy();next_request[2]=str(out/(mode+'-should-not-exist'))
    if mode=='limits':
     np,npin=manifest(mode+'-changed',[next_request],session=32<<20)
     message=(json.dumps(dict(path=str(np),sha256=npin))+'\n').encode()
    else: message=b'{"path":'
    stdout,_=process.communicate(input=message,timeout=15)
    assert process.returncode!=0 and not stdout
    assert not Path(next_request[2]).exists()
   finally:
    if process.poll() is None:process.kill();process.wait()
  assert error in (out/(mode+'.log')).read_text()
  verify=r['cases'][0]['argv'].copy();verify[1]=request[2]
  v=subprocess.run(verify,capture_output=True,check=True,timeout=30)
  accepted=json.loads(v.stdout);assert accepted['verified']
  assert {f:sha((Path(request[2])/f).read_bytes()) for f in expected}==expected
  (out/(mode+'-verified.json')).write_bytes(v.stdout)
  results.append(dict(mode=mode,rejected=True,prior_proof_verified=True))
 # Reject a bad manifest pin before producing any response.
 invalid=subprocess.run([*prefix,'--worker',str(p),'0'*64],env=env,capture_output=True,timeout=30)
 assert invalid.returncode!=0 and b'ParentBatchPinMismatch' in invalid.stderr and not invalid.stdout
 (out/'bad-pin.log').write_bytes(invalid.stderr)
 results.append(dict(mode='bad-pin',rejected=True))
(out/'summary.json').write_text(json.dumps(results,indent=2)+'\n')
print(json.dumps(results))
