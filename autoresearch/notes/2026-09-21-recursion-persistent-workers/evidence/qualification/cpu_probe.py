import hashlib,json,os,sys
from pathlib import Path
ROOT=Path('/Users/theodorepender/code/cryptography/stwo-zig')
sys.path.insert(0,str(ROOT/'scripts'))
from recursive_proof_scheduler import Job,execute
from recursive_proof_worker_pool import ProducerPool
from zig_serial_build import build_lock
out=Path('/tmp/stwo-recursion-worker-qualification-20260921/cpu')
out.mkdir()
r=json.loads(Path('/tmp/pr198-typed-closure-ladder-20260921-v1/8-metal/parent-3-0-accepted.json').read_text())
a=r['producer']['argv'];a=a[a.index('--profile'):]
producer=Path('/tmp/stwo-recursion-worker-cpu-20260921/bin/recursive-segment-v2-detached-parent-prove')
expected={f:bytes(r['cases'][0]['receipt'][k]).hex() for f,k in [('key.json','key_sha256'),('claims.json','claims_sha256'),('proof.bin','proof_sha256')]}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
report=dict(producer_sha256=sha(producer),expected=expected)
jobs=[]
for i in range(2):
    request=a.copy();request[2]=str(out/f'parent-{i}')
    verify=r['cases'][0]['argv'].copy();verify[1]=request[2]
    jobs.append(Job(f'parent-{i}',() if i==0 else ('parent-0',),(tuple([str(producer),*request]),tuple(verify)),8000000000))
def admit(job,logs):
    v=json.loads(logs[-1].read_text());assert v['verified']
    assert {f:sha(out/job.name/f) for f in expected}==expected
pool=ProducerPool(out/'workers',1)
try:
    with build_lock(label='persistent-cpu-worker-qualification'):
        execute(jobs,out/'logs',workers=1,memory_bytes=8000000000,timeout=120,env={k:v for k,v in os.environ.items() if not k.startswith('STWO_')},admit=admit,report=report,producer_pool=pool)
finally:
    pool.close(failed=True)
    (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(dict(passed=report['passed'],wall_seconds=report['wall_ns']/1e9)))
