from pathlib import Path
import hashlib,json,os,subprocess,time
base=Path('/tmp/stwo-recursion-pcs-cache-20260921/qualification')
receipts=Path('/tmp/pr198-typed-closure-ladder-20260921-v1/8-metal')
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
env={k:v for k,v in os.environ.items() if not k.startswith('STWO_')};env['STWO_RISCV_RECURSIVE_PARENT_PROFILE']='1'
for mode in ['cpu','metal-tree']:
 out=base/mode;out.mkdir()
 paths=[receipts/'parent-3-0-accepted.json']*2 if mode=='cpu' else sorted(receipts.glob('parent-*-accepted.json'))
 rs=[json.loads(p.read_bytes()) for p in paths]
 outputs=[out/f'node-{i}' for i in range(len(rs))]
 original_to_output={r['producer']['argv'][r['producer']['argv'].index('--profile')+2]:str(outputs[i]) for i,r in enumerate(rs)} if mode!='cpu' else {}
 requests=[]
 for i,r in enumerate(rs):
  a=r['producer']['argv'];a=a[a.index('--profile'):].copy();a[2]=str(outputs[i])
  for j in [3,6]:a[j]=original_to_output.get(a[j],a[j])
  requests.append(a)
 manifest={'version':1,'session_byte_budget':67108864,'retained_scratch_byte_limit':268435456,'requests':requests}
 path=out/'requests.json';path.write_text(json.dumps(manifest,indent=2)+'\n')
 if mode=='cpu':
  binary=Path('/tmp/stwo-recursion-pcs-cache-cpu-20260921/bin/recursive-segment-v2-detached-parent-prove');prefix=[]
 else:
  binary=Path('/tmp/stwo-recursion-pcs-cache-metal-20260921/bin/recursive-segment-v2-detached-parent-prove-metal');a=rs[0]['producer']['argv'];prefix=a[1:a.index('--profile')]
 argv=[str(binary),*prefix,'--batch',str(path),sha(path)]
 started=time.monotonic_ns()
 with (out/'batch.log').open('x') as log:subprocess.run(['/usr/bin/time','-l',*argv],env=env,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=300)
 elapsed=(time.monotonic_ns()-started)/1e9
 report=next(json.loads(s) for s in (out/'batch.log').read_text().splitlines() if s.startswith('{"endpoint":"detached_parent_batch"'))
 assert report['requests']==len(rs)
 for i,r in enumerate(rs):
  verify=r['cases'][0]['argv'].copy();verify[1]=str(outputs[i]);v=subprocess.run(verify,env=env,capture_output=True,text=True,check=True,timeout=60)
  parsed=json.loads(v.stdout);assert parsed['verified'] and not parsed['native_inputs_used']
  expected={f:bytes(r['cases'][0]['receipt'][k]).hex() for f,k in [('key.json','key_sha256'),('claims.json','claims_sha256'),('proof.bin','proof_sha256')]}
  assert {f:sha(outputs[i]/f) for f in expected}==expected
  (out/f'verified-{i}.json').write_text(v.stdout)
 summary={'scope':'diagnostic batch with fresh standalone acceptance and qualified byte identity','argv':argv,'producer_sha256':sha(binary),'receipt_sha256':[sha(p) for p in paths],'process_seconds':elapsed,'batch':report}
 (out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n')
 print(mode,'verified',len(rs),'wall_seconds',elapsed,'plan_builds',report['plan_builds'],'pcs_builds',report['pcs_plan_builds'],'pcs_hits',report['pcs_plan_hits'],'pcs_bytes',report['pcs_plan_retained_bytes'],flush=True)
