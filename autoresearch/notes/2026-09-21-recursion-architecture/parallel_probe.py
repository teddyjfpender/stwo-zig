"""Diagnostic sibling-process concurrency; existing qualified binaries, no builds."""
import concurrent.futures, hashlib, json, os, pathlib, statistics, subprocess, time
out=pathlib.Path('/tmp/stwo-recursion-peer-research-20260921/parallel-probe')
out.mkdir(exist_ok=False)
base=pathlib.Path('/tmp/pr198-typed-closure-ladder-20260921-v1/8-metal')
binary=pathlib.Path('/tmp/stwo-recursion-final-metal-20260921/bin/recursive-segment-v2-detached-parent-prove-metal')
sha=lambda p:hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()
receipts=[json.loads((base/f'parent-2-{i}-accepted.json').read_text()) for i in range(2)]
env={k:v for k,v in os.environ.items() if not k.startswith('STWO_')}
env['STWO_RISCV_RECURSIVE_PARENT_PROFILE']='1'
samples=[]
for run,mode in enumerate(['serial','parallel','parallel','serial','serial','parallel']):
 def prove(i):
  argv=receipts[i]['producer']['argv'].copy();argv[0]=str(binary)
  bundle=out/f'{run}-{mode}-{i}';argv[argv.index('--profile')+2]=str(bundle)
  started=time.monotonic_ns()
  with (out/f'{run}-{i}.log').open('w') as log:
   subprocess.run(['/usr/bin/time','-l',*argv],env=env,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=180)
  return {'node':i,'seconds':(time.monotonic_ns()-started)/1e9,'argv':argv,'bundle':str(bundle)}
 started=time.monotonic_ns()
 if mode=='parallel':
  with concurrent.futures.ThreadPoolExecutor(2) as pool: rows=list(pool.map(prove,range(2)))
 else:rows=[prove(i) for i in range(2)]
 elapsed=(time.monotonic_ns()-started)/1e9
 for row in rows:
  i=row['node'];receipt=receipts[i];verify=receipt['cases'][0]['argv'].copy();verify[1]=row['bundle']
  result=subprocess.run(verify,env=env,capture_output=True,text=True,check=True,timeout=60)
  verified=json.loads(result.stdout);assert verified['verified'] and not verified['native_inputs_used']
  expected={name:bytes(receipt['cases'][0]['receipt'][field]).hex() for name,field in [('key.json','key_sha256'),('claims.json','claims_sha256'),('proof.bin','proof_sha256')]}
  actual={name:sha(pathlib.Path(row['bundle'])/name) for name in expected};assert actual==expected
  row.update(verified=True,artifacts=actual,verify_argv=verify)
  (out/f'{run}-{i}.verified.json').write_text(result.stdout)
 samples.append({'mode':mode,'pair_seconds':elapsed,'nodes':rows})
 (out/'samples.json').write_text(json.dumps(samples,indent=2)+'\n')
 print(run,mode,elapsed,'both independently verified, byte identical',flush=True)
medians={mode:statistics.median(r['pair_seconds'] for r in samples if r['mode']==mode) for mode in ['serial','parallel']}
summary={'scope':'diagnostic, three pairs per mode, no warmup, same GPU; no production scheduler qualification','median_pair_seconds':medians,'speedup':medians['serial']/medians['parallel'],'binary_sha256':sha(binary),'receipt_sha256':[sha(base/f'parent-2-{i}-accepted.json') for i in range(2)],'environment':{'STWO_RISCV_RECURSIVE_PARENT_PROFILE':'1'}}
(out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary),flush=True)
