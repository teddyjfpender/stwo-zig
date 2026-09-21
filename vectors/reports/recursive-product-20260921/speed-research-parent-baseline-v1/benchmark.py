from pathlib import Path
import json,os,subprocess,time,hashlib,re,statistics
out=Path('vectors/reports/recursive-product-20260921/speed-research-parent-baseline-v1').resolve()
work=Path('/tmp/pr198-speed-parent-baseline-v1');work.mkdir(exist_ok=False)
env={k:v for k,v in os.environ.items() if not k.startswith('STWO_')};env['STWO_RISCV_RECURSIVE_PARENT_PROFILE']='1';env['STWO_ZIG_METAL_REQUIRE_GPU']='0'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
rows=[]
for i in range(3):
 for backend in ('cpu','metal'):
  tree=Path('/tmp/pr198-typed-closure-ladder-20260921-v1')/('8-'+backend)
  receipt=json.loads((tree/'parent-3-0-accepted.json').read_text())
  argv=receipt['producer']['argv'].copy();idx=argv.index('--profile')+2;candidate=work/f'{backend}-{i}';argv[idx]=str(candidate)
  log=out/f'{backend}-{i}.log';start=time.monotonic_ns()
  with log.open('w') as stream:subprocess.run(argv,env=env,stdout=stream,stderr=subprocess.STDOUT,check=True,timeout=120)
  elapsed=time.monotonic_ns()-start
  verify=receipt['cases'][0]['argv'].copy();verify[1]=str(candidate)
  result=subprocess.run(verify,env=env,text=True,capture_output=True,check=True,timeout=30)
  accepted=json.loads(result.stdout);assert accepted['verified'] and not accepted['native_inputs_used']
  for name in ('key.json','claims.json','proof.bin'):assert sha(candidate/name)==sha(tree/'parent-3-0'/name),name
  (out/f'{backend}-{i}-verified.json').write_text(result.stdout)
  phases=[]
  for line in log.read_text().splitlines():
   if line.startswith('DETACHED_PARENT_'):
    fields=dict(re.findall(r'(\w+)=(\S+)',line));phases.append({'kind':line.split()[0],**fields})
  rows.append({'backend':backend,'sample':i,'process_ns':elapsed,'argv':argv,'binary_sha256':sha(Path(argv[0])),'phases':phases,'verified':True,'baseline_artifacts_identical':True})
  (out/'samples.json').write_text(json.dumps(rows,indent=2)+'\n')
  print(backend,i,round(elapsed/1e9,3),'seconds; verified identical artifacts',flush=True)
summary={b:{'samples':3,'median_process_seconds':statistics.median(x['process_ns'] for x in rows if x['backend']==b)/1e9} for b in ('cpu','metal')}
(out/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary),flush=True)
