from pathlib import Path
import hashlib,json,shutil,sys,os,subprocess,time,math
root=Path.cwd();sys.path.insert(0,str(root/'scripts'))
from riscv_recursive_product import source_snapshot
src=Path('/tmp/pr198-typed-final-ladder-20260921-v1')
out=root/'vectors/reports/recursive-product-20260921/typed-recursion-final-qualified-v1'
data=json.loads((src/'summary.json').read_text())
assert data['passed'] and data['total_cases']==1110 and data['identical_cross_backend_artifacts']==78
snapshot=json.loads((src/'source-snapshot.json').read_text())
assert snapshot==json.loads((out/'qualified-source-snapshot.json').read_text())==source_snapshot()
rows=[]
for n in (1,2,4,8):
 for backend in ('cpu','metal'):
  d=json.loads((src/f'{n}-{backend}-summary.json').read_text())
  assert d['passed'] and d['root']['verified']
  assert not d['root']['native_inputs_used']
  m=d['measurements'];receipt=d['root']['child'] if n==1 else d['root']
  tree=src/f'{n}-{backend}'
  tree_report=json.loads((tree/'report.json').read_text())
  leaf_receipts=[]
  for leaf in sorted(tree.glob('leaf-*-accepted.json')):
   accepted=json.loads(leaf.read_text());r=accepted['cases'][0]['receipt'];leaf_receipts.append(r.get('child',r))
  assert len(leaf_receipts)==n
  if n==1:
   gate_argv=next(x['argv'] for x in tree_report['steps'] if x['name']=='verify-leaf-0')
   arg=lambda key:gate_argv[gate_argv.index(key)+1]
   argv=[arg('--verifier'),'--root',arg('--bundle'),arg('--key-sha256'),arg('--expected-wire')]
  else:
   accepted=json.loads((tree/f'parent-{n.bit_length()-1}-0-accepted.json').read_text())
   argv=accepted['cases'][0]['argv']
  log=out/f'root-{n}-{backend}-memory.json'
  started=time.monotonic_ns()
  with log.open('w') as stream:
   process=subprocess.Popen(argv,stdout=stream,stderr=subprocess.STDOUT)
   _,status,usage=os.wait4(process.pid,0)
   process.returncode=os.waitstatus_to_exitcode(status)
  assert process.returncode==0
  measured=json.loads(log.read_text());assert measured['verified'] and not measured['native_inputs_used']
  measured_receipt=measured.get('child',measured)
  assert measured_receipt['proof_sha256']==receipt['proof_sha256']
  direct_ns=sum(r['verify_ns'] for r in leaf_receipts)
  saved_ns=direct_ns-receipt['verify_ns']
  economics={'direct_detached_leaf_verify_ms':direct_ns/1e6,'direct_detached_leaf_proof_bytes':sum(r['proof_bytes'] for r in leaf_receipts),'root_vs_leaf_verify_ratio':direct_ns/receipt['verify_ns'],'parent_production_seconds':m['parent_production_ns']/1e9,'consumer_count_to_amortize_parent_production':math.ceil(m['parent_production_ns']/saved_ns) if saved_ns>0 else None,'root_verifier_peak_rss_bytes':usage.ru_maxrss*(1 if sys.platform=='darwin' else 1024),'root_memory_run_process_ns':time.monotonic_ns()-started,'root_memory_run_argv':argv}
  rows.append({'segments':n,'backend':backend,'production_seconds':(m['leaf_production_ns']+m['parent_production_ns'])/1e9,'peak_rss_bytes':m['maximum_rss_bytes'],'root_proof_bytes':receipt['proof_bytes'],'root_verify_ms':receipt['verify_ns']/1e6,'cases':d['total_cases'],**economics})
  shutil.copyfile(src/f'{n}-{backend}-summary.json',out/f'ladder-{n}-{backend}-summary.json')
shutil.copyfile(src/'summary.json',out/'ladder-summary.json')
(out/'ladder-measurements.json').write_text(json.dumps(rows,indent=2)+'\n')
for name in ('pr198-run-typed-final-ladder-v1.py','pr198-save-typed-final-ladder-v1.py'):
 shutil.copyfile(Path('/tmp')/name,out/name)
print(json.dumps(rows,indent=2),flush=True)
print('Retained final continuation evidence: 1,110 checks and 78 identical artifacts.',flush=True)
