from pathlib import Path
import json,hashlib,subprocess,sys,os
root=Path.cwd();sys.path.insert(0,str(root/'scripts'))
from riscv_recursive_product import source_snapshot
from riscv_segment_v2_detached_gate import records
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
base=root/'vectors/reports/recursive-product-20260918/larger-memory-ladder-qualified-v1'
out=Path('/tmp/pr198-typed-closure-ladder-20260921-v1');out.mkdir(exist_ok=False)
products={b:Path('/tmp/pr198-product-'+b+'-typed-closure-20260921-v1') for b in ['cpu','metal']}
snapshot=source_snapshot();reports={};total=0
for p in products.values():
 d=json.loads((p/'product.json').read_text());assert d['passed'];assert d['source_sha256']==snapshot
(out/'source-snapshot.json').write_text(json.dumps(snapshot,indent=2)+'\n')
env=dict(os.environ);env['STWO_ZIG_METAL_REQUIRE_GPU']='0'
for n in [1,2,4,8]:
 for b in ['cpu','metal']:
  assert source_snapshot()==snapshot
  p=products[b];admission=base/f'admissions/{n}.json';other=base/f'admissions/{n}-seed14-inputs.json';tree=out/f'{n}-{b}'
  bins={'leaf-verifier':p/'cpu/bin/recursive-segment-v2-detached-verify','parent-verifier':p/'cpu/bin/recursive-segment-v2-detached-parent-verify','leaf-producer':p/b/('bin/recursive-segment-v2-detached-leaf-prove'+('-metal' if b=='metal' else '')),'parent-producer':p/b/('bin/recursive-segment-v2-detached-parent-prove'+('-metal' if b=='metal' else ''))}
  args=[sys.executable,'scripts/riscv_segment_v2_detached_tree_gate.py','--admission',str(admission),'--admission-sha256',sha(admission),'--backend',b,'--output',str(tree)]
  for role,path in bins.items():args+=['--'+role,str(path),'--'+role+'-sha256',sha(path)]
  if b=='metal':args+=['--aot-bundle',str(p/'aot'),'--aot-manifest-sha256',sha(p/'aot/stwo_zig_core.manifest.json'),'--aot-profile','recursive-framework-v1']
  print(f'{n}-{b}: complete tree started',flush=True)
  with (out/f'{n}-{b}.log').open('w') as log:subprocess.run(args,env=env,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=1800)
  substitution=out/f'{n}-{b}-substitution.json'
  sub=[sys.executable,'scripts/riscv_segment_v2_statement_substitution.py','--admission',str(admission),'--admission-sha256',sha(admission),'--other-inputs',str(other),'--other-inputs-sha256',sha(other),'--tree',str(tree),'--output',str(substitution)]
  for role in ['leaf-verifier','parent-verifier']:sub+=['--'+role,str(bins[role]),'--'+role+'-sha256',sha(bins[role])]
  with (out/f'{n}-{b}-substitution.log').open('w') as log:subprocess.run(sub,env=env,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=300)
  d=json.loads((tree/'report.json').read_text());assert d['passed'];s=json.loads(substitution.read_text());assert s['passed']
  old=json.loads((base/f'{n}-{b}-summary.json').read_text());artifacts={name:sha(tree/name) for name in old['artifacts']};assert artifacts==old['artifacts']
  cases=sum(len(json.loads(f.read_text())['cases']) for f in tree.glob('*-accepted.json'))+len(s['cases']);assert cases==old['total_cases'];total+=cases
  device={}
  if b=='metal':
   text=(tree/'produce-leaves.log').read_text();native=records(text,'SEGMENT_V2_TWO_CHILD_NATIVE_METAL');leaf=records(text,'DETACHED_LEAF_TYPED_DEVICE_INTERACTION');parent=[]
   for f in tree.glob('parent-*-accepted.json.producer.log'):parent.extend(records(f.read_text(),'DETACHED_PARENT_TYPED_DEVICE_INTERACTION'))
   assert len(native)==n and all(x['table_interaction_dispatches']=='24' for x in native)
   assert len(leaf)==n and all(x['components']=='36' and x['inactive_zero_components']=='1' and x['dispatches']=='144' for x in leaf)
   assert len(parent)==n-1 and all(x['components']=='29' and x['dispatches']=='116' for x in parent)
   device={'native_dispatches':n*24,'leaf_typed_dispatches':n*144,'parent_typed_dispatches':(n-1)*116}
  summary={'passed':True,'segments':n,'backend':b,'total_cases':cases,'artifacts':artifacts,'admission_sha256':sha(admission),'alternate_inputs_sha256':sha(other),'tree_command':args,'substitution_command':sub,'device':device,'root':d['root'],'local_tree':str(tree),'measurements':{k:d[k] for k in ['leaf_production_ns','parent_production_ns','maximum_rss_bytes']}}
  reports[f'{n}-{b}']=summary;(out/f'{n}-{b}-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
  print(f'{n}-{b}: passed {cases} checks, baseline artifacts identical',flush=True)
 assert reports[f'{n}-cpu']['artifacts']==reports[f'{n}-metal']['artifacts']
assert total==1110 and source_snapshot()==snapshot
(out/'summary.json').write_text(json.dumps({'passed':True,'total_cases':total,'identical_cross_backend_artifacts':78,'production_security_qualified':False,'reports':reports},indent=2)+'\n')
print('Ladder passed: 1110 checks, 78 baseline-identical artifacts.',flush=True)


