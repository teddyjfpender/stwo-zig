import hashlib,json,os,subprocess,sys
from pathlib import Path
root=Path.cwd();sys.path.insert(0,str(root/'scripts'))
from riscv_segment_v2_detached_gate import records
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
base=root/'vectors/reports/recursive-product-20260918/larger-memory-ladder-qualified-v1';oldproduct=Path('/tmp/pr198-product-metal-typed-closure-20260921-v1');out=Path('/tmp/stwo-recursion-research-20260921')
env={k:v for k,v in os.environ.items() if not k.startswith('STWO_')};env['STWO_ZIG_METAL_REQUIRE_GPU']='0'
# Confirm the exact final rebuilt Metal binary before complete-tree promotion.
subprocess.run([sys.executable,'autoresearch/benchmarks/recursion/parent_pair.py',
 '--receipt','/tmp/pr198-typed-closure-ladder-20260921-v1/8-metal/parent-3-0-accepted.json',
 '--baseline','/tmp/stwo-recursion-baseline-bin-20260921/bin/recursive-segment-v2-detached-parent-prove-metal',
 '--candidate','/tmp/stwo-recursion-final-metal-20260921/bin/recursive-segment-v2-detached-parent-prove-metal',
 '--output',str(out/'final-metal'),'--rounds','3'],check=True)
results={}
for arm in ('baseline','candidate'):
 tree=out/('tree-'+arm);admission=base/'admissions/8.json'
 bins={'leaf-verifier':oldproduct/'cpu/bin/recursive-segment-v2-detached-verify','parent-verifier':oldproduct/'cpu/bin/recursive-segment-v2-detached-parent-verify'}
 if arm=='baseline':
  bins.update({'leaf-producer':Path('/tmp/stwo-recursion-baseline-leaf-20260921/bin/recursive-segment-v2-detached-leaf-prove-metal'),'parent-producer':Path('/tmp/stwo-recursion-baseline-bin-20260921/bin/recursive-segment-v2-detached-parent-prove-metal')})
 else:
  bins.update({role:Path('/tmp/stwo-recursion-final-metal-20260921/bin')/name for role,name in [('leaf-producer','recursive-segment-v2-detached-leaf-prove-metal'),('parent-producer','recursive-segment-v2-detached-parent-prove-metal')]})
 args=[sys.executable,'scripts/riscv_segment_v2_detached_tree_gate.py','--admission',str(admission),'--admission-sha256',sha(admission),'--backend','metal','--output',str(tree)]
 for role,path in bins.items():args+=['--'+role,str(path),'--'+role+'-sha256',sha(path)]
 args+=['--aot-bundle',str(oldproduct/'aot'),'--aot-manifest-sha256',sha(oldproduct/'aot/stwo_zig_core.manifest.json'),'--aot-profile','recursive-framework-v1']
 print(arm,'full eight-segment tree started',flush=True)
 with (out/f'tree-{arm}.log').open('w') as log:subprocess.run(args,env=env,stdout=log,stderr=subprocess.STDOUT,check=True,timeout=600)
 report=json.loads((tree/'report.json').read_text());assert report['passed'] and report['inputs_unchanged']
 qualified=json.loads((base/'8-metal-summary.json').read_text());artifacts={name:sha(tree/name) for name in qualified['artifacts']};assert artifacts==qualified['artifacts']
 text=(tree/'produce-leaves.log').read_text();native=records(text,'SEGMENT_V2_TWO_CHILD_NATIVE_METAL');leaf=records(text,'DETACHED_LEAF_TYPED_DEVICE_INTERACTION');parents=[]
 for log in tree.glob('parent-*-accepted.json.producer.log'):parents.extend(records(log.read_text(),'DETACHED_PARENT_TYPED_DEVICE_INTERACTION'))
 assert len(native)==8 and all(x['table_interaction_dispatches']=='24' for x in native)
 assert len(leaf)==8 and all(x['components']=='36' and x['dispatches']=='144' for x in leaf)
 assert len(parents)==7 and all(x['components']=='29' and x['dispatches']=='116' for x in parents)
 cases=sum(len(json.loads(f.read_text())['cases']) for f in tree.glob('*-accepted.json'))
 results[arm]={'command':args,'cases':cases,'artifacts':artifacts,'leaf_seconds':report['leaf_production_ns']/1e9,'parent_seconds':report['parent_production_ns']/1e9,'complete_gate_seconds':report['complete_gate_ns']/1e9,'passed':True}
 results[arm]['production_seconds']=results[arm]['leaf_seconds']+results[arm]['parent_seconds']
 (out/'tree-summary.json').write_text(json.dumps(results,indent=2)+'\n');print(arm,results[arm]['production_seconds'], 'seconds;',cases,'checks; all qualified artifacts identical',flush=True)
print('single pair only; not a statistical total-tree speedup claim',flush=True)
