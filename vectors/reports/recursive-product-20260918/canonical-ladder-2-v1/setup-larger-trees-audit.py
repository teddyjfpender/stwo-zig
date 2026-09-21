from pathlib import Path
import json,hashlib,subprocess,sys,os
ROOT=Path.cwd();sys.path.insert(0,str(ROOT/'scripts'))
from zig_serial_build import build_lock
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
count=int(sys.argv[1]);assert count in (2,8)
source=ROOT/f'vectors/reports/riscv-proving-stack-reset-20260908/small-detached-recursion-v1/tree-admissions/q193-{count}.json'
expected_pin={2:'288c1bf7cac43353792c0d30b4aecc451f61b48d2adc93a57941362940de8a5a',8:'6d7bbd731204e18f786543ab69bd43647369e9ec929d699db1cc59a5be302e36'}[count]
assert sha(source)==expected_pin
admission=json.loads(source.read_text())
for node in admission['leaves']+[n for level in admission['parents'] for n in level]:
 for field in ('key','expected'):
  artifact=node[field];p=(source.parent/artifact['path']).resolve();assert sha(p)==artifact['sha256'];artifact['path']=str(p)
out=Path(f'/tmp/pr198-canonical-{count}-setup-20260918-v1');out.mkdir()
bin=Path('/tmp/pr198-product-cpu-leaf-setup-20260918-v1/cpu/bin')
producer=bin/'recursive-segment-v2-concrete-outer-proof';parent=bin/'recursive-segment-v2-detached-parent-prove';verifier=bin/'recursive-segment-v2-detached-parent-verify'
steps=[]
def run(name,args,heavy=False):
 with (out/(name+'.log')).open('x') as log:
  if heavy:
   with build_lock(label='larger-tree-key-setup'):r=subprocess.run(args,stdout=log,stderr=subprocess.STDOUT)
  else:r=subprocess.run(args,stdout=log,stderr=subprocess.STDOUT)
 steps.append({'name':name,'argv':args,'exit_code':r.returncode});(out/'steps.json').write_text(json.dumps(steps,indent=2)+'\n');assert r.returncode==0,(name,out/(name+'.log'))
 print(count,name,'passed',flush=True)
args=[str(producer),'--memory-addresses','1','--segments-output',str(out/'leaves'),'--segment-count',str(count),'--initial-memory-word','13','--proof-profile','recursive_q193_v1','--native-backend','cpu','--recursive-backend','cpu']
for i,node in enumerate(admission['leaves']):args += [f'--child-{i}-key',node['key']['path'],f'--child-{i}-key-sha256',node['key']['sha256']]
run('produce-leaves',args,True)
previous=admission['leaves'];directories=[out/'leaves'/f'child-{i}' for i in range(count)]
for level_index,level in enumerate(admission['parents']):
 root=level_index==len(admission['parents'])-1;nextdirs=[]
 for index,node in enumerate(level):
  name=f'parent-{level_index+1}-{index}';key=out/(name+'-key.json')
  profile=('tiny-parent-root-v2' if root else 'tiny-parent-span-v2') if level_index else ('tiny-memory-root-v2' if root else ('tiny-memory-span-v2' if index==0 else 'tiny-memory-continuation-span-v2'))
  children=previous[2*index:2*index+2];childdirs=directories[2*index:2*index+2]
  args=[str(parent),'derive-key','--profile',profile,str(key)]
  for child,directory in zip(children,childdirs):args += [str(directory),child['key']['sha256'],child['expected']['path']]
  args+=['--proof-profile','recursive_q193_v1'];run(name+'-setup',args,True)
  node['key']={'path':str(key),'sha256':sha(key)}
  # Root setup ends without creating a candidate root. Intermediate proofs are
  # needed to establish the next level, and each is independently verified.
  if root:continue
  bundle=out/name;report=out/(name+'-accepted.json')
  args=['python3',str(ROOT/'scripts/riscv_segment_v2_detached_parent_gate.py'),'--proof-profile','recursive_q193_v1','--producer',str(parent),'--producer-sha256',sha(parent),'--verifier',str(verifier),'--verifier-sha256',sha(verifier),'--bundle',str(bundle),'--parent-key',str(key),'--key-sha256',sha(key),'--expected-root',node['expected']['path'],'--expected-root-sha256',node['expected']['sha256'],'--publication-mode','intermediate','--child-family','parent' if level_index else 'segment','--memory-profile','continuation' if level_index==0 and index>0 else 'initial','--output',str(report)]
  for side,child,directory in zip(('left','right'),children,childdirs):args += ['--'+side,str(directory),child['key']['sha256'],child['expected']['path']]
  run(name+'-qualification',args);assert json.loads(report.read_text())['passed'];nextdirs.append(bundle)
 previous=level;directories=nextdirs
for node in admission['leaves']+[n for level in admission['parents'] for n in level]:
 for field in ('key','expected'):node[field]['path']=os.path.relpath(node[field]['path'],out)
p=out/'admission.json';p.write_text(json.dumps(admission,indent=2)+'\n')
(out/'setup.json').write_text(json.dumps({'source_admission_sha256':expected_pin,'admission_sha256':sha(p),'root_proof_created':False,'intermediate_proofs_created':count-2,'binaries':{str(p):sha(p) for p in (producer,parent,verifier)}},indent=2)+'\n')
print('ADMISSION',p,sha(p),flush=True)
