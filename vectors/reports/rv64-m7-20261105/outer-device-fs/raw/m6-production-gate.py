#!/usr/bin/env python3
"""Bounded exact prefix replay + actual GPU-derived INTER parameter consumer."""
from pathlib import Path
import hashlib,json,subprocess,sys,re,time
root=Path('/workspace/m3/src/m7-device-fs-p1');out=Path('/workspace/m3/runs/m7-device-fs-p1');out.mkdir(parents=True,exist_ok=True)
sys.path.insert(0,str(root/'scripts'));import rv64_resident_basket as Basket
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
driver='/workspace/m3/build/m7-device-fs-p1/rv64-word16-ethereum-gpu-combined'
addon='/workspace/m3/build/m7-outer-fs-ops/libstwo-rv64-outer-fs-ops.so'
expected={'library':'a25cc3b23ae21994e01cf0e332f1f79b666c402197bc5ed84920bf7575226e45'}
addon_sha='2b94d8c11c157eeea61e071f5ecc8acb81f4d12a70790a1ca878d9ca8130ab7a'
def snap(path,leaves):return {'native':{p.name:sha(p) for p in sorted(path.glob('*.bin'))},'bundle':sha(path/'bundle.json'),'recursive':Basket.recursive_snapshot(path,leaves)}
assert sha(addon)==addon_sha
provenance={'schema':'rv64-m7-outer-device-fs-check/v1','driver':{'path':driver,'sha256':sha(driver)},'addon':{'path':addon,'sha256':addon_sha},'scope':'Exact prefix replay CPU shadow plus actual GPU-derived INTER params; RC/OODS host consumers remain; no full resident FS or performance claim'}
(out/'m6-provenance.json').write_text(json.dumps(provenance,indent=2)+'\n')
for block in [26235156,24628607]:
 reference=Path(f'/workspace/m3/runs/m7-fold-v3/daemon-{block}-r2-combined-m6-v3');base=json.loads((reference/'receipt.json').read_text());plan=json.loads((reference/'plan.json').read_text());assets=plan['assets'];base_snap=snap(Path(base['requests'][0]['proof']),base['requests'][0]['leaves'])
 for key,digest in expected.items():
  if key=='library':assert sha(assets[key])==digest
 tag='outer-device-fs-m6-check';run=out/f'daemon-{block}-r1-{tag}'
 command=[sys.executable,str(root/'scripts/rv64_m4_resident.py'),'daemon',str(block),'--stream','m7-device-fs-p1','--build-stream','m7-device-fs-p1','--repeat','1','--store','none','--receive','first','--tag',tag,'--driver',driver,'--library',assets['library'],'--receiver',assets['receiver'],'--no-default-env']
 env=dict(plan['environment']);env.update(STWO_RV64_PACK_FOLD_CACHE='0',STWO_RV64_OUTER_DEVICE_FS='check',STWO_RV64_OUTER_FS_OPS_LIBRARY=addon)
 for key,value in sorted(env.items()):command+=['--env',key+'='+value]
 (out/f'{block}-m6-command.json').write_text(json.dumps(command,indent=2)+'\n')
 with (out/f'{block}-m6.log').open('w') as log:result=subprocess.run(command,cwd=root,stdout=log,stderr=subprocess.STDOUT,timeout=600)
 if result.returncode:raise SystemExit(f'FAILED block={block} exit={result.returncode}')
 actual=json.loads((run/'receipt.json').read_text());comparisons=[]
 for request in actual['requests']:
  actual_snap=snap(Path(request['proof']),request['leaves']);matches={k:actual_snap[k]==base_snap[k] for k in actual_snap};assert all(matches.values()),matches
  comparisons.append({'trial':request['trial'],'matches':matches,'stages':request['stages'],'proof_bytes_root':request['proof_bytes_root']})
 stderr=(run/'producer.stderr').read_text();lookup=re.findall(r'GPU_OUTER_DEVICE_FS check_ok ordinal=(\d+) class=([0-9a-f]+) leaf=(\w+) phase=lookup_params ops=(\d+) draw_blocks=(\d+)',stderr);prefix=re.findall(r'GPU_OUTER_DEVICE_FS check_ok ordinal=(\d+) class=([0-9a-f]+) leaf=(\w+) phase=before_pcs ops=(\d+) draw_blocks=(\d+)',stderr);consumers=re.findall(r'GPU_OUTER_DEVICE_FS inter_consumed ordinal=(\d+)',stderr)
 n=sum(len(json.loads((Path(r['proof'])/'recursion-om31/pipeline.json').read_text())['nodes']) for r in actual['requests'])
 assert len(lookup)==len(prefix)==len(consumers)==n,(len(lookup),len(prefix),len(consumers),n)
 report={'schema':'rv64-m7-outer-device-fs-case/v1','block':block,'reference':str(reference/'receipt.json'),'receipt':str(run/'receipt.json'),'all_artifacts_byte_identical':True,'proof_comparisons':comparisons,'receivers':actual['receivers'],'lookup_replay':lookup,'full_prefix_replay':prefix,'actual_inter_consumers':len(consumers),'expected_nodes':n,'assets':actual['assets'],'addon':provenance['addon'],'scope':provenance['scope']}
 (out/f'{block}-m6-gate.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report),flush=True)
print('OUTER_DEVICE_FS_M6_CONSUMER_GATE_PASS',flush=True)
