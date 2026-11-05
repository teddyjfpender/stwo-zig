#!/usr/bin/env python3
from pathlib import Path
import hashlib,json,subprocess,sys
root=Path('/workspace/m3/src/m7-device-fs');out=Path('/workspace/m3/runs/m7-device-fs');driver=Path('/workspace/m3/build/m7-device-controller/zig-out/bin/rv64-word16-ethereum-gpu-combined');library=Path('/workspace/m3/build/m7-device-controller/cuda/native/libstwo-rv64-native.so');receiver=Path('/workspace/m3/build/m6-integrate/zig-out/bin/rv64-word16-ethereum-recursion-receiver');sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(driver)=='76b2a5ca7deea679c3df498c50637c985aeed046ca9135e4f7d0cc86bd1cb2f4';assert sha(library)=='116a3658ed4aecb1dff18d56e4a3be62d651411dc845da018a8362830a7590aa'
files=['src/integrations/circuit_cpu/om31/device_prove.zig','src/integrations/riscv_cuda/rv64/outer_source.zig'];j={'schema':'rv64-m7-controller-isolated/v1','label':'M','base_checkpoint':'6c01f0a23','scope':'Explicitlyisolatedblockservicesaftermixedblockcapacityfailure; samefrozendriver/image/fullv3preset. PoolTLSborrowandnative_completionguardincluded. Doesnotqualifymixedblockresidentcapacity.','driver_sha256':sha(driver),'library_sha256':sha(library),'source_delta_sha256':{f:sha(root/f) for f in files}};(out/'controller-isolated-provenance.json').write_text(json.dumps(j,indent=2)+'\n')
for block in [26235156,24628607]:
 for mode in ['1','0']:
  assert sha(driver)==j['driver_sha256'] and sha(library)==j['library_sha256'];assert all(sha(root/f)==h for f,h in j['source_delta_sha256'].items())
  tag='owner-isolated-'+('on' if mode=='1' else 'off');run=out/f'daemon-{block}-r2-{tag}'
  command=[sys.executable,str(root/'scripts/rv64_m4_resident.py'),'daemon',str(block),'--stream','m7-device-fs','--build-stream','m7-device-fs','--repeat','2','--store','none','--receive','first' if mode=='1' else 'none','--nsys','--driver',str(driver),'--library',str(library),'--receiver',str(receiver),'--tag',tag]
  for value in ['STWO_RV64_LEAF_SEED_TAPE=1','STWO_RV64_PACK_FOLD_CACHE=1','STWO_RV64_CPU_COMPACT_INGRESS=1','STWO_RV64_COMPOSITION_ENQUEUE=0','STWO_RV64_BLAKE_SAMPLE_PREFILL=1','STWO_RV64_NVTX=1','STWO_RV64_OUTER_OWNER_CONTROLLER='+mode]:command+=['--env',value]
  (out/f'isolated-{block}-{mode}-command.json').write_text(json.dumps(command,indent=2)+'\n')
  with (out/f'isolated-{block}-{mode}.log').open('w') as log:result=subprocess.run(command,cwd=root,stdout=log,stderr=subprocess.STDOUT)
  if result.returncode:raise SystemExit(f'ISOLATED_BLOCK_FAILURE block={block} controller={mode} exit={result.returncode}')
  subprocess.run([sys.executable,'/workspace/m3/src/m7-admission/vectors/reports/rv64-m7-20261105/admission/raw/compare.py',str(run/'receipt.json'),str(out/f'isolated-{block}-{mode}-parity.json')],check=True)
print('ISOLATED_CONTROLLER_PAIR_PASS')
