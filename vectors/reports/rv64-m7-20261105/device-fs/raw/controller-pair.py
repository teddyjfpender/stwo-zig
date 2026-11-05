#!/usr/bin/env python3
from pathlib import Path
import hashlib,json,os,subprocess,sys,time
root=Path('/workspace/m3/src/m7-device-fs');out=Path('/workspace/m3/runs/m7-device-fs');driver=Path('/workspace/m3/build/m7-device-controller/zig-out/bin/rv64-word16-ethereum-gpu-combined');library=Path('/workspace/m3/build/m7-device-controller/cuda/native/libstwo-rv64-native.so');receiver=Path('/workspace/m3/build/m6-integrate/zig-out/bin/rv64-word16-ethereum-recursion-receiver')
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(driver)=='e93af1894f9a8fcc720328f4ccd9d56b89895d58a63632550cf50653b1edb198';assert sha(library)=='116a3658ed4aecb1dff18d56e4a3be62d651411dc845da018a8362830a7590aa'
files=['src/backends/cuda/native/rv64/pcs_native.cu','src/backends/cuda/native/rv64/pcs_native.h','src/backends/cuda/native/rv64/pcs_pipeline.cuh','src/integrations/circuit_cpu/om31/device_prove.zig']+[f'src/integrations/riscv_cuda/rv64/{name}.zig' for name in ['outer_source','outer_fixed','trace_commit','resident_composition','outer_source_main','outer_source_interaction','nvtx_stage']]
provenance={'schema':'rv64-m7-controller-frozen-pair/v1','label':'M','base_commit':'b053aefe2','nvtx_checkpoint':'7a0bf4213','root_nvtx_hooks_from':'7508aca49 (only helper+4stage entryhooks)','driver_sha256':sha(driver),'library_sha256':sha(library),'receiver_sha256':sha(receiver),'source_sha256':{f:sha(root/f) for f in files},'scope':'Samebinary/image and fullv3preset; controller is only configuration delta. Historical87c inherited-cache binary rejected before any fullrequest. Hardnative_done barrier retained. Planner/GKRdisabled.'}
(out/'controller-pair-provenance.json').write_text(json.dumps(provenance,indent=2)+'\n')
common=[sys.executable,str(root/'scripts/rv64_m4_resident.py'),'daemon','26235156','24628607','--stream','m7-device-fs','--build-stream','m7-device-fs','--repeat','2','--store','none','--receive','first','--nsys','--driver',str(driver),'--library',str(library),'--receiver',str(receiver)]
for value in ['STWO_RV64_LEAF_SEED_TAPE=1','STWO_RV64_PACK_FOLD_CACHE=1','STWO_RV64_CPU_COMPACT_INGRESS=1','STWO_RV64_COMPOSITION_ENQUEUE=0','STWO_RV64_BLAKE_SAMPLE_PREFILL=1','STWO_RV64_NVTX=1']:
 common+=['--env',value]
for mode in ([sys.argv[1]] if len(sys.argv)>1 else ['1','0']):
 assert sha(driver)==provenance['driver_sha256'] and sha(library)==provenance['library_sha256']
 assert all(sha(root/f)==h for f,h in provenance['source_sha256'].items())
 tag='owner-controller-'+('on' if mode=='1' else 'off')
 command=common+['--tag',tag,'--env','STWO_RV64_OUTER_OWNER_CONTROLLER='+mode]
 (out/(tag+'-command.json')).write_text(json.dumps(command,indent=2)+'\n')
 with (out/(tag+'.log')).open('w') as log:
  result=subprocess.run(command,cwd=root,stdout=log,stderr=subprocess.STDOUT)
 if result.returncode:raise SystemExit(f'{tag}: producer/receiver failed {result.returncode}')
 run=out/f'daemon-26235156-24628607-r2-{tag}'
 subprocess.run([sys.executable,'/workspace/m3/src/m7-admission/vectors/reports/rv64-m7-20261105/admission/raw/compare.py',str(run/'receipt.json'),str(out/(tag+'-parity.json'))],check=True)
print('CONTROLLER_FROZEN_PAIR_PASS')
