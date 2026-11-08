#!/usr/bin/env python3
from pathlib import Path
import hashlib,json,os,subprocess,sys,time
root=Path('/workspace/m3/src/m7-q102-953');out=Path('/workspace/m3/runs/m7-q102');out.mkdir(exist_ok=True)
driver=Path('/workspace/m3/build/m7-q102/zig-out/bin/rv64-word16-ethereum-gpu-combined')
receiver=Path('/workspace/m3/build/m7-q102/zig-out/bin/rv64-word16-ethereum-recursion-receiver')
library=Path('/workspace/m3/build/m7-combined-residency/cuda/native/libstwo-rv64-native.so')
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
assert sha(library)=='a25cc3b23ae21994e01cf0e332f1f79b666c402197bc5ed84920bf7575226e45'
preset=['CUDA_MODULE_LOADING=EAGER','CUDA_VISIBLE_DEVICES=0,1','STWO_RV64_BLAKE_SAMPLE_PREFILL=1','STWO_RV64_COMPOSITION_ENQUEUE=1','STWO_RV64_CORE_SINGLE_STREAM=1','STWO_RV64_CPU_COMPACT_INGRESS=1','STWO_RV64_DEVICE_ARENA=auto','STWO_RV64_GPU_CPU_REPLAY=1','STWO_RV64_GPU_DEVICES=0,1','STWO_RV64_GPU_DEVICE_BINDING=1','STWO_RV64_GPU_DEVICE_CAPS=30064771072,30064771072','STWO_RV64_GPU_DEVICE_TRACE=1','STWO_RV64_GPU_PLANNED_CPU_WORKERS=4','STWO_RV64_GPU_RETAINED_SCOPES=64','STWO_RV64_LEAF_SEED_TAPE=1','STWO_RV64_NVTX=1','STWO_RV64_OUTER_ASSIGNMENT_GRAPH=1','STWO_RV64_OUTER_ASSIGNMENT_NARROW_RUNS=1','STWO_RV64_OUTER_OWNER_CONTROLLER=1','STWO_RV64_PACK_FOLD_CACHE=1','STWO_RV64_PCS_ROLLING_BETA2=1','STWO_RV64_PHASE_CACHE_TRIM=1','STWO_RV64_RC_ROLE_WORKSPACE=0','STWO_ZIG_RV64_SETUP_CACHE=']
profiles={'q108-control':'m6_outer_diet_k4_cap3_r1_b2_q108_p20_fold4_v1','q102-p26':'m7_outer_diet_k4_cap3_r1_b2_q102_p26_fold4_v1'}
files=['src/integrations/circuit_cpu/om31/protocol.zig','src/integrations/riscv_cpu/word16_execution/om31_security_candidate.zig','src/integrations/riscv_cuda/rv64/pcs_native.zig','src/integrations/riscv_cpu/rv64_recursion/om31_native/execution_wrap.zig']
j={'schema':'rv64-m7-q102-production-gate/v1','source_base':'9531c5c16','patch':'5ac430fb8 PROFILE HUNKS ONLY; MC observer formatting/implementation hunk excluded','source_sha256':{f:sha(root/f) for f in files},'driver_sha256':sha(driver),'receiver_sha256':sha(receiver),'library_sha256':sha(library),'preset':preset,'profiles':profiles,'runs':[]}
def save(): (out/'production-gate.json').write_text(json.dumps(j,indent=2)+'\n')
save()
env={k:v for k,v in os.environ.items() if not k.startswith(('STWO_RV64_','STWO_ZIG_RV64_SETUP'))}
for block in (26235156,24628607):
 for label,profile in profiles.items():
  assert sha(driver)==j['driver_sha256'] and sha(receiver)==j['receiver_sha256'] and sha(library)==j['library_sha256']
  assert all(sha(root/f)==h for f,h in j['source_sha256'].items())
  tag=label+'-v1';run=Path('/workspace/m3/runs/m7-q102-953')/f'daemon-{block}-r2-{tag}'
  cmd=[sys.executable,str(root/'scripts/rv64_m4_resident.py'),'daemon',str(block),'--stream','m7-q102-953','--build-stream','m7-q102','--repeat','2','--store','none','--receive','first','--security-profile','d2_native_b4_q54_p20_fold4','--coalesce-truth-families','--driver',str(driver),'--library',str(library),'--receiver',str(receiver),'--tag',tag,'--no-default-env']
  for flag in preset+['STWO_RV64_OUTER_PROFILE='+profile]: cmd+=['--env',flag]
  (out/f'{block}-{label}-command.json').write_text(json.dumps(cmd,indent=2)+'\n')
  with (out/f'{block}-{label}.log').open('w') as log: rc=subprocess.run(cmd,cwd=root,env=env,stdout=log,stderr=subprocess.STDOUT).returncode
  entry={'block':block,'label':label,'profile':profile,'run':str(run),'exit':rc};j['runs'].append(entry);save()
  if rc:raise SystemExit(f'Q102_GATE_FAILURE block={block} profile={profile} exit={rc}')
  receipt=json.loads((run/'receipt.json').read_text());assert receipt['receivers'] and all(x['accepted'] for x in receipt['receivers'])
  entry['fresh_receiver_accepted']=True;save()
print('Q102_PAIRED_BOTH_DEV_PASS')
