#!/usr/bin/env python3
from pathlib import Path
import hashlib,json,subprocess,sys
root=Path('/workspace/m3/src/m7-rc-workspace');out=Path('/workspace/m3/runs/m7-rc-workspace');out.mkdir(parents=True,exist_ok=True);driver=Path('/workspace/m3/build/m7-rc-workspace/rv64-word16-ethereum-gpu-combined');library=Path('/workspace/m3/build/m7-controller-graphs/cuda/native/libstwo-rv64-native.so');receiver=Path('/workspace/m3/build/m6-integrate/zig-out/bin/rv64-word16-ethereum-recursion-receiver');sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
build=json.loads(Path('/workspace/m3/runs/m7-device-fs/rc-driver-build.json').read_text());assert build['exit_code']==0;assert sha(driver)==build['driver_sha256'];assert sha(library)=='69f18a25c23c042b7fc00d2477097de64c69ea59fd46d2eee6fc9e154dc665e0'
provenance={'schema':'rv64-m7-rc-workspace-production/v1','label':'M','scope':'IsolatedservicefunctionalRCgate; controllerON, graphOFF due wrappernegative, GKROFF/plannerOFF. Onlyroleworkspace/enqueueflag vary. No mixedblockcapacity claim.','driver_sha256':sha(driver),'library_sha256':sha(library),'source_sha256':build['source_sha256'],'build_receipt':build}
(out/'provenance.json').write_text(json.dumps(provenance,indent=2)+'\n')
cases=[(26235156,'1','0',True,False),(24628607,'1','0',True,True),(24628607,'0','0',False,True),(26235156,'1','1',False,False),(24628607,'1','1',False,False)]
for block,workspace,enqueue,receive,nsys in cases:
 assert sha(driver)==provenance['driver_sha256'] and sha(library)==provenance['library_sha256'];assert all(sha(root/f)==h for f,h in build['source_sha256'].items())
 tag=f'rc-role-{workspace}-enqueue-{enqueue}';run=out/f'daemon-{block}-r2-{tag}'
 command=[sys.executable,str(root/'scripts/rv64_m4_resident.py'),'daemon',str(block),'--stream','m7-rc-workspace','--build-stream','m7-rc-workspace','--repeat','2','--store','none','--receive','first' if receive else 'none','--driver',str(driver),'--library',str(library),'--receiver',str(receiver),'--tag',tag]
 if nsys:command+=['--nsys']
 for value in ['STWO_RV64_LEAF_SEED_TAPE=1','STWO_RV64_PACK_FOLD_CACHE=1','STWO_RV64_CPU_COMPACT_INGRESS=1','STWO_RV64_BLAKE_SAMPLE_PREFILL=1','STWO_RV64_NVTX=1','STWO_RV64_OUTER_OWNER_CONTROLLER=1','STWO_RV64_OUTER_ASSIGNMENT_GRAPH=0','STWO_RV64_COMPOSITION_ENQUEUE='+enqueue,'STWO_RV64_RC_ROLE_WORKSPACE='+workspace]:command+=['--env',value]
 (out/f'{block}-{workspace}-{enqueue}-command.json').write_text(json.dumps(command,indent=2)+'\n')
 with (out/f'{block}-{workspace}-{enqueue}.log').open('w') as log:result=subprocess.run(command,cwd=root,stdout=log,stderr=subprocess.STDOUT)
 if result.returncode:raise SystemExit(f'RC_FUNCTIONAL_FAILURE block={block} workspace={workspace} enqueue={enqueue} exit={result.returncode}')
 stderr=(run/'producer.stderr').read_text();admitted=stderr.count('GPU_RC_WORKSPACE_ADMITTED');refused=stderr.count('GPU_RC_WORKSPACE_REFUSED');assert not refused
 if workspace=='1':assert admitted>0,'requestedworkspaceinactive'
 else:assert admitted==0,'workspaceOFFnotrespected'
 subprocess.run([sys.executable,str(root/'vectors/reports/rv64-m7-20261105/admission/raw/compare.py'),str(run/'receipt.json'),str(out/f'{block}-{workspace}-{enqueue}-parity.json')],check=True)
 print(json.dumps({'block':block,'workspace':workspace,'enqueue':enqueue,'admitted_callbacks':admitted,'receipt':str(run/'receipt.json')}),flush=True)
print('RC_WORKSPACE_PRODUCTION_GATE_PASS')
