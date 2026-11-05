from pathlib import Path
import json,time,subprocess,sys,os
root=Path('/workspace/m3/src/m7-integrate');sys.path.insert(0,str(root/'scripts'))
import rv64_m7_integration_stack as S
import rv64_m4_resident as R
b=Path('/workspace/m3/runs/m7-integrate');out=b/'p1-outer-chunks-profile-20261106-01'
primary=b/'p1-outer-chunks-headline-20261106-01'
gate=b/'p1-outer-chunks-gate-20261106-01/gate.json'
record={'status':'WAITING_PRIMARY_FRESH_ACCEPTANCE_AND_GATE','services':[]}
S.write(out/'experiment.json',record)
while True:
 p=json.loads((primary/'experiment.json').read_text())
 g=json.loads(gate.read_text()) if gate.exists() else {}
 if g.get('status')=='FAIL':raise RuntimeError('gate failed; no profile launched')
 if p.get('status')=='TIMED_BYTE_PARITY_AND_FRESH_ACCEPTED_METRICS_AUDIT_PENDING' and g.get('status')=='PASS':break
 if any(s.get('exit_code',0) not in (None,0) for s in p.get('services',[])):raise RuntimeError('primary service failed')
 time.sleep(5)
m=json.loads((primary/'artifact.json').read_text());S.validate_manifest(m);S.write(out/'artifact.json',m)
reference=json.loads((Path(p['services'][0]['run'])/'receipt.json').read_text())['requests'][0]
fingerprints=S.fingerprints(reference)
record.update(status='PROFILE_PAIR_RUNNING',primary=str(primary),gate=str(gate));S.write(out/'experiment.json',record)
try:
 for i,arm in enumerate(['baseline','fullstack'],6):
  S.validate_manifest(m)
  argv,tag=S.command(m,arm,i,root.name,True,out.name)
  argv+=['--request-timeout','180']
  run=b/f'daemon-24628607-r2-{tag}'
  item={'arm':arm,'run':str(run),'argv':argv};record['services'].append(item);S.write(out/'experiment.json',record)
  with (out/(arm+'.log')).open('w') as log:item['exit_code']=subprocess.run(argv,cwd=root,env=S.clean_environment(os.environ),stdout=log,stderr=subprocess.STDOUT).returncode
  S.write(out/'experiment.json',record)
  assert item['exit_code']==0,'profile failed or watchdog; preserve incomplete capture'
  receipt=json.loads((run/'receipt.json').read_text());assert len(receipt['requests'])==2
  assert all(S.fingerprints(r)==fingerprints for r in receipt['requests'])
  item['payload_byte_parity']=True;S.write(out/'experiment.json',record)
 for item in record['services']:
  run=Path(item['run']);item['fresh_receivers']=R.receive_run(run,'all',16)
  assert len(item['fresh_receivers'])==2 and all(x['accepted'] for x in item['fresh_receivers'])
  for name,argv in [('gpu-seconds',[sys.executable,str(root/'scripts/rv64_m7_gpu_seconds.py'),str(run),'--accepted-run',str(run)]),('after-native',[sys.executable,str(root/'scripts/rv64_m7_native_ownership.py'),str(run),'--phase','after-native','--output',str(run/'after-native-ownership.json')]),('capture-native',[sys.executable,str(root/'scripts/rv64_m7_native_ownership.py'),str(run),'--phase','capture-native','--output',str(run/'capture-native-ownership.json')])]:
   with (out/(item['arm']+'-'+name+'.log')).open('w') as log:r=subprocess.run(argv,cwd=root,env=S.clean_environment(os.environ),stdout=log,stderr=subprocess.STDOUT)
   assert r.returncode==0,name
  S.write(out/'experiment.json',record)
 record['status']='PROFILE_PAIR_EXACT_FRESH_ACCEPTED_RAW_METRICS_PENDING_INTEGRITY_AUDIT'
except BaseException as e:record.update(status='PROFILE_FAILED',error=str(e));raise
finally:S.write(out/'experiment.json',record)
