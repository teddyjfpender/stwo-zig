import os,json,pathlib,fcntl,subprocess,time,hashlib
base='/tmp/rv64-final-om-fri-v1/rv64-word16-ethereum-gkr';new='/private/tmp/stwo-rv64-gkr-stream-dense-upper/zig-out/bin/rv64-word16-ethereum-gkr';cfg='/tmp/stwo-rv64-ethereum-round5-native-jobs-v1/request.json';jobs='/tmp/stwo-rv64-ethereum-round5-native-jobs-v1/jobs';resource='/tmp/rv64-om-fri-cpu0-candidate-resource.json'
r=json.load(open('/tmp/rv64-final-source-configs/candidate-k18.json'));r['defer_local_binding']=True;pathlib.Path(resource).write_text(json.dumps(r,indent=2)+'\n');records=[];expected=None
with open('/private/tmp/stwo-rv64-perf-heavy.lock','a+') as lock:
 fcntl.flock(lock,fcntl.LOCK_EX);print('locked',time.time(),flush=True)
 for kind,exe in [('a0',base),('b0',new),('b1',new),('a1',base)]:
  out=f'/tmp/stwo-rv64-om-blocked-finalizer-cpu0-{kind}-v1';log=f'/tmp/rv64-om-blocked-finalizer-cpu0-{kind}.log';env=os.environ.copy()
  for k in ['STWO_ZIG_GKR_TREE_CHECKPOINTS','STWO_ZIG_GKR_TIGHT_ADMISSION']:env.pop(k,None)
  env['STWO_ZIG_GKR_STREAM_BOTTOM']='1'
  for k in ['STWO_ZIG_PROFILE_OM_FRI','STWO_ZIG_PROFILE_WIDE_QUOTIENT']:env.pop(k,None)
  start=time.time();print('start',kind,start,flush=True)
  with open(log,'w') as f:rc=subprocess.run(['/usr/bin/time','-l',exe,'produce-candidate',cfg,jobs,out,'1',resource],env=env,stdout=f,stderr=subprocess.STDOUT).returncode
  if rc:raise RuntimeError((kind,rc))
  with open(log+'.fresh','w') as f:rc=subprocess.run(['/usr/bin/time','-l',base,'verify-prefix-candidate',cfg,out,str(12<<30)],stdout=f,stderr=subprocess.STDOUT).returncode
  if rc:raise RuntimeError(('fresh',kind,rc))
  hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in pathlib.Path(out).iterdir() if p.name in ['bundle.json','cpu-0.bin','cells.bin','stage-one.bin']}
  if expected is None:expected=hashes
  assert hashes==expected,(kind,'artifact mismatch')
  report=json.load(open(out+'/report.json'));records.append({'kind':kind,'binary_sha256':hashlib.sha256(pathlib.Path(exe).read_bytes()).hexdigest(),'start_unix':start,'end_unix':time.time(),'out':out,'log':log,'prove_ns':report['prove_ns'],'hashes':hashes,'fresh':True})
  pathlib.Path('/tmp/rv64-om-blocked-finalizer-cpu0-abba-records.json').write_text(json.dumps(records,indent=2)+'\n');print('done',kind,report['prove_ns']/1e9,flush=True)
print('complete',time.time(),flush=True)
