import os,json,pathlib,fcntl,subprocess,time,hashlib
exe='/private/tmp/stwo-rv64-gkr-stream-dense-upper/zig-out/bin/rv64-word16-ethereum-gkr'
base='/tmp/rv64-final-deferred-v1/rv64-word16-ethereum-gkr'
cfg='/tmp/stwo-rv64-ethereum-round5-native-jobs-v1/request.json'
jobs='/tmp/stwo-rv64-ethereum-round5-native-jobs-v1/jobs'
resource='/tmp/rv64-om-fri-cpu0-candidate-resource.json'
out='/tmp/stwo-rv64-om-deep-profile-cpu0-v1'
log='/tmp/rv64-om-deep-profile-cpu0.log'
with open('/private/tmp/stwo-rv64-perf-heavy.lock','a+') as lock:
 fcntl.flock(lock,fcntl.LOCK_EX)
 env=os.environ.copy()
 for k in ['STWO_ZIG_GKR_TREE_CHECKPOINTS','STWO_ZIG_GKR_TIGHT_ADMISSION']:env.pop(k,None)
 env['STWO_ZIG_GKR_STREAM_BOTTOM']='1'
 env['STWO_ZIG_PROFILE_WIDE_QUOTIENT']='1'
 with open(log,'w') as f:subprocess.run(['/usr/bin/time','-l',exe,'produce-candidate',cfg,jobs,out,'1',resource],env=env,stdout=f,stderr=subprocess.STDOUT,check=True)
 with open(log+'.fresh','w') as f:subprocess.run([base,'verify-prefix-candidate',cfg,out,str(12<<30)],stdout=f,stderr=subprocess.STDOUT,check=True)
 for name in ['bundle.json','cpu-0.bin','cells.bin','stage-one.bin']:
  assert pathlib.Path(out,name).read_bytes()==pathlib.Path('/tmp/stwo-rv64-om-fri-cpu0-packed-v1',name).read_bytes(),name
 print('all4exact freshaccepted',flush=True)
 for line in pathlib.Path(log).read_text().splitlines():
  if line.startswith('OM_DEEP_PHASE'):print(line)
