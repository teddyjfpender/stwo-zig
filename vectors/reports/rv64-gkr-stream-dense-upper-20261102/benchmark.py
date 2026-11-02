import os,fcntl,subprocess,time,json,hashlib,pathlib
root=pathlib.Path('/private/tmp/stwo-rv64-gkr-stream-dense-upper');exe=root/'zig-out/bin/rv64-word16-ethereum-gkr';cfg='/tmp/stwo-rv64-ethereum-round5-native-jobs-v1/request.json';jobs='/tmp/stwo-rv64-ethereum-round5-native-jobs-v1/jobs';base=json.load(open('/tmp/rv64-final-source-configs/q70-k18.json'))
records=[]
with open('/private/tmp/stwo-rv64-perf-heavy.lock','a+') as lock:
 fcntl.flock(lock,fcntl.LOCK_EX);print('locked',time.time(),flush=True)
 for count,order in [(1,['dense104','stream80','checkpoint68','checkpoint68','stream80','dense104']),(2,['dense104','stream80','stream80','dense104'])]:
  res=dict(base);res['schedule']=dict(base['schedule']);res['schedule'].update(lanes=1 if count==1 else 2,workers_per_lane=16 if count==1 else 8)
  resource=f'/tmp/rv64-stream-dense-prefix{count}-resources.json';pathlib.Path(resource).write_text(json.dumps(res,indent=2)+'\n');expected=None
  for ordinal,mode in enumerate(order):
   out=pathlib.Path(f'/tmp/stwo-rv64-stream-dense-p{count}-{ordinal}-{mode}-v1');log=f'/tmp/rv64-stream-dense-p{count}-{ordinal}-{mode}.log';env=os.environ.copy()
   for k in ['STWO_ZIG_GKR_TREE_CHECKPOINTS','STWO_ZIG_GKR_TIGHT_ADMISSION','STWO_ZIG_GKR_STREAM_BOTTOM']:env.pop(k,None)
   env['STWO_ZIG_GKR_TREE_METRICS']='1'
   if mode=='dense104':env['STWO_ZIG_GKR_TIGHT_ADMISSION']='1'
   else:env['STWO_ZIG_GKR_STREAM_BOTTOM']='1'
   if mode=='checkpoint68':env['STWO_ZIG_GKR_TREE_CHECKPOINTS']='2'
   before=time.time();print('start',count,ordinal,mode,before,flush=True)
   with open(log,'w') as f:rc=subprocess.run(['/usr/bin/time','-l',str(exe),'produce-control',cfg,jobs,str(out),str(count),resource],env=env,stdout=f,stderr=subprocess.STDOUT).returncode
   if rc:raise RuntimeError((count,mode,rc))
   with open(log+'.fresh','w') as f:rc=subprocess.run(['/usr/bin/time','-l',str(exe),'verify-prefix-control',cfg,str(out)],stdout=f,stderr=subprocess.STDOUT).returncode
   if rc:raise RuntimeError(('fresh',count,mode,rc))
   artifacts={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in out.iterdir() if p.name in ['bundle.json','cells.bin','stage-one.bin'] or (p.name.startswith('cpu-') and p.suffix=='.bin')}
   if expected is None:expected=artifacts
   assert expected==artifacts,(count,mode,'artifact mismatch')
   report=json.load(open(out/'report.json'));records.append({'count':count,'ordinal':ordinal,'mode':mode,'start_unix':before,'end_unix':time.time(),'out':str(out),'log':log,'prove_ns':report['prove_ns'],'policy':report['gkr_tree_policy'],'workers':report['workers'],'artifacts':artifacts,'fresh':True})
   pathlib.Path('/tmp/rv64-stream-dense-abba-records.json').write_text(json.dumps(records,indent=2)+'\n');print('done',count,ordinal,mode,report['prove_ns']/1e9,flush=True)
print('complete',time.time(),flush=True)
