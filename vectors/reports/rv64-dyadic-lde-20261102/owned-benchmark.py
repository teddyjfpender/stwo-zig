import os,json,pathlib,subprocess,time,hashlib,re
base='/tmp/rv64-final-om-fri-v1/rv64-word16-ethereum-gkr'
new='/private/tmp/stwo-rv64-dyadic-lde/zig-out/bin/rv64-word16-ethereum-gkr'
cfg='/tmp/stwo-rv64-ethereum-round5-native-jobs-v1/request.json';jobs='/tmp/stwo-rv64-ethereum-round5-native-jobs-v1/jobs';resource='/tmp/rv64-om-fri-cpu0-candidate-resource.json'
records=[];expected=None
freshenv={k:v for k,v in os.environ.items() if not k.startswith('STWO_ZIG_GKR_')}
env=freshenv.copy();env['STWO_ZIG_GKR_STREAM_BOTTOM']='1';env['STWO_ZIG_PROFILE_OM_DOMAIN']='1';env['STWO_ZIG_PCS_KERNEL_TIMING']='1'
for index,(kind,exe) in enumerate([('old',base),('new',new),('new',new),('old',base)]):
 out=pathlib.Path(f'/tmp/stwo-rv64-dyadic-owned-lde-{index}-{kind}-v1');log=pathlib.Path(f'/tmp/rv64-dyadic-owned-lde-{index}-{kind}.log')
 assert not out.exists(),str(out)
 start=time.time()
 with log.open('w') as f:
  subprocess.run(['/usr/bin/time','-l',exe,'produce-candidate',cfg,jobs,str(out),'1',resource],env=env,stdout=f,stderr=subprocess.STDOUT,check=True)
 names=['bundle.json','cpu-0.bin','cells.bin','stage-one.bin'];hashes={n:hashlib.sha256((out/n).read_bytes()).hexdigest() for n in names}
 if expected is None:expected=hashes
 assert hashes==expected,'artifact mismatch'
 with pathlib.Path(str(log)+'.fresh').open('w') as f:
  subprocess.run([base,'verify-prefix-candidate',cfg,str(out),str(12<<30)],env=freshenv,stdout=f,stderr=subprocess.STDOUT,check=True)
 text=log.read_text();profiles=[]
 for line in text.splitlines():
  if line.startswith('OM_DOMAIN_STAGE '):profiles.append({k:int(v) for k,v in re.findall(r'(\w+)=(\d+)',line)})
 kernels=[{k:int(v) for k,v in re.findall(r'(\w+)=(\d+)',line)} for line in text.splitlines() if line.startswith('pcs_kernel ')]
 report=json.loads((out/'report.json').read_text()); stages=json.loads((out/'physical-0000.stages.json').read_text()); sums={}
 def visit(items):
  for item in items:
   sums[item['id']]=sums.get(item['id'],0)+item['seconds'];visit(item.get('children')or[])
 visit(stages['stages'])
 record={'index':index,'kind':kind,'binary_sha256':hashlib.sha256(pathlib.Path(exe).read_bytes()).hexdigest(),'prove_ns':report['prove_ns'],'wall_with_fresh_seconds':time.time()-start,'profile_domain_rows_ns':sum(x['rows_ns'] for x in profiles),'profile_domain_fft_ns':sum(x['fft_ns'] for x in profiles),'profiles':profiles,'stage_seconds':sums,'producer_kernels_including_setup':kernels,'hashes':hashes,'fresh':True,'out':str(out),'log':str(log)}
 records.append(record);pathlib.Path('/tmp/rv64-dyadic-owned-lde-abba.json').write_text(json.dumps(records,indent=2)+'\n')
 print(json.dumps({k:record[k] for k in ['index','kind','prove_ns','profile_domain_rows_ns','profile_domain_fft_ns','fresh']}),flush=True)
print('all_four_artifacts_exact_and_fresh',flush=True)
