#!/usr/bin/env python3
"""One source-justified expanded fold cache pair, no numerical code change."""
from pathlib import Path
import hashlib,json,os,subprocess,sys,threading,time,re
root=Path('/workspace/m3/src/m7-fold-expanded');out=Path('/workspace/m3/runs/m7-fold-expanded');out.mkdir(parents=True,exist_ok=True)
sys.path.insert(0,str(root/'scripts'));import rv64_resident_basket as Basket
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
expected={'driver':'9cf6589f1b479f4c6b1049cc98860c55bfbb2fa680e4716ffd976748f782a2f6','library':'a25cc3b23ae21994e01cf0e332f1f79b666c402197bc5ed84920bf7575226e45','receiver':'ddcbcf4b24aaf770f8b42d22188ea3c3c9b7f57726db1d0aa9cb09be27069b42'}
def snapshot(path,leaves):
 return {'native':{p.name:sha(p) for p in sorted(path.glob('*.bin'))},'bundle':sha(path/'bundle.json'),'recursive':Basket.recursive_snapshot(path,leaves)}
def monitor(stop,driver,result):
 seen={}
 while not stop.is_set():
  for proc in Path('/proc').glob('[0-9]*'):
   try:
    args=proc.joinpath('cmdline').read_bytes().split(b'\0')
    if not args or os.fsdecode(args[0])!=driver or b'combined-serve' not in args:continue
    values={}
    for line in proc.joinpath('status').read_text().splitlines():
     if line.startswith(('VmRSS:','VmHWM:')):key,amount,_=line.split();values[key[:-1]]=int(amount)*1024
    item=seen.setdefault(proc.name,{'pid':int(proc.name),'samples':0,'sampled_rss_peak_bytes':0,'sampled_hwm_bytes':0});item['samples']+=1
    item['sampled_rss_peak_bytes']=max(item['sampled_rss_peak_bytes'],values.get('VmRSS',0));item['sampled_hwm_bytes']=max(item['sampled_hwm_bytes'],values.get('VmHWM',0))
   except (FileNotFoundError,PermissionError,ProcessLookupError):pass
  stop.wait(.1)
 result.update(scope='Sampled /proc of the actual frozen combined-serve process, excluding receiver/helpers; 100ms sampling, HWM may miss final subinterval',processes=list(seen.values()))
def analyse(run,mode):
 receipt=json.loads((run/'receipt.json').read_text());stderr=(run/'producer.stderr').read_text()
 fold_keys=set(re.findall(r'FOLD_SEED_TAPE used node=\d+ class=([0-9a-f]+)',stderr))
 pp={};tasks={}
 for line in stderr.splitlines():
  m=re.search(r'GPU_OUTER_PP_PACK adopt class=(\w+) logical_bytes=(\d+) physical_bytes=(\d+)',line)
  if m and m[1] in fold_keys:pp[m[1]]={'raw':int(m[2]),'packed':int(m[3])}
  m=re.search(r'GPU_OUTER_PLAN_PACK adopt class=(\w+) logical_task_bytes=(\d+) physical_task_bytes=(\d+) held_bytes=(\d+)',line)
  if m:
   assert int(m[4])<=6*2**30
   if m[1] in fold_keys:tasks[m[1]]={'raw':int(m[2]),'held':int(m[3])}
 pp_unpacks=[line for line in stderr.splitlines() if 'GPU_OUTER_PP_PACK unpack' in line and any('class='+k in line for k in fold_keys)]
 task_unpacks=[line for line in stderr.splitlines() if 'GPU_OUTER_PLAN_PACK unpack' in line and any('class='+k in line for k in fold_keys)]
 assert fold_keys,'no fold tape reuse measured'
 if mode=='0':assert not pp_unpacks and not task_unpacks,'rawfoldstillunpacks';assert all(x['raw']==x['held'] for x in tasks.values())
 else:assert pp_unpacks and task_unpacks,'compressedcontrolinactive'
 rows=[]
 for request in receipt['requests']:
  path=Path(request['proof']);pipeline=json.loads((path/'recursion-om31/pipeline.json').read_text());folds=[]
  for node in pipeline['nodes']:
   if node['kind']=='fold':
    st=node['stamps'];folds.append({'node':node['id'],'prep_ns':st['prep_end']-st['prep_start'],'graph_ns':node['graph_ns'],'host_plan_ns':node['host_plan_ns'],'authority_ns':node['authority_ns'],'verify_ns':node['verify_ns'],'publish_retire_ns':node['publish_ns'],'device_ns':st['device_end']-st['device_start']})
  rows.append({'trial':request['trial'],'stages':request['stages'],'folds':folds,'last_leaf_finish_ns':pipeline['last_leaf_finish_ns'],'tail_after_last_leaf_ns':pipeline['tail_after_last_leaf_ns'],'dag_wall_ns':pipeline['dag_wall_ns']})
 return {'fold_classes':sorted(fold_keys),'fold_task_adopts':tasks,'fold_pp_compressed_adopts':pp,'fold_pp_unpack_calls':len(pp_unpacks),'fold_task_unpack_calls':len(task_unpacks),'requests':rows}
provenance={'schema':'rv64-m7-expanded-fold-pair/v1','label':'M','scope':'ExistingPACK_FOLD_CACHE flag only; samefrozen9cf/a25/ddcb; D2+partialfamilycoalescing; noNSYS botharms; no robustwallclaim fromsingleloadedpairs','expected_assets':expected,'cache_caps_bytes':{'pp':6*2**30,'tasks':6*2**30},'combined_host_bytes':48*2**30,'source_checkpoint':'bfa72f3ff withreport/helperonly'}
(out/'provenance.json').write_text(json.dumps(provenance,indent=2)+'\n')
for block in [26235156,24628607]:
 reference=Path(f'/workspace/m3/runs/m7-fold-v3/daemon-{block}-r2-combined-d2-coalesce-v1');base=json.loads((reference/'receipt.json').read_text());plan=json.loads((reference/'plan.json').read_text());assets=plan['assets']
 for key,digest in expected.items():assert sha(assets[key])==digest
 base_snap=snapshot(Path(base['requests'][0]['proof']),base['requests'][0]['leaves'])
 for mode in ['0','1']:
  for key,digest in expected.items():assert sha(assets[key])==digest
  tag='fold-cache-pack-'+mode;run=out/f'daemon-{block}-r2-{tag}'
  command=[sys.executable,str(root/'scripts/rv64_m4_resident.py'),'daemon',str(block),'--stream','m7-fold-expanded','--build-stream','m7-fold-expanded','--repeat','2','--store','none','--receive','first' if mode=='0' else 'none','--security-profile','d2_native_b4_q54_p20_fold4','--coalesce-truth-families','--tag',tag,'--driver',assets['driver'],'--library',assets['library'],'--receiver',assets['receiver'],'--no-default-env']
  env=dict(plan['environment']);env['STWO_RV64_PACK_FOLD_CACHE']=mode
  for key,value in sorted(env.items()):command+=['--env',key+'='+value]
  (out/f'{block}-{mode}-command.json').write_text(json.dumps(command,indent=2)+'\n')
  stop=threading.Event();rss={};sampler=threading.Thread(target=monitor,args=(stop,assets['driver'],rss));sampler.start()
  try:
   with (out/f'{block}-{mode}.log').open('w') as log:result=subprocess.run(command,cwd=root,stdout=log,stderr=subprocess.STDOUT)
  finally:stop.set();sampler.join();(out/f'{block}-{mode}-rss.json').write_text(json.dumps(rss,indent=2)+'\n')
  if result.returncode:raise SystemExit(f'FAILED block={block} pack={mode} exit={result.returncode}')
  actual=json.loads((run/'receipt.json').read_text());comparisons=[]
  for request in actual['requests']:
   snap=snapshot(Path(request['proof']),request['leaves']);matches={k:snap[k]==base_snap[k] for k in snap};assert all(matches.values()),matches
   comparisons.append({'trial':request['trial'],'matches':matches,'stages':request['stages'],'proof_bytes_root':request['proof_bytes_root']})
  report={'schema':'rv64-m7-expanded-fold-case/v1','label':'M','block':block,'pack':mode,'receipt':str(run/'receipt.json'),'assets':actual['assets'],'reference':str(reference/'receipt.json'),'proof_comparisons':comparisons,'all_artifacts_byte_identical':True,'receivers':actual['receivers'],'rss':rss,'analysis':analyse(run,mode)}
  (out/f'{block}-{mode}-gate.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report),flush=True)
print('EXPANDED_FOLD_PAIR_PASS')
