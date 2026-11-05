import pathlib,json,sqlite3,collections,hashlib,sys
run=pathlib.Path(sys.argv[1]);r=json.load(open(run/'receipt.json'));db=sqlite3.connect(run/'nsys/timeline.sqlite');epoch=db.execute('select utcEpochNs from TARGET_INFO_SESSION_START_TIME').fetchone()[0]
def union(xs):
 total=0;hi=None
 for a,b in sorted(xs):
  if hi is None or a>hi:total+=b-a;hi=b
  elif b>hi:total+=b-hi;hi=b
 return total/1e9
def critical(pipe,tree):
 nodes=pipe['nodes'];prev={}
 for lane in range(pipe['lanes']):
  seq=sorted((x for x in nodes if x['lane']==lane),key=lambda x:x['stamps']['device_start'])
  for a,b in zip(seq,seq[1:]):prev[b['id']]=a['id']
 segments=[]
 def end(kind,n):return nodes[n]['stamps'][{'P':'prep_end','D':'device_end','F':'finish_end'}[kind]]
 def walk(kind,n):
  z=nodes[n];t=z['stamps'];stop=end(kind,n)
  if kind=='F': start=t['finish_start'];dep=('D',n);label='host_finish_verify_publish';gap='finish_queue'
  elif kind=='D':
   start=t['device_start'];candidates=[('P',n)]+([('D',prev[n])] if n in prev else []);dep=max(candidates,key=lambda x:end(*x));label='device_owner_callback_wall';gap='native_gate_or_device_queue'
  else:
   start=t['prep_start'];kids=tree['nodes'][n]['children'];dep=max((('F',k) for k in kids),key=lambda x:end(*x)) if kids else None;label='host_prepare';gap='native_ready_or_host_queue' if not kids else 'fold_ready_or_host_queue'
  dep_end=end(*dep) if dep else 0
  assert dep_end<=start<=stop,(kind,n,dep_end,start,stop)
  if dep:walk(*dep)
  if start>dep_end:segments.append({'owner':gap,'node':n,'start_ns':dep_end,'end_ns':start})
  segments.append({'owner':label,'node':n,'start_ns':start,'end_ns':stop})
 root=len(nodes)-1;walk('F',root);sums=collections.defaultdict(int)
 for s in segments:sums[s['owner']]+=s['end_ns']-s['start_ns']
 sums['after_root_worker_until_dag_end']=pipe['dag_wall_ns']-nodes[root]['stamps']['finish_end']
 return {'scope':'one service dependency path including lane serialization; queue gaps remain explicitly unowned without release/worker timestamps','seconds':{k:v/1e9 for k,v in sums.items()},'segments':segments}
out=[]
for q in r['requests']:
 p=pathlib.Path(q['proof']);c=json.load(open(p/'combined-report.json'));pipe=json.load(open(p/'recursion-om31/pipeline.json'));tree=json.load(open(p/'recursion-om31/tree.json'))
 end=(run/'spool/done'/f'{q["ordinal"]:04d}-24628607.json').stat().st_mtime_ns-epoch;lo=end-q['client_latency_ns'];start=end-q['marker']['request_wall_ns'];boundary=start+c['capture_ns']+c['native_setup_ns']+c['native_prove_ns']
 exact_count=r['cuda_api']['per_request']['requests'][q['ordinal']]['cudaLaunchKernel'];count=db.execute("select count(*) from CUPTI_ACTIVITY_KIND_RUNTIME r join StringIds s on r.nameId=s.id where s.value like 'cudaLaunchKernel%' and r.start between ? and ?",(lo,end)).fetchone()[0];assert count==exact_count
 kernels=db.execute('select k.start,k.end,k.deviceId,s.value from CUPTI_ACTIVITY_KIND_KERNEL k join StringIds s on k.demangledName=s.id where k.start>=? and k.start<?',(lo,end)).fetchall()
 groups=collections.defaultdict(list)
 for a,b,d,n in kernels:
  phase='native' if b<boundary-5_000_000 else 'recursion' if a>boundary+5_000_000 else 'boundary_unassigned'
  groups[(phase,d)].append((a,b));groups[('all',d)].append((a,b))
 gpu={}
 for phase in ['all','native','recursion','boundary_unassigned']:
  per={str(d):union(groups[(phase,d)]) for d in [0,1]};gpu[phase]={'busy_gpu_seconds':sum(per.values()),'per_device_seconds':per,'kernel_duration_sum_seconds':sum(b-a for a,b,d,n in kernels if phase=='all' or (('native' if b<boundary-5_000_000 else 'recursion' if a>boundary+5_000_000 else 'boundary_unassigned')==phase))/1e9}
 wall={k:c[k]/1e9 for k in ['capture_ns','native_setup_ns','native_prove_ns','recursion_after_native_ns']};wall['request_cleanup_and_audit_ns']=(q['marker']['request_wall_ns']-sum(c[k] for k in ['capture_ns','native_setup_ns','native_prove_ns','recursion_after_native_ns']))/1e9
 item={'block':q['block'],'trial':q['trial'],'request_wall_s':q['marker']['request_wall_ns']/1e9,'exclusive_request_stage_seconds':wall,'native_verification_overlapping_recursion_s':c['native_verify_ns']/1e9,'recursion_pipeline_wall_s':pipe['dag_wall_ns']/1e9,'recursion_tail_after_last_leaf_s':pipe['tail_after_last_leaf_ns']/1e9,'host_work_seconds':{'prepare':sum(x['stamps']['prep_end']-x['stamps']['prep_start'] for x in pipe['nodes'])/1e9,'finish':sum(x['stamps']['finish_end']-x['stamps']['finish_start'] for x in pipe['nodes'])/1e9},'critical_service_path':critical(pipe,tree),'gpu':gpu,'kernel_count':len(kernels),'window_validation':{'runtime_launch_count':count,'exact_harness_utc_window_launch_count':exact_count,'derived_window_ns':[lo,end],'native_end_ns':boundary,'boundary_padding_ns':5_000_000},'lane_device_callback_seconds':[x/1e9 for x in pipe['lane_device_stage_ns']]}
 out.append(item);print('REQUEST',q['trial'],json.dumps({k:v for k,v in item.items() if k not in ['critical_service_path','window_validation']}));print('CRITICAL',item['critical_service_path']['seconds'])
report={'schema':'rv64-m7-request-ownership/v1','label':'M','scope':'One profiler capture, qualified v3 binary, no wall A/B or tuning. Kernel busy is interval union/device (GPU-seconds); sum of durations also given. Native/recursion split uses reported native stage end, guarded by5ms unassigned band. Request windows reconstructed from acknowledgement mtime+latency and validated against exact harness launch counts. NVTX ranges absent, so inner TC/RC/PCS ownership remains unassigned.','driver_sha256':r['assets']['driver'],'library_sha256':r['assets']['library'],'driver_source_attestation':'qualified prefill-v3 build197b from a365+two overrides; helper source96a99+NVTX trace option; raw receipt source_commit is null and not invented','requests':out,'sqlite_sha256':hashlib.sha256((run/'nsys/timeline.sqlite').read_bytes()).hexdigest()}
pathlib.Path(sys.argv[2]).write_text(json.dumps(report,indent=2)+'\n')
