#!/usr/bin/env python3
"""Reproduce the accepted 19-node D2 schedule, using read-only existing receipts.
No timings are synthesized for native clock origin, host worker IDs or memory.
Known-edge slack is an UPPER BOUND, not a feasible rescheduling promise.
"""
import argparse,bisect,collections,hashlib,itertools,json,pathlib,sqlite3

def union(xs):
 out=[]
 for a,b in sorted(xs):
  if b<=a:continue
  if out and a<=out[-1][1]:out[-1]=(out[-1][0],max(b,out[-1][1]))
  else:out.append((a,b))
 return out

def clip(xs,a,b):return [(max(x,a),min(y,b)) for x,y in xs if x<b and y>a]
def subtract(xs,ys):
 out=[]
 for a,b in xs:
  at=a
  for x,y in clip(ys,a,b):
   if at<x:out.append((at,x))
   at=max(at,y)
  if at<b:out.append((at,b))
 return out

def dur(xs):return sum(b-a for a,b in xs)
def sha(p):return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--pipeline',required=True);ap.add_argument('--tree',required=True);ap.add_argument('--sqlite',required=True);ap.add_argument('--class-log',required=True);ap.add_argument('--out',required=True);args=ap.parse_args()
 p=json.loads(pathlib.Path(args.pipeline).read_text());tree=json.loads(pathlib.Path(args.tree).read_text());ns=p['nodes'];assert len(ns)==len(tree['nodes'])==19 and p['lanes']==2
 assert not p['stream']['admitted_device_overlap']
 for i,n in enumerate(ns):
  assert i==n['id'];s=n['stamps'];assert s['taken']<=s['prep_start']<=s['prep_end']<=s['device_start']<=s['device_end']<=s['finish_start']<=s['finish_end']
  assert n['first_leaf']==tree['nodes'][i]['first_leaf'] and n['leaf_count']==tree['nodes'][i]['leaf_count']
  for child in tree['nodes'][i]['children']:assert ns[child]['stamps']['finish_end']<=s['taken']
 root=len(ns)-1;deadline=ns[root]['stamps']['finish_end']
 # Three stages per node; actual device lane serialization is a hard resource edge.
 stages={};pred=collections.defaultdict(list);succ=collections.defaultdict(list)
 def edge(a,b):pred[b].append(a);succ[a].append(b)
 for n in ns:
  i=n['id'];s=n['stamps']
  for k,a,b in [('prep','prep_start','prep_end'),('device','device_start','device_end'),('finish','finish_start','finish_end')]:stages[f'{i}:{k}']={'start':s[a],'end':s[b]}
  edge(f'{i}:prep',f'{i}:device');edge(f'{i}:device',f'{i}:finish')
  for child in tree['nodes'][i]['children']:edge(f'{child}:finish',f'{i}:prep')
 lane_pred={}
 for lane in range(p['lanes']):
  ordered=sorted((n for n in ns if n['lane']==lane),key=lambda n:n['stamps']['device_start'])
  for prev,n in zip([None]+ordered,ordered):
   lane_pred[n['id']]=prev['id'] if prev else None
   if prev:edge(f'{prev["id"]}:device',f'{n["id"]}:device')
 order=sorted(stages,key=lambda k:stages[k]['start'])
 latest={k:deadline-(v['end']-v['start']) for k,v in stages.items()}
 for k in reversed(order):
  d=stages[k]['end']-stages[k]['start']
  if succ[k]:latest[k]=min(latest[x] for x in succ[k])-d
  assert latest[k]>=stages[k]['start']
 # Observed last known predecessor, with unexplained gaps retained as unknown waits.
 observed=[];at=f'{root}:finish'
 while True:
  observed.append(at)
  if not pred[at]:break
  at=max(pred[at],key=lambda x:stages[x]['end'])
 observed.reverse()
 # NVTX/controller mapping uses immutable temporal order on each owner thread;
 # equal-length alternatives must have a mutually consistent containment offset.
 db=sqlite3.connect('file:'+str(pathlib.Path(args.sqlite).resolve())+'?mode=ro',uri=True);strings=dict(db.execute('select id,value from StringIds'))
 window=(45713537241,51639866055)
 ranges=[(a,b,t,text or strings.get(ti,'')) for a,b,t,text,ti in db.execute('select start,end,globalTid,text,textId from NVTX_EVENTS where start>=? and end<=? and end>start',window)]
 groups=collections.defaultdict(list)
 for a,b,tid,name in ranges:
  if name=='rv64/owner/controller':groups[tid].append((a,b))
 assert sum(map(len,groups.values()))==19 and len(groups)==2
 candidates=[]
 for tids in itertools.permutations(groups):
  mapped={};low=0;high=1<<63;okay=True
  for lane,tid in enumerate(tids):
   nodes=sorted([n for n in ns if n['lane']==lane],key=lambda n:n['stamps']['device_start']);rs=sorted(groups[tid])
   if len(nodes)!=len(rs):okay=False;break
   for n,(a,b) in zip(nodes,rs):
    mapped[n['id']]=(a,b,tid);low=max(low,b-n['stamps']['device_end']);high=min(high,a-n['stamps']['device_start'])
  if okay and low<=high:candidates.append((mapped,low,high))
 assert len(candidates)==1;mapping,offset_low,offset_high=candidates[0]
 runtime=list(db.execute('select start,end,globalTid,correlationId,nameId from CUPTI_ACTIVITY_KIND_RUNTIME where end>? and start<?',window));corr={c:t for a,b,t,c,n in runtime}
 api=collections.defaultdict(list);wait=collections.defaultdict(list)
 for a,b,t,c,n in runtime:
  api[t].append((a,b))
  if strings[n].startswith(('cudaEventSynchronize','cudaStreamSynchronize','cudaDeviceSynchronize')):wait[t].append((a,b))
 kernels=collections.defaultdict(list);copies=collections.defaultdict(list);physical=collections.defaultdict(set)
 for tab,target in [('CUPTI_ACTIVITY_KIND_KERNEL',kernels),('CUPTI_ACTIVITY_KIND_MEMCPY',copies),('CUPTI_ACTIVITY_KIND_MEMSET',copies)]:
  for a,b,dev,c in db.execute('select start,end,deviceId,correlationId from '+tab+' where end>? and start<?',window):
   if c in corr:target[corr[c]].append((a,b));physical[corr[c]].add(dev)
 for d in (api,wait,kernels,copies):
  for t in d:d[t]=union(d[t])
 classes={}
 for entry in json.loads(pathlib.Path(args.class_log).read_text()):
  import re
  m=re.search(r'node=(\d+) class=([0-9a-f]+)',entry['text'])
  if m:classes[int(m[1])]=m[2] # Last occurrence is warm request; full class hash is not logged.
 def partition(a,b,tid):
  kk=clip(kernels[tid],a,b);cc=subtract(clip(copies[tid],a,b),kk);gpu=union(kk+cc);aa=subtract(clip(api[tid],a,b),gpu);hh=subtract([(a,b)],union(gpu+aa))
  result={'kernel_ns':dur(kk),'copy_only_ns':dur(cc),'api_without_gpu_ns':dur(aa),'untraced_host_without_gpu_api_ns':dur(hh)}
  assert sum(result.values())==b-a
  return result
 phase_names={'rv64/recursion/MAIN-assignment','rv64/TC/MAIN','rv64/recursion/INTER-witness','rv64/TC/INTER','rv64/composition','rv64/owner/pcs'}
 rows=[]
 for n in ns:
  i=n['id'];s=n['stamps'];kids=tree['nodes'][i]['children'];child=max(kids,key=lambda x:ns[x]['stamps']['finish_end']) if kids else None;lp=lane_pred[i]
  known=max(s['prep_end'],ns[lp]['stamps']['device_end'] if lp is not None else 0)
  blocker='lane:'+str(lp) if lp is not None and ns[lp]['stamps']['device_end']>s['prep_end'] else 'prep:'+str(i)
  if lp is None:blocker='native barrier (clock alignment UNKNOWN)'
  a,b,tid=mapping[i];assert len(physical[tid])==1
  totals=partition(a,b,tid);ww=clip(wait[tid],a,b)
  children=[r for r in ranges if r[2]==tid and r[3] in phase_names and a<=r[0] and r[1]<=b]
  cuts=sorted({a,b}|{v for r in children for v in r[:2]});phases={}
  for lo,hi in zip(cuts,cuts[1:]):
   covering=[r for r in children if r[0]<=lo and hi<=r[1]]
   name=min(covering,key=lambda r:r[1]-r[0])[3] if covering else 'unmarked_controller'
   bucket=phases.setdefault(name,collections.Counter());bucket.update(partition(lo,hi,tid));bucket['wall_ns']+=hi-lo
  assert sum(v['wall_ns']for v in phases.values())==b-a
  rows.append({'id':i,'kind':n['kind'],'first_leaf':n['first_leaf'],'leaf_count':n['leaf_count'],'children':kids,'last_child':child,'lane':n['lane'],'physical_gpu':next(iter(physical[tid])),'lane_predecessor':lp,'device_last_known_gate':blocker,'native_publish_stream_ns':p['stream']['leaf_ready_ns'][n['first_leaf']] if n['kind']=='leaf' else None,'native_publish_pipeline_ns':None,'memory_ready_ns':None,'memory_gate':'UNKNOWN; planner inactive','host_worker_id':None,'host_admission':'taken observed; throttle/authority-slot readiness unlogged','stamps':s,'device_dispatch_residual_ns':s['device_start']-known,'prep_after_last_child_ns':s['prep_start']-ns[child]['stamps']['finish_end'] if child is not None else None,'finish_queue_ns':s['finish_start']-s['device_end'],'verify_ns':n['verify_ns'],'publish_ns':n['publish_ns'],'finish_other_ns':s['finish_end']-s['finish_start']-n['verify_ns']-n['publish_ns'],'next_lane_overlaps_finish':any(x['lane']==n['lane'] and s['device_end']<=x['stamps']['device_start']<s['finish_end'] for x in ns),'known_edge_slack_upper_ns':{k:latest[f'{i}:{k}']-stages[f'{i}:{k}']['start'] for k in ('prep','device','finish')},'on_observed_last_predecessor_chain':any(f'{i}:{k}' in observed for k in ('prep','device','finish')),'tree_authority_hex':bytes(tree['nodes'][i]['authority']).hex(),'tree_digest_hex':bytes(tree['nodes'][i]['digest']).hex(),'class_log_prefix_hex':classes.get(i),'full_class_hash':None,'device_scope_hash':None,'controller_nvtx':{'start':a,'end':b,'global_tid':tid,**totals,'phases':phases,'named_ranges':[{"name":r[3],"start":r[0],"end":r[1]}for r in children],'blocking_api_wall_ns_nonadditive':dur(ww)}})
 out={'schema':'rv64-m7-critical-chain/v1','status':'OBSERVED_ACCEPTED_D2_WARM_SCHEDULE_SOURCE_AUDIT','pipeline_sha256':sha(args.pipeline),'tree_sha256':sha(args.tree),'sqlite_sha256':sha(args.sqlite),'class_log_sha256':sha(args.class_log),'node_count':19,'lanes':2,'logical_lanes_per_physical_gpu':1,'pipeline_wall_ns':p['dag_wall_ns'],'root_finish_ns':deadline,'post_root_finish_pipeline_ns':p['dag_wall_ns']-deadline,'root_publication_ns':p['root_publication_ns'],'stream_native_done_unaligned_ns':p['stream']['native_done_ns'],'device_wait_for_native_observed_ns':p['device_wait_for_native_ns'],'native_clock_origin_pipeline_ns':None,'nsys_minus_pipeline_containment_offset_interval_ns':[offset_low,offset_high],'observed_last_known_predecessor_chain':observed,'slack_scope':'Upper bound under known child+lane edges and fixed stage durations. Host-resource/authority/memory gating unlogged. Not promised attainable rescheduling or saved time.','rows':rows}
 pathlib.Path(args.out).write_text(json.dumps(out,indent=2)+'\n')
 print('observed chain:', ' -> '.join(observed));print('wrote',args.out)
if __name__=='__main__':main()
