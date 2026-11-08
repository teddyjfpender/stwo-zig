from pathlib import Path
import json,hashlib
out=Path('/workspace/m3/runs/m7-q102');base=Path('/workspace/m3/runs/m7-q102-953')
def sha(p):
 with p.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def files(p):
 return {str(f.relative_to(p)):sha(f) for f in sorted(p.rglob('*')) if f.is_file() and (f.suffix=='.bin' or f.suffix=='.proof' or f.name in ('bundle.json','tree.json'))}
summary={'schema':'rv64-m7-q102-paired-results/v1','status':'BOTH_DEV_FRESH_ACCEPTED_NO_LATENCY_WIN','timing_status':'single cold/warm observations; load1m exceeds quiet8 throughout, no qualified speedup or regression claim','memory_status':'autoarena; NVML whole-device sampled peak only, process<=28GB unqualified','rows':[],'comparisons':{}}
for b in [26235156,24628607]:
 proofs={}
 for arm in ['q108-control','q102-p26']:
  run=base/f'daemon-{b}-r2-{arm}-v1';r=json.loads((run/'receipt.json').read_text())
  proofs[arm]=[]
  for q in r['requests']:
   proof=Path(q['proof']);f=files(proof);proofs[arm].append(f)
   pipe=json.loads((proof/'recursion-om31/pipeline.json').read_text());rec=json.loads((proof/'recursion-om31/report.json').read_text())
   row={'block':b,'arm':arm,'trial':q['trial'],'proof':str(proof),'request_wall_ns':q['marker']['request_wall_ns'],'client_latency_ns':q['client_latency_ns'],'stages':q['stages'],'root_bytes':q['proof_bytes_root'],'root_sha256':sha(proof/'recursion-om31/root.proof'),'pipeline_dag_ns':pipe['dag_wall_ns'],'pipeline_tail_ns':pipe['tail_after_last_leaf_ns'],'fold_padded_variables':{str(n['id']):n['variables'] for n in pipe['nodes'] if n['kind']=='fold'},'post_native_recursion_s':q['stages']['recursion_s'],'raw_recursion_total_ns':rec['total_ns'],'native_verify_s':q['stages']['native_verify_s'],'fresh_receiver':r['receivers'] if q['trial']==0 else 'byte identity to same-arm fresh accepted cold verified below','loadavg_before':r['load_avg_before'],'loadavg_after':r['load_avg_after'],'rss_service_peak_bytes':r['producer_process']['peak_rss_bytes'],'nvml_whole_device_peak_bytes':r['physical_gpu_memory']['peak_used_bytes'],'receipt_sha256':sha(run/'receipt.json'),'artifact_fingerprints':f}
   summary['rows'].append(row)
  assert proofs[arm][0]==proofs[arm][1],(b,arm,'cold warm artifact mismatch')
 def native(f):return {k:v for k,v in f.items() if not k.startswith('recursion-om31/')}
 a,c=proofs['q108-control'][1],proofs['q102-p26'][1]
 assert native(a)==native(c),(b,'native artifacts changed across outer policy')
 old=next(x for x in summary['rows'] if x['block']==b and x['arm']=='q108-control' and x['trial']==1);new=next(x for x in summary['rows'] if x['block']==b and x['arm']=='q102-p26' and x['trial']==1)
 summary['comparisons'][str(b)]={'cold_warm_complete_artifacts_identical_each_arm':True,'complete_artifact_count':len(a),'native_artifacts_identical_between_profiles':True,'native_artifact_count':len(native(a)),'warm_request_delta_percent':100*(new['request_wall_ns']/old['request_wall_ns']-1),'root_bytes_saved':old['root_bytes']-new['root_bytes'],'root_bytes_delta_percent':100*(new['root_bytes']/old['root_bytes']-1),'fold_padding_halving':False}
(out/'results.json').write_text(json.dumps(summary,indent=2)+'\n');print(json.dumps(summary['comparisons'],indent=2))
