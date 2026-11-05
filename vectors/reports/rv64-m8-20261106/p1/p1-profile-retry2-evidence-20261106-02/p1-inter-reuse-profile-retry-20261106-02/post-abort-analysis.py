from pathlib import Path
import json,os,subprocess,sys
root=Path('/workspace/m3/src/m7-integrate');sys.path.insert(0,str(root/'scripts'))
import rv64_m4_resident as R
import rv64_m7_integration_stack as S
import rv64_gate as G
out=Path('/workspace/m3/runs/m7-integrate/p1-inter-reuse-profile-retry-20261106-02')
experiment=json.loads((out/'experiment.json').read_text());manifest=json.loads((out/'artifact.json').read_text());S.validate_manifest(manifest)
baseline=Path(experiment['services'][0]['run']);candidate=Path(experiment['services'][1]['run'])
record={'status':'VALIDATING_COMPLETED_PROFILE_PROOFS','whole_profile_pair_pass':False,'candidate_warm':'ABORTED_CAPACITY_STALL_NO_ROOT','receivers':[],'candidate_completed':[]}
S.write(out/'post-abort-analysis.json',record)
record['receivers']+=R.receive_run(baseline,'all',16)
S.write(out/'post-abort-analysis.json',record)
reference=json.loads((baseline/'receipt.json').read_text())['requests'][0]
plan=json.loads((candidate/'plan.json').read_text())
assert not plan.get('store',{}).get('directory')
for ordinal,item in enumerate(json.loads((candidate/'request-timeline.json').read_text())):
 block=item['block'];proof=candidate/'spool/out'/item['name']/str(block)/'proof'
 stages,report,combined=R.P.stage_breakdown(proof,{0:item['service']['request_wall_ns']})
 entry={'block':block,'trial':ordinal,'ordinal':ordinal,'proof':str(proof),'leaves':report['cpu_proofs']+report['truth_proofs'],'stages':stages,'marker':{'request_wall_ns':item['service']['request_wall_ns']},'utc_window_ns':item['utc_window_ns'],'client_latency_ns':item['client_latency_ns'],'proof_bytes_root':(proof/'recursion-om31/root.proof').stat().st_size}
 assert S.fingerprints(entry)==S.fingerprints(reference)
 verdict=R.receive_one(plan,block,proof,candidate,16);verdict.update(trial=ordinal,store_present_during_receive=False);assert verdict['accepted']
 record['receivers'].append(verdict);record['candidate_completed'].append(entry);S.write(out/'post-abort-analysis.json',record)
partial=candidate/'spool/out/0001-24628607/24628607/proof'
fingerprints=lambda p:{str(f.relative_to(p)):S.sha(f) for f in p.rglob('*') if f.is_file() and G.payload_name(str(f.relative_to(p)))}
actual=fingerprints(partial);expected=fingerprints(Path(reference['proof']))
record['warm_partial']={'all_present_files_match':all(expected.get(k)==v for k,v in actual.items()),'file_count':len(actual),'missing':sorted(expected.keys()-actual.keys()),'fingerprints':actual,'complete_root':(partial/'recursion-om31/root.proof').exists()}
analysis=out/'candidate-completed-cold';analysis.mkdir(exist_ok=False)
(analysis/'nsys').symlink_to(candidate/'nsys');(analysis/'spool').symlink_to(candidate/'spool')
S.write(analysis/'receipt.json',{'schema':'rv64-completed-request-reconstruction/v1','status':'PARTIAL_COLD_ONLY_AFTER_ABORTED_WARM','whole_service_pass':False,'source_run':str(candidate),'source_timeline_sha256':S.sha(candidate/'request-timeline.json'),'assets':plan['asset_sha256'],'requests':record['candidate_completed'],'receivers':[v for v in record['receivers'] if v['proof'].startswith(str(candidate))]})
env=S.clean_environment(os.environ)
with (out/'candidate-nsys-export.log').open('w') as log:
 code=subprocess.run(['nsys','export','--type','sqlite','--force-overwrite','true','-o',str(candidate/'nsys/timeline.sqlite'),str(candidate/'nsys/timeline.nsys-rep')],env=env,stdout=log,stderr=subprocess.STDOUT).returncode
record['candidate_nsys_export_exit']=code;record['metrics']=[]
for arm,run in [('baseline',baseline),('candidate_cold_only',analysis)]:
 metric={'arm':arm,'run':str(run),'steps':[]};record['metrics'].append(metric)
 commands=[('gpu-seconds',[sys.executable,str(root/'scripts/rv64_m7_gpu_seconds.py'),str(run),'--accepted-run',str(run)]),('after-native',[sys.executable,str(root/'scripts/rv64_m7_native_ownership.py'),str(run),'--phase','after-native','--output',str(run/'after-native-ownership.json')]),('capture-native',[sys.executable,str(root/'scripts/rv64_m7_native_ownership.py'),str(run),'--phase','capture-native','--output',str(run/'capture-native-ownership.json')])]
 for name,argv in commands:
  with (out/(arm+'-'+name+'.log')).open('w') as log:rc=subprocess.run(argv,cwd=root,env=env,stdout=log,stderr=subprocess.STDOUT).returncode
  metric['steps'].append({'name':name,'exit_code':rc})
 S.write(out/'post-abort-analysis.json',record)
record['status']='COMPLETED_3_PROFILE_PROOFS_FRESH_ACCEPTED_WARM_FAILURE_REMAINS'
S.write(out/'post-abort-analysis.json',record);(out/'post-abort-analysis.exit').write_text('0\n')
