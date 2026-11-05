import json,pathlib,sys,time
root=pathlib.Path('/workspace/m3/src/m7-integrate');sys.path.insert(0,str(root/'scripts'))
import rv64_m4_resident as R
import rv64_m7_integration_stack as S
import rv64_gate as G
base=pathlib.Path('/workspace/m3/runs/m7-integrate')
out=base/'p1-columns-small-20261106-01'
experiment=json.loads((out/'experiment.json').read_text())
manifest=json.loads((out/'artifact.json').read_text());S.validate_manifest(manifest)
baseline=pathlib.Path(experiment['services'][0]['run'])
candidate=pathlib.Path(experiment['services'][1]['run'])
ref=json.loads((baseline/'receipt.json').read_text())['requests'][0]
record={'status':'VALIDATING_COMPLETED_REQUESTS_AFTER_WARM_TIMEOUT','whole_service_pass':False,'timing_qualified':False,'receivers':[],'candidate_completed':[],'candidate_warm':'TIMEOUT_120S_NO_COMPLETE_ROOT'}
S.write(out/'post-abort-validation.json',record)
record['receivers']+=R.receive_run(baseline,'all',16)
S.write(out/'post-abort-validation.json',record)
plan=json.loads((candidate/'plan.json').read_text())
store=plan.get('store',{}).get('directory')
assert not store or not pathlib.Path(store).exists()
for ordinal,item in enumerate(json.loads((candidate/'request-timeline.json').read_text())):
 block=item['block'];proof=candidate/'spool/out'/item['name']/str(block)/'proof'
 stages,report,combined=R.P.stage_breakdown(proof,{0:item['service']['request_wall_ns']})
 entry={'block':block,'trial':ordinal,'ordinal':ordinal,'proof':str(proof),'leaves':report['cpu_proofs']+report['truth_proofs'],'stages':stages,'marker':{'request_wall_ns':item['service']['request_wall_ns']}}
 parity=S.fingerprints(entry,True)==S.fingerprints(ref,True)
 assert parity,'completed candidate cold differs from baseline'
 verdict=R.receive_one(plan,block,proof,candidate,16)
 verdict.update(trial=ordinal,store_present_during_receive=False)
 record['candidate_completed'].append(dict(entry,payload_and_capture_parity=parity))
 record['receivers'].append(verdict);S.write(out/'post-abort-validation.json',record)
partial=candidate/'spool/out/0001-26235156/26235156/proof'
rp=pathlib.Path(ref['proof'])
partial_files={str(p.relative_to(partial)):S.sha(p) for p in partial.rglob('*') if p.is_file() and G.payload_name(str(p.relative_to(partial)))}
reference_files={str(p.relative_to(rp)):S.sha(p) for p in rp.rglob('*') if p.is_file() and G.payload_name(str(p.relative_to(rp)))}
record['warm_partial']={'file_count':len(partial_files),'all_present_files_match':all(reference_files.get(k)==v for k,v in partial_files.items()),'missing':sorted(reference_files.keys()-partial_files.keys()),'fingerprints':partial_files,'complete_root':(partial/'recursion-om31/root.proof').exists()}
record['status']='COMPLETED_PROOFS_FRESH_ACCEPTED_WARM_TIMEOUT_REMAINS' if all(v['accepted'] for v in record['receivers']) else 'RECEIVER_REJECTION'
S.write(out/'post-abort-validation.json',record)
(out/'post-abort-validation.exit').write_text('0\n' if all(v['accepted'] for v in record['receivers']) else '1\n')
print(record['status'])
