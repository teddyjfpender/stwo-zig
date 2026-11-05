from pathlib import Path
import json,sys
root=Path('/workspace/m3/src/m7-integrate');sys.path.insert(0,str(root/'scripts'))
import rv64_m4_resident as R
import rv64_m7_integration_stack as S
import rv64_gate as G
base=Path('/workspace/m3/runs/m7-integrate');out=base/'p1-inter-reuse-small-20261106-01'
x=json.loads((out/'experiment.json').read_text());manifest=json.loads((out/'artifact.json').read_text());S.validate_manifest(manifest)
baseline=Path(x['services'][0]['run']);candidate=Path(x['services'][1]['run'])
record={'status':'VALIDATING_BASELINE_AFTER_CANDIDATE_BORROW_FAILURE','candidate_complete_root':False,'candidate_error':'InvalidPcsBorrowPromise','receivers':[]}
S.write(out/'post-abort-validation.json',record)
record['receivers']=R.receive_run(baseline,'all',16)
reference=Path(json.loads((baseline/'receipt.json').read_text())['requests'][0]['proof'])
partial=candidate/'spool/out/0000-26235156/26235156/proof'
fingerprints=lambda proof:{str(p.relative_to(proof)):S.sha(p) for p in proof.rglob('*') if p.is_file() and G.payload_name(str(p.relative_to(proof)))}
a=fingerprints(partial);r=fingerprints(reference)
record['partial']={'file_count':len(a),'all_present_files_match':all(r.get(k)==v for k,v in a.items()),'missing':sorted(r.keys()-a.keys()),'fingerprints':a}
record['status']='BASELINE_FRESH_ACCEPTED_CANDIDATE_NO_ROOT' if all(v['accepted'] for v in record['receivers']) else 'BASELINE_RECEIVER_FAILURE'
S.write(out/'post-abort-validation.json',record);(out/'post-abort-validation.exit').write_text('0\n' if all(v['accepted'] for v in record['receivers']) else '1\n')
