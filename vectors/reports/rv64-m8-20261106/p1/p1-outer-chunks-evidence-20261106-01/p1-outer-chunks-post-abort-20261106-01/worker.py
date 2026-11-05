from pathlib import Path
import json,sys
root=Path('/workspace/m3/src/m7-integrate');sys.path.insert(0,str(root/'scripts'))
import rv64_m7_integration_stack as S
import rv64_m4_resident as R
b=Path('/workspace/m3/runs/m7-integrate');primary=b/'p1-outer-chunks-headline-20261106-01';out=b/'p1-outer-chunks-post-abort-20261106-01'
e=json.loads((primary/'experiment.json').read_text())
record={'status':'VERIFYING_COMPLETED_PROOFS_AFTER_HEADLINE_FAILURE','whole_canonical_pass':False,'services':[]}
S.write(out/'validation.json',record)
ref=None
for service in e['services']:
 run=Path(service['run'])
 if service.get('exit_code')!=0:continue
 receipt=json.loads((run/'receipt.json').read_text());assert len(receipt['requests'])==2
 for request in receipt['requests']:
  f=S.fingerprints(request)
  if ref is None:ref=f
  assert f==ref
 item={'run':str(run),'arm':service['arm'],'warm':receipt['requests'][1],'receivers':R.receive_run(run,'all',16)}
 assert len(item['receivers'])==2 and all(x['accepted'] for x in item['receivers'])
 record['services'].append(item);S.write(out/'validation.json',record)
failed=Path(e['services'][-1]['run']);proof=failed/'spool/out/0000-24628607/24628607/proof'
actual={str(p.relative_to(proof)):{'bytes':p.stat().st_size,'sha256':S.sha(p)} for p in proof.rglob('*') if p.is_file() and (p.suffix in ('.bin','.proof') or p.name in ('bundle.json','candidate-source-bounds.json') or str(p.relative_to(proof))=='recursion-om31/tree.json')}
record['failed_request']={'run':str(failed),'complete_root':(proof/'recursion-om31/root.proof').exists(),'present_payload_count':len(actual),'present_payloads_match_reference':all(ref.get(k)==v for k,v in actual.items()),'missing':sorted(set(ref)-set(actual)),'fingerprints':actual}
record.update(status='ALL10_COMPLETED_PROOFS_FRESH_CPU_ACCEPTED_HEADLINE_FAILURE_REMAINS',fresh_accepts=sum(len(x['receivers']) for x in record['services']))
S.write(out/'validation.json',record)
