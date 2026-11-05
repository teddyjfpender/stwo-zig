from pathlib import Path
import json,sys,time
root=Path('/workspace/m3/src/m7-integrate');sys.path.insert(0,str(root/'scripts'))
import rv64_m4_resident as R
import rv64_m7_integration_stack as S
out=Path('/workspace/m3/runs/m7-integrate/p1-inter-reuse-headline-20261106-02')
experiment=json.loads((out/'experiment.json').read_text());manifest=json.loads((out/'artifact.json').read_text());S.validate_manifest(manifest)
services=[s for s in experiment['services'] if not s['profiled']]
assert len(services)==6 and all(s.get('exit_code')==0 and s.get('payload_byte_parity') for s in services)
record={'status':'VALIDATING_12_TIMED_PROOFS_AFTER_PROFILE_STARTUP_FAILURE','profile_error':'Nsight process probe timeout before READY; no profiled request','services':[]}
S.write(out/'post-abort-receivers.json',record)
for entry in services:
 receivers=R.receive_run(Path(entry['run']),'all',16)
 assert len(receivers)==2 and all(v.get('accepted') for v in receivers)
 record['services'].append({'run':entry['run'],'arm':entry['arm'],'order_index':entry['order_index'],'receivers':receivers});S.write(out/'post-abort-receivers.json',record)
record['status']='ALL_12_TIMED_PROOFS_FRESH_CPU_ACCEPTED';S.write(out/'post-abort-receivers.json',record);(out/'post-abort-receivers.exit').write_text('0\n')
