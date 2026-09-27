"""Accept only finished, binary-matching phases; retain all raw samples."""
from pathlib import Path
import hashlib,json
H=Path(__file__).resolve().parent
phases=[('hashes','results.json','qualification.json','peer.dylib','local.dylib'),('stages','stage-results.json','stage-qualification.json','peer_stages.dylib','local_stages.dylib'),('more','more-results.json','more-qualification.json','peer_more.dylib','local_more.dylib'),('primitives','primitive-results.json','primitive-qualification.json','rust-peer/target/release/libzisk_component_primitives.dylib','local_primitives.dylib'),('fri','fri-results.json','fri-qualification.json','peer_fri.dylib','local_fri.dylib'),('protocol','protocol-results.json','protocol-qualification.json','peer_protocol.dylib','local_protocol.dylib')]
accepted=[];pending=[]
for name,r,q,peer,local in phases:
 if not (H/q).exists():pending.append(name);continue
 qualification=json.loads((H/q).read_text())
 for arm,path in [('zisk',peer),('stwo',local)]:
  assert hashlib.sha256((H/path).read_bytes()).hexdigest()==qualification['binaries'][arm],(name,arm,'binary changed')
 for row in json.loads((H/r).read_text()):
  accepted.append(dict(phase=name,**row))
battery=[]
bq=H/'battery-protocol/protocol-qualification.json'
if bq.exists():
 qualification=json.loads(bq.read_text())
 assert qualification['power_source']=='battery'
 for arm,path in [('zisk','peer_protocol.dylib'),('stwo','local_protocol.dylib')]:
  assert hashlib.sha256((H/path).read_bytes()).hexdigest()==qualification['binaries'][arm],('battery-protocol',arm,'binary changed')
 for row in json.loads((H/'battery-protocol/protocol-results.json').read_text()):
  assert row['power_source']=='battery'
  battery.append(dict(phase='protocol',**row))
result=dict(accepted_cases=len(accepted),battery_cases=len(battery),total_recorded_cases=len(accepted)+len(battery),pending_ac_phases=pending,battery_results=battery,scope='CPU component campaign; not full proof or GPU comparison',results=accepted)
(H/'campaign-results.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps({k:v for k,v in result.items() if k not in ('results','battery_results')},indent=2))
