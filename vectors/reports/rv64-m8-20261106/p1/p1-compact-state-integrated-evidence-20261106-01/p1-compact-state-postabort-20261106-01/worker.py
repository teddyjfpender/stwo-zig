from pathlib import Path
import json,sys,subprocess,os,time
root=Path('/workspace/m3/src/m7-integrate');sys.path.insert(0,str(root/'scripts'));import rv64_m7_integration_stack as S;import rv64_gate as G
b=Path('/workspace/m3/runs/m7-integrate');out=b/'p1-compact-state-postabort-20261106-01'
base=b/'daemon-26235156-r2-p1-compact-state-small-20261106-04-one-stack-v5-smoke-00-baseline';failed=b/'daemon-26235156-r2-p1-compact-state-small-20261106-04-one-stack-v5-smoke-01-fullstack'
d={'status':'BASELINE_RECEIVER_RUNNING','candidate_status':'120s watchdog, no root, headline skipped'}
S.write(out/'postabort.json',d)
try:
 env=S.clean_environment(os.environ)
 with (out/'baseline-receive.log').open('w') as log:r=subprocess.run([sys.executable,str(root/'scripts/rv64_m4_resident.py'),'receive','--run',str(base),'--which','all','--receiver-workers','16'],cwd=root,env=env,stdout=log,stderr=subprocess.STDOUT)
 assert r.returncode==0
 receipt=json.loads((base/'receipt.json').read_text());assert len(receipt['receivers'])==2 and all(v['accepted'] for v in receipt['receivers'])
 ref=b/'daemon-26235156-r2-p1-outer-chunks-small-20261106-01-one-stack-v5-smoke-00-baseline'
 expected=S.fingerprints(json.loads((ref/'receipt.json').read_text())['requests'][0],require_capture=True)
 golden=json.loads((G.GOLDEN/'26235156-combined-d2-coalesce-v1/trial-1/artifact-fingerprints.json').read_text())
 d['frozen_parity']=[]
 for request in receipt['requests']:
  assert S.fingerprints(request,require_capture=True)==expected
  d['frozen_parity'].append(G.frozen_parity(Path(request['proof']),golden))
 d['fresh_receivers']=receipt['receivers']
 reference=Path(receipt['requests'][0]['proof']);partial=failed/'spool/out/0000-26235156/26235156/proof'
 actual={str(p.relative_to(partial)):{'bytes':p.stat().st_size,'sha256':S.sha(p)} for p in partial.rglob('*') if p.is_file() and G.payload_name(str(p.relative_to(partial)))}
 known={str(p.relative_to(reference)):{'bytes':p.stat().st_size,'sha256':S.sha(p)} for p in reference.rglob('*') if p.is_file() and G.payload_name(str(p.relative_to(reference)))}
 d['partial_audit']={'present':actual,'all_present_match':all(known.get(k)==v for k,v in actual.items()),'missing':sorted(set(known)-set(actual)),'has_root':'recursion-om31/root.proof' in actual,'scope':'Partial files are not proof acceptance'}
 d['status']='BASELINE2_FRESH_ACCEPTED_EXACT_REFERENCE_AND_FROZEN;GATE_RUNNING';S.write(out/'postabort.json',d)
 m=json.loads((b/'p1-compact-state-smoke-controller-20261106-04/artifact.json').read_text());S.validate_manifest(m)
 assets={k:m['assets'][k] for k in ['library','sparse','observer','process_budget_guard']}
 runtime={'schema':'rv64-pinned-cuda-runtime/v1','scope':'Current compact-state source image; default feature flags remain off in preservation gate.','assets':assets,'asset_sha256':{k:S.sha(p) for k,p in assets.items()}}
 S.write(out/'runtime.json',runtime)
 gate=b/'p1-compact-state-gate-20261106-01'
 argv=['bash','scripts/rv64_gate.sh','--stream','m7-integrate','--out',str(gate),'--runtime',str(out/'runtime.json'),'--source-commit',m['source_commit']]
 with (out/'gate.log').open('w') as log:r=subprocess.run(argv,cwd=root,env=dict(env,ZIG_GLOBAL_CACHE_DIR='/workspace/m3/cache/zig-global',TMPDIR='/workspace/m3/tmp'),stdout=log,stderr=subprocess.STDOUT)
 assert r.returncode==0 and json.loads((gate/'gate.json').read_text())['status']=='PASS'
 d.update(status='BASELINE2_FRESH_ACCEPTED_EXACT;PRESERVATION_GATE_PASS',gate=str(gate))
except BaseException as e:d.update(status='FAIL',error=repr(e));raise
finally:S.write(out/'postabort.json',d)
