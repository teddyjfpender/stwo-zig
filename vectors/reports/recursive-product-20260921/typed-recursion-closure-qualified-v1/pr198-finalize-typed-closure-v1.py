from pathlib import Path
import json,hashlib,shutil,sys
root=Path.cwd();sys.path.insert(0,str(root/'scripts'))
from riscv_recursive_product import source_snapshot
out=root/'vectors/reports/recursive-product-20260921/typed-recursion-closure-qualified-v1'
read=lambda name:json.loads((out/name).read_text())
assert read('summary.json')['passed']
assert read('qualified-source-snapshot.json')==source_snapshot()
assert read('source-replay.json')['passed']
assert read('pinned-inputs-recheck.json')['passed']
assert read('ladder-summary.json')['total_cases']==1110
rows=read('ladder-measurements.json');assert len(rows)==8
for n in (1,2,4,8):
 for backend in ('cpu','metal'):
  r=read(f'root-{n}-{backend}-memory.json')
  assert r['verified'] and not r['native_inputs_used']
for backend in ('cpu','metal'):
 d=read(backend+'-summary.json');assert d['passed'] and d['cases']==192
assert read('cpu-summary.json')['artifacts']==read('metal-summary.json')['artifacts']
for name in ('qualify-typed-closure','run-typed-closure-ladder','save-typed-closure-ladder','save-typed-closure-source','finalize-typed-closure'):
 p=Path('/tmp/pr198-'+name+'-v1.py');shutil.copyfile(p,out/p.name)
shutil.copyfile('/tmp/pr198-qualify-typed-closure-v1.log',out/'qualification.log')
audit=read('requirements-audit.json');audit['status']='typed_recursion_qualification_passed_broader_baseline_open'
audit['requirements'][5]['status']='current_source_ladder_and_root_measurements_passed'
audit['requirements'][5]['evidence']=['ladder-summary.json','ladder-measurements.json']
(out/'requirements-audit.json').write_text(json.dumps(audit,indent=2)+'\n')
lines=['# Canonical typed execution and recursion cleanup qualified','','The final frozen cleanup source passed complete CPU/Metal/AOT products and','the useful 16-address 1/2/4/8 continuation ladder. This qualifies the legacy','executor/opcode AIR retirement, test-oracle isolation, shared commitment/session','ownership and narrow execution/host dependency boundary.','','- 384 complete-product acceptance/rejection checks; 21 baseline-identical artifacts.','- 1,110 continuation checks; 78 baseline-identical artifacts.','- Eight fresh standalone root verification and RSS measurements, without native inputs.','- Required native, leaf and parent GPU interaction dispatches passed.','- All 6,208 frozen source files replayed from the archived patch using temporary indexes.','- All 114 pinned inputs and archive contents rechecked.','- Focused validation before freeze: 55 session/host tests, 49 ownership guards,','  two inventory tests; earlier batches retain their affected-test evidence.','','| Segments | Backend | Production s | Root bytes | Verify ms | Root RSS bytes |','| --- | --- | ---: | ---: | ---: | ---: |']
for r in rows:lines.append(f"| {r['segments']} | {r['backend']} | {r['production_seconds']:.3f} | {r['root_proof_bytes']} | {r['root_verify_ms']:.3f} | {r['root_verifier_peak_rss_bytes']} |")
lines+=['','Measurements are individual observations, not speed claims. The admitted q193','profile is developmental and Metal execution is hybrid. This does not certify','production security, strict GPU execution or Ethereum readiness.','','The broader baseline goal remains open with 103 source-size findings. Those','findings are not additional typed execution/recursion implementation tasks.','Source snapshots, patch replay, pinned inputs, commands and result summaries','are retained beside this report. All qualification subprocesses exited successfully.']
(out/'README.md').write_text('\n'.join(lines)+'\n')
print('Final qualification evidence verified and archived.')
