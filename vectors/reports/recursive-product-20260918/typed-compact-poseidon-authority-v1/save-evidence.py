from pathlib import Path
import json,hashlib,shutil,sys
root=Path.cwd();sys.path.insert(0,str(root/'scripts'))
from riscv_recursive_product import source_snapshot
out=root/'vectors/reports/recursive-product-20260918/typed-compact-poseidon-authority-v1'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
baseline=json.loads((root/'vectors/reports/recursive-product-20260917/canonical-identity-v2/cpu-summary.json').read_text())['artifacts'];snapshots=[]
for backend in ('cpu','metal'):
 p=Path('/tmp/pr198-product-'+backend+'-typed-compact-20260918-v1');d=json.loads((p/'product.json').read_text());t=json.loads((p/'tree/report.json').read_text());assert d['passed'] and t['passed'];snapshots.append(d['source_sha256'])
 artifacts={n:sha(p/'tree'/n) for n in baseline};assert artifacts==baseline
 cases=sum(len(json.loads(f.read_text())['cases']) for f in list((p/'tree').glob('*-accepted.json'))+list(p.glob('substitution-*.json')));assert cases==192
 summary={'passed':True,'backend':backend,'local_product':str(p),'cases':cases,'artifacts':artifacts,'binary_sha256':d['binary_sha256'],'admission_sha256':d['admission_sha256'],'steps':d['steps'],'root':t['root']}
 for k in ('native_table_interactions','leaf_typed_interactions','parent_typed_interactions'):
  if k in d:summary[k]=d[k]
 (out/(backend+'-summary.json')).write_text(json.dumps(summary,indent=2)+'\n')
assert snapshots[0]==snapshots[1]
current=source_snapshot();changed=sorted(n for n in set(current)|set(snapshots[0]) if current.get(n)!=snapshots[0].get(n));assert changed==['scripts/riscv_recursive_product.py'],changed
(out/'qualified-source-snapshot.json').write_text(json.dumps(snapshots[0],indent=2)+'\n')
(out/'post-gate-command-default.json').write_text(json.dumps({'changed_files':changed,'sha256':sha(root/changed[0]),'change':'Default admission now equals the explicit canonical admission used by both passing proof gates; substitution admission unchanged.'},indent=2)+'\n')
(out/'summary.json').write_text(json.dumps({'passed':True,'production_security_qualified':False,'canonical_tree_cases':384,'canonical_baseline_identical_artifacts':21,'compact_target_passed':127,'parent_target_passed':228,'parent_target_skipped':1,'source_closure_tests':32,'inventory_tests':2,'physical_columns':303,'ordered_direct_constraints':288,'typed_materialized_columns':284,'lookup_events':4,'interaction_batches':2,'protocol_identity_unchanged':True,'post_gate_changes':'CLI default admission only; documentation appended afterward'},indent=2)+'\n')
shutil.copyfile('/tmp/pr198-save-typed-compact-v1.py',out/'save-evidence.py')
print('Saved typed compact authority qualification: 384 proof checks; 21 identical artifacts.')
