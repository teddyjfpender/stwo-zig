from pathlib import Path
import json,hashlib,shutil,sys
root=Path.cwd();sys.path.insert(0,str(root/'scripts'))
from riscv_recursive_product import source_snapshot
out=root/'vectors/reports/recursive-product-20260918/canonical-parent-retirement-v1'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
baseline=json.loads((root/'vectors/reports/recursive-product-20260917/canonical-identity-v2/cpu-summary.json').read_text())['artifacts'];snapshots=[]
for backend in ('cpu','metal'):
 p=Path('/tmp/pr198-product-'+backend+'-canonical-parent-20260918-v1');d=json.loads((p/'product.json').read_text());t=json.loads((p/'tree/report.json').read_text());assert d['passed'] and t['passed'];snapshots.append(d['source_sha256'])
 artifacts={n:sha(p/'tree'/n) for n in baseline};assert artifacts==baseline
 cases=sum(len(json.loads(f.read_text())['cases']) for f in list((p/'tree').glob('*-accepted.json'))+list(p.glob('substitution-*.json')));assert cases==192
 summary={'passed':True,'backend':backend,'local_product':str(p),'cases':cases,'artifacts':artifacts,'binary_sha256':d['binary_sha256'],'admission_sha256':d['admission_sha256'],'steps':d['steps'],'root':t['root']}
 for k in ('native_table_interactions','leaf_typed_interactions','parent_typed_interactions'):
  if k in d:summary[k]=d[k]
 (out/(backend+'-summary.json')).write_text(json.dumps(summary,indent=2)+'\n')
assert snapshots[0]==snapshots[1]
current=source_snapshot();changed=sorted(n for n in set(current)|set(snapshots[0]) if current.get(n)!=snapshots[0].get(n));assert changed==['src/frontends/riscv/test_inventory.zig'],changed
(out/'qualified-source-snapshot.json').write_text(json.dumps(snapshots[0],indent=2)+'\n')
(out/'post-gate-test-inventory.json').write_text(json.dumps({'changed_files':changed,'sha256':sha(root/changed[0]),'checks':2,'passed':True},indent=2)+'\n')
for name in ('pr198-parent-retirement-inventory-v1.log','pr198-save-parent-retirement-v1.py'):shutil.copyfile(Path('/tmp')/name,out/name)
for source in ('src/frontends/riscv/recursion/air/direct_constraint_program.zig','src/frontends/riscv/poseidon2_protocol_identity_test_root.zig','scripts/tests/test_product_closure.py','src/frontends/riscv/test_inventory.zig'):
 shutil.copyfile(root/source,out/'qualified-source'/Path(source).name)
(out/'summary.json').write_text(json.dumps({'passed':True,'production_security_qualified':False,'canonical_tree_cases':384,'canonical_baseline_identical_artifacts':21,'focused_passed':223,'focused_skipped':1,'source_closure_tests':32,'inventory_tests':2,'audited_parent_key_references':14,'retired_parent_variants':['qm31_mul_full','wide_poseidon','compact_poseidon_legacy_source_digest'],'post_gate_changes':'test inventory wiring only; documentation appended afterward'},indent=2)+'\n')
print('Saved 384 checks and 21 identical artifacts; source snapshots match across backends.')
