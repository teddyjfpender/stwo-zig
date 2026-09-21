from pathlib import Path
import subprocess,sys,json,hashlib,gzip,shutil
root=Path.cwd();sys.path.insert(0,str(root/'scripts'))
from riscv_recursive_product import source_snapshot
out=root/'vectors/reports/recursive-product-20260921/typed-recursion-final-qualified-v1'
snapshot=source_snapshot()
(out/'qualified-source-snapshot.json').write_text(json.dumps(snapshot,indent=2)+'\n')
baseline=json.loads((root/'vectors/reports/recursive-product-20260917/canonical-identity-v2/cpu-summary.json').read_text())['artifacts']
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
for backend in ('cpu','metal'):
 p=Path('/tmp/pr198-product-'+backend+'-typed-final-20260921-v1')
 subprocess.run([sys.executable,'scripts/riscv_recursive_product.py','--backend',backend,'--output',str(p)],check=True)
 d=json.loads((p/'product.json').read_text());t=json.loads((p/'tree/report.json').read_text())
 assert d['passed'] and t['passed'] and d['source_sha256']==snapshot==source_snapshot()
 artifacts={n:sha(p/'tree'/n) for n in baseline};assert artifacts==baseline
 cases=sum(len(json.loads(f.read_text())['cases']) for f in list((p/'tree').glob('*-accepted.json'))+list(p.glob('substitution-*.json')));assert cases==192
 summary={'passed':True,'backend':backend,'local_product':str(p),'cases':cases,'artifacts':artifacts,'binary_sha256':d['binary_sha256'],'admission_sha256':d['admission_sha256'],'steps':d['steps'],'root':t['root']}
 for k in ('native_table_interactions','leaf_typed_interactions','parent_typed_interactions'):
  if k in d:summary[k]=d[k]
 (out/(backend+'-summary.json')).write_text(json.dumps(summary,indent=2)+'\n')
 with gzip.open(out/(backend+'-product.json.gz'),'wb') as f:f.write((p/'product.json').read_bytes())
subprocess.run([sys.executable,'/tmp/pr198-run-typed-final-ladder-v1.py'],check=True)
subprocess.run([sys.executable,'/tmp/pr198-save-typed-final-ladder-v1.py'],check=True)
assert source_snapshot()==snapshot
(out/'summary.json').write_text(json.dumps({'passed':True,'canonical_tree_cases':384,'canonical_baseline_identical_artifacts':21,'continuation_cases':1110,'continuation_baseline_identical_artifacts':78,'focused_package_ownership_checks':66,'production_security_qualified':False,'goal_complete':False},indent=2)+'\n')
shutil.copyfile('/tmp/pr198-qualify-typed-final-v1.py',out/'qualify.py')
print('Canonical public surface qualification passed.',flush=True)
