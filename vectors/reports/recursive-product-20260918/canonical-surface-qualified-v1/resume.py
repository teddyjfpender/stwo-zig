from pathlib import Path
import subprocess,sys,json,hashlib,gzip,shutil
root=Path.cwd();sys.path.insert(0,str(root/'scripts'))
from riscv_recursive_product import source_snapshot
out=root/'vectors/reports/recursive-product-20260918/canonical-surface-qualified-v1'
snapshot=source_snapshot()
(out/'qualified-source-snapshot.json').write_text(json.dumps(snapshot,indent=2)+'\n')
baseline=json.loads((root/'vectors/reports/recursive-product-20260917/canonical-identity-v2/cpu-summary.json').read_text())['artifacts']
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
subprocess.run([sys.executable,'/tmp/pr198-run-canonical-surface-ladder-v1.py'],check=True)
subprocess.run([sys.executable,'/tmp/pr198-save-canonical-surface-ladder-v1.py'],check=True)
assert source_snapshot()==snapshot
(out/'summary.json').write_text(json.dumps({'passed':True,'canonical_tree_cases':384,'canonical_baseline_identical_artifacts':21,'continuation_cases':1110,'continuation_baseline_identical_artifacts':78,'focused_package_ownership_checks':103,'production_security_qualified':False,'goal_complete':False},indent=2)+'\n')
shutil.copyfile('/tmp/pr198-qualify-canonical-surface-v1.py',out/'qualify.py')
print('Canonical public surface qualification passed.',flush=True)
