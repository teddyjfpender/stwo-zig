from pathlib import Path
import json,hashlib,gzip,subprocess,shutil,sys
root=Path.cwd();sys.path.insert(0,str(root/'scripts'))
from riscv_recursive_product import source_snapshot
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
out=root/'vectors/reports/recursive-product-20260918/shared-producer-accounting-qualified-v1'
snapshot=source_snapshot();summaries={}
baseline=json.loads((root/'vectors/reports/recursive-product-20260917/canonical-identity-v2/cpu-summary.json').read_text())['artifacts']
for backend in ['cpu','metal']:
 p=Path('/tmp/pr198-product-'+backend+'-shared-tracker-20260918-v1');d=json.loads((p/'product.json').read_text());t=json.loads((p/'tree/report.json').read_text());assert d['passed'] and t['passed'] and d['source_sha256']==snapshot
 artifacts={name:sha(p/'tree'/name) for name in baseline};assert artifacts==baseline
 cases=sum(len(json.loads(f.read_text())['cases']) for f in list((p/'tree').glob('*-accepted.json'))+list(p.glob('substitution-*.json')));assert cases==192
 summaries[backend]={'passed':True,'backend':backend,'local_product':str(p),'total_cases':cases,'baseline_identical_artifacts':21,'artifacts':artifacts,'binary_sha256':d['binary_sha256'],'steps':d['steps'],'admission_sha256':d['admission_sha256'],'root':t['root'],'measurements':{k:t[k] for k in ['leaf_production_ns','parent_production_ns','maximum_rss_bytes']}}
 for k in ['native_table_interactions','leaf_typed_interactions','parent_typed_interactions']:
  if k in d:summaries[backend][k]=d[k]
ladder=Path('/tmp/pr198-shared-tracker-ladder-20260918-v1');l=json.loads((ladder/'summary.json').read_text());assert l['passed'] and l['total_cases']==1110 and json.loads((ladder/'source-snapshot.json').read_text())==snapshot
assert 'All 1 tests passed.' in Path('/tmp/pr198-tracked-allocator-focused-v1.log').read_text()
assert '2/2 tests passed' in Path('/tmp/pr198-tracked-allocator-integration-v1.log').read_text()
assert 'Ran 15 tests' in Path('/tmp/pr198-tracked-allocator-ownership-v1.log').read_text()
out.mkdir(exist_ok=False)
paths=['src','scripts','build_support','design','conformance','build.zig','build.zig.zon'];patch=subprocess.check_output(['git','diff','--binary','HEAD','--',*paths])
for name in subprocess.check_output(['git','ls-files','--others','--exclude-standard','--',*paths]).decode().splitlines():
 r=subprocess.run(['git','diff','--binary','--no-index','--','/dev/null',name],capture_output=True);assert r.returncode in (0,1);patch+=r.stdout
(out/'source.patch.gz').write_bytes(gzip.compress(patch,mtime=0));(out/'source-snapshot.json').write_text(json.dumps(snapshot,indent=2)+'\n')
for b,d in summaries.items():(out/(b+'-summary.json')).write_text(json.dumps(d,indent=2)+'\n')
for f in ladder.glob('*-summary.json'):shutil.copyfile(f,out/f.name)
shutil.copyfile(ladder/'summary.json',out/'ladder-summary.json')
for n in [1,2,4,8]:
 for b in ['cpu','metal']:
  shutil.copyfile(ladder/f'{n}-{b}/report.json',out/f'{n}-{b}-tree-report.json')
  shutil.copyfile(ladder/f'{n}-{b}-substitution.json',out/f'{n}-{b}-substitution.json')
for source,target in [('pr198-tracked-allocator-focused-v1.log','allocator-test.log'),('pr198-tracked-allocator-integration-v1.log','integration-tests.log'),('pr198-tracked-allocator-ownership-v1.log','ownership.log'),('pr198-tracked-allocator-transfer-v1.json','transfer-audit.json'),('pr198-legacy-wrapper-audit-v1.md','remaining-wrapper-audit.md'),('pr198-run-shared-tracker-ladder-v1.py','replay-ladder.py'),('pr198-move-tracked-allocator-v1.py','move-allocator.py'),('pr198-save-shared-tracker-v1.py','save-qualification.py')]:shutil.copyfile('/tmp/'+source,out/target)
(out/'original-allocator.txt').write_text(Path('/tmp/pr198-tracked-allocator-original-v1.txt').read_text())
(out/'summary.json').write_text(json.dumps({'passed':True,'production_security_qualified':False,'canonical_tree_cases':384,'ladder_cases':1110,'ladder_baseline_identical_artifacts':78,'focused_tests':3,'ownership_tests':15,'allocator_body_identical_after_type_rename':True,'legacy_outer_wrapper_migrated':False,'leaf_device_ladder_qualified':True,'source_patch_sha256':sha(out/'source.patch.gz')},indent=2)+'\n')
print('Saved shared producer accounting and current leaf-device ladder qualification.')
for name,d in l['reports'].items():print(name,d['measurements'])
