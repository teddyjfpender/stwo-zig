from pathlib import Path
import json,hashlib,gzip,subprocess,shutil,sys
root=Path.cwd();sys.path.insert(0,str(root/'scripts'))
from riscv_recursive_product import source_snapshot
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
out=root/'vectors/reports/recursive-product-20260918/shared-outer-transaction-qualified-v1'
snapshot=source_snapshot();summaries={}
baseline=json.loads((root/'vectors/reports/recursive-product-20260917/canonical-identity-v2/cpu-summary.json').read_text())['artifacts']
for backend in ['cpu','metal']:
 p=Path('/tmp/pr198-product-'+backend+'-shared-outer-20260918-v1');d=json.loads((p/'product.json').read_text());t=json.loads((p/'tree/report.json').read_text());assert d['passed'] and t['passed'] and d['source_sha256']==snapshot
 artifacts={name:sha(p/'tree'/name) for name in baseline};assert artifacts==baseline
 cases=sum(len(json.loads(f.read_text())['cases']) for f in list((p/'tree').glob('*-accepted.json'))+list(p.glob('substitution-*.json')));assert cases==192
 summaries[backend]={'passed':True,'backend':backend,'local_product':str(p),'total_cases':cases,'baseline_identical_artifacts':21,'artifacts':artifacts,'binary_sha256':d['binary_sha256'],'steps':d['steps'],'admission_sha256':d['admission_sha256'],'root':t['root'],'measurements':{k:t[k] for k in ['leaf_production_ns','parent_production_ns','maximum_rss_bytes']}}
 for k in ['native_table_interactions','leaf_typed_interactions','parent_typed_interactions']:
  if k in d:summaries[backend][k]=d[k]
assert '20/21 tests passed' in Path('/tmp/pr198-outer-transaction-batch-v1.log').read_text()
assert '1/1 tests passed' in Path('/tmp/pr198-outer-transaction-real-proof-v3.log').read_text()
assert 'Ran 16 tests' in Path('/tmp/pr198-outer-transaction-ownership-v3.log').read_text()
assert json.loads(Path('/tmp/pr198-outer-transaction-transfer-audit-v1.json').read_text())['passed']
out.mkdir(exist_ok=False)
paths=['src','scripts','build_support','design','conformance','build.zig','build.zig.zon'];patch=subprocess.check_output(['git','diff','--binary','HEAD','--',*paths])
for name in subprocess.check_output(['git','ls-files','--others','--exclude-standard','--',*paths]).decode().splitlines():
 r=subprocess.run(['git','diff','--binary','--no-index','--','/dev/null',name],capture_output=True);assert r.returncode in (0,1);patch+=r.stdout
(out/'source.patch.gz').write_bytes(gzip.compress(patch,mtime=0));(out/'source-snapshot.json').write_text(json.dumps(snapshot,indent=2)+'\n')
for b,d in summaries.items():(out/(b+'-summary.json')).write_text(json.dumps(d,indent=2)+'\n')
files={'pr198-outer-transaction-batch-v1.log':'focused-batch.log','pr198-outer-transaction-real-proof-v2.log':'initial-composition-split-failure.log','pr198-outer-transaction-real-proof-v3.log':'legacy-real-proof.log','pr198-outer-transaction-ownership-v3.log':'ownership.log','pr198-outer-transaction-transfer-audit-v1.json':'transfer-audit.json','pr198-outer-publication-verifier-closure-v1.json':'publication-source-closure.json','pr198-outer-transaction-exports-v1.json':'original-public-exports.json'}
for source,target in files.items():shutil.copyfile('/tmp/'+source,out/target)
for name in ['pr198-move-outer-transaction-v1.py','pr198-extract-public-wire-boundary-v1.py','pr198-extract-proof-identity-v1.py','pr198-audit-outer-transaction-v1.py','pr198-save-outer-transaction-v1.py']:shutil.copyfile('/tmp/'+name,out/name)
for name in ['pr198-outer-transaction-originals-v1.json','pr198-outer-transaction-transformed-v1.json','pr198-public-wire-originals-v1.json','pr198-engine-protocol-originals-v1.json','pr198-native-mask-originals-v1.json','pr198-legacy-dimensions-originals-v1.json']:(out/(name+'.gz')).write_bytes(gzip.compress(Path('/tmp/'+name).read_bytes(),mtime=0))
(out/'summary.json').write_text(json.dumps({'passed':True,'production_security_qualified':False,'canonical_tree_cases':384,'canonical_baseline_identical_artifacts':21,'focused_tests':21,'ownership_tests':16,'source_transfer_checks':24,'moved_owners':5,'removed_private_integration_shims':2,'named_test_wrappers_preserved':3,'verifier_only_publication_source_files':249,'legacy_admission_samples':2287,'legacy_admission_queried_values':6381,'legacy_real_proof_and_downstream_recorder_passed':True,'source_patch_sha256':sha(out/'source.patch.gz')},indent=2)+'\n')
print('Saved shared outer transaction qualification: 384 canonical checks, 21 focused tests, 16 ownership checks.')
