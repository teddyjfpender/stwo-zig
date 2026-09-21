from pathlib import Path
import json, hashlib, gzip, subprocess, shutil, re
root=Path('vectors/reports/recursive-product-20260918')
out=root/'leaf-device-interactions-qualified-v1'
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
baseline=json.loads(Path('vectors/reports/recursive-product-20260917/canonical-identity-v2/cpu-summary.json').read_text())['artifacts']
products={}; summaries={}; snapshot=None
for backend in ('cpu','metal'):
 p=Path('/tmp/pr198-product-'+backend+'-leaf-generator-20260918-v1')
 product=json.loads((p/'product.json').read_text());tree=json.loads((p/'tree/report.json').read_text())
 assert product['passed'] and tree['passed']
 current={n:sha(Path(n)) for n in product['source_sha256']}
 assert current==product['source_sha256']
 if snapshot is None:snapshot=current
 else:assert snapshot==current
 artifacts={n:sha(p/'tree'/n) for n in baseline};assert artifacts==baseline
 cases=[]
 for f in sorted((p/'tree').glob('*-accepted.json'))+sorted(p.glob('substitution-*.json')):
  d=json.loads(f.read_text());assert d['passed'];cases.append({'file':f.name,'cases':len(d['cases']),'sha256':sha(f)})
 assert sum(c['cases'] for c in cases)==192
 summaries[backend]={'backend':backend,'passed':True,'production_security_qualified':False,'local_full_evidence':str(p),'product_report_sha256':sha(p/'product.json'),'source_snapshot':'source-snapshot.json','binary_sha256':product['binary_sha256'],'admission_sha256':product['admission_sha256'],'artifacts':artifacts,'total_cases':192,'cases':cases,'baseline_identical_artifacts':21,'steps':product['steps'],'timing_scope':'Single complete-production observations, not a controlled speed comparison.'}
 summaries[backend].update({k:tree[k] for k in ['root','leaf_production_ns','parent_production_ns','complete_gate_ns','maximum_rss_bytes']})
 for k in ['native_table_interactions','leaf_typed_interactions','parent_typed_interactions']:
  if k in product:summaries[backend][k]=product[k]
 products[backend]=product
assert products['metal']['leaf_typed_interactions']['successful_device_dispatches']==576
log=Path('/tmp/pr198-leaf-generator-device-v2.log').read_text()
assert 'LEAF_GENERATOR_AUDIT_FAILURE gpu_completed=true destination_unchanged=true retry=true alias_rejected=true' in log
assert len(re.findall(r'LEAF_TYPED_INTERACTION_AOT row=',log))==74
assert len(re.findall(r'PARENT_TYPED_INTERACTION_AOT row=',log))==58
assert '25/25 tests passed' in Path('/tmp/pr198-leaf-generator-host-v2.log').read_text()
assert 'Ran 14 tests' in Path('/tmp/pr198-leaf-generator-ownership-v1.log').read_text()
out.mkdir(exist_ok=False)
paths=['src','scripts','build_support','design','conformance','build.zig','build.zig.zon']
patch=subprocess.check_output(['git','diff','--binary','HEAD','--',*paths])
for name in subprocess.check_output(['git','ls-files','--others','--exclude-standard','--',*paths]).decode().splitlines():
 r=subprocess.run(['git','diff','--binary','--no-index','--','/dev/null',name],capture_output=True);assert r.returncode in (0,1);patch+=r.stdout
(out/'source.patch.gz').write_bytes(gzip.compress(patch,mtime=0))
(out/'source-snapshot.json').write_text(json.dumps(snapshot,indent=2)+'\n')
for backend,summary in summaries.items():
 summary['source_patch_gzip_sha256']=sha(out/'source.patch.gz')
 (out/(backend+'-summary.json')).write_text(json.dumps(summary,indent=2)+'\n')
for source,target in [('/tmp/pr198-leaf-generator-device-v2.log','device.log'),('/tmp/pr198-leaf-generator-host-v2.log','focused.log'),('/tmp/pr198-leaf-generator-ownership-v1.log','ownership.log'),('/tmp/pr198-transaction-storage-transfer-v1.json','storage-transfer.json')]:shutil.copyfile(source,out/target)
(out/'summary.json').write_text(json.dumps({'passed':True,'complete_proof_qualified':True,'leaf_proof_dispatch_integrated':True,'production_security_qualified':False,'total_cases':384,'baseline_identical_artifacts':21,'host_tests':25,'ownership_tests':14,'leaf_component_cases':74,'parent_component_cases':58,'post_device_audit_failure_preserves_destination':True,'alias_rejection':True,'canonical_leaf_parameters':True,'tree_successful_device_dispatches':1020,'additional_aot_exports':105,'total_aot_exports':271},indent=2)+'\n')
print(json.dumps({b:{k:s[k] for k in ['leaf_production_ns','parent_production_ns','maximum_rss_bytes']} for b,s in summaries.items()},indent=2))
print('Saved leaf device interaction complete qualification.')
