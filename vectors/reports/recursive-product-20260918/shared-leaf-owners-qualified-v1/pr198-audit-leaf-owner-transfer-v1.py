from pathlib import Path
import json,re,hashlib
root=Path('src/frontends/riscv/recursion');records=[]
def unwrapped(s):
 s=s.split('return struct {\n',1)[1]
 return s[:s.rfind('    };')]
def check(label,expected,actual):
 normalize=lambda x:re.sub(r'\s+','',x)
 a,b=normalize(expected),normalize(actual)
 records.append({'source':label,'equal_after_documented_transform':a==b,'expected_normalized_sha256':hashlib.sha256(a.encode()).hexdigest(),'actual_normalized_sha256':hashlib.sha256(b.encode()).hexdigest()})
 if a!=b:
  i=next((i for i,(x,y) in enumerate(zip(a,b)) if x!=y),min(len(a),len(b)))
  print(label,'DIFF',a[max(0,i-80):i+160],b[max(0,i-80):i+160])
noncore=json.loads(Path('/tmp/pr198-noncore-transformed-v1.json').read_text())
for kind,expected in noncore.items():
 actual=(root/f'detached_leaf_noncore_{kind}_v2.zig').read_text()
 check('noncore-'+kind,expected,actual if kind=='contract' else unwrapped(actual))
core=json.loads(Path('/tmp/pr198-fri-core-transformed-v1.json').read_text())
aliases=[]
for name,expected in core.items():
 part=re.search(r'_part_(\d+)\.zig$',name)
 if part:
  for helper in re.findall(r'pub fn (testMovedCore\w+)\(',expected):aliases.append(f'pub const {helper} = Part{part[1]}.{helper};\n')
for name,expected in core.items():
 if name=='recursive_fri_outer.zig':
  expected=expected.replace('const Context = struct {','const Context = struct {\n    pub const d_Backend = Backend;')+''.join(aliases)
  actual=unwrapped((root/'detached_fri_core_v2.zig').read_text())
 else:
  target=name.replace('recursive_fri_outer_part_','detached_fri_core_part_').replace('recursive_fri_outer_manifest_generic_v4.zig','detached_fri_core_manifest_generic_v4.zig')
  actual=(root/target).read_text()
  expected=expected.replace('../air/typed_poseidon2_authority.zig','../air/lang/typed_poseidon2_authority.zig')
 check(name,expected,actual)
cohort=json.loads(Path('/tmp/pr198-leaf-cohort-transformed-v1.json').read_text())
for name,expected in cohort.items():
 if 'tuple_closure' in name:target='detached_leaf_tuple_diagnostic_v2.zig'
 elif name.endswith('_contract.zig'):target='detached_leaf_cohort_contract_v2.zig'
 elif name.endswith('_support.zig'):target='detached_leaf_cohort_support_v2.zig'
 else:target='detached_leaf_cohort_v2.zig'
 actual=(root/target).read_text()
 check(name,expected,actual if 'tuple_closure' in name else unwrapped(actual))
report={'all_transfers_match':all(r['equal_after_documented_transform'] for r in records),'files':records,'normalization':'Whitespace ignored after the recorded module moves, explicit backend/type parameters, direct dependency imports, and promotion of existing tests to callable helpers. Original sources and transformation scripts are retained separately.'}
Path('/tmp/pr198-leaf-owners-transfer-audit-v1.json').write_text(json.dumps(report,indent=2)+'\n')
print('Transfer audit:',len(records),'files;',report['all_transfers_match'])
assert report['all_transfers_match']
