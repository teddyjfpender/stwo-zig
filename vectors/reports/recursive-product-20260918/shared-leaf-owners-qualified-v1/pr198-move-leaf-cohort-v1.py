from pathlib import Path
import re,json
base=Path('src/integrations/riscv_cpu');dest=Path('src/frontends/riscv/recursion')
names=['recursive_segment_v2_outer_cohort.zig','recursive_segment_v2_outer_cohort_contract.zig','recursive_segment_v2_outer_cohort_support.zig','recursive_segment_v2_tuple_closure_diagnostic.zig']
originals={n:(base/n).read_text() for n in names};Path('/tmp/pr198-leaf-cohort-originals-v1.json').write_text(json.dumps(originals))
transformed={}
for n,old in originals.items():
 s=old.replace('const frontend = @import("stwo_riscv_frontend");\n','').replace('const recursion = frontend.recursion;\n','').replace('const air = recursion.air;\n','').replace('const air = frontend.recursion.air;\n','')
 for alias,path in [('leaf_outer','recursive_segment_v2_leaf_outer.zig'),('core_mod','recursive_fri_outer.zig')]:s=s.replace(f'const {alias} = @import("{path}");\n','')
 s=s.replace('@import("recursive_segment_v2_noncore_owner.zig")','@import("detached_leaf_noncore_owner_v2.zig").For(leaf_outer)')
 s=s.replace('@import("recursive_segment_v2_tuple_closure_diagnostic.zig")','@import("detached_leaf_tuple_diagnostic_v2.zig")')
 for kind in ('contract','support'):s=s.replace(f'@import("recursive_segment_v2_outer_cohort_{kind}.zig")',f'@import("detached_leaf_cohort_{kind}_v2.zig").For(leaf_outer, core_mod)')
 s=s.replace('@import("recursive_segment_v2_verifier_components.zig")','@import("detached_segment_recording_components_v1.zig")').replace('@import("recursive_segment_v2_authority_boundary.zig")','@import("detached_segment_authority_boundary_v1.zig")')
 s=re.sub(r'\brecursion\.air\.(\w+)',lambda m:'@import("air/'+m[1]+'.zig")',s)
 s=re.sub(r'\brecursion\.(\w+)',lambda m:'@import("'+m[1]+'.zig")',s)
 s=re.sub(r'\bair\.(\w+)',lambda m:'@import("air/'+m[1]+'.zig")',s)
 tests=[]
 def replace_test(m):
  helper='testMovedLeafCohort'+str(len(tests));tests.append((m[1],helper));return f'pub fn {helper}() !void {{'
 s=re.sub(r'test "([^"]+)" \{',replace_test,s)
 transformed[n]=s
 if 'tuple_closure' in n:target='detached_leaf_tuple_diagnostic_v2.zig'
 elif n.endswith('_contract.zig'):target='detached_leaf_cohort_contract_v2.zig'
 elif n.endswith('_support.zig'):target='detached_leaf_cohort_support_v2.zig'
 else:target='detached_leaf_cohort_v2.zig'
 if 'tuple_closure' not in n:s='//! Shared concrete leaf cohort ownership.\npub fn For(comptime leaf_outer: type, comptime core_mod: type) type {\n    return struct {\n'+s+'\n    };\n}\n'
 (dest/target).write_text(s)
 if n.endswith(('_contract.zig','_support.zig')):(base/n).unlink();continue
 module='detached_leaf_tuple_diagnostic_v2' if 'tuple_closure' in n else 'detached_leaf_cohort_v2'
 factory='' if 'tuple_closure' in n else '.For(@import("recursive_segment_v2_leaf_outer.zig"), @import("recursive_fri_outer.zig"))'
 facade=f'//! Integration binding for the shared {module} owner.\nconst owner = @import("stwo_riscv_frontend").recursion.{module}{factory};\n\n'
 exports=re.findall(r'^pub (?:const|fn) (\w+)',old,re.M)
 facade+=''.join(f'pub const {name} = owner.{name};\n' for name in exports)
 facade+='\n'+''.join(f'test "{name}" {{\n    try owner.{helper}();\n}}\n' for name,helper in tests)
 (base/n).write_text(facade)
p=dest/'mod.zig';s=p.read_text();s+='\npub const detached_leaf_cohort_v2 = @import("detached_leaf_cohort_v2.zig");\npub const detached_leaf_tuple_diagnostic_v2 = @import("detached_leaf_tuple_diagnostic_v2.zig");\n';p.write_text(s)
p=Path('scripts/tests/test_product_closure.py');s=p.read_text();needle='                         "src/frontends/riscv/recursion/detached_fri_core_v2.zig"),';assert needle in s;s=s.replace(needle,'                         "src/frontends/riscv/recursion/detached_fri_core_v2.zig",\n                         "src/frontends/riscv/recursion/detached_leaf_cohort_v2.zig"),');p.write_text(s)
Path('/tmp/pr198-leaf-cohort-transformed-v1.json').write_text(json.dumps(transformed))
