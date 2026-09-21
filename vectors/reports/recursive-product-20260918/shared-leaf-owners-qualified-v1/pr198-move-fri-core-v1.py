from pathlib import Path
import re,json
base=Path('src/integrations/riscv_cpu');dest=Path('src/frontends/riscv/recursion')
files=[base/'recursive_fri_outer.zig',*sorted(base.glob('recursive_fri_outer_part_*.zig')),base/'recursive_fri_outer_manifest_generic_v4.zig']
originals={p.name:p.read_text() for p in files};Path('/tmp/pr198-fri-core-originals-v1.json').write_text(json.dumps(originals))
all_text='\n'.join(originals.values())
recursion_names=sorted(n for n in set(re.findall(r'\brecursion\.(\w+)',all_text)) if (dest/(n+'.zig')).exists())
air_names=sorted(n for n in set(re.findall(r'\bair\.(\w+)',all_text)) if (dest/'air'/(n+'.zig')).exists())
deps='//! Narrow shared dependencies for the generic native FRI core.\n'
deps+=''.join(f'pub const {n} = @import("{n}.zig");\n' for n in recursion_names if n!='air')
deps+='pub const air = struct {\n'+''.join(f'    pub const {n} = @import("air/{n}.zig");\n' for n in air_names)+'};\n'
(dest/'detached_fri_core_dependencies_v2.zig').write_text(deps)
main=originals['recursive_fri_outer.zig'];test_wrappers=[];test_aliases=[];transformed={}
for filename,s in originals.items():
 part=re.search(r'_part_(\d+)\.zig$',filename)
 suffix='main' if part is None else part[1]
 tests=[]
 def replace_test(m):
  name=m[1];helper=f'testMovedCore{suffix}_{len(tests)}';tests.append((name,helper));return f'pub fn {helper}() !void {{'
 s=re.sub(r'test "([^"]+)" \{',replace_test,s)
 for name,helper in tests:
  test_wrappers.append(f'test "{name}" {{\n    try owner.{helper}();\n}}\n')
  if part:test_aliases.append(f'pub const {helper} = Part{suffix}.{helper};\n')
 s=s.replace('recursive_fri_outer_part_', 'detached_fri_core_part_').replace('recursive_fri_outer_manifest_generic_v4.zig','detached_fri_core_manifest_generic_v4.zig')
 if filename.endswith('_part_00.zig'):
  s=s.replace('@import("stwo_cpu_backend").CpuBackend','context.d_Backend')
  s=s.replace('@import("stwo_riscv_frontend")','''struct {
            pub const recursion = @import("detached_fri_core_dependencies_v2.zig");
            pub const air = struct {
                pub const memory_commitment = struct { pub const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig"); };
                pub const public_data = @import("../air/public_data.zig");
                pub const public_data_v2 = @import("../air/public_data_v2.zig");
                pub const statement = @import("../air/statement.zig");
                pub const typed_poseidon2_authority = @import("../air/typed_poseidon2_authority.zig");
            };
        }''')
 if filename.endswith('_part_18.zig'):s=s.replace('@import("recursive_fri_component_parameters.zig")','@import("air/verifier_component_parameters.zig")')
 transformed[filename]=s
 if filename=='recursive_fri_outer.zig':continue
 target=filename.replace('recursive_fri_outer_part_','detached_fri_core_part_').replace('recursive_fri_outer_manifest_generic_v4.zig','detached_fri_core_manifest_generic_v4.zig')
 (dest/target).write_text(s)
main=transformed['recursive_fri_outer.zig']+''.join(test_aliases)
main=main.replace('const Context = struct {','const Context = struct {\n    pub const d_Backend = Backend;')
(dest/'detached_fri_core_v2.zig').write_text('//! Shared native FRI core; concrete backend selection belongs to the caller.\npub fn ForBackend(comptime Backend: type) type {\n    return struct {\n'+main+'\n    };\n}\n')
exports=re.findall(r'^pub (?:const|fn) (\w+)',originals['recursive_fri_outer.zig'],re.M)
facade='//! CPU binding for the shared native FRI core.\nconst owner = @import("stwo_riscv_frontend").recursion.detached_fri_core_v2.ForBackend(@import("stwo_cpu_backend").CpuBackend);\n\n'
facade+=''.join(f'pub const {n} = owner.{n};\n' for n in exports)+'\n'+''.join(test_wrappers)
(base/'recursive_fri_outer.zig').write_text(facade)
for p in files:
 if p.name!='recursive_fri_outer.zig':p.unlink()
p=dest/'mod.zig';s=p.read_text();s+='\npub const detached_fri_core_v2 = @import("detached_fri_core_v2.zig");\n';p.write_text(s)
p=Path('scripts/tests/test_product_closure.py');s=p.read_text();needle='                         "src/frontends/riscv/recursion/detached_leaf_noncore_owner_v2.zig"),';assert needle in s;s=s.replace(needle,'                         "src/frontends/riscv/recursion/detached_leaf_noncore_owner_v2.zig",\n                         "src/frontends/riscv/recursion/detached_fri_core_v2.zig"),');p.write_text(s)
Path('/tmp/pr198-fri-core-transformed-v1.json').write_text(json.dumps(transformed))
print('Moved core with',len(exports),'public bindings,',len(test_wrappers),'preserved test wrappers,',len(recursion_names),'recursion and',len(air_names),'AIR dependencies.')
