from pathlib import Path
import re,json
base=Path('src/integrations/riscv_cpu'); dest=Path('src/frontends/riscv/recursion')
originals={k:(base/f'recursive_segment_v2_noncore_{k}.zig').read_text() for k in ('owner','contract','support','runtime')}
Path('/tmp/pr198-noncore-originals-v1.json').write_text(json.dumps(originals))
transformed={}
for kind,s in originals.items():
 s=s.replace('const frontend = @import("stwo_riscv_frontend");\n','').replace('const recursion = frontend.recursion;\n','').replace('const leaf_outer = @import("recursive_segment_v2_leaf_outer.zig");\n','')
 s=re.sub(r'\brecursion\.air\.(\w+)',lambda m:'@import("air/'+m[1]+'.zig")',s)
 s=re.sub(r'\brecursion\.(\w+)',lambda m:'@import("'+m[1]+'.zig")',s)
 s=re.sub(r'\bfrontend\.air\.(\w+)',lambda m:'@import("../air/'+m[1]+'.zig")',s)
 for name in ('contract','support','runtime'):
  old=f'@import("recursive_segment_v2_noncore_{name}.zig")'
  new=f'@import("detached_leaf_noncore_{name}_v2.zig")'+('' if name=='contract' else '.For(leaf_outer)')
  s=s.replace(old,new)
 transformed[kind]=s
 if kind!='contract':
  s='//! Shared leaf noncore '+kind+'; the caller supplies the prepared leaf types.\npub fn For(comptime leaf_outer: type) type {\n    return struct {\n'+s+'\n    };\n}\n'
 (dest/f'detached_leaf_noncore_{kind}_v2.zig').write_text(s)
Path('/tmp/pr198-noncore-transformed-v1.json').write_text(json.dumps(transformed))
exports=re.findall(r'^pub (?:const|fn) (\w+)',originals['owner'],re.M)
facade='//! Integration binding for the shared leaf noncore owner.\nconst owner = @import("stwo_riscv_frontend").recursion.detached_leaf_noncore_owner_v2.For(@import("recursive_segment_v2_leaf_outer.zig"));\n\n'
facade+=''.join(f'pub const {name} = owner.{name};\n' for name in exports)
(base/'recursive_segment_v2_noncore_owner.zig').write_text(facade)
for kind in ('contract','support','runtime'):(base/f'recursive_segment_v2_noncore_{kind}.zig').unlink()
p=dest/'mod.zig';s=p.read_text();needle='pub const detached_native_leaf_preparation_v2 =';i=s.index('\n',s.index(needle))+1;s=s[:i]+'pub const detached_leaf_noncore_owner_v2 = @import("detached_leaf_noncore_owner_v2.zig");\n'+s[i:];p.write_text(s)
p=Path('scripts/tests/test_product_closure.py');s=p.read_text();needle='                         "src/frontends/riscv/recursion/detached_native_leaf_preparation_v2.zig"),';assert needle in s;s=s.replace(needle,'                         "src/frontends/riscv/recursion/detached_native_leaf_preparation_v2.zig",\n                         "src/frontends/riscv/recursion/detached_leaf_noncore_owner_v2.zig"),');p.write_text(s)
print('Moved four noncore implementation files; removed three private integration files; preserved',len(exports),'public bindings.')
