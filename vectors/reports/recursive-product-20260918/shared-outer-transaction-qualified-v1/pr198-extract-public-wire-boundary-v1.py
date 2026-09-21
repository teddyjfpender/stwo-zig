from pathlib import Path
import re,json
root=Path('src/frontends/riscv/recursion');cp=root/'segment_outer_cohort_v2_cohort_plan_v2.zig';ct=root/'segment_outer_cohort_v2_contract.zig'
a=cp.read_text();b=ct.read_text();Path('/tmp/pr198-public-wire-originals-v1.json').write_text(json.dumps({str(cp):a,str(ct):b}))
def extract(s,start):
 i=s.index(start);brace=s.index('{',i);depth=1;j=brace+1
 while depth:
  if s[j]=='{':depth+=1
  elif s[j]=='}':depth-=1
  j+=1
 if s[j:j+1]==';':j+=1
 return s[i:j]
body=extract(a,'pub const PublicWireBoundaryV2 = struct');funcs={name:extract(a,'pub fn '+name+'(') for name in ['publicWireBoundaryIdentity','requireCanonical','allZero','hashQM31']};hashint=extract(b,'pub fn hashInt(')
err=extract(b,'pub const Error =');err=err.replace('manifest_mod.Error || catalog_mod.Error ||','manifest_mod.Error ||')
version=re.search(r'pub const PUBLIC_WIRE_BOUNDARY_FORMAT_VERSION[^;]+;',b)[0];domain=re.search(r'pub const PUBLIC_WIRE_BOUNDARY_ID_DOMAIN[^;]+;',b)[0]
header='//! Verifier-only public-wire boundary value, identity and validation.\nconst std = @import("std");\nconst stwo_core = @import("stwo_core");\nconst QM31 = stwo_core.fields.qm31.QM31;\nconst digest = @import("../air/lang/digest.zig");\nconst relation = @import("../air/lang/relation.zig");\nconst manifest_mod = @import("air/segment_outer_manifest_contract_v2.zig");\n\n'
new=header+'\n\n'.join([version,domain,err,body,*funcs.values(),hashint])+'\n';(root/'segment_public_wire_boundary_v2.zig').write_text(new)
alias='@import("segment_public_wire_boundary_v2.zig")'
a=a.replace(body,'pub const PublicWireBoundaryV2 = '+alias+'.PublicWireBoundaryV2;')
for name,body in funcs.items():a=a.replace(body,'pub const '+name+' = '+alias+'.'+name+';')
b=b.replace(extract(b,'pub const Error ='),'pub const Error = '+alias+'.Error;').replace(version,'pub const PUBLIC_WIRE_BOUNDARY_FORMAT_VERSION = '+alias+'.PUBLIC_WIRE_BOUNDARY_FORMAT_VERSION;').replace(domain,'pub const PUBLIC_WIRE_BOUNDARY_ID_DOMAIN = '+alias+'.PUBLIC_WIRE_BOUNDARY_ID_DOMAIN;').replace(hashint,'pub const hashInt = '+alias+'.hashInt;')
cp.write_text(a);ct.write_text(b)
p=root/'segment_verified_artifact_v2.zig';s=p.read_text().replace('@import("segment_outer_cohort_v2.zig")','@import("segment_public_wire_boundary_v2.zig")').replace('@import("air/segment_outer_adapter_manifest_v2.zig")','@import("air/segment_outer_manifest_contract_v2.zig")');p.write_text(s)
p=root/'mod.zig';p.write_text(p.read_text()+'pub const segment_public_wire_boundary_v2 = @import("segment_public_wire_boundary_v2.zig");\n')
