from pathlib import Path
import re,json
base=Path('src/integrations/riscv_cpu');shared=Path('src/frontends/riscv/recursion')
names={'recursive_binary_verified_publication':'binary_verified_publication','recursive_segment_v2_verified_publication':'segment_verified_publication_v2','recursive_segment_v2_verified_artifact':'segment_verified_artifact_v2','recursive_segment_v2_outer_engine_support':'segment_outer_transaction_support_v2','recursive_segment_v2_outer_engine':'segment_outer_transaction_v2'}
original={n:(base/(n+'.zig')).read_text() for n in names};Path('/tmp/pr198-outer-transaction-originals-v1.json').write_text(json.dumps(original))
tests={'recursive_segment_v2_verified_publication':'testNoPublicMint','recursive_segment_v2_verified_artifact':'testNoDetachedMint','recursive_segment_v2_outer_engine':'testProtocolContract'}
transformed={};publics={}
for n,dest in names.items():
 s=original[n];publics[n]=re.findall(r'^pub (?:const|fn) (\w+)',s,re.M)
 # Only explicit dependencies used by this owner, not the complete frontend facade.
 deps=sorted(set(re.findall(r'\brecursion\.([A-Za-z0-9_]+)',s))-{'air'})
 airdeps=sorted(set(re.findall(r'\brecursion\.air\.([A-Za-z0-9_]+)',s)))
 rec='const recursion = struct {\n'+''.join('    const '+x+' = @import("'+x+'.zig");\n' for x in deps)
 if airdeps:rec+='    const air = struct {\n'+''.join('        const '+x+' = @import("air/'+x+'.zig");\n' for x in airdeps)+'    };\n'
 rec+='};'
 s=s.replace('const frontend = @import("stwo_riscv_frontend");\n','').replace('const recursion = frontend.recursion;',rec).replace('frontend.air.public_data_v2','@import("../air/public_data_v2.zig")')
 for old,new in names.items():s=s.replace('@import("'+old+'.zig")','@import("'+new+'.zig")')
 s=s.replace('@import("recursive_segment_v2_outer_engine_storage.zig")','@import("transaction_storage_v2.zig")')
 # Pure publication code needs only the protocol hash type, not a prover engine.
 if n=='recursive_segment_v2_verified_publication':
  s=s.replace('    const engine = @import("engine.zig");\n','').replace('recursion.engine.Hasher','channel.MerkleHasher')
 if n=='recursive_segment_v2_outer_engine_support':
  s=s.replace('const CpuBackend = @import("stwo_cpu_backend").CpuBackend;\n','').replace('    const engine = @import("engine.zig");\n','')
  s=s.replace('const Engine = recursion.engine.ProverEngineForBackend(CpuBackend);','const Engine = struct { const Channel = @import("poseidon2_channel.zig").Channel; };').replace('recursion.engine.Hasher','@import("poseidon2_channel.zig").MerkleHasher').replace('recursion.engine.MerkleChannel','@import("poseidon2_channel.zig").MerkleChannel')
 testname=None
 if n in tests:
  m=re.search(r'^test "([^"]+)" \{',s,re.M);assert m;testname=m[1];s=s[:m.start()]+'pub fn '+tests[n]+'() !void {'+s[m.end():]
 if n=='recursive_segment_v2_outer_engine':
  s=s.replace('const CpuBackend = @import("stwo_cpu_backend").CpuBackend;','const CpuBackend = Backend;').replace('const core_outer = @import("recursive_fri_outer.zig");','const core_outer = Diagnostics;')
  i=s.index('const std =');s=s[:i].replace('CPU proof transaction','Shared proof transaction')+'pub fn ForBackend(comptime Backend: type, comptime Diagnostics: type) type {\n    return struct {\n'+s[i:]+'\n    };\n}\n'
  prefix='//! CPU backend and diagnostic bindings for the shared publication transaction.\nconst recursion = @import("stwo_riscv_frontend").recursion;\nconst diagnostics_source = @import("recursive_fri_outer.zig");\nconst Diagnostics = struct {\n    pub const COMPOSITION_DIAGNOSTIC_ENV = diagnostics_source.COMPOSITION_DIAGNOSTIC_ENV;\n    pub const validateCompositionDiagnosticRoster = diagnostics_source.validateCompositionDiagnosticRoster;\n    pub const diagnoseCompositionComponents = diagnostics_source.diagnoseCompositionComponents;\n};\nconst implementation = recursion.'+dest+'.ForBackend(@import("stwo_cpu_backend").CpuBackend, Diagnostics);\n'
 else:prefix='//! Compatibility aliases for the shared recursion owner.\nconst implementation = @import("stwo_riscv_frontend").recursion.'+dest+';\n'
 facade=prefix+'\n'+''.join('pub const '+x+' = implementation.'+x+';\n' for x in publics[n])
 if testname:facade+='\ntest "'+testname+'" {\n    try implementation.'+tests[n]+'();\n}\n'
 (base/(n+'.zig')).write_text(facade);(shared/(dest+'.zig')).write_text(s);transformed[dest]=s
p=shared/'mod.zig';s=p.read_text();s+='\n'+''.join('pub const '+n+' = @import("'+n+'.zig");\n' for n in names.values());p.write_text(s)
Path('/tmp/pr198-outer-transaction-transformed-v1.json').write_text(json.dumps(transformed))
Path('/tmp/pr198-outer-transaction-exports-v1.json').write_text(json.dumps(publics,indent=2)+'\n')
print('Moved',len(names),'owners;',sum(len(v) for v in publics.values()),'public declarations retained as aliases; 3 named test wrappers retained.')
