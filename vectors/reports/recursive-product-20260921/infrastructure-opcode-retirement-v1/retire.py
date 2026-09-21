from pathlib import Path
import re
base=Path('src/frontends/riscv/air');p=base/'component.zig';s=p.read_text();Path('/tmp/pr198-infra-component-before.zig').write_text(s)
a=s.index('    fn oodsWorkProfileErased(');b=s.index('    fn prepareDomainEvaluatorErased(',a)
profiles=s[a:b].replace('    fn oodsWorkProfileErased','    pub fn oodsWorkProfileErased').replace('    fn compositionWorkProfileErased','    pub fn compositionWorkProfileErased').replace('*const @This()', '*const Component')
profiles=profiles.replace('            .opcode => return error.UnsupportedOodsWorkProfile,\n','').replace('            .opcode => return error.UnsupportedCompositionWorkProfile,\n','')
(base/'component_work_profiles.zig').write_text('''//! Source-derived work accounting for program and memory infrastructure AIR.
const std = @import("std");
const composition_work_support = @import("composition_work_support.zig");
const program_commitment = @import("program/commitment.zig");
const program_interaction = @import("program/interaction.zig");
const memory_interaction = @import("memory_commitment/interaction.zig");

pub fn For(comptime Component: type) type {
    return struct {
'''+''.join('    '+line+'\n' for line in profiles.splitlines())+'    };\n}\n')
s=s[:a]+s[b:]
s=s.replace('pub const Kind = enum { opcode, program, memory };','pub const Kind = enum { program, memory };')
a=s.index('        component.composition_work_profile = switch');b=s.index('        return component;',a)
s=s[:a]+'''        component.composition_work_profile = WorkProfiles.compositionWorkProfileErased;
        component.oods_work_profile = WorkProfiles.oodsWorkProfileErased;
'''+s[b:]
s=s.replace('    const Adapter = core_air_derive.ComponentAdapter(','    const WorkProfiles = @import("component_work_profiles.zig").For(@This());\n    const Adapter = core_air_derive.ComponentAdapter(')
s=s.replace('        .opcode => @intCast(interaction_gen.OPCODE_INTERACTION_COLS),\n','')
a=s.index('            .opcode => 2 +');b=s.index('            .program =>',a);s=s[:a]+s[b:]
a=s.index('            .opcode => {');b=s.index('            .program => {',a);s=s[:a]+s[b:]
s=s.replace('            .opcode => trace_mod.nColumnsForFamily(self.desc.family),\n','')
s=s.replace('    state_claim: QM31 = QM31.zero(),\n','').replace('    prog_claim: QM31 = QM31.zero(),\n','').replace('    opcode_memory_claims: [opcode_memory.N_ACCESSES]QM31 =\n        .{QM31.zero()} ** opcode_memory.N_ACCESSES,\n','').replace('            .opcode_main_sources = descriptor_main_sources,\n','').replace('    opcode_main_sources: usize,\n','')
s=s.replace('//! Per-shard RISC-V AIR component with real LogUp constraints.','//! Program and memory infrastructure AIR component with real LogUp constraints.')
a=s.index('//! Opcode components enforce');b=s.index('\nconst std',a)
s=s[:a]+'''//! Program components enforce ROM emission; memory components enforce boundary
//! transitions. Opcode AIR is owned exclusively by typed semantic components.
//! Hash, lookup-table and clock-update infrastructure use dedicated components.
'''+s[b:]
s=s.replace('//!           (family-specific for opcode shards, 16 for the program ROM, and\n//!           16 for a memory-boundary shard).','//!           (16 for the program ROM and 16 for a memory-boundary shard).')
p.write_text(s)
p=base/'component_prepared_execution.zig';s=p.read_text();Path('/tmp/pr198-infra-execution-before.zig').write_text(s)
a=s.index('    const opcode_main_sources');b=s.index('    const column_accumulator',a);s=s[:a]+s[b:]
a=s.index('            .opcode => {');b=s.index('            .program => {',a);s=s[:a]+s[b:];p.write_text(s)
for p in [base/'component.zig',base/'component_prepared_execution.zig']:
 s=p.read_text()
 for m in list(re.finditer(r'^const (\w+) = @import\([^\n]+;\n',s,re.M)):
  if len(re.findall(r'\b'+re.escape(m[1])+r'\b',s))==1:s=s.replace(m[0],'')
 p.write_text(s)
