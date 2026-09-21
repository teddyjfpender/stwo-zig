from pathlib import Path
import textwrap
p=Path('src/frontends/riscv/runner/segment_session.zig');s=p.read_text();Path('/tmp/pr198-segment-session-before.zig').write_text(s)
a=s.index('/// Controls whether');b=s.index('pub fn ConfiguredSegmentResult',a)
contracts=s[a:b]
Path('src/frontends/riscv/runner/segment_session_contract.zig').write_text('''//! Execution session options and borrowed diagnostic observer contracts.
const Cpu = @import("cpu.zig").Cpu;
const Memory = @import("memory.zig").Memory;
const trace = @import("trace.zig");
const memory_state = @import("memory_state.zig");
const state_chain = @import("state_chain.zig");
const HostInterface = @import("../host/mod.zig").HostInterface;
const SegmentClockFrame = @import("result.zig").SegmentClockFrame;

'''+contracts)
s=s[:a]+''.join('pub const '+n+' = session_contract.'+n+';\n' for n in ['TraceRetention','RetirementObserverV1','PreRetirementBoundaryV1','PreRetirementBoundaryObserverV1','SessionOptions'])+'\n'+s[b:]
a=s.index('const StepOutcome = struct');b=s.index('pub fn ExecutionSession',a);outcome=s[a:b].replace('const StepOutcome','pub const StepOutcome');s=s[:a]+s[b:]
a=s.index('        fn retireOne(');b=s.index('    };\n}',a);methods=s[a:b]
methods=methods.replace('        fn retireOne(','        pub fn retireOne(').replace('self: *Self','self: anytype').replace('self.observeLastCoreRow(exec_trace)','observeLastCoreRow(self, exec_trace)')
imports='''//! Instruction retirement for the canonical session; lifecycle and publication
//! remain with ExecutionSession. Observers retain their pre/post commit order.
const custom0 = @import("../isa/custom0.zig");
const isa_profile = @import("../isa/profile.zig");
const access_clock = @import("../access_clock.zig");
const ExecutionProfile = @import("../isa/execution_profile.zig").ExecutionProfile;
const generated_retirement = @import("generated_retirement.zig");
const guest_precompile = @import("guest_precompile/mod.zig");
const trace = @import("trace.zig");
const state_chain = @import("state_chain.zig");
const result_mod = @import("result.zig");
const access_witness = @import("access_witness.zig");

'''
Path('src/frontends/riscv/runner/segment_session_retirement.zig').write_text(imports+outcome+'''pub fn For(
    comptime profile: ExecutionProfile,
    comptime ethereum_stack_swap_candidate: bool,
    comptime ethereum_bulk_memcpy_candidate: bool,
    comptime ExtensionState: type,
) type {
    return struct {
'''+methods+'    };\n}\n')
s=s[:a]+s[b:]
s=s.replace('        const Self = @This();','''        const Self = @This();
        const retireOne = session_retirement.For(
            profile,
            ethereum_stack_swap_candidate,
            ethereum_bulk_memcpy_candidate,
            ExtensionState,
        ).retireOne;''')
for line in ['const custom0 = @import("../isa/custom0.zig");','const isa_profile = @import("../isa/profile.zig");','const decode = @import("decode.zig");','const generated_retirement = @import("generated_retirement.zig");','const guest_precompile = @import("guest_precompile/mod.zig");','const access_witness = @import("access_witness.zig");']:
 assert line in s;s=s.replace(line+'\n','')
s=s.replace('const session_support = @import("segment_session_support.zig");','''const session_support = @import("segment_session_support.zig");
const session_contract = @import("segment_session_contract.zig");
const session_retirement = @import("segment_session_retirement.zig");''')
p.write_text(s)
