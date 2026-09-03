//! Candidate-only CUSTOM-0 dispatch for the explicitly allocated U256 SWAP.
//!
//! Nothing imports this module from the production execution session.  A
//! candidate runner must own this dispatcher and the matching tape, then call
//! `retireCustom0` only after fetching a CUSTOM-0 word.  The semantic runner
//! remains transactional and publishes its external retirement clock only
//! after every memory/state/tape reservation succeeds.

const std = @import("std");

const abi = @import("../../isa/stack_swap_candidate_v1.zig");
const private_registry = @import("../../isa/stack_swap_private_registry_v1.zig");
const Cpu = @import("../cpu.zig").Cpu;
const Memory = @import("../memory.zig").Memory;
const MemoryLayout = @import("../memory_state.zig").MemoryLayout;
const StateChainTracker = @import("../state_chain.zig").StateChainTracker;
const Trace = @import("../trace.zig").Trace;
const tape_mod = @import("stack_swap_session_tape_v1.zig");
const runner = @import("stack_swap_v1.zig");

pub const production_active = false;

pub const Error = runner.Error || error{
    InvalidStackSwapCandidateDispatch,
    StackSwapCandidateAuthorityMismatch,
};

pub const Dispatcher = struct {
    authority: abi.Authority,

    pub fn canonical() !Dispatcher {
        return .{ .authority = try private_registry.authority() };
    }

    pub fn init(authority: abi.Authority) !Dispatcher {
        try private_registry.validateAuthority(authority);
        return .{ .authority = authority };
    }

    pub fn validate(self: Dispatcher) !void {
        try private_registry.validateAuthority(self.authority);
    }

    pub fn claims(self: Dispatcher, inst_word: u32) bool {
        self.validate() catch return false;
        return inst_word == self.authority.fixed_word;
    }

    pub fn retireCustom0(
        self: Dispatcher,
        inst_word: u32,
        execution_clock: u32,
        cpu: *Cpu,
        memory: *Memory,
        layout: MemoryLayout,
        tracker: *StateChainTracker,
        trace: *Trace,
        tape: *tape_mod.Builder,
    ) Error!void {
        try self.validate();
        if (@as(u7, @truncate(inst_word)) != abi.major_opcode or
            !self.claims(inst_word))
        {
            return error.InvalidStackSwapCandidateDispatch;
        }
        if (!std.meta.eql(tape.authority, self.authority))
            return error.StackSwapCandidateAuthorityMismatch;
        try runner.executeWithRecordedClock(
            inst_word,
            execution_clock,
            cpu,
            memory,
            layout,
            tracker,
            trace,
            tape,
        );
    }
};

comptime {
    if (production_active or private_registry.production_active or
        abi.production_active)
    {
        @compileError("stack-swap candidate dispatch became production-active");
    }
}
