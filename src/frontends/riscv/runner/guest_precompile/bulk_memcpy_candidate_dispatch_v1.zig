//! Candidate-only CUSTOM-0 dispatcher for the private bulk memcpy member.
//!
//! Production execution never imports this path. The dispatcher accepts only
//! the exact registry authority and fixed instruction, then delegates to the
//! transactional runner after the shared external-clock token is prepared.

const std = @import("std");

const abi = @import("../../isa/bulk_memcpy_candidate_v1.zig");
const private_registry = @import("../../isa/bulk_memcpy_private_registry_v1.zig");
const Cpu = @import("../cpu.zig").Cpu;
const Memory = @import("../memory.zig").Memory;
const MemoryLayout = @import("../memory_state.zig").MemoryLayout;
const StateChainTracker = @import("../state_chain.zig").StateChainTracker;
const Trace = @import("../trace.zig").Trace;
const tape_mod = @import("bulk_memcpy_session_tape_v1.zig");
const runner = @import("bulk_memcpy_v1.zig");

pub const production_active = false;

pub const Error = runner.Error || error{
    InvalidBulkMemcpyCandidateDispatch,
    BulkMemcpyCandidateAuthorityMismatch,
    BulkMemcpyPrivateRegistryCollision,
    InvalidBulkMemcpyPrivateMemberDescriptor,
    InvalidBulkMemcpyPrivateRegistryAllocation,
    InvalidBulkMemcpyPrivateRegistryAuthority,
    BulkMemcpyPrivateRegistryAuthorityMismatch,
};

pub const Dispatcher = struct {
    authority: private_registry.Authority,

    pub fn canonical() !Dispatcher {
        return .{ .authority = try private_registry.authority() };
    }

    pub fn init(authority: private_registry.Authority) !Dispatcher {
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
        segment_external_origin: usize,
        aggregate_calls_before: usize,
        aggregate_rows_before: usize,
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
            return error.InvalidBulkMemcpyCandidateDispatch;
        }
        try runner.executeWithAggregateRecordedClock(
            inst_word,
            execution_clock,
            segment_external_origin,
            aggregate_calls_before,
            aggregate_rows_before,
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
        @compileError("bulk-memcpy candidate dispatch became production-active");
    }
}

test "bulk memcpy dispatcher claims only exact registered word" {
    const dispatcher = try Dispatcher.canonical();
    try dispatcher.validate();
    try std.testing.expect(dispatcher.claims(abi.fixed_word));
    try std.testing.expect(!dispatcher.claims(abi.fixed_word ^ 1));
}
