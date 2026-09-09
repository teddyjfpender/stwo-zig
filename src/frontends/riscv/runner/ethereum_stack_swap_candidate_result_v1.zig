//! Owned results for the nonproduction Ethereum+SWAP execution session.

const std = @import("std");

const authority_mod = @import("../isa/ethereum_stack_swap_candidate_v1.zig");
const result_mod = @import("result.zig");
const combined_state = @import("guest_precompile/ethereum_stack_swap_candidate_v1.zig");
const swap_tape = @import("guest_precompile/stack_swap_session_tape_v1.zig");

pub const production_active = false;

pub const SegmentResult = struct {
    authority: authority_mod.Authority,
    ethereum: result_mod.EthereumSegmentResult,
    stack_swap: swap_tape.Frozen,

    /// Structural check only. Admission callers must use `validateAgainst`
    /// with transaction-external authority and segment-origin custody.
    pub fn validateAuthority(self: *const SegmentResult) !void {
        try self.authority.validate();
        try self.stack_swap.validateAgainst(
            self.authority.stack_swap,
            self.stack_swap.external_step_origin,
        );
    }

    pub fn validateAgainst(
        self: *const SegmentResult,
        expected_authority: authority_mod.Authority,
        expected_external_step_origin: usize,
    ) !void {
        try expected_authority.validate();
        if (!std.meta.eql(self.authority, expected_authority))
            return error.EthereumStackSwapCandidateAuthorityMismatch;
        try self.stack_swap.validateAgainst(
            expected_authority.stack_swap,
            expected_external_step_origin,
        );
    }

    pub fn deinit(self: *SegmentResult) void {
        self.stack_swap.deinit();
        self.ethereum.deinit();
        self.* = undefined;
    }
};

pub const RunResult = struct {
    authority: authority_mod.Authority,
    ethereum: result_mod.EthereumRunResult,
    stack_swap: swap_tape.Frozen,

    /// Structural check only. Admission callers must use `validateAgainst`
    /// with transaction-external authority and segment-origin custody.
    pub fn validateAuthority(self: *const RunResult) !void {
        try self.authority.validate();
        try self.stack_swap.validateAgainst(
            self.authority.stack_swap,
            self.stack_swap.external_step_origin,
        );
    }

    pub fn validateAgainst(
        self: *const RunResult,
        expected_authority: authority_mod.Authority,
        expected_external_step_origin: usize,
    ) !void {
        try expected_authority.validate();
        if (!std.meta.eql(self.authority, expected_authority))
            return error.EthereumStackSwapCandidateAuthorityMismatch;
        try self.stack_swap.validateAgainst(
            expected_authority.stack_swap,
            expected_external_step_origin,
        );
    }

    pub fn deinit(self: *RunResult) void {
        self.stack_swap.deinit();
        self.ethereum.deinit();
        self.* = undefined;
    }
};

pub fn freezeSegment(
    base: result_mod.SegmentResult,
    state: *combined_state.State,
) SegmentResult {
    return .{
        .authority = state.authority,
        .ethereum = result_mod.freezeEthereumSegment(base, &state.ethereum),
        .stack_swap = state.stack_swap.freeze(),
    };
}

/// Transfers an already-frozen single segment into a one-shot result.
pub fn runFromSegment(
    base: result_mod.RunResult,
    segment: *const SegmentResult,
) RunResult {
    return .{
        .authority = segment.authority,
        .ethereum = result_mod.ethereumRunFromSegment(base, &segment.ethereum),
        .stack_swap = segment.stack_swap,
    };
}

comptime {
    if (production_active or authority_mod.production_active or
        combined_state.production_active)
    {
        @compileError("Ethereum+SWAP candidate result became production-active");
    }
    _ = std.meta.fields(SegmentResult);
}
