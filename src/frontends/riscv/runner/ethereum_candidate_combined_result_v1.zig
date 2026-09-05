//! Owned result for the nonproduction combined Ethereum candidate session.

const std = @import("std");

const authority_mod =
    @import("../isa/ethereum_candidate_combined_authority_v1.zig");
const result_mod = @import("result.zig");
const combined_state = @import("guest_precompile/ethereum_candidate_combined_v1.zig");
const bulk_tape = @import("guest_precompile/bulk_memcpy_session_tape_v1.zig");
const swap_tape = @import("guest_precompile/stack_swap_session_tape_v1.zig");

pub const production_active = false;

pub const SegmentResult = struct {
    authority: authority_mod.Authority,
    ethereum: result_mod.EthereumSegmentResult,
    bulk_memcpy: bulk_tape.Frozen,
    stack_swap: swap_tape.Frozen,

    pub fn validateAgainst(
        self: *const SegmentResult,
        expected_authority: authority_mod.Authority,
        expected_external_step_origin: usize,
    ) !void {
        try validateCommon(
            self.authority,
            expected_authority,
            &self.bulk_memcpy,
            &self.stack_swap,
            expected_external_step_origin,
        );
    }

    pub fn deinit(self: *SegmentResult) void {
        self.bulk_memcpy.deinit();
        self.stack_swap.deinit();
        self.ethereum.deinit();
        self.* = undefined;
    }
};

pub const RunResult = struct {
    authority: authority_mod.Authority,
    ethereum: result_mod.EthereumRunResult,
    bulk_memcpy: bulk_tape.Frozen,
    stack_swap: swap_tape.Frozen,

    pub fn validateAgainst(
        self: *const RunResult,
        expected_authority: authority_mod.Authority,
        expected_external_step_origin: usize,
    ) !void {
        try validateCommon(
            self.authority,
            expected_authority,
            &self.bulk_memcpy,
            &self.stack_swap,
            expected_external_step_origin,
        );
    }

    pub fn deinit(self: *RunResult) void {
        self.bulk_memcpy.deinit();
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
        .bulk_memcpy = state.bulk_memcpy.freeze(),
        .stack_swap = state.stack_swap.freeze(),
    };
}

pub fn runFromSegment(
    base: result_mod.RunResult,
    segment: *const SegmentResult,
) RunResult {
    return .{
        .authority = segment.authority,
        .ethereum = result_mod.ethereumRunFromSegment(base, &segment.ethereum),
        .bulk_memcpy = segment.bulk_memcpy,
        .stack_swap = segment.stack_swap,
    };
}

fn validateCommon(
    actual_authority: authority_mod.Authority,
    expected_authority: authority_mod.Authority,
    bulk_memcpy: *const bulk_tape.Frozen,
    stack_swap: *const swap_tape.Frozen,
    expected_external_step_origin: usize,
) !void {
    try expected_authority.validate();
    if (!std.meta.eql(actual_authority, expected_authority) or
        bulk_memcpy.externalStepOrigin() != expected_external_step_origin)
    {
        return error.EthereumCombinedCandidateAuthorityMismatch;
    }
    try bulk_memcpy.validate();
    try stack_swap.validateAgainst(
        expected_authority.stack_swap.stack_swap,
        expected_external_step_origin,
    );
}

comptime {
    if (production_active or authority_mod.production_active or
        combined_state.production_active)
    {
        @compileError("combined candidate result became active");
    }
    _ = std.meta.fields(SegmentResult);
}
