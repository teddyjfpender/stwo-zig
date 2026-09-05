//! Owned results for the nonproduction Ethereum+bulk-memcpy session.

const std = @import("std");

const authority_mod = @import("../isa/ethereum_bulk_memcpy_candidate_v1.zig");
const result_mod = @import("result.zig");
const combined_state = @import("guest_precompile/ethereum_bulk_memcpy_candidate_v1.zig");
const bulk_tape = @import("guest_precompile/bulk_memcpy_session_tape_v1.zig");

pub const production_active = false;

pub const SegmentResult = struct {
    authority: authority_mod.Authority,
    ethereum: result_mod.EthereumSegmentResult,
    bulk_memcpy: bulk_tape.Frozen,

    pub fn validateAuthority(self: *const SegmentResult) !void {
        try self.authority.validate();
        try self.bulk_memcpy.validate();
    }

    pub fn validateAgainst(
        self: *const SegmentResult,
        expected_authority: authority_mod.Authority,
        expected_external_step_origin: usize,
    ) !void {
        try expected_authority.validate();
        if (!std.meta.eql(self.authority, expected_authority) or
            self.bulk_memcpy.external_step_origin != expected_external_step_origin)
        {
            return error.EthereumBulkMemcpyCandidateAuthorityMismatch;
        }
        try self.bulk_memcpy.validate();
    }

    pub fn deinit(self: *SegmentResult) void {
        self.bulk_memcpy.deinit();
        self.ethereum.deinit();
        self.* = undefined;
    }
};

pub const RunResult = struct {
    authority: authority_mod.Authority,
    ethereum: result_mod.EthereumRunResult,
    bulk_memcpy: bulk_tape.Frozen,

    pub fn validateAuthority(self: *const RunResult) !void {
        try self.authority.validate();
        try self.bulk_memcpy.validate();
    }

    pub fn validateAgainst(
        self: *const RunResult,
        expected_authority: authority_mod.Authority,
        expected_external_step_origin: usize,
    ) !void {
        try expected_authority.validate();
        if (!std.meta.eql(self.authority, expected_authority) or
            self.bulk_memcpy.external_step_origin != expected_external_step_origin)
        {
            return error.EthereumBulkMemcpyCandidateAuthorityMismatch;
        }
        try self.bulk_memcpy.validate();
    }

    pub fn deinit(self: *RunResult) void {
        self.bulk_memcpy.deinit();
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
    };
}

comptime {
    if (production_active or authority_mod.production_active or
        combined_state.production_active)
    {
        @compileError("Ethereum+bulk-memcpy result became production-active");
    }
    _ = std.meta.fields(SegmentResult);
}
