//! Exact row-34 provider schedule for the field-native common fold.
//!
//! The first 116 calls are the parent NodePublicV2 field boundary.  The
//! verifier-core suffix is appended by the shared rows-18--34 bundle.  This
//! contract is deliberately distinct from temporal/H1/canonical-empty
//! schedules even though it reuses the same physical Poseidon AIR.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const field_public = @import("recursive_common_fold_field_public_v2.zig");

pub const Call = frontend.air.memory_commitment.poseidon2_air.Call;
pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 1;
pub const PROVIDER_COMPONENT_INDEX: u8 = 34;
pub const STATEMENT_AUTHORITY_CALL_COUNT: usize =
    field_public.POSEIDON_CALL_COUNT;

const LAYOUT_DOMAIN =
    "stwo-zig/recursive-common-fold-row34-layout/v2\x00";
const BUFFER_DOMAIN =
    "stwo-zig/recursive-common-fold-row34-calls/v2\x00";

pub const Error = error{
    ArithmeticOverflow,
    CommonFoldPoseidonScheduleMismatch,
    NonCanonicalCommonFoldPoseidonCall,
};

pub const CallRange = struct {
    start: u32,
    end: u32,

    pub fn count(self: CallRange) Error!usize {
        if (self.end < self.start)
            return error.CommonFoldPoseidonScheduleMismatch;
        return @as(usize, self.end - self.start);
    }

    fn validateWithin(self: CallRange, total: usize) Error!void {
        if (self.end < self.start or self.end > total)
            return error.CommonFoldPoseidonScheduleMismatch;
    }
};

pub const Layout = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    transcript: CallRange,
    statement_authority: CallRange,
    verifier_core: CallRange,
    boundary_prefix_call_count: u32,
    verifier_core_range_populated: bool,
    call_set_complete: bool,
    total_call_count: u32,
    call_buffer_id: [32]u8,
    identity: [32]u8,

    pub fn initBoundary(calls: []const Call) Error!Layout {
        if (calls.len != STATEMENT_AUTHORITY_CALL_COUNT)
            return error.CommonFoldPoseidonScheduleMismatch;
        const boundary = try toU32(calls.len);
        var result = Layout{
            .transcript = .{ .start = 0, .end = 0 },
            .statement_authority = .{ .start = 0, .end = boundary },
            .verifier_core = .{ .start = boundary, .end = boundary },
            .boundary_prefix_call_count = boundary,
            .verifier_core_range_populated = false,
            .call_set_complete = false,
            .total_call_count = boundary,
            .call_buffer_id = callBufferIdentity(calls),
            .identity = undefined,
        };
        result.identity = layoutIdentity(&result);
        try result.validate(calls);
        return result;
    }

    pub fn initComplete(
        transcript_count: usize,
        authority_count: usize,
        verifier_core_count: usize,
        calls: []const Call,
    ) Error!Layout {
        if (transcript_count != 0 or
            authority_count != STATEMENT_AUTHORITY_CALL_COUNT or
            verifier_core_count == 0)
        {
            return error.CommonFoldPoseidonScheduleMismatch;
        }
        const boundary = try toU32(authority_count);
        const total = std.math.add(
            usize,
            authority_count,
            verifier_core_count,
        ) catch return error.ArithmeticOverflow;
        if (calls.len != total)
            return error.CommonFoldPoseidonScheduleMismatch;
        var result = Layout{
            .transcript = .{ .start = 0, .end = 0 },
            .statement_authority = .{ .start = 0, .end = boundary },
            .verifier_core = .{ .start = boundary, .end = try toU32(total) },
            .boundary_prefix_call_count = boundary,
            .verifier_core_range_populated = true,
            .call_set_complete = true,
            .total_call_count = try toU32(total),
            .call_buffer_id = callBufferIdentity(calls),
            .identity = undefined,
        };
        result.identity = layoutIdentity(&result);
        try result.validate(calls);
        return result;
    }

    pub fn validate(self: *const Layout, calls: []const Call) Error!void {
        try self.validateReceipt();
        if (calls.len != self.total_call_count or
            !std.mem.eql(u8, &self.call_buffer_id, &callBufferIdentity(calls)))
        {
            return error.CommonFoldPoseidonScheduleMismatch;
        }
        for (calls) |call| try validateCall(call);
    }

    pub fn validateReceipt(self: *const Layout) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.transcript.start != 0 or self.transcript.end != 0 or
            self.statement_authority.start != 0 or
            self.statement_authority.end != self.verifier_core.start or
            self.verifier_core.end != self.total_call_count or
            self.boundary_prefix_call_count != self.verifier_core.start or
            self.verifier_core_range_populated != self.call_set_complete or
            self.boundary_prefix_call_count != STATEMENT_AUTHORITY_CALL_COUNT)
        {
            return error.CommonFoldPoseidonScheduleMismatch;
        }
        try self.transcript.validateWithin(self.total_call_count);
        try self.statement_authority.validateWithin(self.total_call_count);
        try self.verifier_core.validateWithin(self.total_call_count);
        if (try self.statement_authority.count() !=
            STATEMENT_AUTHORITY_CALL_COUNT)
        {
            return error.CommonFoldPoseidonScheduleMismatch;
        }
        const core_count = try self.verifier_core.count();
        if ((self.call_set_complete and core_count == 0) or
            (!self.call_set_complete and core_count != 0) or
            !std.mem.eql(u8, &self.identity, &layoutIdentity(self)))
        {
            return error.CommonFoldPoseidonScheduleMismatch;
        }
    }
};

pub fn callBufferIdentity(calls: []const Call) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(BUFFER_DOMAIN);
    hashInt(&hash, u64, calls.len);
    for (calls) |call| {
        hashInt(&hash, u8, @intFromBool(call.wide));
        hashInt(&hash, u8, @intFromBool(call.io));
        hashInt(&hash, u8, @intFromBool(call.narrow_output != null));
        hashInt(&hash, u32, call.narrow_output orelse 0);
        for (call.input) |word| hashInt(&hash, u32, word);
    }
    return hash.finalResult();
}

fn layoutIdentity(value: *const Layout) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(LAYOUT_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hashInt(&hash, u32, value.statement_authority.start);
    hashInt(&hash, u32, value.statement_authority.end);
    hashInt(&hash, u32, value.verifier_core.start);
    hashInt(&hash, u32, value.verifier_core.end);
    hashInt(&hash, u8, @intFromBool(value.call_set_complete));
    hash.update(&value.call_buffer_id);
    return hash.finalResult();
}

fn validateCall(call: Call) Error!void {
    if (call.wide or !call.io or call.narrow_output != null)
        return error.CommonFoldPoseidonScheduleMismatch;
    for (call.input) |word| if (word >= stwo_core.fields.m31.Modulus)
        return error.NonCanonicalCommonFoldPoseidonCall;
}

fn toU32(value: usize) Error!u32 {
    return std.math.cast(u32, value) orelse error.ArithmeticOverflow;
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 1 or
        PROVIDER_COMPONENT_INDEX != 34 or
        STATEMENT_AUTHORITY_CALL_COUNT != 116)
    {
        @compileError("common-fold Poseidon schedule drifted");
    }
}
