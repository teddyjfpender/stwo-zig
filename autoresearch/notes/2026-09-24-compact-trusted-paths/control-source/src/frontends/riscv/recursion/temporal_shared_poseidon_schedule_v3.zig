//! Exact row-34 provider schedule for a temporal SegmentV2 parent.
//!
//! Rows 0--9 own the transcript prefix, rows 10--17 emit no Poseidon
//! requester tuples, and rows 18--33 own the recursive-verifier suffix.  The
//! empty statement range is explicit and authenticated; it is not inferred
//! from an absent buffer or borrowed from the SegmentV2 leaf V2 schedule.

const std = @import("std");
const stwo_core = @import("stwo_core");

const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");

pub const Call = poseidon2_air.Call;
pub const Sha256Digest = [32]u8;

pub const FORMAT_VERSION: u16 = 3;
pub const SCHEMA_VERSION: u16 = 1;
pub const PROVIDER_COMPONENT_INDEX: u8 = 34;
pub const RANGE_COUNT: usize = 3;
pub const PROVIDER_INSTANCE_COUNT: usize = 1;
pub const STATEMENT_AUTHORITY_CALL_COUNT: usize = 0;
pub const HOT_VALIDATION_HEAP_ALLOCATIONS: usize = 0;
pub const HOT_IDENTITY_HEAP_ALLOCATIONS: usize = 0;
pub const COMPLETE_SCHEDULE_COLD_ALLOCATIONS: usize = 1;

pub const CALL_LAYOUT_ID_DOMAIN =
    "stwo-zig/typed-air/recursive-temporal-parent-row34-layout/v3\x00";
pub const CALL_BUFFER_ID_DOMAIN =
    "stwo-zig/typed-air/recursive-temporal-parent-row34-calls/v3\x00";

pub const Error = error{
    ArithmeticOverflow,
    CallLayoutMismatch,
    NonCanonicalCallWord,
};

pub const RangeOrigin = enum(u8) {
    transcript = 0,
    statement_authority = 1,
    verifier_core = 2,
};

pub const CallRange = struct {
    start: u32,
    end: u32,

    pub fn count(self: CallRange) Error!usize {
        if (self.end < self.start) return error.CallLayoutMismatch;
        return @as(usize, self.end - self.start);
    }

    pub fn validateWithin(self: CallRange, total: usize) Error!void {
        if (self.end < self.start or self.end > total)
            return error.CallLayoutMismatch;
    }
};

pub const SharedPoseidonCallLayoutV3 = struct {
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    transcript: CallRange,
    statement_authority: CallRange,
    verifier_core: CallRange,
    boundary_prefix_call_count: u32,
    verifier_core_range_populated: bool,
    call_set_complete: bool,
    total_call_count: u32,
    call_buffer_id: Sha256Digest,
    identity: Sha256Digest,

    /// Constructs the authenticated rows-0--17 prefix. The authority count is
    /// retained in the signature so accidental use of the V2 policy fails
    /// closed at this boundary.
    pub fn initBoundaryPrefix(
        transcript_call_count: usize,
        authority_call_count: usize,
        calls: []const Call,
    ) Error!SharedPoseidonCallLayoutV3 {
        if (authority_call_count != STATEMENT_AUTHORITY_CALL_COUNT or
            transcript_call_count == 0 or calls.len != transcript_call_count)
        {
            return error.CallLayoutMismatch;
        }
        const transcript_end = try usizeToU32(transcript_call_count);
        var result = SharedPoseidonCallLayoutV3{
            .transcript = .{ .start = 0, .end = transcript_end },
            .statement_authority = .{
                .start = transcript_end,
                .end = transcript_end,
            },
            .verifier_core = .{
                .start = transcript_end,
                .end = transcript_end,
            },
            .boundary_prefix_call_count = transcript_end,
            .verifier_core_range_populated = false,
            .call_set_complete = false,
            .total_call_count = transcript_end,
            .call_buffer_id = callBufferIdentity(calls),
            .identity = undefined,
        };
        result.identity = callLayoutIdentity(&result);
        try result.validate(calls);
        return result;
    }

    pub fn initTemporalBoundary(
        transcript_call_count: usize,
        calls: []const Call,
    ) Error!SharedPoseidonCallLayoutV3 {
        return initBoundaryPrefix(
            transcript_call_count,
            STATEMENT_AUTHORITY_CALL_COUNT,
            calls,
        );
    }

    pub fn initComplete(
        transcript_call_count: usize,
        authority_call_count: usize,
        verifier_core_call_count: usize,
        calls: []const Call,
    ) Error!SharedPoseidonCallLayoutV3 {
        if (authority_call_count != STATEMENT_AUTHORITY_CALL_COUNT or
            transcript_call_count == 0 or verifier_core_call_count == 0)
        {
            return error.CallLayoutMismatch;
        }
        const total = try add(transcript_call_count, verifier_core_call_count);
        if (calls.len != total) return error.CallLayoutMismatch;
        const transcript_end = try usizeToU32(transcript_call_count);
        const total_u32 = try usizeToU32(total);
        var result = SharedPoseidonCallLayoutV3{
            .transcript = .{ .start = 0, .end = transcript_end },
            .statement_authority = .{
                .start = transcript_end,
                .end = transcript_end,
            },
            .verifier_core = .{
                .start = transcript_end,
                .end = total_u32,
            },
            .boundary_prefix_call_count = transcript_end,
            .verifier_core_range_populated = true,
            .call_set_complete = true,
            .total_call_count = total_u32,
            .call_buffer_id = callBufferIdentity(calls),
            .identity = undefined,
        };
        result.identity = callLayoutIdentity(&result);
        try result.validate(calls);
        return result;
    }

    pub fn validate(
        self: *const SharedPoseidonCallLayoutV3,
        calls: []const Call,
    ) Error!void {
        try self.validateReceipt();
        if (self.total_call_count != calls.len)
            return error.CallLayoutMismatch;
        for (calls) |call| try validateCall(call);
        const expected_buffer_id = callBufferIdentity(calls);
        if (!std.mem.eql(u8, &self.call_buffer_id, &expected_buffer_id))
            return error.CallLayoutMismatch;
    }

    pub fn validateReceipt(
        self: *const SharedPoseidonCallLayoutV3,
    ) Error!void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            self.transcript.start != 0 or
            self.transcript.end != self.statement_authority.start or
            self.statement_authority.end != self.verifier_core.start or
            self.verifier_core.end != self.total_call_count or
            self.boundary_prefix_call_count != self.verifier_core.start or
            self.verifier_core_range_populated != self.call_set_complete or
            self.total_call_count == 0)
        {
            return error.CallLayoutMismatch;
        }
        try self.transcript.validateWithin(self.total_call_count);
        try self.statement_authority.validateWithin(self.total_call_count);
        try self.verifier_core.validateWithin(self.total_call_count);
        const transcript_count = try self.transcript.count();
        const authority_count = try self.statement_authority.count();
        const core_count = try self.verifier_core.count();
        if (transcript_count == 0 or
            authority_count != STATEMENT_AUTHORITY_CALL_COUNT)
        {
            return error.CallLayoutMismatch;
        }
        if (self.call_set_complete) {
            if (core_count == 0 or
                self.total_call_count <= self.boundary_prefix_call_count)
            {
                return error.CallLayoutMismatch;
            }
        } else if (core_count != 0 or
            self.total_call_count != self.boundary_prefix_call_count)
        {
            return error.CallLayoutMismatch;
        }
        const expected_identity = callLayoutIdentity(self);
        if (!std.mem.eql(u8, &self.identity, &expected_identity))
            return error.CallLayoutMismatch;
    }

    pub fn ranges(self: SharedPoseidonCallLayoutV3) [RANGE_COUNT]CallRange {
        return .{ self.transcript, self.statement_authority, self.verifier_core };
    }
};

pub const Layout = SharedPoseidonCallLayoutV3;

pub const OwnedCompletePoseidonScheduleV3 = struct {
    allocator: std.mem.Allocator,
    calls: []Call,
    layout: SharedPoseidonCallLayoutV3,

    pub fn init(
        allocator: std.mem.Allocator,
        boundary_layout: *const SharedPoseidonCallLayoutV3,
        boundary_calls: []const Call,
        verifier_core_calls: []const Call,
    ) (Error || std.mem.Allocator.Error)!OwnedCompletePoseidonScheduleV3 {
        try boundary_layout.validate(boundary_calls);
        if (boundary_layout.call_set_complete or verifier_core_calls.len == 0)
            return error.CallLayoutMismatch;
        for (verifier_core_calls) |call| try validateCall(call);
        const total = try add(boundary_calls.len, verifier_core_calls.len);
        const calls = try allocator.alloc(Call, total);
        errdefer allocator.free(calls);
        @memcpy(calls[0..boundary_calls.len], boundary_calls);
        @memcpy(calls[boundary_calls.len..], verifier_core_calls);
        const layout = try SharedPoseidonCallLayoutV3.initComplete(
            try boundary_layout.transcript.count(),
            try boundary_layout.statement_authority.count(),
            verifier_core_calls.len,
            calls,
        );
        const result = OwnedCompletePoseidonScheduleV3{
            .allocator = allocator,
            .calls = calls,
            .layout = layout,
        };
        try result.validateAgainst(boundary_layout, boundary_calls);
        return result;
    }

    pub fn deinit(self: *OwnedCompletePoseidonScheduleV3) void {
        self.allocator.free(self.calls);
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const OwnedCompletePoseidonScheduleV3,
        boundary_layout: *const SharedPoseidonCallLayoutV3,
        boundary_calls: []const Call,
    ) Error!void {
        try boundary_layout.validate(boundary_calls);
        try self.layout.validate(self.calls);
        if (boundary_layout.call_set_complete or
            self.layout.boundary_prefix_call_count != boundary_calls.len or
            self.calls.len <= boundary_calls.len or
            !callSlicesEqual(self.calls[0..boundary_calls.len], boundary_calls))
        {
            return error.CallLayoutMismatch;
        }
    }
};

pub const OwnedCompleteSchedule = OwnedCompletePoseidonScheduleV3;

pub fn callBufferIdentity(calls: []const Call) Sha256Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(CALL_BUFFER_ID_DOMAIN);
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

pub fn callLayoutIdentity(
    layout: *const SharedPoseidonCallLayoutV3,
) Sha256Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(CALL_LAYOUT_ID_DOMAIN);
    hashInt(&hash, u16, layout.format_version);
    hashInt(&hash, u16, layout.schema_version);
    hashInt(&hash, u32, layout.transcript.start);
    hashInt(&hash, u32, layout.transcript.end);
    hashInt(&hash, u32, layout.statement_authority.start);
    hashInt(&hash, u32, layout.statement_authority.end);
    hashInt(&hash, u32, layout.verifier_core.start);
    hashInt(&hash, u32, layout.verifier_core.end);
    hashInt(&hash, u32, layout.boundary_prefix_call_count);
    hashInt(&hash, u8, @intFromBool(layout.verifier_core_range_populated));
    hashInt(&hash, u8, @intFromBool(layout.call_set_complete));
    hashInt(&hash, u32, layout.total_call_count);
    hash.update(&layout.call_buffer_id);
    return hash.finalResult();
}

fn validateCall(call: Call) Error!void {
    if (call.wide or !call.io or call.narrow_output != null)
        return error.CallLayoutMismatch;
    for (call.input) |word| if (word >= stwo_core.fields.m31.Modulus)
        return error.NonCanonicalCallWord;
}

fn callSlicesEqual(left: []const Call, right: []const Call) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| {
        if (a.wide != b.wide or a.io != b.io or
            a.narrow_output != b.narrow_output or
            !std.mem.eql(u32, &a.input, &b.input))
        {
            return false;
        }
    }
    return true;
}

fn usizeToU32(value: usize) Error!u32 {
    return std.math.cast(u32, value) orelse error.ArithmeticOverflow;
}

fn add(left: usize, right: usize) Error!usize {
    return std.math.add(usize, left, right) catch error.ArithmeticOverflow;
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

comptime {
    if (FORMAT_VERSION != 3 or SCHEMA_VERSION != 1 or
        PROVIDER_COMPONENT_INDEX != 34 or RANGE_COUNT != 3 or
        PROVIDER_INSTANCE_COUNT != 1 or
        STATEMENT_AUTHORITY_CALL_COUNT != 0 or
        HOT_VALIDATION_HEAP_ALLOCATIONS != 0 or
        HOT_IDENTITY_HEAP_ALLOCATIONS != 0 or
        COMPLETE_SCHEDULE_COLD_ALLOCATIONS != 1)
    {
        @compileError("temporal shared Poseidon schedule V3 ABI drifted");
    }
}
