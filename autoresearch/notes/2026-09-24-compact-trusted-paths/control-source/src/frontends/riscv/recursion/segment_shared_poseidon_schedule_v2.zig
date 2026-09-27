//! Single source of truth for the resumed-segment V2 row-34 call schedule.
//!
//! The verified native ingress owns an immutable transcript/statement-
//! authority prefix.  The recursive verifier core appends its calls.  This
//! module authenticates that exact order and buffer; neither the outer cohort
//! nor a CPU integration may define a competing layout or digest.

const std = @import("std");
const stwo_core = @import("stwo_core");

const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");

pub const Call = poseidon2_air.Call;
pub const Sha256Digest = [32]u8;

pub const FORMAT_VERSION: u16 = 2;
pub const SCHEMA_VERSION: u16 = 2;
pub const PROVIDER_COMPONENT_INDEX: u8 = 34;
pub const RANGE_COUNT: usize = 3;
pub const PROVIDER_INSTANCE_COUNT: usize = 1;
pub const HOT_VALIDATION_HEAP_ALLOCATIONS: usize = 0;
pub const HOT_IDENTITY_HEAP_ALLOCATIONS: usize = 0;
pub const COMPLETE_SCHEDULE_COLD_ALLOCATIONS: usize = 1;

pub const CALL_LAYOUT_ID_DOMAIN =
    "stwo-zig/typed-air/recursive-segment-v2-row34-layout/v1\x00";
pub const CALL_BUFFER_ID_DOMAIN =
    "stwo-zig/typed-air/recursive-segment-v2-row34-calls/v1\x00";

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

/// Pointer-free authenticated order receipt. The boundary form intentionally
/// has an empty verifier-core range and cannot be mistaken for a complete
/// provider. The complete form requires all three non-empty ranges.
pub const SharedPoseidonCallLayoutV2 = struct {
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

    pub fn initBoundaryPrefix(
        transcript_call_count: usize,
        authority_call_count: usize,
        calls: []const Call,
    ) Error!SharedPoseidonCallLayoutV2 {
        const total = try add(transcript_call_count, authority_call_count);
        if (calls.len != total or transcript_call_count == 0 or
            authority_call_count == 0)
        {
            return error.CallLayoutMismatch;
        }
        var result = SharedPoseidonCallLayoutV2{
            .transcript = .{
                .start = 0,
                .end = try usizeToU32(transcript_call_count),
            },
            .statement_authority = .{
                .start = try usizeToU32(transcript_call_count),
                .end = try usizeToU32(total),
            },
            .verifier_core = .{
                .start = try usizeToU32(total),
                .end = try usizeToU32(total),
            },
            .boundary_prefix_call_count = try usizeToU32(total),
            .verifier_core_range_populated = false,
            .call_set_complete = false,
            .total_call_count = try usizeToU32(total),
            .call_buffer_id = callBufferIdentity(calls),
            .identity = undefined,
        };
        result.identity = callLayoutIdentity(&result);
        try result.validate(calls);
        return result;
    }

    pub fn initComplete(
        transcript_call_count: usize,
        authority_call_count: usize,
        verifier_core_call_count: usize,
        calls: []const Call,
    ) Error!SharedPoseidonCallLayoutV2 {
        const boundary = try add(transcript_call_count, authority_call_count);
        const total = try add(boundary, verifier_core_call_count);
        if (calls.len != total or transcript_call_count == 0 or
            authority_call_count == 0 or verifier_core_call_count == 0)
        {
            return error.CallLayoutMismatch;
        }
        var result = SharedPoseidonCallLayoutV2{
            .transcript = .{
                .start = 0,
                .end = try usizeToU32(transcript_call_count),
            },
            .statement_authority = .{
                .start = try usizeToU32(transcript_call_count),
                .end = try usizeToU32(boundary),
            },
            .verifier_core = .{
                .start = try usizeToU32(boundary),
                .end = try usizeToU32(total),
            },
            .boundary_prefix_call_count = try usizeToU32(boundary),
            .verifier_core_range_populated = true,
            .call_set_complete = true,
            .total_call_count = try usizeToU32(total),
            .call_buffer_id = callBufferIdentity(calls),
            .identity = undefined,
        };
        result.identity = callLayoutIdentity(&result);
        try result.validate(calls);
        return result;
    }

    pub fn validate(
        self: *const SharedPoseidonCallLayoutV2,
        calls: []const Call,
    ) Error!void {
        try self.validateReceipt();
        if (self.total_call_count != calls.len)
            return error.CallLayoutMismatch;
        for (calls) |call| try validateCall(call);
        if (!std.mem.eql(
            u8,
            &self.call_buffer_id,
            &callBufferIdentity(calls),
        )) return error.CallLayoutMismatch;
    }

    /// Validates the pointer-free ordering receipt without pretending that it
    /// authenticates an absent call buffer. Buffer custody must use
    /// `validate`; cohort plans use this only after construction consumed a
    /// validated layout/call pair.
    pub fn validateReceipt(self: *const SharedPoseidonCallLayoutV2) Error!void {
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
        if (transcript_count == 0 or authority_count == 0)
            return error.CallLayoutMismatch;
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
        if (!std.mem.eql(u8, &self.identity, &callLayoutIdentity(self))) {
            return error.CallLayoutMismatch;
        }
    }

    pub fn ranges(self: SharedPoseidonCallLayoutV2) [RANGE_COUNT]CallRange {
        return .{ self.transcript, self.statement_authority, self.verifier_core };
    }
};

/// Cold owner for the final call buffer. It copies an authenticated prefix
/// byte-for-byte, appends core calls once, and seals the shared layout before
/// publication. Validation and all later reads allocate nothing.
pub const OwnedCompletePoseidonScheduleV2 = struct {
    allocator: std.mem.Allocator,
    calls: []Call,
    layout: SharedPoseidonCallLayoutV2,

    pub fn init(
        allocator: std.mem.Allocator,
        boundary_layout: *const SharedPoseidonCallLayoutV2,
        boundary_calls: []const Call,
        verifier_core_calls: []const Call,
    ) (Error || std.mem.Allocator.Error)!OwnedCompletePoseidonScheduleV2 {
        try boundary_layout.validate(boundary_calls);
        if (boundary_layout.call_set_complete or verifier_core_calls.len == 0)
            return error.CallLayoutMismatch;
        for (verifier_core_calls) |call| try validateCall(call);
        const total = try add(boundary_calls.len, verifier_core_calls.len);
        const calls = try allocator.alloc(Call, total);
        errdefer allocator.free(calls);
        @memcpy(calls[0..boundary_calls.len], boundary_calls);
        @memcpy(calls[boundary_calls.len..], verifier_core_calls);
        const layout = try SharedPoseidonCallLayoutV2.initComplete(
            try boundary_layout.transcript.count(),
            try boundary_layout.statement_authority.count(),
            verifier_core_calls.len,
            calls,
        );
        const result = OwnedCompletePoseidonScheduleV2{
            .allocator = allocator,
            .calls = calls,
            .layout = layout,
        };
        try result.validateAgainst(boundary_layout, boundary_calls);
        return result;
    }

    pub fn deinit(self: *OwnedCompletePoseidonScheduleV2) void {
        self.allocator.free(self.calls);
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const OwnedCompletePoseidonScheduleV2,
        boundary_layout: *const SharedPoseidonCallLayoutV2,
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
    layout: *const SharedPoseidonCallLayoutV2,
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
    if (FORMAT_VERSION != 2 or SCHEMA_VERSION != 2 or
        PROVIDER_COMPONENT_INDEX != 34 or RANGE_COUNT != 3 or
        PROVIDER_INSTANCE_COUNT != 1 or HOT_VALIDATION_HEAP_ALLOCATIONS != 0 or
        HOT_IDENTITY_HEAP_ALLOCATIONS != 0 or
        COMPLETE_SCHEDULE_COLD_ALLOCATIONS != 1)
    {
        @compileError("SegmentV2 shared Poseidon schedule ABI drifted");
    }
}
