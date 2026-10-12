//! Ordered Poseidon call buffer for a directly proven recursive leaf.
//!
//! Each part must come from a separately constrained requester. This module
//! owns their exact concatenation and guards witness writes against mutation;
//! it does not confer authority on the requesters or close their lookup bus.

const std = @import("std");
const core = @import("stwo_core");
const poseidon = @import("../air/memory_commitment/poseidon2_air.zig");

pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const Call = poseidon.Call;
pub const MIN_LOG_SIZE: u32 = 4;
pub const MAX_LOG_SIZE: u32 = 30;
pub const Range = struct { start: usize, len: usize };

pub const Buffer = struct {
    allocator: std.mem.Allocator,
    calls: []Call,
    ranges: []Range,
    log_size: u32,

    pub fn init(allocator: std.mem.Allocator, parts: []const []const Call) !Buffer {
        if (parts.len == 0) return error.EmptyPoseidonCallParts;
        const ranges = try allocator.alloc(Range, parts.len);
        errdefer allocator.free(ranges);
        var total: usize = 0;
        for (parts, ranges) |part, *range| {
            if (part.len == 0) return error.EmptyPoseidonCallPart;
            range.* = .{ .start = total, .len = part.len };
            total = try std.math.add(usize, total, part.len);
        }
        if (total >= core.fields.m31.Modulus) return error.TooManyPoseidonCalls;
        const calls = try allocator.alloc(Call, total);
        errdefer allocator.free(calls);
        for (parts, ranges) |part, range| @memcpy(calls[range.start..][0..range.len], part);
        const log_size: u32 = @max(MIN_LOG_SIZE, std.math.log2_int_ceil(usize, total));
        if (log_size > MAX_LOG_SIZE) return error.TooManyPoseidonCalls;
        const result = Buffer{
            .allocator = allocator,
            .calls = calls,
            .ranges = ranges,
            .log_size = log_size,
        };
        try result.validateAgainst(parts);
        return result;
    }

    pub fn deinit(self: *Buffer) void {
        self.allocator.free(self.calls);
        self.allocator.free(self.ranges);
        self.* = undefined;
    }

    pub fn validateAgainst(self: *const Buffer, parts: []const []const Call) !void {
        if (parts.len == 0 or parts.len != self.ranges.len or
            self.calls.len == 0 or self.calls.len >= core.fields.m31.Modulus or
            self.log_size > MAX_LOG_SIZE or
            self.log_size != @max(MIN_LOG_SIZE, std.math.log2_int_ceil(usize, self.calls.len)))
            return error.PoseidonCallBufferMismatch;
        var at: usize = 0;
        for (parts, self.ranges) |part, range| {
            if (part.len == 0 or range.start != at or range.len != part.len)
                return error.PoseidonCallBufferMismatch;
            const end = std.math.add(usize, at, part.len) catch return error.PoseidonCallBufferMismatch;
            if (end > self.calls.len) return error.PoseidonCallBufferMismatch;
            for (part, self.calls[at..end]) |expected, actual| {
                try validateCall(expected);
                if (!std.meta.eql(expected, actual)) return error.PoseidonCallBufferMismatch;
            }
            at = end;
        }
        if (at != self.calls.len) return error.PoseidonCallBufferMismatch;
    }
};

fn validateCall(call: Call) !void {
    if (call.wide or !call.io or call.narrow_output != null)
        return error.InvalidRecursivePoseidonCallMode;
    for (call.input) |word| if (word >= core.fields.m31.Modulus)
        return error.NonCanonicalPoseidonCallWord;
}
