//! Protocol clocks for register and RW-memory accesses.
//!
//! The architectural state bus keeps its one-based instruction clock.  The
//! memory-access bus refines each instruction into three strictly ordered
//! accesses inside a four-wide bucket:
//!
//!   access_clock(c, i) = 4 * (c - 1) + i + 1,  i in {0, 1, 2}.
//!
//! The unused fourth value makes malformed public clocks recognizable without
//! adding a committed column.  Every opcode AIR derives its emitted access
//! clock from the committed instruction clock and the access's actual ordinal;
//! only predecessor clocks remain witness cells.

const std = @import("std");

pub const STRIDE: u32 = 4;
pub const MAX_ACCESSES_PER_INSTRUCTION: u32 = 3;

pub const Ordinal = enum(u2) {
    first = 0,
    second = 1,
    third = 2,
};

/// Encode one actual access of a one-based instruction clock.
pub fn encode(instruction_clock: u32, ordinal: Ordinal) u32 {
    std.debug.assert(instruction_clock != 0);
    const encoded = (@as(u64, instruction_clock) - 1) * STRIDE +
        @intFromEnum(ordinal) + 1;
    return @intCast(encoded);
}

/// Largest access clock an execution of `instruction_count` steps may expose.
pub fn maximum(instruction_count: u32) u64 {
    if (instruction_count == 0) return 0;
    return (@as(u64, instruction_count) - 1) * STRIDE +
        MAX_ACCESSES_PER_INSTRUCTION;
}

/// Whether a nonzero value is one of the three protocol access subclocks.
pub fn isCanonical(clock: u32) bool {
    if (clock == 0) return false;
    return ((clock - 1) % STRIDE) < MAX_ACCESSES_PER_INSTRUCTION;
}

/// Whether `clock` is a canonical access of this execution.
///
/// Zero is the initial boundary and is accepted only when the caller permits
/// it (registers that were never touched and unretired completion records).
pub fn isWithinExecution(clock: u32, instruction_count: u32, allow_zero: bool) bool {
    if (clock == 0) return allow_zero;
    return isCanonical(clock) and @as(u64, clock) <= maximum(instruction_count);
}

test "access clock: instruction buckets are ordered and reserve every fourth value" {
    try std.testing.expectEqual(@as(u32, 1), encode(1, .first));
    try std.testing.expectEqual(@as(u32, 2), encode(1, .second));
    try std.testing.expectEqual(@as(u32, 3), encode(1, .third));
    try std.testing.expectEqual(@as(u32, 5), encode(2, .first));
    try std.testing.expect(!isCanonical(4));
    try std.testing.expect(!isCanonical(8));
}

test "access clock: public execution bound includes the last actual ordinal" {
    try std.testing.expectEqual(@as(u64, 0), maximum(0));
    try std.testing.expectEqual(@as(u64, 3), maximum(1));
    try std.testing.expectEqual(@as(u64, 7), maximum(2));
    try std.testing.expect(isWithinExecution(7, 2, false));
    try std.testing.expect(!isWithinExecution(8, 2, false));
    try std.testing.expect(isWithinExecution(0, 2, true));
    try std.testing.expect(!isWithinExecution(0, 2, false));
}
