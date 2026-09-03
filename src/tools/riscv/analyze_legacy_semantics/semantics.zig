//! Independent, byte-for-byte model of Revm 42 `analyze_legacy` scanning.
//!
//! This module deliberately does not import Revm or the guest.  The observer
//! binds the exact retained Revm source separately and uses this implementation
//! only to derive diagnostic quantities from authenticated guest bytes.

const std = @import("std");

pub const PUSH1: u8 = 0x60;
pub const JUMPDEST: u8 = 0x5b;
pub const STOP: u8 = 0x00;
pub const DUPN: u8 = 0xe6;

pub const Analysis = struct {
    bitmap_bytes: u32,
    eof_immediate_padding: u32,
    jumpdest_count: u32,
    opcode_positions: []u32,
    push_count: u32,
    push_overflow: u32,
    total_padding: u32,

    pub fn deinit(self: *Analysis, allocator: std.mem.Allocator) void {
        allocator.free(self.opcode_positions);
        self.* = undefined;
    }

    pub fn scanIterations(self: Analysis) u32 {
        return @intCast(self.opcode_positions.len);
    }
};

/// Reproduce the exact scan and padding arithmetic in Revm bytecode 42.0.0.
pub fn analyze(
    allocator: std.mem.Allocator,
    bytecode: []const u8,
) error{ OutOfMemory, InputTooLarge }!Analysis {
    if (bytecode.len > std.math.maxInt(u32)) return error.InputTooLarge;

    var positions: std.ArrayList(u32) = .empty;
    errdefer positions.deinit(allocator);
    var iterator: usize = 0;
    var previous: u8 = 0;
    var last: u8 = 0;
    var push_count: u32 = 0;
    var jumpdest_count: u32 = 0;
    while (iterator < bytecode.len) {
        try positions.append(allocator, @intCast(iterator));
        previous = last;
        last = bytecode[iterator];
        if (last == JUMPDEST) {
            jumpdest_count = std.math.add(u32, jumpdest_count, 1) catch
                return error.InputTooLarge;
            iterator += 1;
        } else {
            const push_offset = last -% PUSH1;
            if (push_offset < 32) {
                push_count = std.math.add(u32, push_count, 1) catch
                    return error.InputTooLarge;
                iterator += @as(usize, push_offset) + 2;
            } else {
                iterator += 1;
            }
        }
    }

    const push_overflow: u32 = @intCast(iterator - bytecode.len);
    const eof_immediate_padding: u32 = if (last == STOP)
        @intFromBool(isDupnSwapnExchange(previous))
    else
        1 + @as(u32, @intFromBool(isDupnSwapnExchange(last)));
    const total_padding = std.math.add(
        u32,
        push_overflow,
        eof_immediate_padding,
    ) catch return error.InputTooLarge;
    const bitmap_bytes: u32 = @intCast((bytecode.len + 7) / 8);
    return .{
        .bitmap_bytes = bitmap_bytes,
        .eof_immediate_padding = eof_immediate_padding,
        .jumpdest_count = jumpdest_count,
        .opcode_positions = try positions.toOwnedSlice(allocator),
        .push_count = push_count,
        .push_overflow = push_overflow,
        .total_padding = total_padding,
    };
}

fn isDupnSwapnExchange(opcode: u8) bool {
    return opcode -% DUPN < 3;
}

test "scan skips PUSH data and records only opcode positions" {
    var result = try analyze(std.testing.allocator, &.{
        PUSH1, JUMPDEST, JUMPDEST, STOP,
    });
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(u32, &.{ 0, 2, 3 }, result.opcode_positions);
    try std.testing.expectEqual(@as(u32, 1), result.push_count);
    try std.testing.expectEqual(@as(u32, 1), result.jumpdest_count);
    try std.testing.expectEqual(@as(u32, 0), result.total_padding);
}

test "truncated PUSH and Revm EOF immediate padding are independent" {
    var truncated = try analyze(std.testing.allocator, &.{ PUSH1, 1, 0x61, 2 });
    defer truncated.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(u32, &.{ 0, 2 }, truncated.opcode_positions);
    try std.testing.expectEqual(@as(u32, 1), truncated.push_overflow);
    try std.testing.expectEqual(@as(u32, 1), truncated.eof_immediate_padding);
    try std.testing.expectEqual(@as(u32, 2), truncated.total_padding);

    var immediate = try analyze(std.testing.allocator, &.{DUPN});
    defer immediate.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u32, 0), immediate.push_overflow);
    try std.testing.expectEqual(@as(u32, 2), immediate.eof_immediate_padding);
    try std.testing.expectEqual(@as(u32, 2), immediate.total_padding);
}

test "empty bytecode has no scan, bitmap, or padding" {
    var result = try analyze(std.testing.allocator, &.{});
    defer result.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), result.opcode_positions.len);
    try std.testing.expectEqual(@as(u32, 0), result.bitmap_bytes);
    try std.testing.expectEqual(@as(u32, 0), result.total_padding);
}
