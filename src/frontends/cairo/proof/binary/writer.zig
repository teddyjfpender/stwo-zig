//! Legacy bincode 1.3 fixed-width encoding primitives.

const std = @import("std");

pub fn byte(output: anytype, value: u8) !void {
    try output.writeByte(value);
}

pub fn int(output: anytype, comptime T: type, value: T) !void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, value, .little);
    try output.writeAll(&encoded);
}

pub fn length(output: anytype, value: usize) !void {
    try int(output, u64, std.math.cast(u64, value) orelse
        return error.BinaryLengthOverflow);
}

pub fn optional(output: anytype, present: bool) !void {
    try byte(output, @intFromBool(present));
}

test "bincode primitives use the legacy fixed-width layout" {
    var storage: [32]u8 = undefined;
    var output = std.Io.Writer.fixed(&storage);
    try optional(&output, true);
    try int(&output, u32, 0x12345678);
    try length(&output, 2);
    try std.testing.expectEqualSlices(
        u8,
        &.{
            1,
            0x78,
            0x56,
            0x34,
            0x12,
            2,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
        },
        output.buffered(),
    );
}
