//! Versioned little-endian subprocess wire format. Not the Bend runtime layout.
const std = @import("std");
pub const request_magic: u32 = 0x31444e42;
pub const response_magic: u32 = 0x314f4e42;
pub const version: u32 = 1;
pub const max_log_size = 24;
pub const Operation = enum(u32) { fft = 0, ifft = 1, multiply = 2, prefix = 3 };
pub fn word(out: *std.ArrayList(u8), allocator: std.mem.Allocator, value: u32) !void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .little);
    try out.appendSlice(allocator, &bytes);
}
