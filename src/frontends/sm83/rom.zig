//! Validated borrowed ROM input for the unbanked SM83 proof slice.

const std = @import("std");

pub const SIZE: usize = 0x8000;
pub const LOG_SIZE: u32 = 15;

pub const Rom = struct {
    bytes: []const u8,

    pub fn init(bytes: []const u8) error{InvalidRomLength}!Rom {
        if (bytes.len != SIZE) return error.InvalidRomLength;
        return .{ .bytes = bytes };
    }

    pub fn digest(self: Rom) [32]u8 {
        var output: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(self.bytes, &output, .{});
        return output;
    }
};

test "ROM input has one canonical unbanked size and digest" {
    const bytes = [_]u8{0} ** SIZE;
    const rom = try Rom.init(&bytes);
    try std.testing.expectEqual(SIZE, rom.bytes.len);
    try std.testing.expect(!std.mem.allEqual(u8, &rom.digest(), 0));
    try std.testing.expectError(error.InvalidRomLength, Rom.init(bytes[0 .. SIZE - 1]));
}
