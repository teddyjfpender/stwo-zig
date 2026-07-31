//! Validated borrowed flat-memory image for execution statements.

const std = @import("std");
const rom_mod = @import("rom.zig");

pub const SIZE: usize = 0x10000;

pub const Image = struct {
    bytes: []const u8,

    pub fn init(bytes: []const u8) error{InvalidMemoryLength}!Image {
        if (bytes.len != SIZE) return error.InvalidMemoryLength;
        return .{ .bytes = bytes };
    }

    pub fn digest(self: Image) [32]u8 {
        var output: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(self.bytes, &output, .{});
        return output;
    }

    pub fn validateRom(self: Image, rom: rom_mod.Rom) error{RomMemoryMismatch}!void {
        if (!std.mem.eql(u8, self.bytes[0..rom_mod.SIZE], rom.bytes))
            return error.RomMemoryMismatch;
    }
};

test "memory image is fixed-width and binds its ROM window" {
    const bytes = [_]u8{0} ** SIZE;
    const image = try Image.init(&bytes);
    const rom = try rom_mod.Rom.init(bytes[0..rom_mod.SIZE]);
    try image.validateRom(rom);
    try std.testing.expect(!std.mem.allEqual(u8, &image.digest(), 0));
    try std.testing.expectError(
        error.InvalidMemoryLength,
        Image.init(bytes[0 .. SIZE - 1]),
    );
}
