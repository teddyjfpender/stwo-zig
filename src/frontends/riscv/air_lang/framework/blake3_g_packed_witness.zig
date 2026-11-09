const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const component = @import("blake3_g_packed.zig");
pub fn witness(input: [6]u32) !component.Row {
    var ops = Writer{};
    for (input) |value| ops.word(value);
    _ = try core.crypto.blake3_compression.g(Writer, &ops, input);
    std.debug.assert(ops.at == component.COLUMN_COUNT);
    return ops.row;
}
const Writer = struct {
    pub const Word = u32;
    row: component.Row = undefined,
    at: usize = 0,
    fn value(self: *Writer, n: u32) void {
        self.row[self.at] = M31.fromCanonical(n);
        self.at += 1;
    }
    fn word(self: *Writer, n: u32) void {
        for (0..4) |i| self.value((n >> @as(u5, @intCast(i * 8))) & 255);
    }
    pub fn add(self: *Writer, a: u32, b: u32) !u32 {
        self.word(a +% b);
        var carry: u32 = 0;
        for (0..2) |i| {
            const shift: u5 = @intCast(i * 16);
            carry = (((a >> shift) & 65535) + ((b >> shift) & 65535) + carry) >> 16;
            self.value(carry);
        }
        return a +% b;
    }
    pub fn add3(self: *Writer, a: u32, b: u32, message: u32) !u32 {
        self.word(a +% b +% message);
        var carry: u32 = 0;
        for (0..2) |i| {
            const shift: u5 = @intCast(i * 16);
            carry = (((a >> shift) & 65535) + ((b >> shift) & 65535) + ((message >> shift) & 65535) + carry) >> 16;
            self.value(carry & 1);
            self.value(carry >> 1);
        }
        return a +% b +% message;
    }
    pub fn xorRotate(self: *Writer, a: u32, b: u32, comptime rotation: u5) !u32 {
        const xors = a ^ b;
        self.word(xors);
        const result = std.math.rotr(u32, xors, rotation);
        if (rotation == 16 or rotation == 8) return result;
        if (rotation == 7) {
            self.word(result);
            const rotated = std.math.rotr(u32, xors, 8);
            self.value((rotated >> 15) & 1);
            self.value(rotated >> 31);
            return result;
        }
        if (rotation != 12) @compileError("unsupported BLAKE3 rotation");
        self.word(result);
        const rotated = std.math.rotr(u32, xors, 8);
        for (0..2) |i| {
            const low = (rotated >> @as(u5, @intCast(i * 16))) & 15;
            self.value(low);
            self.value(low << 4);
        }
        return result;
    }
};
