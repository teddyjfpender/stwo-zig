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
        for (0..4) |i| {
            const shift: u5 = @intCast(i * 8);
            carry = (((a >> shift) & 255) + ((b >> shift) & 255) + carry) >> 8;
            self.value(carry);
        }
        return a +% b;
    }
    pub fn xorRotate(self: *Writer, a: u32, b: u32, comptime rotation: u5) !u32 {
        const xors = a ^ b;
        self.word(xors);
        const result = std.math.rotr(u32, xors, rotation);
        if (rotation == 16 or rotation == 8) return result;
        const shift = rotation % 8;
        for (0..4) |i| {
            const byte = (xors >> @as(u5, @intCast(i * 8))) & 255;
            const low = byte & ((1 << shift) - 1);
            const high = byte >> shift;
            self.value(low);
            self.value(low << (8 - shift));
            self.value(high);
            if (shift == 4) self.value(high << 4);
        }
        self.word(result);
        return result;
    }
};
