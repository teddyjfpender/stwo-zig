//! Independent Core OM31 reference for the native device lookup-parameter ABI.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const O = core.fields.om31.OM31;

pub fn main() !void {
    var seed: u64 = 0x927abc48dbe10369;
    for (0..84) |case| {
        var inputs: [16]M = undefined;
        for (&inputs) |*v| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            v.* = .{ .v = @intCast(seed % 2147483647) };
        }
        if (case == 0) {
            @memset(&inputs, M.zero());
        } else if (case == 1) {
            @memset(&inputs, M.zero());
            inputs[0] = M.one();
            inputs[8] = M.one();
        } else if (case == 2) {
            @memset(&inputs, .{ .v = 2147483646 });
        } else if (case < 20) {
            @memset(&inputs, M.zero());
            inputs[(case - 3) % 8] = .{ .v = 2147483646 };
            inputs[8 + (case - 3) % 8] = M.one();
        }
        var words: [72]u32 = undefined;
        for (inputs, 0..) |v, i| words[i] = v.v;
        const z = O.fromM31Array(inputs[0..8].*);
        const alpha = O.fromM31Array(inputs[8..16].*);
        for (z.toM31Array(), 0..) |v, c| words[16 + c] = v.v;
        var power = O.one();
        for (0..6) |i| {
            for (power.toM31Array(), 0..) |v, c| words[24 + i * 8 + c] = v.v;
            power = power.mul(alpha);
        }
        // The pod is little-endian; serialize explicitly for a portable corpus.
        var bytes: [72 * 4]u8 = undefined;
        for (words, 0..) |v, i| std.mem.writeInt(u32, bytes[4 * i ..][0..4], v, .little);
        try std.fs.File.stdout().writeAll(&bytes);
    }
}
