const std = @import("std");
const F = @import("../fields/m31.zig");
const P = @import("poseidon2_m31_w24.zig");
const S = @import("poseidon2_m31_sponge.zig");
const Packed = @import("poseidon2_m31_sponge4.zig");
const Record = struct {
    hash: std.crypto.hash.sha2.Sha256 = std.crypto.hash.sha2.Sha256.init(.{}),
    next: u32 = 25,
    ops: u32 = 0,
    fn event(self: *Record, tag: u32, a: u32, b: u32) u32 {
        var bytes: [12]u8 = undefined;
        std.mem.writeInt(u32, bytes[0..4], tag, .little);
        std.mem.writeInt(u32, bytes[4..8], a, .little);
        std.mem.writeInt(u32, bytes[8..12], b, .little);
        self.hash.update(&bytes);
        const result = self.next;
        self.next += 1;
        self.ops += 1;
        return result;
    }
};
const RecordOps = struct {
    record: *Record,
    pub fn constant(self: @This(), x: u32) !u32 {
        return self.record.event(1, x, 0);
    }
    pub fn add(self: @This(), x: u32, y: u32) !u32 {
        return self.record.event(2, x, y);
    }
    pub fn sub(self: @This(), x: u32, y: u32) !u32 {
        return self.record.event(3, x, y);
    }
    pub fn mul(self: @This(), x: u32, y: u32) !u32 {
        return self.record.event(4, x, y);
    }
};
test "Poseidon width24 absent-hook operation stream remains source exact" {
    var record: Record = .{};
    var state: [P.WIDTH]u32 = undefined;
    for (&state, 0..) |*v, i| v.* = @intCast(i + 1);
    try P.permuteFor(u32, RecordOps{ .record = &record }, &state);
    for (state) |v| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, v, .little);
        record.hash.update(&bytes);
    }
    const digest = record.hash.finalResult();
    // Captured before the optional native hook was introduced.
    const expected = [_]u8{ 0x82, 0x40, 0x74, 0x0e, 0xb0, 0x7c, 0x13, 0x1e, 0xa9, 0xf8, 0xc4, 0x14, 0x42, 0xbe, 0x88, 0xc5, 0x00, 0x36, 0x78, 0x39, 0xc4, 0xaf, 0xe0, 0x2d, 0xa4, 0x6b, 0xa7, 0x02, 0xf1, 0x61, 0x51, 0x08 };
    try std.testing.expectEqual(@as(u32, 4040), record.ops);
    try std.testing.expectEqualSlices(u8, &expected, &digest);
}

test "Sponge4 domains padding state transfer and rate boundaries match four scalar sponges" {
    const counts = [_]usize{ 0, 1, 2, 9, 11, 12, 13, 18, 23, 24, 25, 47, 48, 49, 63, 64, 65, 127, 128, 129, 255, 256, 479 };
    var prng = std.Random.DefaultPrng.init(0x50414444494e47);
    const random = prng.random();
    for (std.enums.values(S.Domain)) |domain| for (counts) |count| {
        var scalar: [4]S.Sponge = @splat(S.Sponge.init(domain));
        var lane_sponge = Packed.Sponge4.init(domain);
        for (0..count) |i| {
            var words: [4]u32 = undefined;
            for (&words, 0..) |*word, lane| word.* = if (i % 17 == 0) (F.Modulus - 1 - @as(u32, @intCast(lane))) else random.uintLessThan(u32, F.Modulus);
            lane_sponge.absorb(words);
            for (&scalar, words) |*s, word| s.absorb(F.M31.fromCanonical(word));
            if (i % 7 == 0) {
                var written: [4]S.Sponge = undefined;
                lane_sponge.writeStates(&written);
                for (scalar, written) |expected, got| {
                    try std.testing.expectEqual(expected.at, got.at);
                    try std.testing.expectEqualDeep(expected.state, got.state);
                }
                lane_sponge = Packed.Sponge4.fromStates(&written);
            }
        }
        const got = lane_sponge.finish();
        for (scalar, got) |expected, digest| try std.testing.expectEqualSlices(u8, &expected.digest(), &digest);
    };
}
