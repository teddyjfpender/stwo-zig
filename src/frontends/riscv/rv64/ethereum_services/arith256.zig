//! Native arith256_mod for the admitted v3 packet. Pure witness: the
//! arith256 truth AIR re-derives r from the carried identity and r < m.
const std = @import("std");
pub fn limbs(words: []const u64) u256 {
    var value: u256 = 0;
    for (words, 0..) |word, i| value |= @as(u256, word) << @intCast(64 * i);
    return value;
}
/// r = (a*b + c) mod m, and r = 0 when m = 0 (ABI).
pub fn mulAddMod(a: u256, b: u256, c: u256, m: u256) u256 {
    if (m == 0) return 0;
    return @truncate((@as(u512, a) * @as(u512, b) + @as(u512, c)) % @as(u512, m));
}
/// Words 16..20 (r) of the packet after one call.
pub fn mulAddModPacket(packet: [20]u64) [4]u64 {
    const r = mulAddMod(limbs(packet[0..4]), limbs(packet[4..8]), limbs(packet[8..12]), limbs(packet[12..16]));
    var out: [4]u64 = undefined;
    for (&out, 0..) |*w, i| w.* = @truncate(r >> @intCast(64 * i));
    return out;
}
test "packet arith256_mod matches the candidate executor's semantics" {
    const Candidate = @import("candidate_services.zig");
    var prng = std.Random.DefaultPrng.init(0x21);
    const rng = prng.random();
    for (0..256) |i| {
        var packet: [20]u64 = undefined;
        for (&packet) |*w| w.* = rng.int(u64);
        if (i % 7 == 0) @memset(packet[12..16], 0);
        if (i % 5 == 0) @memset(packet[13..16], 0);
        const expected = Candidate.mulAddMod(limbs(packet[0..4]), limbs(packet[4..8]), limbs(packet[8..12]), limbs(packet[12..16]));
        try std.testing.expectEqual(expected, limbs(&mulAddModPacket(packet)));
    }
}
