//! Native SHA-256 compression for the admitted v3 packet. Pure witness: the
//! SHA-256 truth AIR re-derives every output bit; this never grants authority.
const std = @import("std");
const K = [64]u32{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};
fn rotr(x: u32, comptime n: u5) u32 {
    return std.math.rotr(u32, x, n);
}
pub fn compress(state: *[8]u32, block: *const [64]u8) void {
    var w: [64]u32 = undefined;
    for (0..16) |t| w[t] = std.mem.readInt(u32, block[4 * t ..][0..4], .big);
    for (16..64) |t| {
        const s0 = rotr(w[t - 15], 7) ^ rotr(w[t - 15], 18) ^ (w[t - 15] >> 3);
        const s1 = rotr(w[t - 2], 17) ^ rotr(w[t - 2], 19) ^ (w[t - 2] >> 10);
        w[t] = s1 +% w[t - 7] +% s0 +% w[t - 16];
    }
    var a = state[0];
    var b = state[1];
    var c = state[2];
    var d = state[3];
    var e = state[4];
    var f = state[5];
    var g = state[6];
    var h = state[7];
    for (0..64) |t| {
        const t1 = h +% (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) +% ((e & f) ^ (~e & g)) +% K[t] +% w[t];
        const t2 = (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22)) +% ((a & b) ^ (a & c) ^ (b & c));
        h = g;
        g = f;
        f = e;
        e = d +% t1;
        d = c;
        c = b;
        b = a;
        a = t1 +% t2;
    }
    for (state, [8]u32{ a, b, c, d, e, f, g, h }) |*s, x| s.* +%= x;
}
/// Words 0..4 of the packet after one compression.
pub fn compressPacket(packet: [12]u64) [4]u64 {
    var state: [8]u32 = undefined;
    for (&state, 0..) |*v, i| v.* = @truncate(packet[i / 2] >> @intCast(32 * (i % 2)));
    var block: [64]u8 = undefined;
    for (0..8) |i| std.mem.writeInt(u64, block[8 * i ..][0..8], packet[4 + i], .little);
    compress(&state, &block);
    var out: [4]u64 = undefined;
    for (&out, 0..) |*v, i| v.* = @as(u64, state[2 * i]) | (@as(u64, state[2 * i + 1]) << 32);
    return out;
}
test "packet compression matches std.crypto on abc" {
    var packet: [12]u64 = @splat(0);
    const iv = [8]u32{ 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
    for (0..4) |i| packet[i] = @as(u64, iv[2 * i]) | (@as(u64, iv[2 * i + 1]) << 32);
    var block: [64]u8 = @splat(0);
    @memcpy(block[0..3], "abc");
    block[3] = 0x80;
    block[63] = 24;
    for (0..8) |i| packet[4 + i] = std.mem.readInt(u64, block[8 * i ..][0..8], .little);
    const out = compressPacket(packet);
    var digest: [32]u8 = undefined;
    for (0..8) |i| std.mem.writeInt(u32, digest[4 * i ..][0..4], @truncate(out[i / 2] >> @intCast(32 * (i % 2))), .big);
    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("abc", &expected, .{});
    try std.testing.expectEqualSlices(u8, &expected, &digest);
}
