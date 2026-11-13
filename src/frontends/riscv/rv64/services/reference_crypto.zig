//! Independent mathematical references used by AIR tests and candidate callers.
//! Deliberately separate from optimized witness primitives; no service dispatch.
const std = @import("std");
pub fn mulAdd(x: u256, y: u256, z: u256) u512 {
    return @as(u512, x) * @as(u512, y) + @as(u512, z);
}

pub fn mulAddMod(x: u256, y: u256, z: u256, m: u256) u256 {
    if (m == 0) return 0;
    return @truncate(mulAdd(x, y, z) % @as(u512, m));
}

const K256 = [64]u32{
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

/// FIPS 180-4 section 6.2.2, one block. Independent of std's Sha256 so the
/// test vectors exercise this code, not the library.
pub fn sha256Compress(state: *[8]u32, block: *const [64]u8) void {
    var w: [64]u32 = undefined;
    for (0..16) |t| w[t] = std.mem.readInt(u32, block[4 * t ..][0..4], .big);
    for (16..64) |t| {
        const s0 = std.math.rotr(u32, w[t - 15], 7) ^ std.math.rotr(u32, w[t - 15], 18) ^ (w[t - 15] >> 3);
        const s1 = std.math.rotr(u32, w[t - 2], 17) ^ std.math.rotr(u32, w[t - 2], 19) ^ (w[t - 2] >> 10);
        w[t] = w[t - 16] +% s0 +% w[t - 7] +% s1;
    }
    var v = state.*;
    for (0..64) |t| {
        const s1 = std.math.rotr(u32, v[4], 6) ^ std.math.rotr(u32, v[4], 11) ^ std.math.rotr(u32, v[4], 25);
        const ch = (v[4] & v[5]) ^ (~v[4] & v[6]);
        const t1 = v[7] +% s1 +% ch +% K256[t] +% w[t];
        const s0 = std.math.rotr(u32, v[0], 2) ^ std.math.rotr(u32, v[0], 13) ^ std.math.rotr(u32, v[0], 22);
        const maj = (v[0] & v[1]) ^ (v[0] & v[2]) ^ (v[1] & v[2]);
        const t2 = s0 +% maj;
        // Build into a temporary: result-location semantics would alias `v`.
        const next = [8]u32{ t1 +% t2, v[0], v[1], v[2], v[3] +% t1, v[4], v[5], v[6] };
        v = next;
    }
    for (state, v) |*h, x| h.* +%= x;
}
