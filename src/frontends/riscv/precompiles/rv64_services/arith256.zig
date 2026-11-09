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
    return mod512(@as(u512, a) * @as(u512, b) + @as(u512, c), m);
}
/// Exactly x mod m (m != 0) by schoolbook long division on 64-bit limbs
/// (Knuth vol. 2 algorithm D, as in Hacker's Delight `divmnu` with doubled
/// digit width). LLVM lowers a generic `u512 % u512` to a bit-serial loop;
/// this is the same value (differentially tested against it) in ~50x less time.
pub fn mod512(x: u512, m: u256) u256 {
    std.debug.assert(m != 0);
    var v: [4]u64 = undefined;
    for (&v, 0..) |*w, i| w.* = @truncate(m >> @intCast(64 * i));
    var n: usize = 4;
    while (v[n - 1] == 0) n -= 1;
    if (n == 1) {
        var r: u128 = 0;
        var i: usize = 8;
        while (i > 0) {
            i -= 1;
            r = ((r << 64) | @as(u64, @truncate(x >> @intCast(64 * i)))) % v[0];
        }
        return @intCast(r);
    }
    const s: u6 = @intCast(@clz(v[n - 1]));
    // Normalize: vn = v << s, un = x << s (nine digits).
    var vn: [4]u64 = @splat(0);
    var i: usize = n - 1;
    while (i > 0) : (i -= 1) vn[i] = (v[i] << s) | if (s == 0) 0 else v[i - 1] >> @intCast(@as(u7, 64) - s);
    vn[0] = v[0] << s;
    var u: [8]u64 = undefined;
    for (&u, 0..) |*w, k| w.* = @truncate(x >> @intCast(64 * k));
    var un: [9]u64 = undefined;
    un[8] = if (s == 0) 0 else u[7] >> @intCast(@as(u7, 64) - s);
    i = 7;
    while (i > 0) : (i -= 1) un[i] = (u[i] << s) | if (s == 0) 0 else u[i - 1] >> @intCast(@as(u7, 64) - s);
    un[0] = u[0] << s;
    const B: u128 = 1 << 64;
    var j: usize = 8 - n + 1;
    while (j > 0) {
        j -= 1;
        const num = (@as(u128, un[j + n]) << 64) | un[j + n - 1];
        var qhat: u128 = num / vn[n - 1];
        var rhat: u128 = num - qhat * vn[n - 1];
        while (qhat >= B or qhat * vn[n - 2] > (rhat << 64) + un[j + n - 2]) {
            qhat -= 1;
            rhat += vn[n - 1];
            if (rhat >= B) break;
        }
        // Multiply and subtract qhat * vn from un[j .. j+n].
        var k: i128 = 0;
        for (0..n) |t| {
            const p: u128 = qhat * vn[t];
            const diff: i128 = @as(i128, un[t + j]) - k - @as(i128, @as(u64, @truncate(p)));
            un[t + j] = @truncate(@as(u128, @bitCast(diff)));
            k = @as(i128, @intCast(p >> 64)) - (diff >> 64);
        }
        const top: i128 = @as(i128, un[j + n]) - k;
        un[j + n] = @truncate(@as(u128, @bitCast(top)));
        if (top < 0) {
            // qhat was one too large: add vn back.
            var carry: u128 = 0;
            for (0..n) |t| {
                const sum: u128 = @as(u128, un[t + j]) + vn[t] + carry;
                un[t + j] = @truncate(sum);
                carry = sum >> 64;
            }
            un[j + n] +%= @truncate(carry);
        }
    }
    // Remainder = un[0..n] >> s.
    var r: u256 = 0;
    for (0..n) |t| {
        const lo = un[t] >> s;
        const hi: u64 = if (s == 0) 0 else un[t + 1] << @intCast(@as(u7, 64) - s);
        r |= @as(u256, lo | hi) << @intCast(64 * t);
    }
    return r;
}
test "arith256 long division equals the generic u512 remainder" {
    var prng = std.Random.DefaultPrng.init(0xa21256);
    const rng = prng.random();
    const edge = [_]u64{ 0, 1, 2, 0x7fff_ffff_ffff_ffff, 0x8000_0000_0000_0000, 0x8000_0000_0000_0001, 0xffff_ffff_ffff_fffe, 0xffff_ffff_ffff_ffff };
    for (0..400000) |case| {
        var xw: [8]u64 = undefined;
        var mw: [4]u64 = undefined;
        for (&xw) |*w| w.* = if (case % 3 == 0) edge[rng.uintLessThan(usize, edge.len)] else rng.int(u64);
        for (&mw) |*w| w.* = if (case % 2 == 0) edge[rng.uintLessThan(usize, edge.len)] else rng.int(u64);
        // Vary the divisor length 1..4 limbs and the dividend length.
        const ml = 1 + case % 4;
        for (mw[ml..]) |*w| w.* = 0;
        const xl = 1 + (case / 4) % 8;
        for (xw[xl..]) |*w| w.* = 0;
        var x: u512 = 0;
        for (xw, 0..) |w, i| x |= @as(u512, w) << @intCast(64 * i);
        var m: u256 = 0;
        for (mw, 0..) |w, i| m |= @as(u256, w) << @intCast(64 * i);
        if (m == 0) m = 1 + @as(u256, rng.int(u8));
        try std.testing.expectEqual(@as(u256, @intCast(x % m)), mod512(x, m));
    }
}
/// Words 16..20 (r) of the packet after one call.
pub fn mulAddModPacket(packet: [20]u64) [4]u64 {
    const r = mulAddMod(limbs(packet[0..4]), limbs(packet[4..8]), limbs(packet[8..12]), limbs(packet[12..16]));
    var out: [4]u64 = undefined;
    for (&out, 0..) |*w, i| w.* = @truncate(r >> @intCast(64 * i));
    return out;
}
test "packet arith256_mod matches the candidate executor's semantics" {
    const Candidate = @import("stwo_riscv_rv64").modules.ethereum_services_candidate_services;
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
