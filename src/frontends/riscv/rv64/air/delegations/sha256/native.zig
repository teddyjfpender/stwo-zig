//! Native SHA-256 compression witness. This is producer advice only: every
//! value placed here is re-derived by the AIR from Boolean columns and exact
//! carried sums, and the Wire35 bus binds its inputs/outputs to guest RAM.
const std = @import("std");
const L = @import("layout.zig");

/// One compression: the packet's eight FIPS state words and its 64-byte block
/// in stream order (SHA-256's big-endian word parse applies to these bytes).
pub const Input = struct { state: [8]u32, block: [64]u8 };

pub fn rotr(x: u32, comptime n: u5) u32 {
    return std.math.rotr(u32, x, n);
}
pub fn bigSigma0(x: u32) u32 {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}
pub fn bigSigma1(x: u32) u32 {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}
pub fn smallSigma0(x: u32) u32 {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}
pub fn smallSigma1(x: u32) u32 {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}
pub fn ch(x: u32, y: u32, z: u32) u32 {
    return (x & y) ^ (~x & z);
}
pub fn maj(x: u32, y: u32, z: u32) u32 {
    return (x & y) ^ (x & z) ^ (y & z);
}
pub fn messageWord(block: *const [64]u8, j: usize) u32 {
    return std.mem.readInt(u32, block[4 * j ..][0..4], .big);
}

/// Straight FIPS 180-4 section 6.2.2 reference compression.
pub fn compress(state: [8]u32, block: *const [64]u8) [8]u32 {
    var w: [64]u32 = undefined;
    for (0..16) |t| w[t] = messageWord(block, t);
    for (16..64) |t| w[t] = smallSigma1(w[t - 2]) +% w[t - 7] +% smallSigma0(w[t - 15]) +% w[t - 16];
    var v = state;
    for (0..64) |t| {
        const t1 = v[7] +% bigSigma1(v[4]) +% ch(v[4], v[5], v[6]) +% L.K[t] +% w[t];
        const t2 = bigSigma0(v[0]) +% maj(v[0], v[1], v[2]);
        // A temporary: assigning a tuple literal to v would alias its fields.
        const next = [8]u32{ t1 +% t2, v[0], v[1], v[2], v[3] +% t1, v[4], v[5], v[6] };
        v = next;
    }
    var out: [8]u32 = undefined;
    for (&out, state, v) |*o, h, x| o.* = h +% x;
    return out;
}

/// Exact column witness for one row; every value is below 256.
pub const Row = [L.MAIN]u8;

fn putWord(row: *Row, base: usize, value: u32) void {
    for (0..32) |i| row[base + i] = @intCast((value >> @intCast(i)) & 1);
}
fn putCarry(row: *Row, base: usize, comptime bits: usize, value: u32) void {
    std.debug.assert(value < (1 << bits));
    for (0..bits) |i| row[base + i] = @intCast((value >> @intCast(i)) & 1);
}
/// Sum of 32-bit terms split as the AIR does: low halves with carry c_lo, then
/// high halves plus c_lo with carry c_hi (discarded mod 2^32).
fn carried(terms: []const u32) struct { value: u32, lo: u32, hi: u32 } {
    var lo: u32 = 0;
    var hi: u32 = 0;
    for (terms) |t| {
        lo += t & 0xffff;
        hi += t >> 16;
    }
    const c_lo = lo >> 16;
    hi += c_lo;
    const c_hi = hi >> 16;
    return .{ .value = (lo & 0xffff) | ((hi & 0xffff) << 16), .lo = c_lo, .hi = c_hi };
}

/// Witness one active (or padding) row. ACTIVE is set by the caller.
pub fn fill(row: *Row, input: Input) [8]u32 {
    @memset(row, 0);
    var w: [64]u32 = undefined;
    for (0..16) |t| w[t] = messageWord(&input.block, t);
    for (16..64) |t| {
        const s = carried(&.{ smallSigma1(w[t - 2]), w[t - 7], smallSigma0(w[t - 15]), w[t - 16] });
        w[t] = s.value;
        putCarry(row, L.scheduleCarry(t, false, 0), 2, s.lo);
        putCarry(row, L.scheduleCarry(t, true, 0), 2, s.hi);
    }
    for (w, 0..) |value, t| putWord(row, L.w(t, 0), value);
    // A[j + 4], E[j + 4] for j = -4..63.
    var av: [68]u32 = undefined;
    var ev: [68]u32 = undefined;
    for (0..4) |i| {
        av[3 - i] = input.state[i];
        ev[3 - i] = input.state[4 + i];
    }
    for (0..64) |t| {
        const j = t + 4;
        const s1 = bigSigma1(ev[j - 1]);
        const c = ch(ev[j - 1], ev[j - 2], ev[j - 3]);
        const s0 = bigSigma0(av[j - 1]);
        const m = maj(av[j - 1], av[j - 2], av[j - 3]);
        const next_e = carried(&.{ av[j - 4], ev[j - 4], s1, c, L.K[t], w[t] });
        const next_a = carried(&.{ ev[j - 4], s1, c, L.K[t], w[t], s0, m });
        ev[j] = next_e.value;
        av[j] = next_a.value;
        putCarry(row, L.roundCarry(t, .e, false, 0), 3, next_e.lo);
        putCarry(row, L.roundCarry(t, .e, true, 0), 3, next_e.hi);
        putCarry(row, L.roundCarry(t, .a, false, 0), 3, next_a.lo);
        putCarry(row, L.roundCarry(t, .a, true, 0), 3, next_a.hi);
    }
    for (0..68) |j| {
        putWord(row, L.a(j, 0), av[j]);
        putWord(row, L.e(j, 0), ev[j]);
    }
    var out: [8]u32 = undefined;
    for (0..8) |i| {
        const x = if (i < 4) av[67 - i] else ev[67 - (i - 4)];
        const s = carried(&.{ input.state[i], x });
        out[i] = s.value;
        putCarry(row, L.finalCarry(i, false), 1, s.lo);
        putCarry(row, L.finalCarry(i, true), 1, s.hi);
        for (0..4) |b| row[L.OUT + 4 * i + b] = @truncate(s.value >> @intCast(8 * b));
    }
    return out;
}

/// The packet words as the bridge reads them: 12 little-endian u64 words.
pub fn fromPacket(words: []const u64) Input {
    std.debug.assert(words.len >= 12);
    var out: Input = undefined;
    for (0..8) |i| out.state[i] = @truncate(words[i / 2] >> @intCast(32 * (i % 2)));
    for (0..8) |i| std.mem.writeInt(u64, out.block[8 * i ..][0..8], words[4 + i], .little);
    return out;
}
/// The four written packet words for a new state.
pub fn toPacket(state: [8]u32) [4]u64 {
    var out: [4]u64 = undefined;
    for (&out, 0..) |*v, i| v.* = @as(u64, state[2 * i]) | (@as(u64, state[2 * i + 1]) << 32);
    return out;
}
/// The 32 LE bytes carried by Wire35 coordinate `wire` (0..2 inputs, 3 output).
pub fn wireBytes(input: Input, output: [8]u32, wire: u32) [32]u8 {
    var out: [32]u8 = undefined;
    switch (wire) {
        0 => for (0..8) |i| std.mem.writeInt(u32, out[4 * i ..][0..4], input.state[i], .little),
        1 => @memcpy(&out, input.block[0..32]),
        2 => @memcpy(&out, input.block[32..64]),
        3 => for (0..8) |i| std.mem.writeInt(u32, out[4 * i ..][0..4], output[i], .little),
        else => unreachable,
    }
    return out;
}
/// The fixed padding compression: all-zero state and block. Its row satisfies
/// every SHA-256 equation, so no round constraint needs an activity factor.
pub const PADDING = Input{ .state = @splat(0), .block = @splat(0) };

test "native witness matches std.crypto SHA-256 for abc and a two-block message" {
    const iv = [8]u32{ 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
    var block: [64]u8 = @splat(0);
    block[0] = 'a';
    block[1] = 'b';
    block[2] = 'c';
    block[3] = 0x80;
    block[63] = 24;
    var row: Row = undefined;
    const out = fill(&row, .{ .state = iv, .block = block });
    try std.testing.expectEqual(compress(iv, &block), out);
    var digest: [32]u8 = undefined;
    for (0..8) |i| std.mem.writeInt(u32, digest[4 * i ..][0..4], out[i], .big);
    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("abc", &expected, .{});
    try std.testing.expectEqualSlices(u8, &expected, &digest);
}
