//! Fixed-terminal BLAKE2s batching wider than one scalar message.

const std = @import("std");
const builtin = @import("builtin");
const parallel4 = @import("blake2s_parallel4.zig");

const V4 = @Vector(4, u32);
const V8 = @Vector(8, u32);
const Shift4 = @Vector(4, u5);
const V16u8 = @Vector(16, u8);

pub const iv = [_]u32{
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
};

pub const sigma = [10][16]u8{
    .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
    .{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
    .{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
    .{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
    .{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
    .{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
    .{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
    .{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
    .{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
    .{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
};

pub fn stateToDigest(comptime Hash: type, h: [8]u32) Hash {
    var out: Hash = undefined;
    for (0..8) |word| {
        const value = h[word];
        const at = word * @sizeOf(u32);
        out[at + 0] = @truncate(value);
        out[at + 1] = @truncate(value >> 8);
        out[at + 2] = @truncate(value >> 16);
        out[at + 3] = @truncate(value >> 24);
    }
    return out;
}

/// Request-local authority for 40-byte messages whose first 32 bytes are
/// fixed and whose final eight bytes are a changing little-endian nonce.
/// Seven of BLAKE2s round zero's eight G functions are prefix-only.
pub const Fixed40NoncePrefix = struct {
    words: [8]u32,
    round_zero: [16]u32,
};

fn gScalar(
    state: *[16]u32,
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    x: u32,
    y: u32,
) void {
    state[a] +%= state[b] +% x;
    state[d] = std.math.rotr(u32, state[d] ^ state[a], 16);
    state[c] +%= state[d];
    state[b] = std.math.rotr(u32, state[b] ^ state[c], 12);
    state[a] +%= state[b] +% y;
    state[d] = std.math.rotr(u32, state[d] ^ state[a], 8);
    state[c] +%= state[d];
    state[b] = std.math.rotr(u32, state[b] ^ state[c], 7);
}

pub fn prepareFixed40NoncePrefix(
    prefix: *const [32]u8,
    initial_state: [8]u32,
    comptime initial_vector: [8]u32,
) Fixed40NoncePrefix {
    var words: [8]u32 = undefined;
    inline for (0..8) |word| {
        const start = word * @sizeOf(u32);
        words[word] = std.mem.readInt(u32, prefix[start..][0..4], .little);
    }

    var state: [16]u32 = undefined;
    @memcpy(state[0..8], initial_state[0..]);
    @memcpy(state[8..16], initial_vector[0..]);
    state[12] ^= 40;
    state[14] ^= std.math.maxInt(u32);
    gScalar(&state, 0, 4, 8, 12, words[0], words[1]);
    gScalar(&state, 1, 5, 9, 13, words[2], words[3]);
    gScalar(&state, 2, 6, 10, 14, words[4], words[5]);
    gScalar(&state, 3, 7, 11, 15, words[6], words[7]);
    gScalar(&state, 1, 6, 11, 12, 0, 0);
    gScalar(&state, 2, 7, 8, 13, 0, 0);
    gScalar(&state, 3, 4, 9, 14, 0, 0);
    return .{ .words = words, .round_zero = state };
}

fn hashScalarBatch(
    comptime lanes: usize,
    comptime Hasher: type,
    comptime Hash: type,
    scalar_mode: anytype,
    seed: [8]u32,
    data: *const [lanes][64]u8,
) [lanes]Hash {
    var out: [lanes]Hash = undefined;
    for (&out, data) |*digest, *block| {
        var hasher = Hasher.initWithMode(scalar_mode);
        hasher.h = seed;
        hasher.t0 = 64;
        hasher.update(block);
        digest.* = hasher.finalize();
    }
    return out;
}

pub fn hashFinal64FromSeed4(
    comptime Hasher: type,
    comptime Hash: type,
    scalar_mode: anytype,
    use_scalar: bool,
    seed: [8]u32,
    data: *const [4][64]u8,
    comptime load4: anytype,
    comptime compress4: anytype,
    comptime statesToDigests4: anytype,
) [4]Hash {
    if (use_scalar) return hashScalarBatch(4, Hasher, Hash, scalar_mode, seed, data);

    var messages: [16]V4 = undefined;
    load4(data, &messages);
    var states: [8]V4 = undefined;
    for (0..8) |word| states[word] = @splat(seed[word]);
    compress4(&states, &messages, 128, 0, 0xFFFF_FFFF);
    return statesToDigests4(&states);
}

pub fn hashFinal64FromSeed8(
    comptime Hasher: type,
    comptime Hash: type,
    scalar_mode: anytype,
    use_scalar: bool,
    seed: [8]u32,
    data: *const [8][64]u8,
    comptime load4: anytype,
    comptime statesToDigests4: anytype,
    comptime initial_vector: [8]u32,
    comptime message_schedule: [10][16]u8,
) [8]Hash {
    if (use_scalar) return hashScalarBatch(8, Hasher, Hash, scalar_mode, seed, data);

    var messages: [16]V8 = undefined;
    load8(data, &messages, load4);
    var states: [8]V8 = undefined;
    for (0..8) |word| states[word] = @splat(seed[word]);
    compress8(
        &states,
        &messages,
        128,
        0,
        0xFFFF_FFFF,
        initial_vector,
        message_schedule,
    );
    return statesToDigests8(Hash, &states, statesToDigests4);
}

pub fn hashFixedSingleBlock8(
    comptime Hasher: type,
    comptime Hash: type,
    comptime byte_len: usize,
    scalar_mode: anytype,
    use_scalar: bool,
    initial_state: [8]u32,
    data: *const [8][byte_len]u8,
    comptime load4: anytype,
    comptime statesToDigests4: anytype,
    comptime initial_vector: [8]u32,
    comptime message_schedule: [10][16]u8,
) [8]Hash {
    comptime std.debug.assert(byte_len <= 64);
    if (use_scalar) {
        var out: [8]Hash = undefined;
        for (&out, data) |*digest, *message| {
            digest.* = Hasher.hashFixedSingleBlockWithMode(
                byte_len,
                scalar_mode,
                message,
            );
        }
        return out;
    }

    var blocks = [_][64]u8{[_]u8{0} ** 64} ** 8;
    for (&blocks, data) |*block, message| {
        if (byte_len > 0) @memcpy(block[0..byte_len], message[0..]);
    }
    var messages: [16]V8 = undefined;
    load8(&blocks, &messages, load4);
    var states: [8]V8 = undefined;
    for (0..8) |word| states[word] = @splat(initial_state[word]);
    compress8(
        &states,
        &messages,
        @intCast(byte_len),
        0,
        0xFFFF_FFFF,
        initial_vector,
        message_schedule,
    );
    return statesToDigests8(Hash, &states, statesToDigests4);
}

fn load8(
    data: *const [8][64]u8,
    out: *[16]V8,
    comptime load4: anytype,
) void {
    const halves: [2][4][64]u8 = @bitCast(data.*);
    var low: [16]V4 = undefined;
    var high: [16]V4 = undefined;
    load4(&halves[0], &low);
    load4(&halves[1], &high);
    inline for (0..16) |word| out[word] = @bitCast([2]V4{ low[word], high[word] });
}

fn statesToDigests8(
    comptime Hash: type,
    states: *const [8]V8,
    comptime statesToDigests4: anytype,
) [8]Hash {
    var low: [8]V4 = undefined;
    var high: [8]V4 = undefined;
    inline for (0..8) |word| {
        const halves: [2]V4 = @bitCast(states[word]);
        low[word] = halves[0];
        high[word] = halves[1];
    }
    const low_digests = statesToDigests4(&low);
    const high_digests = statesToDigests4(&high);
    var out: [8]Hash = undefined;
    inline for (0..4) |lane| {
        out[lane] = low_digests[lane];
        out[lane + 4] = high_digests[lane];
    }
    return out;
}

fn rotr4(x: V4, comptime bits: u5) V4 {
    if (comptime builtin.cpu.arch.endian() == .little) {
        const bytes: V16u8 = @bitCast(x);
        switch (bits) {
            8 => return @bitCast(@shuffle(u8, bytes, bytes, @Vector(16, i32){
                1,  2,  3,  0,
                5,  6,  7,  4,
                9,  10, 11, 8,
                13, 14, 15, 12,
            })),
            16 => return @bitCast(@shuffle(u8, bytes, bytes, @Vector(16, i32){
                2,  3,  0,  1,
                6,  7,  4,  5,
                10, 11, 8,  9,
                14, 15, 12, 13,
            })),
            else => {},
        }
    }
    const left_bits: u5 = @intCast((@as(u6, 32) - @as(u6, bits)) & 31);
    return (x >> @as(Shift4, @splat(bits))) |
        (x << @as(Shift4, @splat(left_bits)));
}

fn rotr8(x: V8, comptime bits: u5) V8 {
    const halves: [2]V4 = @bitCast(x);
    return @bitCast([2]V4{ rotr4(halves[0], bits), rotr4(halves[1], bits) });
}

inline fn gOne8(
    v: *[16]V8,
    comptime a: usize,
    comptime b: usize,
    comptime c: usize,
    comptime d: usize,
    x: V8,
    y: V8,
) void {
    v[a] = v[a] +% v[b] +% x;
    v[d] = rotr8(v[d] ^ v[a], 16);
    v[c] +%= v[d];
    v[b] = rotr8(v[b] ^ v[c], 12);
    v[a] = v[a] +% v[b] +% y;
    v[d] = rotr8(v[d] ^ v[a], 8);
    v[c] +%= v[d];
    v[b] = rotr8(v[b] ^ v[c], 7);
}

inline fn round8(v: *[16]V8, m: *const [16]V8, comptime s: [16]u8) void {
    parallel4.g4Interleaved(
        V8,
        rotr8,
        v,
        .{ 0, 1, 2, 3 },
        .{ 4, 5, 6, 7 },
        .{ 8, 9, 10, 11 },
        .{ 12, 13, 14, 15 },
        .{ m[s[0]], m[s[2]], m[s[4]], m[s[6]] },
        .{ m[s[1]], m[s[3]], m[s[5]], m[s[7]] },
    );
    parallel4.g4Interleaved(
        V8,
        rotr8,
        v,
        .{ 0, 1, 2, 3 },
        .{ 5, 6, 7, 4 },
        .{ 10, 11, 8, 9 },
        .{ 15, 12, 13, 14 },
        .{ m[s[8]], m[s[10]], m[s[12]], m[s[14]] },
        .{ m[s[9]], m[s[11]], m[s[13]], m[s[15]] },
    );
}

/// Returns only digest word zero for eight fixed-prefix nonce messages. PoW
/// difficulties up to 32 bits depend exclusively on this word.
pub fn hashFixed40NonceFirstWords8(
    prepared: *const Fixed40NoncePrefix,
    nonces: *const [8]u64,
    initial_state: [8]u32,
    comptime message_schedule: [10][16]u8,
) [8]u32 {
    var messages: [16]V8 = undefined;
    inline for (0..8) |word| messages[word] = @splat(prepared.words[word]);
    var low: [8]u32 = undefined;
    var high: [8]u32 = undefined;
    inline for (0..8) |lane| {
        low[lane] = @truncate(nonces[lane]);
        high[lane] = @truncate(nonces[lane] >> 32);
    }
    messages[8] = @bitCast(low);
    messages[9] = @bitCast(high);
    inline for (10..16) |word| messages[word] = @splat(0);

    var state: [16]V8 = undefined;
    inline for (0..16) |word| state[word] = @splat(prepared.round_zero[word]);
    gOne8(&state, 0, 5, 10, 15, messages[8], messages[9]);
    inline for (message_schedule[1..]) |s| round8(&state, &messages, s);
    return @bitCast(@as(V8, @splat(initial_state[0])) ^ state[0] ^ state[8]);
}

fn compress8(
    h: *[8]V8,
    m: *const [16]V8,
    t0: u32,
    t1: u32,
    f0: u32,
    comptime initial_vector: [8]u32,
    comptime message_schedule: [10][16]u8,
) void {
    var v: [16]V8 = undefined;
    for (0..8) |i| {
        v[i] = h[i];
        v[i + 8] = @splat(initial_vector[i]);
    }
    v[12] ^= @as(V8, @splat(t0));
    v[13] ^= @as(V8, @splat(t1));
    v[14] ^= @as(V8, @splat(f0));

    inline for (message_schedule) |s| round8(&v, m, s);

    for (0..8) |i| h[i] ^= v[i] ^ v[i + 8];
}
