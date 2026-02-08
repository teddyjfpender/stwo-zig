const std = @import("std");
const builtin = @import("builtin");

pub const Blake2sHash = [32]u8;

pub const BackendMode = enum {
    auto,
    scalar,
    simd,
};

var backend_mode: BackendMode = .auto;

pub fn setBackendMode(mode: BackendMode) void {
    backend_mode = mode;
}

pub fn getBackendMode() BackendMode {
    return backend_mode;
}

pub fn supportsSimdBackend() bool {
    return switch (builtin.cpu.arch) {
        .x86_64, .aarch64 => true,
        else => false,
    };
}

pub const Blake2sHasher = struct {
    h: [8]u32,
    t0: u32,
    t1: u32,
    buf: [64]u8,
    buf_len: usize,
    finalized: bool,

    const Self = @This();

    pub fn init() Self {
        var h = BLAKE2S_IV;
        h[0] ^= 0x01010020;
        return .{
            .h = h,
            .t0 = 0,
            .t1 = 0,
            .buf = [_]u8{0} ** 64,
            .buf_len = 0,
            .finalized = false,
        };
    }

    pub fn update(self: *Self, data: []const u8) void {
        std.debug.assert(!self.finalized);
        if (data.len == 0) return;

        var at: usize = 0;
        if (self.buf_len > 0 or data.len <= 64) {
            const copy_len = @min(64 - self.buf_len, data.len);
            @memcpy(self.buf[self.buf_len .. self.buf_len + copy_len], data[0..copy_len]);
            self.buf_len += copy_len;
            at += copy_len;

            // Keep a full terminal block buffered so finalize can mark it as last.
            if (self.buf_len < 64 or at == data.len) return;

            self.addCounter(64);
            self.compressBlock(&self.buf, false);
            self.buf_len = 0;
        }

        while (at + 64 < data.len) : (at += 64) {
            var block: [64]u8 = undefined;
            @memcpy(block[0..], data[at .. at + 64]);
            self.addCounter(64);
            self.compressBlock(&block, false);
        }

        if (at <= data.len) {
            const rem = data.len - at;
            std.debug.assert(rem <= 64);
            if (rem > 0) {
                @memcpy(self.buf[0..rem], data[at..]);
            }
            self.buf_len = rem;
        }
    }

    pub fn finalize(self: *Self) Blake2sHash {
        std.debug.assert(!self.finalized);
        self.finalized = true;

        var block: [64]u8 = [_]u8{0} ** 64;
        if (self.buf_len > 0) {
            @memcpy(block[0..self.buf_len], self.buf[0..self.buf_len]);
        }
        self.addCounter(@intCast(self.buf_len));
        self.compressBlock(&block, true);
        return stateToDigest(self.h);
    }

    pub fn hash(data: []const u8) Blake2sHash {
        var hasher = Self.init();
        hasher.update(data);
        return hasher.finalize();
    }

    pub fn hashFixed128(data: *const [128]u8) Blake2sHash {
        var hasher = Self.init();
        hasher.update(data[0..]);
        return hasher.finalize();
    }

    fn addCounter(self: *Self, inc: u32) void {
        const sum: u64 = @as(u64, self.t0) + @as(u64, inc);
        self.t0 = @truncate(sum);
        self.t1 +%= @intCast(sum >> 32);
    }

    fn compressBlock(self: *Self, block: *const [64]u8, is_last: bool) void {
        var m: [16]u32 = undefined;
        loadBlockWords(block, &m);
        const f0: u32 = if (is_last) 0xFFFF_FFFF else 0;
        switch (effectiveMode()) {
            .simd => compressSimd(&self.h, &m, self.t0, self.t1, f0),
            .scalar => compressScalar(&self.h, &m, self.t0, self.t1, f0),
            .auto => unreachable,
        }
    }
};

fn effectiveMode() BackendMode {
    return switch (backend_mode) {
        .auto => if (supportsSimdBackend()) .simd else .scalar,
        .scalar => .scalar,
        .simd => if (supportsSimdBackend()) .simd else .scalar,
    };
}

const BLAKE2S_IV = [_]u32{
    0x6A09E667,
    0xBB67AE85,
    0x3C6EF372,
    0xA54FF53A,
    0x510E527F,
    0x9B05688C,
    0x1F83D9AB,
    0x5BE0CD19,
};

const BLAKE2S_SIGMA = [10][16]u8{
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

fn loadBlockWords(block: *const [64]u8, out: *[16]u32) void {
    var i: usize = 0;
    while (i < 16) : (i += 1) {
        out[i] = readU32LeFromFixed(block, i * 4);
    }
}

fn readU32LeFromFixed(data: *const [64]u8, at: usize) u32 {
    return (@as(u32, data[at + 0])) |
        (@as(u32, data[at + 1]) << 8) |
        (@as(u32, data[at + 2]) << 16) |
        (@as(u32, data[at + 3]) << 24);
}

fn stateToDigest(h: [8]u32) Blake2sHash {
    var out: Blake2sHash = undefined;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        writeU32Le(out[i * 4 .. i * 4 + 4], h[i]);
    }
    return out;
}

fn writeU32Le(dst: []u8, value: u32) void {
    std.debug.assert(dst.len == 4);
    dst[0] = @truncate(value);
    dst[1] = @truncate(value >> 8);
    dst[2] = @truncate(value >> 16);
    dst[3] = @truncate(value >> 24);
}

fn rotr32(x: u32, bits: u5) u32 {
    const left_bits: u5 = @intCast((@as(u6, 32) - @as(u6, bits)) & 31);
    return (x >> bits) | (x << left_bits);
}

fn gScalar(v: *[16]u32, a: usize, b: usize, c: usize, d: usize, x: u32, y: u32) void {
    v[a] = v[a] +% v[b] +% x;
    v[d] = rotr32(v[d] ^ v[a], 16);
    v[c] = v[c] +% v[d];
    v[b] = rotr32(v[b] ^ v[c], 12);
    v[a] = v[a] +% v[b] +% y;
    v[d] = rotr32(v[d] ^ v[a], 8);
    v[c] = v[c] +% v[d];
    v[b] = rotr32(v[b] ^ v[c], 7);
}

fn compressScalar(h: *[8]u32, m: *const [16]u32, t0: u32, t1: u32, f0: u32) void {
    var v: [16]u32 = undefined;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        v[i] = h[i];
        v[i + 8] = BLAKE2S_IV[i];
    }
    v[12] ^= t0;
    v[13] ^= t1;
    v[14] ^= f0;

    var round: usize = 0;
    while (round < 10) : (round += 1) {
        const s = BLAKE2S_SIGMA[round];
        gScalar(&v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        gScalar(&v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        gScalar(&v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        gScalar(&v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        gScalar(&v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        gScalar(&v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        gScalar(&v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        gScalar(&v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    i = 0;
    while (i < 8) : (i += 1) {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

const V4 = @Vector(4, u32);
const Shift4 = @Vector(4, u5);

fn rotr32x4(x: V4, bits: u5) V4 {
    const left_bits: u5 = @intCast((@as(u6, 32) - @as(u6, bits)) & 31);
    const r: Shift4 = @splat(bits);
    const l: Shift4 = @splat(left_bits);
    return (x >> r) | (x << l);
}

fn gather4(values: *const [16]u32, idx: [4]u8) V4 {
    return .{
        values[idx[0]],
        values[idx[1]],
        values[idx[2]],
        values[idx[3]],
    };
}

fn scatter4(values: *[16]u32, idx: [4]u8, vec: V4) void {
    values[idx[0]] = vec[0];
    values[idx[1]] = vec[1];
    values[idx[2]] = vec[2];
    values[idx[3]] = vec[3];
}

fn g4(a: *V4, b: *V4, c: *V4, d: *V4, x: V4, y: V4) void {
    a.* = a.* +% b.* +% x;
    d.* = rotr32x4(d.* ^ a.*, 16);
    c.* = c.* +% d.*;
    b.* = rotr32x4(b.* ^ c.*, 12);
    a.* = a.* +% b.* +% y;
    d.* = rotr32x4(d.* ^ a.*, 8);
    c.* = c.* +% d.*;
    b.* = rotr32x4(b.* ^ c.*, 7);
}

fn compressSimd(h: *[8]u32, m: *const [16]u32, t0: u32, t1: u32, f0: u32) void {
    var v: [16]u32 = undefined;
    var i: usize = 0;
    while (i < 8) : (i += 1) {
        v[i] = h[i];
        v[i + 8] = BLAKE2S_IV[i];
    }
    v[12] ^= t0;
    v[13] ^= t1;
    v[14] ^= f0;

    const col_a = [_]u8{ 0, 1, 2, 3 };
    const col_b = [_]u8{ 4, 5, 6, 7 };
    const col_c = [_]u8{ 8, 9, 10, 11 };
    const col_d = [_]u8{ 12, 13, 14, 15 };

    const diag_a = [_]u8{ 0, 1, 2, 3 };
    const diag_b = [_]u8{ 5, 6, 7, 4 };
    const diag_c = [_]u8{ 10, 11, 8, 9 };
    const diag_d = [_]u8{ 15, 12, 13, 14 };

    var round: usize = 0;
    while (round < 10) : (round += 1) {
        const s = BLAKE2S_SIGMA[round];

        var a = gather4(&v, col_a);
        var b = gather4(&v, col_b);
        var c = gather4(&v, col_c);
        var d = gather4(&v, col_d);
        const x_col: V4 = .{ m[s[0]], m[s[2]], m[s[4]], m[s[6]] };
        const y_col: V4 = .{ m[s[1]], m[s[3]], m[s[5]], m[s[7]] };
        g4(&a, &b, &c, &d, x_col, y_col);
        scatter4(&v, col_a, a);
        scatter4(&v, col_b, b);
        scatter4(&v, col_c, c);
        scatter4(&v, col_d, d);

        a = gather4(&v, diag_a);
        b = gather4(&v, diag_b);
        c = gather4(&v, diag_c);
        d = gather4(&v, diag_d);
        const x_diag: V4 = .{ m[s[8]], m[s[10]], m[s[12]], m[s[14]] };
        const y_diag: V4 = .{ m[s[9]], m[s[11]], m[s[13]], m[s[15]] };
        g4(&a, &b, &c, &d, x_diag, y_diag);
        scatter4(&v, diag_a, a);
        scatter4(&v, diag_b, b);
        scatter4(&v, diag_c, c);
        scatter4(&v, diag_d, d);
    }

    i = 0;
    while (i < 8) : (i += 1) {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

fn digestToHex(digest: Blake2sHash) [64]u8 {
    return std.fmt.bytesToHex(digest, .lower);
}

test "blake2s backend: one-shot known vector" {
    const hash_a = Blake2sHasher.hash("a");
    const hex = digestToHex(hash_a);
    try std.testing.expectEqualStrings(
        "4a0d129873403037c2cd9b9048203687f6233fb6738956e0349bd4320fec3e90",
        &hex,
    );
}

test "blake2s backend: incremental equals one-shot" {
    var state = Blake2sHasher.init();
    state.update("a");
    state.update("b");
    const hash_ab = state.finalize();
    const one_shot = Blake2sHasher.hash("ab");
    try std.testing.expect(std.mem.eql(u8, hash_ab[0..], one_shot[0..]));
}

test "blake2s backend: fixed128 equals generic stream hash" {
    var prng = std.Random.DefaultPrng.init(0x6a09_e667_f3bc_c908);
    const rng = prng.random();
    var i: usize = 0;
    while (i < 64) : (i += 1) {
        var payload: [128]u8 = undefined;
        rng.bytes(payload[0..]);
        const generic = Blake2sHasher.hash(payload[0..]);
        const fixed = Blake2sHasher.hashFixed128(&payload);
        try std.testing.expect(std.mem.eql(u8, generic[0..], fixed[0..]));
    }
}

test "blake2s backend: scalar and simd modes are equivalent" {
    const previous_mode = getBackendMode();
    defer setBackendMode(previous_mode);

    var prng = std.Random.DefaultPrng.init(0x510e_527f_ade6_82d1);
    const rng = prng.random();

    var i: usize = 0;
    while (i < 64) : (i += 1) {
        var payload: [128]u8 = undefined;
        rng.bytes(payload[0..]);

        setBackendMode(.scalar);
        const scalar_digest = Blake2sHasher.hashFixed128(&payload);
        setBackendMode(.simd);
        const simd_digest = Blake2sHasher.hashFixed128(&payload);
        try std.testing.expect(std.mem.eql(u8, scalar_digest[0..], simd_digest[0..]));
    }
}
