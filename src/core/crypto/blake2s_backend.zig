const std = @import("std");
const builtin = @import("builtin");
const block_io = @import("blake2s_blocks.zig");
const contract = @import("blake2s_contract.zig");
const parallel4 = @import("blake2s_parallel4.zig");
const stream4 = @import("blake2s_stream4.zig");
const terminal_parallel = @import("blake2s_terminal_parallel.zig");

pub const Blake2sHash = [32]u8;
const BLAKE2S_IV = terminal_parallel.iv;
const BLAKE2S_SIGMA = terminal_parallel.sigma;
const V4 = block_io.V4;

pub const BackendMode = contract.BackendMode;
pub const BackendSelection = contract.BackendSelection;
pub const SimdContract = contract.SimdContract;

/// Test-only dispatch evidence. Recording is compiled out of production
/// artifacts so observing the contract cannot perturb benchmark results.
pub const TestCompressionCounts = struct {
    scalar: u64,
    simd: u64,
    parallel_simd_4: u64,
};

var test_scalar_compressions = std.atomic.Value(u64).init(0);
var test_simd_compressions = std.atomic.Value(u64).init(0);
var test_parallel_simd_4_compressions = std.atomic.Value(u64).init(0);

var default_backend_mode = std.atomic.Value(u8).init(@intFromEnum(BackendMode.auto));

/// Changes the process default used by subsequently constructed hashers and
/// one-shot operations. Existing hashers retain their captured selection.
/// Configure this at process/session admission; use the explicit `WithMode`
/// APIs when independent callers need different policies concurrently.
pub fn setDefaultBackendMode(mode: BackendMode) void {
    default_backend_mode.store(@intFromEnum(mode), .release);
}

pub fn getDefaultBackendMode() BackendMode {
    return @enumFromInt(default_backend_mode.load(.acquire));
}

pub fn getDefaultBackendSelection() BackendSelection {
    return selectBackend(getDefaultBackendMode());
}

/// Compatibility aliases retained for the original public VCS API.
pub fn setBackendMode(mode: BackendMode) void {
    setDefaultBackendMode(mode);
}

pub fn getBackendMode() BackendMode {
    return getDefaultBackendMode();
}

pub fn getEffectiveBackendMode() BackendMode {
    return getDefaultBackendSelection().effective;
}

pub fn supportsSimdBackend() bool {
    return switch (builtin.cpu.arch) {
        .x86_64, .aarch64 => true,
        else => false,
    };
}

pub fn selectBackend(requested: BackendMode) BackendSelection {
    const simd_supported = supportsSimdBackend();
    return .{
        .requested = requested,
        .effective = switch (requested) {
            .auto => if (simd_supported) .simd else .scalar,
            .scalar => .scalar,
            .simd => if (simd_supported) .simd else .scalar,
        },
        .simd_supported = simd_supported,
        .explicit_simd_width = SimdContract.explicit_width,
    };
}

pub fn resetTestCompressionCounts() void {
    if (comptime !builtin.is_test) return;
    test_scalar_compressions.store(0, .release);
    test_simd_compressions.store(0, .release);
    test_parallel_simd_4_compressions.store(0, .release);
}

pub fn testCompressionCounts() TestCompressionCounts {
    if (comptime !builtin.is_test) return .{ .scalar = 0, .simd = 0, .parallel_simd_4 = 0 };
    return .{
        .scalar = test_scalar_compressions.load(.acquire),
        .simd = test_simd_compressions.load(.acquire),
        .parallel_simd_4 = test_parallel_simd_4_compressions.load(.acquire),
    };
}

pub const Blake2sHasher = struct {
    h: [8]u32,
    t0: u32,
    t1: u32,
    buf: [64]u8,
    buf_len: usize,
    finalized: bool,
    selection: BackendSelection,

    const Self = @This();

    pub fn init() Self {
        return initWithMode(getDefaultBackendMode());
    }

    pub fn initWithMode(mode: BackendMode) Self {
        var h = BLAKE2S_IV;
        h[0] ^= 0x01010020;
        return .{
            .h = h,
            .t0 = 0,
            .t1 = 0,
            .buf = [_]u8{0} ** 64,
            .buf_len = 0,
            .finalized = false,
            .selection = selectBackend(mode),
        };
    }

    pub fn backendSelection(self: *const Self) BackendSelection {
        return self.selection;
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
            self.addCounter(64);
            self.compressBlockBytes(data[at .. at + 64], false);
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
        return terminal_parallel.stateToDigest(Blake2sHash, self.h);
    }

    pub fn hash(data: []const u8) Blake2sHash {
        var hasher = Self.init();
        hasher.update(data);
        return hasher.finalize();
    }

    pub fn hashWithMode(mode: BackendMode, data: []const u8) Blake2sHash {
        var hasher = Self.initWithMode(mode);
        hasher.update(data);
        return hasher.finalize();
    }

    pub fn hashFixedSingleBlock(comptime byte_len: usize, data: *const [byte_len]u8) Blake2sHash {
        return hashFixedSingleBlockWithMode(byte_len, getDefaultBackendMode(), data);
    }

    pub fn hashFixedSingleBlockWithMode(
        comptime byte_len: usize,
        mode: BackendMode,
        data: *const [byte_len]u8,
    ) Blake2sHash {
        comptime std.debug.assert(byte_len <= 64);

        var hasher = Self.initWithMode(mode);
        if (byte_len == 64) {
            hasher.addCounter(64);
            hasher.compressBlockBytes(data[0..], true);
            return terminal_parallel.stateToDigest(Blake2sHash, hasher.h);
        }

        var block: [64]u8 = [_]u8{0} ** 64;
        if (byte_len > 0) {
            @memcpy(block[0..byte_len], data[0..]);
        }
        hasher.addCounter(@intCast(byte_len));
        hasher.compressBlock(&block, true);
        return terminal_parallel.stateToDigest(Blake2sHash, hasher.h);
    }

    /// Hashes four independent, equal-length, single-block messages.
    ///
    /// The SIMD path maps each message to one vector lane. It is intended for
    /// independent fixed-size work such as proof-of-work nonce batches; the
    /// scalar backend retains the exact one-message implementation.
    pub fn hashFixedSingleBlock4(
        comptime byte_len: usize,
        data: *const [4][byte_len]u8,
    ) [4]Blake2sHash {
        return hashFixedSingleBlock4WithMode(
            byte_len,
            getDefaultBackendMode(),
            data,
        );
    }

    pub fn hashFixedSingleBlock4WithMode(
        comptime byte_len: usize,
        mode: BackendMode,
        data: *const [4][byte_len]u8,
    ) [4]Blake2sHash {
        comptime std.debug.assert(byte_len <= 64);

        if (selectBackend(mode).effective == .scalar) {
            var out: [4]Blake2sHash = undefined;
            for (&out, data) |*digest, *message| {
                digest.* = hashFixedSingleBlockWithMode(
                    byte_len,
                    .scalar,
                    message,
                );
            }
            return out;
        }

        const initial = Self.initWithMode(mode);
        var states: [8]V4 = undefined;
        for (0..8) |word_index| states[word_index] = @splat(initial.h[word_index]);

        var blocks = [_][64]u8{[_]u8{0} ** 64} ** 4;
        for (&blocks, data) |*block, message| {
            if (byte_len > 0) @memcpy(block[0..byte_len], message[0..]);
        }
        var messages: [16]V4 = undefined;
        block_io.loadParallel4(&blocks, &messages);
        compressParallel4(
            &states,
            &messages,
            @intCast(byte_len),
            0,
            0xFFFF_FFFF,
        );
        return parallelStatesToDigests(&states);
    }

    /// Hashes eight independent, equal-length, single-block messages.
    pub fn hashFixedSingleBlock8(
        comptime byte_len: usize,
        data: *const [8][byte_len]u8,
    ) [8]Blake2sHash {
        const initial = Self.init();
        return terminal_parallel.hashFixedSingleBlock8(
            Self,
            Blake2sHash,
            byte_len,
            BackendMode.scalar,
            initial.selection.effective == .scalar,
            initial.h,
            data,
            block_io.loadParallel4,
            parallelStatesToDigests,
            BLAKE2S_IV,
            BLAKE2S_SIGMA,
        );
    }

    pub fn hashFixed64(data: *const [64]u8) Blake2sHash {
        return hashFixedSingleBlock(64, data);
    }

    pub fn hashFixed128(data: *const [128]u8) Blake2sHash {
        return hashFixed128WithMode(getDefaultBackendMode(), data);
    }

    pub fn hashFixed128WithMode(mode: BackendMode, data: *const [128]u8) Blake2sHash {
        var hasher = Self.initWithMode(mode);
        hasher.addCounter(64);
        hasher.compressBlockBytes(data[0..64], false);
        hasher.addCounter(64);
        hasher.compressBlockBytes(data[64..128], true);
        hasher.finalized = true;
        return terminal_parallel.stateToDigest(Blake2sHash, hasher.h);
    }

    /// State after hashing one complete, non-terminal 64-byte block.
    pub const Fixed64Seed = [8]u32;

    pub fn seedAfterFixed64(data: *const [64]u8) Fixed64Seed {
        return seedAfterFixed64WithMode(getDefaultBackendMode(), data);
    }

    pub fn seedAfterFixed64WithMode(mode: BackendMode, data: *const [64]u8) Fixed64Seed {
        var hasher = Self.initWithMode(mode);
        hasher.addCounter(64);
        hasher.compressBlockBytes(data[0..], false);
        return hasher.h;
    }

    /// Finishes a 128-byte message from the state returned by
    /// `seedAfterFixed64`, hashing only its terminal 64-byte block.
    pub fn hashFinal64FromSeed(seed: Fixed64Seed, data: *const [64]u8) Blake2sHash {
        return hashFinal64FromSeedWithMode(getDefaultBackendMode(), seed, data);
    }

    pub fn hashFinal64FromSeedWithMode(
        mode: BackendMode,
        seed: Fixed64Seed,
        data: *const [64]u8,
    ) Blake2sHash {
        var h = seed;
        var words: [16]u32 = undefined;
        block_io.loadFixed(data, &words);
        switch (selectBackend(mode).effective) {
            .simd => compressSimd(&h, &words, 128, 0, 0xFFFF_FFFF),
            .scalar => compressScalar(&h, &words, 128, 0, 0xFFFF_FFFF),
            .auto => unreachable,
        }
        return terminal_parallel.stateToDigest(Blake2sHash, h);
    }

    pub fn hashFinal64FromSeed4(
        seed: Fixed64Seed,
        data: *const [4][64]u8,
    ) [4]Blake2sHash {
        return hashFinal64FromSeed4WithMode(getDefaultBackendMode(), seed, data);
    }

    pub fn hashFinal64FromSeed4WithMode(
        mode: BackendMode,
        seed: Fixed64Seed,
        data: *const [4][64]u8,
    ) [4]Blake2sHash {
        return terminal_parallel.hashFinal64FromSeed4(
            Self,
            Blake2sHash,
            BackendMode.scalar,
            selectBackend(mode).effective == .scalar,
            seed,
            data,
            block_io.loadParallel4,
            compressParallel4,
            parallelStatesToDigests,
        );
    }

    /// Finishes eight independent 128-byte messages that share their first
    /// block. A 256-bit logical vector lets LLVM issue the two native AArch64
    /// halves at each BLAKE dependency level instead of completing one
    /// four-message compression before starting the next.
    pub fn hashFinal64FromSeed8(
        seed: Fixed64Seed,
        data: *const [8][64]u8,
    ) [8]Blake2sHash {
        return hashFinal64FromSeed8WithMode(getDefaultBackendMode(), seed, data);
    }

    pub fn hashFinal64FromSeed8WithMode(
        mode: BackendMode,
        seed: Fixed64Seed,
        data: *const [8][64]u8,
    ) [8]Blake2sHash {
        return terminal_parallel.hashFinal64FromSeed8(
            Self,
            Blake2sHash,
            BackendMode.scalar,
            selectBackend(mode).effective == .scalar,
            seed,
            data,
            block_io.loadParallel4,
            parallelStatesToDigests,
            BLAKE2S_IV,
            BLAKE2S_SIGMA,
        );
    }

    pub fn hashEqualFromSeed4(
        seed: Fixed64Seed,
        data: *const [4][]const u8,
    ) [4]Blake2sHash {
        return hashEqualFromSeed4WithMode(getDefaultBackendMode(), seed, data);
    }

    pub fn hashEqualFromSeed4WithMode(
        mode: BackendMode,
        seed: Fixed64Seed,
        data: *const [4][]const u8,
    ) [4]Blake2sHash {
        // All lanes must have one non-zero common length. Inputs are read-only,
        // need only byte alignment, and may overlap or alias exactly. The last
        // partial block is zero-padded in fixed-size stack scratch.
        const len = data[0].len;
        for (data[1..]) |message| std.debug.assert(message.len == len);
        std.debug.assert(len > 0);
        std.debug.assert(len <= std.math.maxInt(u32) - 64);

        if (selectBackend(mode).effective == .scalar) {
            var out: [4]Blake2sHash = undefined;
            for (&out, data) |*digest, message| {
                var hasher = Self.initWithMode(.scalar);
                hasher.h = seed;
                hasher.t0 = 64;
                hasher.update(message);
                digest.* = hasher.finalize();
            }
            return out;
        }

        var states: [8]V4 = undefined;
        for (0..8) |word_index| states[word_index] = @splat(seed[word_index]);

        var at: usize = 0;
        var counter: u32 = 64;
        while (at + 64 < len) : (at += 64) {
            var blocks: [4][64]u8 = undefined;
            for (0..4) |lane| @memcpy(blocks[lane][0..], data[lane][at .. at + 64]);
            var messages: [16]V4 = undefined;
            block_io.loadParallel4(&blocks, &messages);
            counter +%= 64;
            compressParallel4(&states, &messages, counter, 0, 0);
        }

        const remaining = len - at;
        var final_blocks = [_][64]u8{[_]u8{0} ** 64} ** 4;
        for (0..4) |lane| @memcpy(final_blocks[lane][0..remaining], data[lane][at..]);
        var final_messages: [16]V4 = undefined;
        block_io.loadParallel4(&final_blocks, &final_messages);
        counter +%= @intCast(remaining);
        compressParallel4(&states, &final_messages, counter, 0, 0xFFFF_FFFF);

        return parallelStatesToDigests(&states);
    }

    pub fn finalizeEqualTail4(
        hashers: *const [4]Self,
        tails: *const [4][]const u8,
    ) [4]Blake2sHash {
        return stream4.finalizeEqualTail4(
            Self,
            V4,
            Blake2sHash,
            hashers,
            tails,
            block_io.loadParallel4,
            compressParallel4,
            parallelStatesToDigests,
        );
    }

    pub fn updateEqual4(
        hashers: *[4]Self,
        data: *const [4][]const u8,
    ) void {
        stream4.updateEqual4(
            Self,
            V4,
            hashers,
            data,
            block_io.loadParallel4,
            compressParallel4,
        );
    }

    /// Absorbs a column group into four independent streams and finalizes
    /// them without ever writing the intermediate hasher state back.
    pub fn finalizeM31Columns4(
        hashers: *const [4]Self,
        columns: anytype,
        position: usize,
    ) [4]Blake2sHash {
        const toDigests = parallelStatesToDigests;
        const compress = compressParallel4;
        return stream4.finalizeM31Columns4(Self, V4, Blake2sHash, hashers, columns, position, compress, toDigests);
    }

    pub fn updateM31Columns4(
        hashers: *[4]Self,
        columns: anytype,
        position: usize,
    ) void {
        stream4.updateM31Columns4(
            Self,
            V4,
            hashers,
            columns,
            position,
            block_io.loadParallel4,
            compressParallel4,
        );
    }

    /// Hashes four equal-length M31 leaf messages directly from column-major
    /// storage. Each column contributes one canonical little-endian u32 word
    /// to every lane. On little-endian SIMD hosts the four adjacent rows are
    /// already exactly the vector layout consumed by `compressParallel4`, so
    /// no row-major message packing or block retransposition is required.
    pub fn hashM31ColumnsFromSeed4WithMode(
        mode: BackendMode,
        seed: Fixed64Seed,
        columns: anytype,
        position: usize,
    ) [4]Blake2sHash {
        return hashM31Columns4FromStateWithMode(
            mode,
            seed,
            64,
            columns,
            position,
        );
    }

    pub fn hashM31Columns4WithMode(
        mode: BackendMode,
        columns: anytype,
        position: usize,
    ) [4]Blake2sHash {
        const initial = Self.initWithMode(mode);
        return hashM31Columns4FromStateWithMode(
            mode,
            initial.h,
            0,
            columns,
            position,
        );
    }

    fn hashM31Columns4FromStateWithMode(
        mode: BackendMode,
        initial_state: [8]u32,
        initial_counter: u32,
        columns: anytype,
        position: usize,
    ) [4]Blake2sHash {
        std.debug.assert(columns.len != 0);
        for (columns) |column| {
            std.debug.assert(position + 4 <= column.values.len);
        }

        if (selectBackend(mode).effective == .scalar or
            comptime builtin.cpu.arch.endian() != .little)
        {
            var out: [4]Blake2sHash = undefined;
            for (&out, 0..) |*digest, lane| {
                var hasher = Self.initWithMode(mode);
                hasher.h = initial_state;
                hasher.t0 = initial_counter;
                for (columns) |column| {
                    var encoded: [4]u8 = undefined;
                    std.mem.writeInt(u32, &encoded, column.values[position + lane].v, .little);
                    hasher.update(&encoded);
                }
                digest.* = hasher.finalize();
            }
            return out;
        }

        var states: [8]V4 = undefined;
        for (0..8) |word_index| states[word_index] = @splat(initial_state[word_index]);

        var column_at: usize = 0;
        var counter = initial_counter;
        while (column_at + 16 < columns.len) : (column_at += 16) {
            var messages: [16]V4 = undefined;
            inline for (0..16) |word| {
                const values: *const [4]u32 = @ptrCast(
                    columns[column_at + word].values.ptr + position,
                );
                messages[word] = values.*;
            }
            counter +%= 64;
            compressParallel4(&states, &messages, counter, 0, 0);
        }

        var final_messages: [16]V4 = @splat(@splat(0));
        const remaining = columns.len - column_at;
        for (0..remaining) |word| {
            const values: *const [4]u32 = @ptrCast(
                columns[column_at + word].values.ptr + position,
            );
            final_messages[word] = values.*;
        }
        counter +%= @intCast(remaining * @sizeOf(u32));
        compressParallel4(&states, &final_messages, counter, 0, 0xFFFF_FFFF);
        return parallelStatesToDigests(&states);
    }

    fn addCounter(self: *Self, inc: u32) void {
        const sum: u64 = @as(u64, self.t0) + @as(u64, inc);
        self.t0 = @truncate(sum);
        self.t1 +%= @intCast(sum >> 32);
    }

    fn compressBlock(self: *Self, block: *const [64]u8, is_last: bool) void {
        var m: [16]u32 = undefined;
        block_io.loadFixed(block, &m);
        self.compressWords(&m, is_last);
    }

    fn compressBlockBytes(self: *Self, block: []const u8, is_last: bool) void {
        std.debug.assert(block.len == 64);
        var m: [16]u32 = undefined;
        block_io.loadSlice(block, &m);
        self.compressWords(&m, is_last);
    }

    fn compressWords(self: *Self, m: *const [16]u32, is_last: bool) void {
        const f0: u32 = if (is_last) 0xFFFF_FFFF else 0;
        switch (self.selection.effective) {
            .simd => compressSimd(&self.h, m, self.t0, self.t1, f0),
            .scalar => compressScalar(&self.h, m, self.t0, self.t1, f0),
            .auto => unreachable,
        }
    }
};

fn parallelStatesToDigests(states: *const [8]V4) [4]Blake2sHash {
    return block_io.parallelStatesToDigests(Blake2sHash, states);
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
    if (comptime builtin.is_test) _ = test_scalar_compressions.fetchAdd(1, .monotonic);
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

const Shift4 = @Vector(4, u5);
const V16u8 = @Vector(16, u8);

fn rotr32x4(x: V4, comptime bits: u5) V4 {
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
    if (comptime builtin.is_test) _ = test_simd_compressions.fetchAdd(1, .monotonic);
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

fn compressParallel4(h: *[8]V4, m: *const [16]V4, t0: u32, t1: u32, f0: u32) void {
    if (comptime builtin.is_test) _ = test_parallel_simd_4_compressions.fetchAdd(1, .monotonic);
    var v: [16]V4 = undefined;
    for (0..8) |i| {
        v[i] = h[i];
        v[i + 8] = @splat(BLAKE2S_IV[i]);
    }
    v[12] ^= @as(V4, @splat(t0));
    v[13] ^= @as(V4, @splat(t1));
    v[14] ^= @as(V4, @splat(f0));

    inline for (BLAKE2S_SIGMA) |s| {
        parallel4.g4Interleaved(
            V4,
            rotr32x4,
            &v,
            .{ 0, 1, 2, 3 },
            .{ 4, 5, 6, 7 },
            .{ 8, 9, 10, 11 },
            .{ 12, 13, 14, 15 },
            .{ m[s[0]], m[s[2]], m[s[4]], m[s[6]] },
            .{ m[s[1]], m[s[3]], m[s[5]], m[s[7]] },
        );
        parallel4.g4Interleaved(
            V4,
            rotr32x4,
            &v,
            .{ 0, 1, 2, 3 },
            .{ 5, 6, 7, 4 },
            .{ 10, 11, 8, 9 },
            .{ 15, 12, 13, 14 },
            .{ m[s[8]], m[s[10]], m[s[12]], m[s[14]] },
            .{ m[s[9]], m[s[11]], m[s[13]], m[s[15]] },
        );
    }

    for (0..8) |i| h[i] ^= v[i] ^ v[i + 8];
}

test {
    _ = @import("tests/blake2s_backend.zig");
    _ = @import("tests/blake2s_dispatch.zig");
}
