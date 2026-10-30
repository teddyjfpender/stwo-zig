//! Exact experimental-v1 BLAKE3 transcript kernels over the existing circuit AIR.
//! Request roots, words and nonces are wires, never interned request constants.
//! This is not a complete STARK verifier or a registry-authorized leaf wrapper.
const std = @import("std");
const core = @import("stwo_core");
const b = @import("mod.zig");
const hash = @import("blake3_reuse_v1.zig");
const native = core.channel.blake3;
const Q = core.fields.qm31.QM31;
const W = b.wrappers.U32Wrapper(b.Var);
pub const Digest = hash.Digest;
pub const production_active = false;
pub const MAX_FRAME_WORDS: usize = 1 << 20;
pub const MAX_ATTEMPTS: u32 = 8;

/// Exact BLAKE3 tree: largest power-of-two left subtree, asymmetric right tail.
/// All transcript frames have a word-aligned canonical prefix and payload.
pub fn hashWords(comptime V: type, ctx: *b.Context(V), words: []const W) !Digest {
    if (words.len > MAX_FRAME_WORDS) return error.Blake3TranscriptFrameTooLarge;
    return subtree(V, ctx, words, 0, true);
}
fn subtree(comptime V: type, ctx: *b.Context(V), words: []const W, first_chunk: u64, root: bool) anyerror!Digest {
    if (words.len <= 256) return hash.chunkWords(V, ctx, words, first_chunk, root);
    const chunks = (words.len + 255) / 256;
    var left_chunks: usize = 1;
    while (left_chunks * 2 < chunks) left_chunks *= 2;
    const split = left_chunks * 256;
    const left = try subtree(V, ctx, words[0..split], first_chunk, false);
    const right = try subtree(V, ctx, words[split..], first_chunk + left_chunks, false);
    return hash.parent(V, ctx, left, right, root);
}
fn constantWords(comptime V: type, ctx: *b.Context(V), value: u64) ![2]W {
    return .{ try b.wrappers.constU32(V, ctx, @truncate(value)), try b.wrappers.constU32(V, ctx, @truncate(value >> 32)) };
}
fn frame(comptime V: type, ctx: *b.Context(V), comptime domain: native.Domain, payload: []const W) !Digest {
    const prefix = native.PROTOCOL_ID ++ [_]u8{@intFromEnum(domain)};
    comptime std.debug.assert(prefix.len % 4 == 0);
    const prefix_words = prefix.len / 4;
    if (payload.len > MAX_FRAME_WORDS - prefix_words) return error.Blake3TranscriptFrameTooLarge;
    const words = try ctx.scratch().alloc(W, prefix_words + payload.len);
    for (words[0..prefix_words], 0..) |*word, i| word.* = try b.wrappers.constU32(V, ctx, std.mem.readInt(u32, prefix[4 * i ..][0..4], .little));
    @memcpy(words[prefix_words..], payload);
    return hashWords(V, ctx, words);
}

pub const Sample = struct { accepted: b.Var, felts: [2]b.Var };
/// Reject exactly 2P and 2P+1, not P or 2P-1. ALL eight words participate,
/// even when a caller needs only one secure field element (four coordinates).
pub fn sampleBlock(comptime V: type, ctx: *b.Context(V), words: Digest) !Sample {
    var accepted = ctx.one();
    for (words) |word| {
        const packed_word = [1]b.Var{word.get()};
        const bits = try b.extract_bits.extractBits(V, ctx, b.simd.Simd.fromPacked(&packed_word, 2), 16);
        // A rejected raw U32 has bits1..31 all set; bit0 is free.
        var upper_fifteen = bits[1];
        for (bits[2..]) |bit| upper_fifteen = try b.simd.mul(V, ctx, upper_fifteen, bit);
        const low = try b.simd.unpackIdx(V, ctx, upper_fifteen, 0);
        const high15 = try b.simd.unpackIdx(V, ctx, upper_fifteen, 1);
        const high0 = try b.simd.unpackIdx(V, ctx, bits[0], 1);
        const rejected = try ctx.mul(low, try ctx.mul(high15, high0));
        accepted = try ctx.mul(accepted, try ctx.sub(ctx.one(), rejected));
    }
    const reduced = try b.blake.reduceHashValue(V, ctx, .{ .words = words });
    return .{ .accepted = accepted, .felts = .{ reduced.low, reduced.high } };
}
/// The attempts count changes topology, but cannot authorize rejection: every
/// earlier digest MUST fail the exact sampler, and the last MUST pass it.
/// A wrapper must independently authorize this bounded schedule/key.
pub fn requireAttempt(comptime V: type, ctx: *b.Context(V), sampled: Sample, terminal: bool) !void {
    try ctx.eq(sampled.accepted, if (terminal) ctx.one() else ctx.zero());
}

/// Exact trailing-zero predicate on an unreduced, range-typed U32 word.
pub fn requirePowWord(comptime V: type, ctx: *b.Context(V), difficulty: u32, word: W) !void {
    if (difficulty > native.MAX_POW_BITS) return error.UnsupportedProofOfWorkDifficulty;
    const packed_word = [1]b.Var{word.get()};
    const bits = try b.extract_bits.extractBits(V, ctx, b.simd.Simd.fromPacked(&packed_word, 2), 16);
    for (0..difficulty) |i| {
        const bit = try b.simd.unpackIdx(V, ctx, bits[i % 16], i / 16);
        try ctx.eq(bit, ctx.zero());
    }
}

pub fn Channel(comptime V: type) type {
    return struct {
        const Self = @This();
        digest: Digest,
        n_draws: u64 = 0,
        pub fn init(ctx: *b.Context(V)) !Self {
            return .{ .digest = try frame(V, ctx, .init, &.{}) };
        }
        fn absorb(self: *Self, digest: Digest) void {
            self.digest = digest;
            self.n_draws = 0;
        }
        pub fn mixRoot(self: *Self, ctx: *b.Context(V), root: Digest) !void {
            self.absorb(try frame(V, ctx, .root, &(self.digest ++ root)));
        }
        pub fn mixU64(self: *Self, ctx: *b.Context(V), value: [2]W) !void {
            self.absorb(try frame(V, ctx, .integer, &(self.digest ++ value)));
        }
        pub fn mixU32s(self: *Self, ctx: *b.Context(V), words: []const W) !void {
            if (words.len > MAX_FRAME_WORDS - 17) return error.Blake3TranscriptFrameTooLarge;
            const payload = try ctx.scratch().alloc(W, 10 + words.len);
            @memcpy(payload[0..8], &self.digest);
            const length = try constantWords(V, ctx, @intCast(words.len));
            @memcpy(payload[8..10], &length);
            @memcpy(payload[10..], words);
            self.absorb(try frame(V, ctx, .words, payload));
        }
        pub fn mixFelts(self: *Self, ctx: *b.Context(V), felts: []const b.Var) !void {
            if (felts.len > (MAX_FRAME_WORDS - 17) / 4) return error.Blake3TranscriptFrameTooLarge;
            const words = try b.blake.unpackQm31sToU32Words(V, ctx, felts);
            const payload = try ctx.scratch().alloc(W, 10 + words.len);
            @memcpy(payload[0..8], &self.digest);
            const length = try constantWords(V, ctx, @intCast(felts.len));
            @memcpy(payload[8..10], &length);
            @memcpy(payload[10..], words);
            self.absorb(try frame(V, ctx, .felts, payload));
        }
        /// Draws do not mutate the digest; only the structural counter advances.
        pub fn drawU32s(self: *Self, ctx: *b.Context(V)) !Digest {
            const next = try std.math.add(u64, self.n_draws, 1);
            const index = try constantWords(V, ctx, self.n_draws);
            const result = try frame(V, ctx, .draw, &(self.digest ++ index));
            self.n_draws = next;
            return result;
        }
        pub fn drawSecurePair(self: *Self, ctx: *b.Context(V), attempts: u32) ![2]b.Var {
            if (attempts == 0 or attempts > MAX_ATTEMPTS) return error.UnsupportedBlake3RejectionSchedule;
            var result: [2]b.Var = undefined;
            for (0..attempts) |i| {
                const sampled = try sampleBlock(V, ctx, try self.drawU32s(ctx));
                try requireAttempt(V, ctx, sampled, i + 1 == attempts);
                if (i + 1 < attempts) for (sampled.felts) |felt| try ctx.markAsUnused(felt);
                result = sampled.felts;
            }
            return result;
        }
        pub fn drawSecureFelt(self: *Self, ctx: *b.Context(V), attempts: u32) !b.Var {
            const pair = try self.drawSecurePair(ctx, attempts);
            // Rejection checks consume all eight raw U32 words. This API
            // intentionally exports only the first reduced secure value.
            try ctx.markAsUnused(pair[1]);
            return pair[0];
        }
        /// One schedule item per pair; odd counts still check all eight words.
        pub fn drawSecureFelts(self: *Self, ctx: *b.Context(V), count: usize, attempts: []const u32) ![]b.Var {
            if (count > MAX_FRAME_WORDS or attempts.len != (count + 1) / 2) return error.UnsupportedBlake3RejectionSchedule;
            const result = try ctx.scratch().alloc(b.Var, count);
            for (attempts, 0..) |schedule, i| {
                const pair = try self.drawSecurePair(ctx, schedule);
                result[2 * i] = pair[0];
                if (2 * i + 1 < count) result[2 * i + 1] = pair[1] else try ctx.markAsUnused(pair[1]);
            }
            return result;
        }
        /// Native predicate uses trailing zeros of RAW first32bits, not M31.
        /// This does not absorb; generic PCS verifies then separately mixU64.
        pub fn verifyPow(self: *const Self, ctx: *b.Context(V), difficulty: u32, nonce: [2]W) !void {
            if (difficulty > native.MAX_POW_BITS) return error.UnsupportedProofOfWorkDifficulty;
            const bits_word = try b.wrappers.constU32(V, ctx, difficulty);
            const digest = try frame(V, ctx, .pow, &(self.digest ++ [1]W{bits_word} ++ nonce));
            try requirePowWord(V, ctx, difficulty, digest[0]);
            for (digest[1..]) |word| try ctx.markAsUnused(word.get());
        }
        pub fn pow(self: *Self, ctx: *b.Context(V), difficulty: u32, nonce: [2]W) !void {
            try self.verifyPow(ctx, difficulty, nonce);
            try self.mixU64(ctx, nonce);
        }
    };
}

test {
    _ = @import("blake3_channel_reuse_v1_test.zig");
}
