//! Blake2s-256 compression from a constant chaining state.
//!
//! Ports the domain-prefixed hashes of `core/vcs_lifted/blake2_merkle.zig`
//! (`Blake2sMerkleHasherProtocolGeneric(_, .domain_prefixed)`): a leaf is
//! `Blake2s(LEAF_PREFIX || values)` and a node is `Blake2s(NODE_PREFIX ||
//! left || right)`, where both prefixes are one full 64-byte block
//! (`makePrefix`). The native hasher compresses that block once and reuses
//! the state (`Blake2sHasher.seedAfterFixed64`, `leafSeed`, `nodeSeed` in
//! `core/crypto/blake2s_backend.zig`, with the byte counter already at 64);
//! `blake2sU32sFrom` does the same in-circuit, so the prefix block is never
//! hashed by gates. It is `builder.blake.blake2sU32s` with two extra inputs:
//! the eight chaining words and the bytes the counter already holds.
//!
//! Constants are interned in the same order as `blake2sU32s`: the zero word,
//! the eight chaining words, then per block the eight IV words of `v[8..16]`
//! with the counter and the last-block flag folded in.

const std = @import("std");
const core = @import("stwo_core");
const builder = @import("../builder/mod.zig");

const Var = builder.Var;
const Context = builder.Context;
const Error = builder.context.Error;
const blake = builder.blake;
const wrappers = builder.wrappers;
const U32Wrapper = wrappers.U32Wrapper;
const HashValue = blake.HashValue;
const BLAKE_SIGMA = core.crypto.blake_sigma.BLAKE_SIGMA;

/// `LEAF_PREFIX` and `NODE_PREFIX` of `core/vcs_lifted/blake2_merkle.zig`.
pub const LEAF_PREFIX = core.vcs_lifted.blake2_merkle.LEAF_PREFIX;
pub const NODE_PREFIX = core.vcs_lifted.blake2_merkle.NODE_PREFIX;
/// Bytes of one domain prefix: the counter of every prefixed hash starts here.
pub const PREFIX_BYTES: u32 = core.vcs_lifted.blake2_merkle.DOMAIN_PREFIX_BYTES;

const block_bytes = 64;
const words_per_block = 16;

/// The state columns fed to `G` in each round (as `builder.blake` keeps it).
const g_state_indices = [8][4]u8{
    .{ 0, 4, 8, 12 },
    .{ 1, 5, 9, 13 },
    .{ 2, 6, 10, 14 },
    .{ 3, 7, 11, 15 },
    .{ 0, 5, 10, 15 },
    .{ 1, 6, 11, 12 },
    .{ 2, 7, 8, 13 },
    .{ 3, 4, 9, 14 },
};

/// The chaining state after the leaf prefix block; `blake2sU32sFrom` with
/// `bytes_before = PREFIX_BYTES` continues a leaf hash from it.
pub const leaf_chaining: [8]u32 = chainingAfterPrefix(LEAF_PREFIX);
/// The chaining state after the node prefix block.
pub const node_chaining: [8]u32 = chainingAfterPrefix(NODE_PREFIX);

/// The Blake2s-256 initial state: the IV with the parameter block (depth 1,
/// fanout 1, digest length 32) folded into the first word.
pub fn initialState() [8]u32 {
    var h = blake.blake2s_iv;
    h[0] ^= 0x01010020;
    return h;
}

/// Little-endian words of a 64-byte block.
pub fn blockWords(block: *const [block_bytes]u8) [words_per_block]u32 {
    var words: [words_per_block]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, block[4 * i ..][0..4], .little);
    return words;
}

/// The Blake2s compression function on the host: `h` absorbs `block` with
/// the byte counter at `t0` (`t1` is always 0) and the last-block flag `last`.
pub fn compressNative(h: *[8]u32, block: [words_per_block]u32, t0: u32, last: bool) void {
    var v: [16]u32 = undefined;
    @memcpy(v[0..8], h);
    for (8..16) |i| {
        var iv = blake.blake2s_iv[i - 8];
        if (i == 12) iv ^= t0;
        if (i == 14 and last) iv ^= 0xFFFF_FFFF;
        v[i] = iv;
    }
    for (BLAKE_SIGMA) |permutation| {
        for (g_state_indices, 0..) |indices, g| {
            const out = blake.blake2sG(v[indices[0]], v[indices[1]], v[indices[2]], v[indices[3]], block[permutation[2 * g]], block[permutation[2 * g + 1]]);
            for (indices, out) |index, word| v[index] = word;
        }
    }
    for (h, 0..) |*word, i| word.* ^= v[i] ^ v[i + 8];
}

/// `Blake2sHasher.seedAfterFixed64(prefix)`: the chaining state after the
/// first (non-final) 64-byte block, with the counter at 64.
pub fn chainingAfterPrefix(prefix: [block_bytes]u8) [8]u32 {
    @setEvalBranchQuota(200_000);
    var h = initialState();
    compressNative(&h, blockWords(&prefix), PREFIX_BYTES, false);
    return h;
}

/// Blake2s-256 of `bytes_before` already-absorbed bytes (whose state is
/// `h_init`) followed by the `n_bytes` bytes of `message` (one `u32` wire per
/// word, zero-padded to whole blocks; unused bytes of the last word must be
/// zero). With `h_init = initialState()` and `bytes_before = 0` this is
/// `builder.blake.blake2sU32s`.
pub fn blake2sU32sFrom(
    comptime V: type,
    ctx: *Context(V),
    h_init: [8]u32,
    bytes_before: u32,
    message: []const U32Wrapper(Var),
    n_bytes: usize,
) Error!HashValue(Var) {
    std.debug.assert(message.len >= std.math.divCeil(usize, n_bytes, 4) catch unreachable);
    const n_blocks = @max(1, std.math.divCeil(usize, n_bytes, block_bytes) catch unreachable);
    const total_words = n_blocks * words_per_block;

    const zero_word = try wrappers.constU32(V, ctx, 0);
    const padded = try ctx.scratch().alloc(U32Wrapper(Var), @max(total_words, message.len));
    @memcpy(padded[0..message.len], message);
    @memset(padded[message.len..], zero_word);

    var h: [8]U32Wrapper(Var) = undefined;
    for (&h, h_init) |*word, value| word.* = try wrappers.constU32(V, ctx, value);

    for (0..n_blocks) |block_idx| {
        const block = padded[block_idx * words_per_block ..][0..words_per_block];
        const absorbed: u32 = @intCast(@min(n_bytes, (block_idx + 1) * block_bytes));
        const t0: u32 = bytes_before +% absorbed;
        const last = block_idx == n_blocks - 1;

        var v: [16]U32Wrapper(Var) = undefined;
        @memcpy(v[0..8], &h);
        for (8..16) |i| {
            var iv = blake.blake2s_iv[i - 8];
            if (i == 12) iv ^= t0;
            // `t1` is always 0, so word 13 is the plain IV.
            if (i == 14 and last) iv ^= 0xFFFF_FFFF;
            v[i] = try wrappers.constU32(V, ctx, iv);
        }

        for (BLAKE_SIGMA) |permutation| {
            for (g_state_indices, 0..) |indices, g| {
                const out = try blake.blakeGGate(V, ctx, v[indices[0]], v[indices[1]], v[indices[2]], v[indices[3]], block[permutation[2 * g]], block[permutation[2 * g + 1]]);
                for (indices, out) |index, word| v[index] = word;
            }
        }

        const prev_h = h;
        for (&h, 0..) |*word, i| word.* = try blake.tripleXor(V, ctx, prev_h[i], v[i], v[i + 8]);
    }

    ctx.stats.blake_updates += n_blocks;
    return .{ .words = h };
}

/// Blake2s of `prefix || bytes` on the host, for tests and conversions.
pub fn prefixedHashNative(prefix: [block_bytes]u8, bytes: []const u8) [32]u8 {
    var hasher = std.crypto.hash.blake2.Blake2s256.init(.{});
    hasher.update(&prefix);
    hasher.update(bytes);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

// Tests.

const QM31 = core.fields.qm31.QM31;
const ivalue = builder.ivalue;
const digestToU32s = core.vcs.blake2_hash.digestToU32s;

fn circuitWords(ctx: *const Context(QM31), hash: HashValue(Var)) [8]u32 {
    var out: [8]u32 = undefined;
    for (&out, hash.words) |*word, wire| word.* = ivalue.unpackU32(QM31, ctx.get(wire.get()));
    return out;
}

test "blake chain: the chaining states equal the native leaf and node seeds" {
    const Hasher = core.vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    try std.testing.expectEqual(Hasher.leafSeed(), leaf_chaining);
    try std.testing.expectEqual(Hasher.nodeSeed(), node_chaining);
    try std.testing.expect(!std.mem.eql(u32, &leaf_chaining, &node_chaining));
}

test "blake chain: the host compression reproduces full Blake2s digests" {
    // A 100-byte message: one full block then a final 36-byte block.
    var bytes: [100]u8 = undefined;
    for (&bytes, 0..) |*byte, i| byte.* = @intCast((i * 37 + 11) & 0xFF);
    var h = initialState();
    compressNative(&h, blockWords(bytes[0..64]), 64, false);
    var tail = [_]u8{0} ** 64;
    @memcpy(tail[0..36], bytes[64..]);
    compressNative(&h, blockWords(&tail), 100, true);
    var expected: [32]u8 = undefined;
    std.crypto.hash.blake2.Blake2s256.hash(&bytes, &expected, .{});
    try std.testing.expectEqual(digestToU32s(expected), h);
}

test "blake chain: prefixed hashes of every message length up to two blocks" {
    var ctx = try Context(QM31).init(std.testing.allocator, 0);
    defer ctx.deinit();
    const prefixes = [_]struct { prefix: [64]u8, chaining: [8]u32 }{
        .{ .prefix = LEAF_PREFIX, .chaining = leaf_chaining },
        .{ .prefix = NODE_PREFIX, .chaining = node_chaining },
    };
    for (prefixes) |case| {
        var n_words: usize = 1;
        while (n_words <= 20) : (n_words += 1) {
            var bytes: [80]u8 = undefined;
            const words = try ctx.scratch().alloc(U32Wrapper(Var), n_words);
            for (words, 0..) |*word, i| {
                const value: u32 = @truncate(0x9E37_79B9 *% (@as(u32, @intCast(i)) + 1) +% n_words);
                std.mem.writeInt(u32, bytes[4 * i ..][0..4], value, .little);
                word.* = try wrappers.guessU32(QM31, &ctx, wrappers.u32Value(QM31, value));
            }
            const hash = try blake2sU32sFrom(QM31, &ctx, case.chaining, PREFIX_BYTES, words, 4 * n_words);
            const expected = prefixedHashNative(case.prefix, bytes[0 .. 4 * n_words]);
            try std.testing.expectEqual(digestToU32s(expected), circuitWords(&ctx, hash));
        }
    }
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}

test "blake chain: the native leaf and node hashers agree with the circuit" {
    const Hasher = core.vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const M31 = core.fields.m31.M31;
    var ctx = try Context(QM31).init(std.testing.allocator, 0);
    defer ctx.deinit();

    const values = [_]M31{ M31.fromCanonical(1), M31.fromCanonical(2), M31.fromCanonical(0x7FFF_FFFE) };
    var leaf_hasher = Hasher.defaultWithInitialState();
    leaf_hasher.updateLeaf(&values);
    const leaf_expected = leaf_hasher.finalize();
    var leaf_words: [values.len]U32Wrapper(Var) = undefined;
    for (&leaf_words, values) |*word, value| {
        const wire = try wrappers.guessM31(QM31, &ctx, wrappers.m31Value(QM31, value));
        word.* = try blake.m31ToU32(QM31, &ctx, wire.get());
    }
    const leaf = try blake2sU32sFrom(QM31, &ctx, leaf_chaining, PREFIX_BYTES, &leaf_words, 4 * values.len);
    try std.testing.expectEqual(digestToU32s(leaf_expected), circuitWords(&ctx, leaf));

    const left = [_]u8{0x01} ** 32;
    const right = [_]u8{0x02} ** 32;
    const node_expected = Hasher.hashChildren(.{ .left = left, .right = right });
    var node_words: [16]U32Wrapper(Var) = undefined;
    const left_hash = try blake.guessHash(QM31, &ctx, blake.hashValueFromDigest(QM31, left));
    const right_hash = try blake.guessHash(QM31, &ctx, blake.hashValueFromDigest(QM31, right));
    @memcpy(node_words[0..8], &left_hash.words);
    @memcpy(node_words[8..], &right_hash.words);
    const node = try blake2sU32sFrom(QM31, &ctx, node_chaining, PREFIX_BYTES, &node_words, 64);
    try std.testing.expectEqual(digestToU32s(node_expected), circuitWords(&ctx, node));
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}

test "blake chain: from the initial state with no prefix it is blake2s_u32s" {
    var ctx = try Context(QM31).init(std.testing.allocator, 0);
    defer ctx.deinit();
    var words: [9]U32Wrapper(Var) = undefined;
    for (&words, 0..) |*word, i| word.* = try wrappers.guessU32(QM31, &ctx, wrappers.u32Value(QM31, @intCast(1000 + i)));
    const chained = try blake2sU32sFrom(QM31, &ctx, initialState(), 0, &words, 36);
    const plain = try blake.blake2sU32s(QM31, &ctx, &words, 36);
    try std.testing.expectEqual(circuitWords(&ctx, plain), circuitWords(&ctx, chained));
}
