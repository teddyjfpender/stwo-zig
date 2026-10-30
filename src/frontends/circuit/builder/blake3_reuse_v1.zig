//! BLAKE3 through the existing circuit AIR's BlakeGGate and TripleXor.
//! No new AIR, hash substitution, registry key or recursion admission is implied.
//! Callers supply range-constrained U32 wires. Compression parameters are
//! structural constants; request-dependent parameters need authenticated wires
//! before a future verifier adapter may use this kernel.
const core = @import("stwo_core");
const b = @import("mod.zig");
const canonical = core.crypto.blake3_compression;
const W = b.wrappers.U32Wrapper(b.Var);
pub const Digest = [8]W;
pub const CHUNK_START: u32 = 1;
pub const CHUNK_END: u32 = 2;
pub const PARENT: u32 = 4;
pub const ROOT: u32 = 8;
pub const production_active = false;

/// Full 16-word compression output, including the second XOF half.
/// Uses the shared canonical seven-round schedule, rather than a second table.
pub fn compress(comptime V: type, ctx: *b.Context(V), cv: Digest, block: [16]W, counter: u64, block_len: u32, flags: u32) ![16]W {
    return compressWords(V, ctx, cv, block, counter, block_len, flags, true);
}

/// Digest/CV consumers need only the first output half. Omitting unused XOF
/// words also preserves the existing Blake G AIR's equal-output multiplicity.
pub fn compressDigest(comptime V: type, ctx: *b.Context(V), cv: Digest, block: [16]W, counter: u64, block_len: u32, flags: u32) !Digest {
    return compressWords(V, ctx, cv, block, counter, block_len, flags, false);
}

fn compressWords(comptime V: type, ctx: *b.Context(V), cv: Digest, block: [16]W, counter: u64, block_len: u32, flags: u32, comptime full_xof: bool) ![if (full_xof) 16 else 8]W {
    if (block_len > 64) return error.InvalidBlake3BlockLength;
    var state: [16]W = undefined;
    @memcpy(state[0..8], &cv);
    for (canonical.IV[0..4], 8..) |value, i| state[i] = try b.wrappers.constU32(V, ctx, value);
    state[12] = try b.wrappers.constU32(V, ctx, @truncate(counter));
    state[13] = try b.wrappers.constU32(V, ctx, @truncate(counter >> 32));
    state[14] = try b.wrappers.constU32(V, ctx, block_len);
    state[15] = try b.wrappers.constU32(V, ctx, flags);
    var message = block;
    for (0..7) |_| {
        inline for (canonical.G_INDICES, 0..) |indices, slot| {
            const out = try b.blake.blakeGGate(V, ctx, state[indices[0]], state[indices[1]], state[indices[2]], state[indices[3]], message[2 * slot], message[2 * slot + 1]);
            inline for (indices, out) |index, word| state[index] = word;
        }
        const previous = message;
        inline for (canonical.PERMUTATION, 0..) |index, i| message[i] = previous[index];
    }
    if (full_xof) {
        // Each G row exports four words under one multiplicity. The upper
        // state half has two XOF consumers, so route it through explicit
        // identity gates: every original G output is then consumed once.
        // The general QM31 gate permits the copy's two independent uses.
        for (state[8..]) |*word| {
            const copy = try ctx.newVar(ctx.get(word.get()));
            try ctx.addInto(word.get(), ctx.zero(), copy);
            word.* = .newUnsafe(copy);
        }
    }
    const zero = try b.wrappers.constU32(V, ctx, 0);
    var out: [if (full_xof) 16 else 8]W = undefined;
    for (0..8) |i| {
        out[i] = try b.blake.tripleXor(V, ctx, state[i], state[i + 8], zero);
        if (full_xof) out[i + 8] = try b.blake.tripleXor(V, ctx, state[i + 8], cv[i], zero);
    }
    return out;
}

/// Whole little-endian words only: no unconstrained ignored bytes are admitted.
/// At most one 1024-byte chunk. `root=false` exports its chaining value for
/// an explicitly constructed BLAKE3 parent tree, at the exact chunk ordinal.
pub fn chunkWords(comptime V: type, ctx: *b.Context(V), words: []const W, chunk_ordinal: u64, root: bool) !Digest {
    if (words.len > 256 or (root and chunk_ordinal != 0)) return error.InvalidBlake3Chunk;
    return chunkPaddedWords(V, ctx, words, words.len * 4, chunk_ordinal, root);
}
fn chunkPaddedWords(comptime V: type, ctx: *b.Context(V), words: []const W, byte_length: usize, chunk_ordinal: u64, root: bool) !Digest {
    var cv: Digest = undefined;
    for (&cv, canonical.IV) |*word, value| word.* = try b.wrappers.constU32(V, ctx, value);
    const zero = try b.wrappers.constU32(V, ctx, 0);
    const blocks = @max(1, (words.len + 15) / 16);
    for (0..blocks) |index| {
        var block: [16]W = @splat(zero);
        const start = @min(words.len, index * 16);
        const length: usize = @min(@as(usize, 16), words.len - start);
        @memcpy(block[0..length], words[start..][0..length]);
        const final = index + 1 == blocks;
        const flags = (if (index == 0) CHUNK_START else @as(u32, 0)) | (if (final) CHUNK_END else @as(u32, 0)) | (if (final and root) ROOT else @as(u32, 0));
        cv = try compressDigest(V, ctx, cv, block, chunk_ordinal, @intCast(@min(@as(usize, 64), byte_length - @min(byte_length, index * 64))), flags);
    }
    return cv;
}

/// Ordered left/right CV parent. ROOT is distinct from an internal chaining CV.
pub fn parent(comptime V: type, ctx: *b.Context(V), left: Digest, right: Digest, root: bool) !Digest {
    var cv: Digest = undefined;
    for (&cv, canonical.IV) |*word, value| word.* = try b.wrappers.constU32(V, ctx, value);
    return compressDigest(V, ctx, cv, left ++ right, 0, 64, PARENT | (if (root) ROOT else @as(u32, 0)));
}

/// Arbitrary constant byte prefix followed by full U32 input words. Byte
/// decomposition is constrained in the existing arithmetic gates, so the
/// arbitrary unaligned domain prefixes cannot create free padding bytes.
/// Limited to one chunk; larger leaf frames require an explicit chunk tree.
pub fn hashPrefixedWords(comptime V: type, ctx: *b.Context(V), prefix: []const u8, words: []const W) !Digest {
    if (prefix.len > 1024 or words.len > (1024 - prefix.len) / 4) return error.InvalidBlake3Chunk;
    // Native experimental-v1 frames have a 28-byte aligned prefix. They
    // share the word wires directly; no byte decomposition is necessary.
    if (prefix.len % 4 == 0) {
        const prefix_words = prefix.len / 4;
        const joined = try ctx.scratch().alloc(W, prefix_words + words.len);
        for (joined[0..prefix_words], 0..) |*word, i| word.* = try b.wrappers.constU32(V, ctx, @import("std").mem.readInt(u32, prefix[4 * i ..][0..4], .little));
        @memcpy(joined[prefix_words..], words);
        return chunkWords(V, ctx, joined, 0, true);
    }
    const length = prefix.len + 4 * words.len;
    const bytes = try ctx.scratch().alloc(b.Var, length);
    for (prefix, bytes[0..prefix.len]) |value, *out| out.* = try ctx.constant(core.fields.qm31.QM31.fromU32Unchecked(value, 0, 0, 0));
    for (words, 0..) |word, i| {
        const packed_word = [1]b.Var{word.get()};
        const bits = try b.extract_bits.extractBits(V, ctx, b.simd.Simd.fromPacked(&packed_word, 2), 16);
        const low = try b.simd.combineBits(V, ctx, bits[0..8]);
        const high = try b.simd.combineBits(V, ctx, bits[8..16]);
        bytes[prefix.len + 4 * i] = try b.simd.unpackIdx(V, ctx, low, 0);
        bytes[prefix.len + 4 * i + 1] = try b.simd.unpackIdx(V, ctx, high, 0);
        bytes[prefix.len + 4 * i + 2] = try b.simd.unpackIdx(V, ctx, low, 1);
        bytes[prefix.len + 4 * i + 3] = try b.simd.unpackIdx(V, ctx, high, 1);
    }
    const output_words = try ctx.scratch().alloc(W, (length + 3) / 4);
    const shift = try ctx.constant(core.fields.qm31.QM31.fromU32Unchecked(256, 0, 0, 0));
    for (output_words, 0..) |*word, index| {
        var lanes: [4]b.Var = @splat(ctx.zero());
        for (&lanes, 0..) |*lane, j| if (4 * index + j < length) {
            lane.* = bytes[4 * index + j];
        };
        const low = try ctx.add(lanes[0], try ctx.mul(lanes[1], shift));
        const high = try ctx.add(lanes[2], try ctx.mul(lanes[3], shift));
        word.* = .newUnsafe(try b.ops.fromPartialEvals(V, ctx, .{ low, high, ctx.zero(), ctx.zero() }));
    }
    return chunkPaddedWords(V, ctx, output_words, length, 0, true);
}

/// Exact experimental-v1 Merkle NODE frame, not BLAKE3's internal PARENT.
pub fn protocolNode(comptime V: type, ctx: *b.Context(V), left: Digest, right: Digest) !Digest {
    const frame = core.channel.blake3.framing;
    return hashPrefixedWords(V, ctx, frame.PROTOCOL_ID ++ [_]u8{@intFromEnum(frame.Domain.node)}, &(left ++ right));
}

test {
    _ = @import("blake3_reuse_v1_test.zig");
}
