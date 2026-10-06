//! In-circuit Blake2s: the G gate, triple XOR, M31-to-u32 and the hash gadgets.
//!
//! Port of `crates/circuits/src/blake.rs` (https://github.com/starkware-libs/proving
//! at 5a7c5ede4299c91a61df19a07cba4f7502c14230). A Blake2s-256 digest is
//! eight `u32` wires `(low_u16, high_u16, 0, 0)` (`HashValue`), or, reduced
//! word by word modulo P, two QM31 wires (`ReducedHashValue`).
//!
//! Constants are interned in upstream order: the zero word, the eight chaining
//! words of the IV (`IV[0] ^ 0x01010020` first), then per block the eight IV
//! words of `v[8..16]` with `t0` and the last-block flag folded in.

const std = @import("std");
const stwo_core = @import("stwo_core");
const context_mod = @import("context.zig");
const ivalue = @import("ivalue.zig");
const ops = @import("ops.zig");
const simd = @import("simd.zig");
const wrappers = @import("wrappers.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const BLAKE_SIGMA = stwo_core.crypto.blake_sigma.BLAKE_SIGMA;
const Var = context_mod.Var;
const Error = context_mod.Error;
const U32Wrapper = wrappers.U32Wrapper;

/// `BLAKE2S_DIGEST_N_WORDS`.
pub const digest_n_words = 8;

/// The Blake2s IV.
pub const blake2s_iv = [8]u32{ 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19 };

/// The state columns fed to `G` in each round.
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

/// Eight raw Blake2s output words, each a `u32` (not reduced modulo P).
pub fn HashValue(comptime T: type) type {
    return struct { words: [digest_n_words]U32Wrapper(T) };
}

/// A digest whose eight words were reduced modulo P and packed four to a
/// QM31: `low` holds words 0..4, `high` words 4..8.
pub fn ReducedHashValue(comptime T: type) type {
    return struct { low: T, high: T };
}

/// `HashValue::from([u32; 8])`: packs each word.
pub fn hashValue(comptime V: type, words: [digest_n_words]u32) HashValue(V) {
    var out: HashValue(V) = undefined;
    for (&out.words, words) |*w, word| w.* = wrappers.u32Value(V, word);
    return out;
}

/// `HashValue::from(Blake2sHash)`: the digest bytes as eight little-endian words.
pub fn hashValueFromDigest(comptime V: type, digest: [32]u8) HashValue(V) {
    return hashValue(V, stwo_core.vcs.blake2_hash.digestToU32s(digest));
}

/// `Guess for HashValue`: each word through `guessU32`, in order.
pub fn guessHash(comptime V: type, ctx: *context_mod.Context(V), value: HashValue(V)) Error!HashValue(Var) {
    var out: HashValue(Var) = undefined;
    for (&out.words, value.words) |*w, word| w.* = try wrappers.guessU32(V, ctx, word);
    return out;
}

/// `Constant for HashValue<QM31>`: each word as a constant, in order.
pub fn constantHash(comptime V: type, ctx: *context_mod.Context(V), value: HashValue(QM31)) Error!HashValue(Var) {
    var out: HashValue(Var) = undefined;
    for (&out.words, value.words) |*w, word| w.* = .newUnsafe(try ctx.constant(word.get()));
    return out;
}

/// `Guess for ReducedHashValue`: `low` then `high`.
pub fn guessReducedHash(comptime V: type, ctx: *context_mod.Context(V), value: ReducedHashValue(V)) Error!ReducedHashValue(Var) {
    const low = try ctx.guess(value.low);
    return .{ .low = low, .high = try ctx.guess(value.high) };
}

/// `qm31_from_bytes`: four little-endian words, each reduced modulo P.
pub fn qm31FromBytes(bytes: [16]u8) QM31 {
    var w: [4]u32 = undefined;
    for (&w, 0..) |*word, i| word.* = std.mem.readInt(u32, bytes[4 * i ..][0..4], .little);
    return ivalue.qm31FromU32s(w[0], w[1], w[2], w[3]);
}

/// `ReducedHashValue::from(Blake2sHash)`.
pub fn reducedHashValueFromDigest(digest: [32]u8) ReducedHashValue(QM31) {
    return .{ .low = qm31FromBytes(digest[0..16].*), .high = qm31FromBytes(digest[16..32].*) };
}

/// `blake2s_m31`: Blake2s of QM31-packed input, reduced to two QM31 wires.
/// Unused bytes of the last input word must be zero.
pub fn blake2sM31(comptime V: type, ctx: *context_mod.Context(V), input: []const Var, n_bytes: usize) Error!ReducedHashValue(Var) {
    const hash = try blake2s(V, ctx, input, n_bytes);
    return reduceHashValue(V, ctx, hash);
}

/// BLAKE2s with a fixed eight-byte personalization field. The personalized
/// parameter block is constrained by the same Blake-G and XOR AIR as the
/// unpersonalized variant; no extra message block is needed.
pub fn blake2sM31Personalized(comptime V: type, ctx: *context_mod.Context(V), input: []const Var, n_bytes: usize, personalization: [8]u8) Error!ReducedHashValue(Var) {
    std.debug.assert(input.len == std.math.divCeil(usize, n_bytes, 16) catch unreachable);
    const words = try unpackQm31sToU32Words(V, ctx, input);
    return reduceHashValue(V, ctx, try blake2sU32sPersonalized(V, ctx, words, n_bytes, personalization));
}

/// `blake2s`: Blake2s of `n_bytes` bytes packed four words per QM31 wire
/// (`input.len == ceil(n_bytes / 16)`). Unused bytes must be zero.
pub fn blake2s(comptime V: type, ctx: *context_mod.Context(V), input: []const Var, n_bytes: usize) Error!HashValue(Var) {
    std.debug.assert(input.len == std.math.divCeil(usize, n_bytes, 16) catch unreachable);
    const words = try unpackQm31sToU32Words(V, ctx, input);
    return blake2sU32s(V, ctx, words, n_bytes);
}

/// `unpack_qm31s_to_u32_words`: each wire's four coordinates, in order, as
/// `u32` wires through `m31_to_u32` (scratch-owned).
pub fn unpackQm31sToU32Words(comptime V: type, ctx: *context_mod.Context(V), input: []const Var) Error![]U32Wrapper(Var) {
    const words = try ctx.scratch().alloc(U32Wrapper(Var), 4 * input.len);
    for (0..input.len) |i| {
        const lanes = simd.Simd.fromPacked(input[i .. i + 1], 4);
        for (0..4) |coord| {
            const lane = try simd.unpackIdx(V, ctx, lanes, coord);
            words[4 * i + coord] = try m31ToU32(V, ctx, lane);
        }
    }
    return words;
}

/// `reduce_hash_value`: each word `low + high · 2^16` in M31, then packed
/// four words to a QM31 with `from_partial_evals`.
pub fn reduceHashValue(comptime V: type, ctx: *context_mod.Context(V), hash: HashValue(Var)) Error!ReducedHashValue(Var) {
    const two_pow_16 = try ctx.constant(QM31.fromBase(M31.fromCanonical(1 << 16)));
    var reduced: [digest_n_words]Var = undefined;
    for (&reduced, hash.words) |*out, word| {
        const packed_word = [1]Var{word.get()};
        const lanes = simd.Simd.fromPacked(&packed_word, 2);
        const low = try simd.unpackIdx(V, ctx, lanes, 0);
        const high = try simd.unpackIdx(V, ctx, lanes, 1);
        // (low) + ((high) * (c_2_pow_16))
        const shifted = try ctx.mul(high, two_pow_16);
        out.* = try ctx.add(low, shifted);
    }
    const low = try ops.fromPartialEvals(V, ctx, reduced[0..4].*);
    const high = try ops.fromPartialEvals(V, ctx, reduced[4..8].*);
    return .{ .low = low, .high = high };
}

/// `blake2s_u32s`: the Blake2s-256 compression of `message` (one `u32` wire
/// per word, zero-padded to whole 64-byte blocks) over `n_bytes` bytes.
/// Unused bytes of the last word must be zero.
pub fn blake2sU32s(comptime V: type, ctx: *context_mod.Context(V), message: []const U32Wrapper(Var), n_bytes: usize) Error!HashValue(Var) {
    return blake2sU32sPersonalized(V, ctx, message, n_bytes, [_]u8{0} ** 8);
}

pub fn blake2sU32sPersonalized(comptime V: type, ctx: *context_mod.Context(V), message: []const U32Wrapper(Var), n_bytes: usize, personalization: [8]u8) Error!HashValue(Var) {
    const block_bytes = 64;
    const words_per_block = 16;
    const n_blocks = @max(1, std.math.divCeil(usize, n_bytes, block_bytes) catch unreachable);
    const total_words = n_blocks * words_per_block;

    const zero_word = try wrappers.constU32(V, ctx, 0);
    const padded = try ctx.scratch().alloc(U32Wrapper(Var), @max(total_words, message.len));
    @memcpy(padded[0..message.len], message);
    @memset(padded[message.len..], zero_word);

    // `h`: the IV XORed with the parameter block (depth 1, fanout 1, digest length 32).
    var h: [8]U32Wrapper(Var) = undefined;
    for (&h, 0..) |*word, i| {
        const parameter: u32 = if (i == 0) 0x01010020 else if (i == 6) std.mem.readInt(u32, personalization[0..4], .little) else if (i == 7) std.mem.readInt(u32, personalization[4..8], .little) else 0;
        word.* = try wrappers.constU32(V, ctx, blake2s_iv[i] ^ parameter);
    }

    for (0..n_blocks) |block_idx| {
        const block = padded[block_idx * words_per_block ..][0..words_per_block];
        const t0: u32 = @intCast(@min(n_bytes, (block_idx + 1) * block_bytes));
        const last = block_idx == n_blocks - 1;

        var v: [16]U32Wrapper(Var) = undefined;
        @memcpy(v[0..8], &h);
        for (8..16) |i| {
            var iv = blake2s_iv[i - 8];
            if (i == 12) iv ^= t0;
            // `t1` is always 0, so word 13 is the plain IV.
            if (i == 14 and last) iv ^= 0xFFFF_FFFF;
            v[i] = try wrappers.constU32(V, ctx, iv);
        }

        for (BLAKE_SIGMA) |permutation| {
            for (g_state_indices, 0..) |indices, g| {
                const out = try blakeGGate(V, ctx, v[indices[0]], v[indices[1]], v[indices[2]], v[indices[3]], block[permutation[2 * g]], block[permutation[2 * g + 1]]);
                for (indices, out) |index, word| v[index] = word;
            }
        }

        const prev_h = h;
        for (&h, 0..) |*word, i| word.* = try tripleXor(V, ctx, prev_h[i], v[i], v[i + 8]);
    }

    ctx.stats.blake_updates += n_blocks;
    return .{ .words = h };
}

/// Adds a TripleXor gate: `a ^ b ^ c` over `u32` wires.
pub fn tripleXor(comptime V: type, ctx: *context_mod.Context(V), a: U32Wrapper(Var), b: U32Wrapper(Var), c: U32Wrapper(Var)) Error!U32Wrapper(Var) {
    const x = ivalue.unpackU32(V, ctx.get(a.get())) ^ ivalue.unpackU32(V, ctx.get(b.get())) ^ ivalue.unpackU32(V, ctx.get(c.get()));
    const out = try ctx.newVar(ivalue.packU32(V, x));
    ctx.stats.triple_xor += 1;
    ctx.gate_counts.triple_xor += 1;
    if (ctx.record_gates) try ctx.circuit.triple_xor.append(ctx.gpa, .{ .input_a = a.get().idx, .input_b = b.get().idx, .input_c = c.get().idx, .out = out.idx });
    return .newUnsafe(out);
}

/// The Blake2s mixing function `G` on state words `(a, b, c, d)` and message
/// words `f0`, `f1`.
pub fn blake2sG(a0: u32, b0: u32, c0: u32, d0: u32, f0: u32, f1: u32) [4]u32 {
    const a1 = a0 +% b0 +% f0;
    const d1 = std.math.rotr(u32, d0 ^ a1, 16);
    const c1 = c0 +% d1;
    const b1 = std.math.rotr(u32, b0 ^ c1, 12);
    const a2 = a1 +% b1 +% f1;
    const d2 = std.math.rotr(u32, d1 ^ a2, 8);
    const c2 = c1 +% d2;
    const b2 = std.math.rotr(u32, b1 ^ c2, 7);
    return .{ a2, b2, c2, d2 };
}

/// Adds an M31ToU32 gate: the M31 `(x, 0, 0, 0)` as the `u32` wire
/// `(x & 0xFFFF, x >> 16, 0, 0)`.
pub fn m31ToU32(comptime V: type, ctx: *context_mod.Context(V), input: Var) Error!U32Wrapper(Var) {
    const out = try ctx.newVar(ivalue.m31ToU32(V, ctx.get(input)));
    try ctx.m31ToU32Into(input, out);
    return .newUnsafe(out);
}

/// Adds a BlakeGGate: `G(a, b, c, d, f0, f1)` over `u32` wires. The four
/// outputs are four consecutive new variables.
pub fn blakeGGate(
    comptime V: type,
    ctx: *context_mod.Context(V),
    a: U32Wrapper(Var),
    b: U32Wrapper(Var),
    c: U32Wrapper(Var),
    d: U32Wrapper(Var),
    f0: U32Wrapper(Var),
    f1: U32Wrapper(Var),
) Error![4]U32Wrapper(Var) {
    const inputs = [6]U32Wrapper(Var){ a, b, c, d, f0, f1 };
    var words: [6]u32 = undefined;
    for (&words, inputs) |*word, input| word.* = ivalue.unpackU32(V, ctx.get(input.get()));
    const out_words = blake2sG(words[0], words[1], words[2], words[3], words[4], words[5]);
    var outputs: [4]U32Wrapper(Var) = undefined;
    for (&outputs, out_words) |*out, word| out.* = .newUnsafe(try ctx.newVar(ivalue.packU32(V, word)));
    const out_base = outputs[0].get().idx;
    for (outputs, 0..) |out, i| std.debug.assert(out.get().idx == out_base + i);
    ctx.gate_counts.blake_g_gate += 1;
    if (ctx.record_gates) try ctx.circuit.blake_g_gate.append(ctx.gpa, .{
        .input_a = a.get().idx,
        .input_b = b.get().idx,
        .input_c = c.get().idx,
        .input_d = d.get().idx,
        .input_f0 = f0.get().idx,
        .input_f1 = f1.get().idx,
        .out_base = out_base,
    });
    return outputs;
}

test {
    _ = @import("blake_test.zig");
}
