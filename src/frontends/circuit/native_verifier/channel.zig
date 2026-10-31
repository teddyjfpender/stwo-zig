//! The in-circuit Fiat-Shamir channel of the native protocol: port of
//! `core/channel/blake2s.zig` (`Blake2sChannelGeneric(false)`, the plain
//! `Blake2sChannel`) and of `Blake2sMerkleChannelGeneric.mixRoot` in
//! `core/vcs_lifted/blake2_merkle.zig`.
//!
//! The digest is eight raw `u32` wires (no reduction modulo P, unlike the
//! `stark_verifier` channel). Byte layouts are the native ones:
//! - `mixU32s` / `mixFelts`: `Blake2s(digest || words)` (a QM31 is its four
//!   canonical limbs as little-endian words);
//! - `mixRoot`: `Blake2s(digest || root)`, 64 bytes;
//! - `drawU32s`: `Blake2s(digest || n_draws || 0x00)`, 37 bytes;
//! - `drawSecureFelt`: four drawn words reduced to M31 as `lo + hi * 2^16`
//!   in the field. The native `drawBaseFelts` redraws when any of the eight
//!   words is `>= 2P`; that branch is not modelled, so a transcript that hits
//!   it (probability `2^-31` per word) is rejected by the circuit;
//! - `pow`: `H(H(0x12345678 || [0; 12] || digest || n_bits) || nonce)` must
//!   end in `n_bits` zero bits (in its first word; `n_bits <= 32`), then the
//!   nonce is mixed with `mixU64`, as `pcs/verifier.zig` does;
//! - `drawQueryBits`: the low `log_domain` bits of each drawn word, one word
//!   per query (`core/queries.zig` `drawQueries`).

const std = @import("std");
const core = @import("stwo_core");
const builder = @import("../builder/mod.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Var = builder.Var;
const Context = builder.Context;
const Error = builder.context.Error;
const blake = builder.blake;
const ivalue = builder.ivalue;
const ops = builder.ops;
const simd = builder.simd;
const Simd = simd.Simd;
const wrappers = builder.wrappers;
const U32Wrapper = wrappers.U32Wrapper;
const M31Wrapper = wrappers.M31Wrapper;
const HashValue = blake.HashValue;

/// `Blake2sChannel.POW_PREFIX`.
pub const POW_PREFIX: u32 = 0x12345678;
/// Words of one `drawU32s`.
pub const WORDS_PER_DRAW: usize = core.channel.blake2s.FELTS_PER_HASH;
/// Secure felts of one draw: eight words, four per QM31.
pub const FELTS_PER_DRAW: usize = WORDS_PER_DRAW / 4;

/// The bits of the drawn query positions: `bits[i]` holds bit `i` (LSB
/// first) of every query index, packed four queries per wire, and
/// `unpacked[i][q]` the same bit as its own wire.
pub const QueryBits = struct {
    bits: []const Simd,
    unpacked: []const []const Var,
    n_queries: usize,
};

pub const NativeChannel = struct {
    digest: HashValue(Var),
    n_draws: u32,

    /// `Blake2sChannel{}`: the zero digest.
    pub fn init(comptime V: type, ctx: *Context(V)) Error!NativeChannel {
        var digest: HashValue(Var) = undefined;
        for (&digest.words) |*word| word.* = try wrappers.constU32(V, ctx, 0);
        return .{ .digest = digest, .n_draws = 0 };
    }

    fn updateDigest(self: *NativeChannel, digest: HashValue(Var)) void {
        self.digest = digest;
        self.n_draws = 0;
    }

    /// `Blake2s(digest || message)` over `n_bytes` bytes, with the digest
    /// words as the first eight message words.
    fn hashWithDigest(self: *const NativeChannel, comptime V: type, ctx: *Context(V), message: []const U32Wrapper(Var), n_bytes: usize) Error!HashValue(Var) {
        const words = try ctx.scratch().alloc(U32Wrapper(Var), blake.digest_n_words + message.len);
        @memcpy(words[0..blake.digest_n_words], &self.digest.words);
        @memcpy(words[blake.digest_n_words..], message);
        return blake.blake2sU32s(V, ctx, words, n_bytes);
    }

    /// `mixU32s`.
    pub fn mixU32s(self: *NativeChannel, comptime V: type, ctx: *Context(V), words: []const U32Wrapper(Var)) Error!void {
        self.updateDigest(try self.hashWithDigest(V, ctx, words, 4 * (blake.digest_n_words + words.len)));
    }

    /// `mixU64`: the low word first.
    pub fn mixU64(self: *NativeChannel, comptime V: type, ctx: *Context(V), lo: U32Wrapper(Var), hi: U32Wrapper(Var)) Error!void {
        try self.mixU32s(V, ctx, &.{ lo, hi });
    }

    /// `mixFelts`: each QM31 as its four limbs, through `m31_to_u32`.
    pub fn mixFelts(self: *NativeChannel, comptime V: type, ctx: *Context(V), felts: []const Var) Error!void {
        const words = try blake.unpackQm31sToU32Words(V, ctx, felts);
        try self.mixU32s(V, ctx, words);
    }

    /// `Blake2sMerkleChannel.mixRoot`: `Blake2s(digest || root)`.
    pub fn mixRoot(self: *NativeChannel, comptime V: type, ctx: *Context(V), root: HashValue(Var)) Error!void {
        try self.mixU32s(V, ctx, &root.words);
    }

    /// `drawU32s`: the 37-byte message `digest || n_draws || 0x00`.
    pub fn drawU32s(self: *NativeChannel, comptime V: type, ctx: *Context(V)) Error![WORDS_PER_DRAW]U32Wrapper(Var) {
        const counter = try wrappers.constU32(V, ctx, self.n_draws);
        const zero = try wrappers.constU32(V, ctx, 0);
        const hash = try self.hashWithDigest(V, ctx, &.{ counter, zero }, 37);
        self.n_draws +%= 1;
        return hash.words;
    }

    /// `drawSecureFelt`: the first four words of a draw, each reduced to M31.
    /// The other four words are unused.
    pub fn drawSecureFelt(self: *NativeChannel, comptime V: type, ctx: *Context(V)) Error!Var {
        const words = try self.drawU32s(V, ctx);
        for (words[4..]) |word| try ctx.markAsMaybeUnused(word.get());
        return feltFromWords(V, ctx, words[0..4]);
    }

    /// `drawSecureFelts`: two felts per draw (scratch-owned).
    pub fn drawSecureFelts(self: *NativeChannel, comptime V: type, ctx: *Context(V), n_felts: usize) Error![]Var {
        const out = try ctx.scratch().alloc(Var, n_felts);
        var produced: usize = 0;
        while (produced < n_felts) {
            const words = try self.drawU32s(V, ctx);
            for (0..FELTS_PER_DRAW) |i| {
                if (produced == n_felts) {
                    for (words[4 * i ..]) |word| try ctx.markAsMaybeUnused(word.get());
                    break;
                }
                out[produced] = try feltFromWords(V, ctx, words[4 * i ..][0..4]);
                produced += 1;
            }
        }
        return out;
    }

    /// `queries.drawQueries`: one word per query, its low `log_domain` bits.
    /// The words are `u32` wires, so the bits come from their two 16-bit
    /// limbs (both fully decomposed; limbs above `log_domain` are unused).
    pub fn drawQueryBits(self: *NativeChannel, comptime V: type, ctx: *Context(V), log_domain: u32, n_queries: usize) Error!QueryBits {
        std.debug.assert(log_domain >= 1 and log_domain <= 32);
        const scratch = ctx.scratch();
        const words = try scratch.alloc(U32Wrapper(Var), n_queries);
        var produced: usize = 0;
        while (produced < n_queries) {
            const drawn = try self.drawU32s(V, ctx);
            for (drawn) |word| {
                if (produced == n_queries) {
                    try ctx.markAsMaybeUnused(word.get());
                    continue;
                }
                words[produced] = word;
                produced += 1;
            }
        }

        const limbs = try splitLimbs(V, ctx, words);
        const low_bits = try builder.extract_bits.extractBits(V, ctx, limbs.low, 16);
        const high_bits: []Simd = if (log_domain > 16)
            try builder.extract_bits.extractBits(V, ctx, limbs.high, 16)
        else
            &.{};
        if (log_domain <= 16) try simd.markPartlyUsed(V, ctx, limbs.high);

        const bits = try scratch.alloc(Simd, log_domain);
        for (bits, 0..) |*bit, i| bit.* = if (i < 16) low_bits[i] else high_bits[i - 16];
        for (low_bits[@min(log_domain, 16)..]) |bit| try simd.markPartlyUsed(V, ctx, bit);
        if (log_domain > 16) {
            for (high_bits[log_domain - 16 ..]) |bit| try simd.markPartlyUsed(V, ctx, bit);
        }

        const unpacked = try scratch.alloc([]const Var, log_domain);
        for (unpacked, bits) |*lanes, bit| lanes.* = try simd.unpack(V, ctx, bit);
        return .{ .bits = bits, .unpacked = unpacked, .n_queries = n_queries };
    }

    /// `verifyPowNonce` then `mixU64(nonce)`: the first word of
    /// `H(H(POW_PREFIX || [0; 12] || digest || n_bits) || nonce)` ends in
    /// `n_bits` zero bits. `nonce` is `(lo, hi)`.
    pub fn pow(self: *NativeChannel, comptime V: type, ctx: *Context(V), n_bits: u32, nonce: [2]U32Wrapper(Var)) Error!void {
        std.debug.assert(n_bits <= 32);
        if (n_bits > 0) {
            const zero = try wrappers.constU32(V, ctx, 0);
            var prefix_message: [13]U32Wrapper(Var) = undefined;
            prefix_message[0] = try wrappers.constU32(V, ctx, POW_PREFIX);
            @memset(prefix_message[1..4], zero);
            @memcpy(prefix_message[4..12], &self.digest.words);
            prefix_message[12] = try wrappers.constU32(V, ctx, n_bits);
            const prefixed = try blake.blake2sU32s(V, ctx, &prefix_message, 52);

            var nonce_message: [10]U32Wrapper(Var) = undefined;
            @memcpy(nonce_message[0..8], &prefixed.words);
            nonce_message[8] = nonce[0];
            nonce_message[9] = nonce[1];
            const hash = try blake.blake2sU32s(V, ctx, &nonce_message, 40);
            for (hash.words[1..]) |word| try ctx.markAsMaybeUnused(word.get());

            const limbs = try splitLimbs(V, ctx, hash.words[0..1]);
            const low_bits = try builder.extract_bits.extractBits(V, ctx, limbs.low, 16);
            for (low_bits[0..@min(n_bits, 16)]) |bit| try ctx.eq(bit.data[0], ctx.zero());
            for (low_bits[@min(n_bits, 16)..]) |bit| try simd.markPartlyUsed(V, ctx, bit);
            if (n_bits > 16) {
                const high_bits = try builder.extract_bits.extractBits(V, ctx, limbs.high, 16);
                for (high_bits[0 .. n_bits - 16]) |bit| try ctx.eq(bit.data[0], ctx.zero());
                for (high_bits[n_bits - 16 ..]) |bit| try simd.markPartlyUsed(V, ctx, bit);
            } else try simd.markPartlyUsed(V, ctx, limbs.high);
        }
        try self.mixU64(V, ctx, nonce[0], nonce[1]);
    }

    /// The digest bytes (value mode only), for parity checks.
    pub fn debugDigest(self: *const NativeChannel, ctx: *const Context(QM31)) [32]u8 {
        var words: [8]u32 = undefined;
        for (&words, self.digest.words) |*word, wire| word.* = ivalue.unpackU32(QM31, ctx.get(wire.get()));
        return core.vcs.blake2_hash.digestFromU32s(words);
    }
};

/// `M31.fromU64(word)` for a `u32` wire `(lo, hi, 0, 0)`: `lo + hi * 2^16`
/// in the field (equal to `word mod P`).
pub fn wordToM31(comptime V: type, ctx: *Context(V), word: U32Wrapper(Var)) Error!Var {
    const two_pow_16 = try ctx.constant(QM31.fromBase(M31.fromCanonical(1 << 16)));
    const packed_word = [1]Var{word.get()};
    const lanes = Simd.fromPacked(&packed_word, 2);
    const low = try simd.unpackIdx(V, ctx, lanes, 0);
    const high = try simd.unpackIdx(V, ctx, lanes, 1);
    const shifted = try ctx.mul(high, two_pow_16);
    return ctx.add(low, shifted);
}

/// `QM31.fromM31Array` of four reduced words.
fn feltFromWords(comptime V: type, ctx: *Context(V), words: *const [4]U32Wrapper(Var)) Error!Var {
    var reduced: [4]Var = undefined;
    for (&reduced, words) |*out, word| out.* = try wordToM31(V, ctx, word);
    return ops.fromPartialEvals(V, ctx, reduced);
}

const Limbs = struct { low: Simd, high: Simd };

/// The low and high 16-bit limbs of `u32` wires, each packed four lanes per
/// wire (`low.len == high.len == words.len`).
fn splitLimbs(comptime V: type, ctx: *Context(V), words: []const U32Wrapper(Var)) Error!Limbs {
    const scratch = ctx.scratch();
    const low = try scratch.alloc(M31Wrapper(Var), words.len);
    const high = try scratch.alloc(M31Wrapper(Var), words.len);
    for (words, low, high) |word, *lo, *hi| {
        const packed_word = [1]Var{word.get()};
        const lanes = Simd.fromPacked(try scratch.dupe(Var, &packed_word), 2);
        lo.* = .newUnsafe(try simd.unpackIdx(V, ctx, lanes, 0));
        hi.* = .newUnsafe(try simd.unpackIdx(V, ctx, lanes, 1));
    }
    return .{ .low = try simd.pack(V, ctx, low), .high = try simd.pack(V, ctx, high) };
}

test {
    _ = @import("channel_test.zig");
}
