//! The in-circuit Fiat-Shamir channel: port of
//! `crates/stark_verifier/src/channel.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230).
//!
//! It replays `Blake2sM31Channel` with `Blake2sM31MerkleChannel::mix_hash`:
//! the digest is two QM31 wires holding the eight digest words reduced
//! modulo P. Every method emits its builder calls in the Rust order, so the
//! draw byte lengths (37 for a draw, 52 and 40 for the proof of work, 64 for
//! a commitment) and the constant interning order are the upstream ones.

const std = @import("std");
const core = @import("stwo_core");
const builder = @import("../builder/mod.zig");
const circle = @import("circle.zig");

const QM31 = core.fields.qm31.QM31;
const Var = builder.Var;
const Context = builder.Context;
const Error = builder.context.Error;
const blake = builder.blake;
const ivalue = builder.ivalue;
const U32Wrapper = builder.wrappers.U32Wrapper;
const HashValue = blake.HashValue;
const ReducedHashValue = blake.ReducedHashValue;

/// `MODULUS_BITS`: bits of an M31 value.
const MODULUS_BITS: u32 = 31;

pub const Channel = struct {
    /// The current digest.
    digest: ReducedHashValue(Var),
    /// Values drawn since the digest last changed.
    n_draws: u32,

    const POW_PREFIX: u32 = 0x12345678;

    /// `Channel::new`: the zero digest.
    pub fn init(comptime V: type, ctx: *const Context(V)) Channel {
        return .{ .digest = .{ .low = ctx.zero(), .high = ctx.zero() }, .n_draws = 0 };
    }

    fn updateDigest(self: *Channel, digest: ReducedHashValue(Var)) void {
        self.digest = digest;
        self.n_draws = 0;
    }

    /// `mix_commitment`: Blake2s over the eight reduced digest words and the
    /// eight unreduced root words, then reduced.
    pub fn mixCommitment(self: *Channel, comptime V: type, ctx: *Context(V), root: HashValue(Var)) Error!void {
        const digest_words = try blake.unpackQm31sToU32Words(V, ctx, &.{ self.digest.low, self.digest.high });
        var message: [16]U32Wrapper(Var) = undefined;
        @memcpy(message[0..8], digest_words);
        @memcpy(message[8..], &root.words);
        const hash = try blake.blake2sU32s(V, ctx, &message, 16 * 4);
        self.updateDigest(try blake.reduceHashValue(V, ctx, hash));
    }

    /// `mix_qm31s`: `blake2s_m31(digest || values)`.
    pub fn mixQm31s(self: *Channel, comptime V: type, ctx: *Context(V), values: []const Var) Error!void {
        const input = try ctx.scratch().alloc(Var, 2 + values.len);
        input[0] = self.digest.low;
        input[1] = self.digest.high;
        @memcpy(input[2..], values);
        self.updateDigest(try blake.blake2sM31(V, ctx, input, 16 * input.len));
    }

    /// `mix_u32s`: `Blake2s(digest_words || values)`, reduced.
    pub fn mixU32s(self: *Channel, comptime V: type, ctx: *Context(V), values: []const U32Wrapper(Var)) Error!void {
        const digest_words = try blake.unpackQm31sToU32Words(V, ctx, &.{ self.digest.low, self.digest.high });
        const message = try ctx.scratch().alloc(U32Wrapper(Var), digest_words.len + values.len);
        @memcpy(message[0..digest_words.len], digest_words);
        @memcpy(message[digest_words.len..], values);
        const hash = try blake.blake2sU32s(V, ctx, message, 4 * message.len);
        self.updateDigest(try blake.reduceHashValue(V, ctx, hash));
    }

    /// `draw_qm31`: the first of two drawn values; the second is marked unused.
    pub fn drawQm31(self: *Channel, comptime V: type, ctx: *Context(V)) Error!Var {
        const drawn = try self.drawTwoQm31s(V, ctx);
        try ctx.markAsUnused(drawn[1]);
        return drawn[0];
    }

    /// `draw_two_qm31s`: `blake2s_m31(digest || n_draws || 0x00)`, 37 bytes;
    /// the zero byte separates drawing from mixing one u32.
    pub fn drawTwoQm31s(self: *Channel, comptime V: type, ctx: *Context(V)) Error![2]Var {
        const n_draws = try ctx.constant(ivalue.qm31FromU32s(self.n_draws, 0, 0, 0));
        const res = try blake.blake2sM31(V, ctx, &.{ self.digest.low, self.digest.high, n_draws }, 16 + 16 + 4 + 1);
        self.n_draws += 1;
        return .{ res.low, res.high };
    }

    /// `draw_point`: the circle point of the drawn `t`,
    /// `((1 - t^2) / (1 + t^2), 2t / (1 + t^2))`.
    pub fn drawPoint(self: *Channel, comptime V: type, ctx: *Context(V)) Error!circle.Point(Var) {
        const t = try self.drawQm31(V, ctx);
        const t2 = try ctx.mul(t, t);
        const denom = try ctx.add(t2, try ctx.constant(QM31.one()));
        const denom_inv = try ctx.inv(denom);
        const one_minus_t2 = try ctx.sub(try ctx.constant(QM31.one()), t2);
        const x = try ctx.mul(one_minus_t2, denom_inv);
        const two_t = try ctx.mul(try ctx.constant(ivalue.qm31FromU32s(2, 0, 0, 0)), t);
        const y = try ctx.mul(two_t, denom_inv);
        return .{ .x = x, .y = y };
    }

    /// `pow`: checks the `n_bits` proof of work of `nonce` and mixes it.
    /// The nonce must be `(lo, hi, 0, 0)`.
    pub fn pow(self: *Channel, comptime V: type, ctx: *Context(V), n_bits: u32, nonce: Var) Error!void {
        std.debug.assert(n_bits <= 30);

        // `H(POW_PREFIX, [0_u8; 12], digest, n_bits)`.
        const prefix = try ctx.constant(ivalue.qm31FromU32s(POW_PREFIX, 0, 0, 0));
        const bits_word = try ctx.constant(ivalue.qm31FromU32s(n_bits, 0, 0, 0));
        const prefixed = try blake.blake2sM31(V, ctx, &.{ prefix, self.digest.low, self.digest.high, bits_word }, 52);

        const high_mask = try ctx.constant(ivalue.qm31FromU32s(0, 0, 1, 1));
        const masked_nonce = try ctx.pointwiseMul(nonce, high_mask);
        try ctx.eq(masked_nonce, ctx.zero());

        // `H(prefixed_digest, nonce)`; its first word must end in n_bits zeros.
        const res = try blake.blake2sM31(V, ctx, &.{ prefixed.low, prefixed.high, nonce }, 40);
        try ctx.markAsUnused(res.high);
        const first_word = try ctx.pointwiseMul(res.low, ctx.one());
        const bits = try builder.extract_bits.extractBits(V, ctx, .fromPacked(&.{first_word}, 1), MODULUS_BITS);
        for (bits[0..n_bits]) |bit| try ctx.eq(bit.data[0], ctx.zero());

        self.updateDigest(try blake.blake2sM31(V, ctx, &.{ self.digest.low, self.digest.high, nonce }, 40));
    }
};

test {
    _ = @import("channel_test.zig");
}
