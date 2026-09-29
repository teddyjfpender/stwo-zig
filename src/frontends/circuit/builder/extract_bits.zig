//! Lane-wise binary decomposition of a `Simd`.
//!
//! Port of `crates/circuits/src/extract_bits.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230). Each round guesses the LSB,
//! subtracts it and halves; the final value is the MSB and is asserted to be a
//! bit. A lane above `2^n_bits - 1` violates a constraint. For `n_bits = 31`
//! the decomposition also rejects `0b111…1` (= P ≡ 0) as the encoding of 0.

const std = @import("std");
const stwo_core = @import("stwo_core");
const context_mod = @import("context.zig");
const simd = @import("simd.zig");
const wrappers = @import("wrappers.zig");

const M31 = stwo_core.fields.m31.M31;
const Simd = simd.Simd;
const Error = context_mod.Error;

/// `extract_bits`: the `n_bits` bit vectors of `input`, least significant
/// first (scratch-owned). `1 <= n_bits <= 31`.
pub fn extractBits(comptime V: type, ctx: *context_mod.Context(V), input: Simd, n_bits: u32) Error![]Simd {
    std.debug.assert(n_bits >= 1 and n_bits <= 31);
    const inv_two = try wrappers.constM31(V, ctx, M31.fromCanonical(2).inv() catch unreachable);
    const bits = try ctx.scratch().alloc(Simd, n_bits);

    var value = input;
    for (bits[0 .. n_bits - 1]) |*bit| {
        const lsb = try simd.guessLsb(V, ctx, value);
        bit.* = lsb;
        value = try simd.sub(V, ctx, value, lsb);
        value = try simd.scalarMul(V, ctx, value, inv_two);
    }
    // `value` is now the MSB.
    try simd.assertBits(V, ctx, value);
    bits[n_bits - 1] = value;

    if (n_bits == 31) try validateExtractBits(V, ctx, input, bits[0]);
    return bits;
}

/// Forbids `0b111…1` as the encoding of 0: with a guessed `aux` (`1/input`,
/// or 0), `(input · aux - 1) · lsb = 0`, so an input of 0 forces `lsb = 0`.
pub fn validateExtractBits(comptime V: type, ctx: *context_mod.Context(V), input: Simd, lsb: Simd) Error!void {
    const zero = try simd.zero(V, ctx, input.len);
    const one = try simd.one(V, ctx, input.len);
    const aux = try simd.guessInvOrZero(V, ctx, input);
    // (((input) * (aux)) - (one)) * (lsb)
    const product = try simd.mul(V, ctx, input, aux);
    const shifted = try simd.sub(V, ctx, product, one);
    const constraint = try simd.mul(V, ctx, shifted, lsb);
    try simd.eq(V, ctx, constraint, zero);
}

// Tests: `crates/circuits/src/extract_bits_test.rs`.

const QM31 = stwo_core.fields.qm31.QM31;
const ivalue = @import("ivalue.zig");
const simd_test = @import("simd_test.zig");

test "extract bits: 31-bit decomposition" {
    var ctx = try context_mod.Context(QM31).init(std.testing.allocator, 0);
    defer ctx.deinit();
    // 2^31 - 1 is identical to 0 once reduced; it stays as a sanity check.
    const input = try simd_test.simdFromU32s(&ctx, &.{ 0, 12, (1 << 31) - 1, (1 << 31) - 2 });
    const bits = try extractBits(QM31, &ctx, input, 31);
    try simd_test.expectPacked(&ctx, bits[0], &.{ivalue.qm31FromU32s(0, 0, 0, 0)});
    try simd_test.expectPacked(&ctx, bits[1], &.{ivalue.qm31FromU32s(0, 0, 0, 1)});
    try simd_test.expectPacked(&ctx, bits[2], &.{ivalue.qm31FromU32s(0, 1, 0, 1)});
    try simd_test.expectPacked(&ctx, bits[3], &.{ivalue.qm31FromU32s(0, 1, 0, 1)});
    for (bits[4..31]) |bit| try simd_test.expectPacked(&ctx, bit, &.{ivalue.qm31FromU32s(0, 0, 0, 1)});
    try std.testing.expect(try ctx.isCircuitValid());
}

test "extract bits: validate rejects 1 as the LSB of 0" {
    for ([_]bool{ true, false }) |success| {
        var ctx = try context_mod.Context(QM31).init(std.testing.allocator, 0);
        defer ctx.deinit();
        const lsb = try simd_test.simdFromU32s(&ctx, &.{ if (success) 0 else 1, 1, 0, 1, 1, 1 });
        const input = try simd_test.simdFromU32s(&ctx, &.{ 0, 1, 2, 3, 4, 5 });
        try validateExtractBits(QM31, &ctx, input, lsb);
        try std.testing.expectEqual(success, try ctx.isCircuitValid());
    }
}

test "extract bits: works as a range check" {
    for ([_]usize{ 4, 3 }) |len| {
        var ctx = try context_mod.Context(QM31).init(std.testing.allocator, 0);
        defer ctx.deinit();
        const n_bits = 5;
        var input_values = [_]u32{3} ** 4;
        input_values[0] = 1 << n_bits;
        const input = try simd_test.simdFromU32s(&ctx, input_values[0..len]);
        _ = try extractBits(QM31, &ctx, input, n_bits);
        try std.testing.expect(!try ctx.isCircuitValid());
    }
}
