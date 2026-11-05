//! Integer counters for typed leaves. Addition proves the integer sum < p;
//! reducing a field sum alone would permit wrapped execution/call counters.
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const C = @import("common.zig");
const B = circuit.builder;
const Word = @import("frame.zig").Word;
const Bounds = @import("../node_summary.zig");
pub fn canonical(ctx: *C.Context, word: Word) !C.Var {
    const base = try circuit.native_verifier.channel.wordToM31(C.Q, ctx, word);
    try ctx.eq((try B.blake.m31ToU32(C.Q, ctx, base)).get(), word.get());
    return base;
}
fn limbs(ctx: *C.Context, word: Word) !Bounds.Mass {
    _ = try canonical(ctx, word);
    const encoded = [1]C.Var{word.get()};
    const lanes = B.simd.Simd.fromPacked(&encoded, 2);
    return .{ .lo = try B.simd.unpackIdx(C.Q, ctx, lanes, 0), .hi = try B.simd.unpackIdx(C.Q, ctx, lanes, 1) };
}
pub fn sum(ctx: *C.Context, words: []const Word, values: []const u64) !Word {
    if (words.len < 2 or words.len > 4 or words.len != values.len) return error.TypedIntegerArity;
    var parts: [4]Bounds.Mass = undefined;
    for (words, 0..) |word, i| parts[i] = try limbs(ctx, word);
    const total = try Bounds.foldMass(ctx, parts[0..words.len], try Bounds.massWitness(values));
    const imaginary = try ctx.constant(C.Q.fromU32Unchecked(0, 1, 0, 0));
    return .newUnsafe(try ctx.add(total.lo, try ctx.mul(total.hi, imaginary)));
}
pub fn addTo(ctx: *C.Context, left: Word, right: Word, out: Word, left_value: u64, right_value: u64) !void {
    const result = try sum(ctx, &.{ left, right }, &.{ left_value, right_value });
    try ctx.eq(result.get(), out.get());
}
pub fn scale(ctx: *C.Context, input: Word, value: u64, coefficient: usize) !Word {
    var result = try B.wrappers.constU32(C.Q, ctx, 0);
    var part = input;
    var part_value = value;
    var total_value: u64 = 0;
    var remaining = coefficient;
    while (remaining != 0) : (remaining >>= 1) {
        if (remaining & 1 != 0) {
            result = try sum(ctx, &.{ result, part }, &.{ total_value, part_value });
            total_value = try std.math.add(u64, total_value, part_value);
        }
        if (remaining > 1) {
            part = try sum(ctx, &.{ part, part }, &.{ part_value, part_value });
            part_value = try std.math.mul(u64, part_value, 2);
        }
    }
    return result;
}
pub fn atMost(ctx: *C.Context, left: Word, right: Word, left_value: u32, right_value: u32) !void {
    const slack: u32 = right_value -% left_value;
    const word = try B.wrappers.guessU32(C.Q, ctx, B.wrappers.u32Value(C.Q, slack));
    try addTo(ctx, left, word, right, left_value, slack);
}
pub fn nonzero(ctx: *C.Context, word: Word, value: u32) !C.Var {
    const base = try canonical(ctx, word);
    const bit = try ctx.guess(if (ctx.trace_only or value == 0) C.Q.zero() else C.Q.one());
    const inverse = try ctx.guess(if (ctx.trace_only or value == 0) C.Q.zero() else try C.Q.fromU32Unchecked(value, 0, 0, 0).inv());
    try ctx.noteWitnessHint(bit, .is_nonzero, base, ctx.zero());
    try ctx.noteWitnessHint(inverse, .pointwise_inverse_or_zero, base, ctx.zero());
    try ctx.eq(try ctx.mul(bit, bit), bit);
    try ctx.eq(try ctx.mul(base, try ctx.sub(ctx.one(), bit)), ctx.zero());
    try ctx.eq(try ctx.mul(base, inverse), bit);
    return bit;
}
fn bounded(ctx: *C.Context, value: u64, comptime bits: u32) !C.Var {
    const scalar = try ctx.guess(C.Q.fromU32Unchecked(@intCast(value),0,0,0));
    try Bounds.rangeBits(ctx,scalar,bits,Bounds.bitsOf(value,bits));
    return scalar;
}
/// left <= right*c as integers, even when right*c exceeds p. All limb
/// equations stay below p; a 48-bit nonnegative slack forbids subtraction wrap.
pub fn atMostScaled(ctx: *C.Context, left: Word, right: Word, left_value: u32, right_value: u32, comptime coefficient: u13) !void {
    const l = try limbs(ctx,left);
    const r = try limbs(ctx,right);
    const radix = try ctx.constant(C.Q.fromU32Unchecked(65536,0,0,0));
    const factor = try ctx.constant(C.Q.fromU32Unchecked(coefficient,0,0,0));
    const product = @as(u64,right_value)*coefficient;
    const first = @as(u64,right_value & 65535)*coefficient;
    const product_lo = try bounded(ctx,product & 65535,16);
    const product_mid = try bounded(ctx,(product>>16) & 65535,16);
    const product_hi = try bounded(ctx,product>>32,13);
    const product_carry = try bounded(ctx,first>>16,13);
    try ctx.eq(try ctx.mul(r.lo,factor),try ctx.add(product_lo,try ctx.mul(product_carry,radix)));
    try ctx.eq(try ctx.add(try ctx.mul(r.hi,factor),product_carry),try ctx.add(product_mid,try ctx.mul(product_hi,radix)));
    const slack = product -% left_value;
    const slack_lo_value = slack & 65535;
    const slack_mid_value = (slack>>16)&65535;
    const slack_lo = try bounded(ctx,slack_lo_value,16);
    const slack_mid = try bounded(ctx,slack_mid_value,16);
    const slack_hi = try bounded(ctx,(slack>>32)&65535,16);
    const carry0_value = ((left_value & 65535)+slack_lo_value)>>16;
    const carry1_value = ((left_value>>16)+slack_mid_value+carry0_value)>>16;
    const carry0 = try bounded(ctx,carry0_value,1);
    const carry1 = try bounded(ctx,carry1_value,1);
    try ctx.eq(try ctx.add(l.lo,slack_lo),try ctx.add(product_lo,try ctx.mul(carry0,radix)));
    try ctx.eq(try ctx.add(try ctx.add(l.hi,slack_mid),carry0),try ctx.add(product_mid,try ctx.mul(carry1,radix)));
    try ctx.eq(try ctx.add(slack_hi,carry1),product_hi);
}
test "wide scaled counter bound works above p and rejects negative slack" {
    const pairs = [_][2]u32{.{15422,2},.{1<<23,1000000},.{7712,1}};
    for(pairs,0..) |pair,i| {
        var ctx=try C.Context.init(std.testing.allocator,0);defer ctx.deinit();ctx.assert_eq_on_eval=false;
        const left=try B.wrappers.guessU32(C.Q,&ctx,B.wrappers.u32Value(C.Q,pair[0]));
        const right=try B.wrappers.guessU32(C.Q,&ctx,B.wrappers.u32Value(C.Q,pair[1]));
        try atMostScaled(&ctx,left,right,pair[0],pair[1],7711);
        try std.testing.expectEqual(i!=2,try ctx.isCircuitValid());
    }
}
test "typed counter sums reject field wrap and substituted outputs" {
    const a = std.testing.allocator;
    for (0..2) |mutation| {
        var ctx = try C.Context.init(a, 0);
        defer ctx.deinit();
        ctx.assert_eq_on_eval = false;
        const left = try B.wrappers.guessU32(C.Q, &ctx, B.wrappers.u32Value(C.Q, 65535));
        const right = try B.wrappers.guessU32(C.Q, &ctx, B.wrappers.u32Value(C.Q, 9));
        const out = try B.wrappers.guessU32(C.Q, &ctx, B.wrappers.u32Value(C.Q, 65544 + @as(u32, @intCast(mutation))));
        try addTo(&ctx, left, right, out, 65535, 9);
        try atMost(&ctx, right, left, 9, 65535);
        try std.testing.expectEqual(mutation == 0, try ctx.isCircuitValid());
    }
    var ctx = try C.Context.init(a, 0);
    defer ctx.deinit();
    const max = try B.wrappers.guessU32(C.Q, &ctx, B.wrappers.u32Value(C.Q, @intCast(Bounds.P - 1)));
    const one = try B.wrappers.constU32(C.Q, &ctx, 1);
    try std.testing.expectError(error.MassExceedsCharacteristic, sum(&ctx, &.{ max, one }, &.{ Bounds.P - 1, 1 }));
}
