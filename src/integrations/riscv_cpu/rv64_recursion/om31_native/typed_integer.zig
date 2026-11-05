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
