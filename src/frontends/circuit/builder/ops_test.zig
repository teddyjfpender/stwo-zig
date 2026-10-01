//! Tests of the builder operations: `crates/circuits/src/ops_test.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230). `expect!` snapshots are kept
//! verbatim.

const std = @import("std");
const stwo_core = @import("stwo_core");
const context_mod = @import("context.zig");
const ivalue = @import("ivalue.zig");
const ops = @import("ops.zig");
const testing = @import("testing.zig");

const QM31 = stwo_core.fields.qm31.QM31;
const M31 = stwo_core.fields.m31.M31;
const Stats = context_mod.Stats;
const TraceContext = context_mod.Context(QM31);
const gpa = std.testing.allocator;

fn q(a: u32, b: u32, c: u32, d: u32) QM31 {
    return ivalue.qm31FromU32s(a, b, c, d);
}

fn m(value: u32) QM31 {
    return q(value, 0, 0, 0);
}

test "ops: basic ops follow eval! order" {
    const x = q(1, 2, 3, 4);
    const y = q(0, 5, 8, 20);
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    const a = try ctx.newVar(x);
    const b = try ctx.newVar(y);
    // ((a) + (b)) * ((a) - (b))
    const sum = try ctx.add(a, b);
    const difference = try ctx.sub(a, b);
    const c = try ctx.mul(sum, difference);
    try std.testing.expect(ctx.get(c).eql(x.add(y).mul(x.sub(y))));
    const expected = [_]QM31{ m(0), m(1), context_mod.u_value, x, y, x.add(y), x.sub(y), x.add(y).mul(x.sub(y)) };
    for (expected, ctx.values()) |e, actual| try std.testing.expect(e.eql(actual));
    try std.testing.expect(try ctx.isCircuitValid());
}

test "ops: a false eq is caught by the circuit check" {
    const x = q(1, 2, 3, 4);
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    const a = try ctx.newVar(x);
    const b = try ctx.newVar(x.add(x));
    try ctx.eq(a, b);
    try std.testing.expect(!try ctx.isCircuitValid());
    try std.testing.expectEqual(null, try ctx.circuit.check(gpa, &.{ m(0), m(1), context_mod.u_value, x, x }));
}

test "ops: eval! with literals" {
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    const a = try ctx.newVar(m(10));
    // (((a) * (20)) - ((2) * (3))) - (10)
    const a20 = try ctx.mul(a, try ctx.constant(m(20)));
    const two = try ctx.constant(m(2));
    const six = try ctx.mul(two, try ctx.constant(m(3)));
    const partial = try ctx.sub(a20, six);
    const res = try ctx.sub(partial, try ctx.constant(m(10)));
    try std.testing.expect(ctx.get(res).eql(m(184)));
}

test "ops: eval! negation" {
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    const a = try ctx.newVar(m(10));
    // (-(a)) + (13)
    const negated = try ops.neg(QM31, &ctx, a);
    const res = try ctx.add(negated, try ctx.constant(m(13)));
    try std.testing.expect(ctx.get(res).eql(m(3)));
}

test "ops: inv" {
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    const x = try ctx.guess(m(10));
    const y = try ctx.guess(m(2));
    const y_inv = try ctx.inv(y);
    const res = try ctx.mul(x, y_inv);
    try std.testing.expect(ctx.get(res).eql(m(5)));
    try testing.expectCircuit(&ctx.circuit,
        \\[6] = [4] * [5]
        \\[7] = [3] * [5]
        \\[6] = [1]
        \\output [2]
        \\
    );
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
    try std.testing.expectEqual(null, try ctx.circuit.firstYieldViolation(gpa));
}

test "ops: div" {
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    const a = try ctx.guess(m(12));
    const b = try ctx.guess(m(4));
    const quotient = try ctx.div(a, b);
    try std.testing.expect(ctx.get(quotient).eql(m(3)));
    try testing.expectCircuit(&ctx.circuit,
        \\[6] = [5] * [4]
        \\[6] = [3]
        \\output [2]
        \\
    );
    try std.testing.expectEqual(@as(usize, 1), ctx.stats.div);
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}

test "ops: pointwise_mul" {
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    const x = try ctx.guess(q(1, 2, 3, 4));
    const y = try ctx.guess(q(5, 6, 7, 8));
    const res = try ctx.pointwiseMul(x, y);
    try std.testing.expect(ctx.get(res).eql(q(5, 12, 21, 32)));
    try std.testing.expect(try ctx.isCircuitValid());
}

test "ops: cond_flip" {
    for ([_][3]u32{ .{ 0, 10, 20 }, .{ 1, 20, 10 } }) |case| {
        var ctx = try TraceContext.init(gpa, 0);
        defer ctx.deinit();
        const selector = try ctx.guess(m(case[0]));
        const a = try ctx.guess(m(10));
        const b = try ctx.guess(m(20));
        const res = try ops.condFlip(QM31, &ctx, selector, a, b);
        try std.testing.expect(ctx.get(res[0]).eql(m(case[1])));
        try std.testing.expect(ctx.get(res[1]).eql(m(case[2])));
        try std.testing.expect(try ctx.isCircuitValid());
    }
}

test "ops: cond_flip_u32" {
    const wrappers = @import("wrappers.zig");
    for ([_]u32{ 0, 1 }) |selector_value| {
        var ctx = try TraceContext.init(gpa, 0);
        defer ctx.deinit();
        const selector = try ctx.guess(m(selector_value));
        const a = try wrappers.guessU32(QM31, &ctx, wrappers.u32Value(QM31, 0xDEAD_BEEF));
        const b = try wrappers.guessU32(QM31, &ctx, wrappers.u32Value(QM31, 0x0123_4567));
        const res = try ops.condFlipU32(QM31, &ctx, selector, a, b);
        const first: u32 = if (selector_value == 0) 0xDEAD_BEEF else 0x0123_4567;
        const second: u32 = if (selector_value == 0) 0x0123_4567 else 0xDEAD_BEEF;
        try std.testing.expectEqual(first, ivalue.unpackU32(QM31, ctx.get(res[0].get())));
        try std.testing.expectEqual(second, ivalue.unpackU32(QM31, ctx.get(res[1].get())));
        try std.testing.expect(try ctx.isCircuitValid());
    }
}

test "ops: conj" {
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    const a = try ctx.guess(q(1, 2, 3, 4));
    const b = try ops.conj(QM31, &ctx, a);
    try std.testing.expect(ctx.get(b).eql(q(1, 2, M31.fromCanonical(3).neg().v, M31.fromCanonical(4).neg().v)));
    // Multiplying by the conjugate lands in CM31.
    const c = try ctx.mul(a, b);
    try std.testing.expect(ctx.get(c).c1.isZero());
    try testing.expectFormat("[5]", b);
    try testing.expectFormat("[6]", c);
    try testing.expectConstants(QM31, &ctx,
        \\{
        \\    (0 + 0i) + (0 + 0i)u: [0],
        \\    (1 + 0i) + (0 + 0i)u: [1],
        \\    (0 + 0i) + (1 + 0i)u: [2],
        \\    (1 + 1i) + (2147483646 + 2147483646i)u: [4],
        \\}
    );
    try testing.expectCircuit(&ctx.circuit,
        \\[6] = [3] * [5]
        \\[5] = [3] x [4]
        \\output [2]
        \\
    );
    try std.testing.expect(try ctx.isCircuitValid());
}

test "ops: im" {
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    const a = try ctx.guess(q(1, 2, 3, 4));
    const b = try ops.im(QM31, &ctx, a);
    try std.testing.expect(ctx.get(b).eql(q(0, 0, 3, 4)));
    try testing.expectFormat("[5]", b);
    try testing.expectConstants(QM31, &ctx,
        \\{
        \\    (0 + 0i) + (0 + 0i)u: [0],
        \\    (1 + 0i) + (0 + 0i)u: [1],
        \\    (0 + 0i) + (1 + 0i)u: [2],
        \\    (0 + 0i) + (1 + 1i)u: [4],
        \\}
    );
    try testing.expectCircuit(&ctx.circuit,
        \\[5] = [3] x [4]
        \\output [2]
        \\
    );
    try std.testing.expect(try ctx.isCircuitValid());
}

test "ops: from_partial_evals" {
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    const evals = [4]context_mod.Var{
        try ctx.guess(q(1, 10, 100, 1000)),
        try ctx.guess(m(2)),
        try ctx.guess(m(3)),
        try ctx.guess(m(4)),
    };
    const res = try ops.fromPartialEvals(QM31, &ctx, evals);
    try std.testing.expect(ctx.get(res).eql(q(1, 12, 103, 1004)));
    try std.testing.expect(try ctx.isCircuitValid());
}

test "ops: stats" {
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    // A fresh context marks `u` as an output.
    var stats: Stats = .{ .outputs = 1 };
    try std.testing.expectEqual(stats, ctx.stats);

    const x = try ctx.guess(m(5));
    const y = try ctx.constant(m(25));
    const x_sqr = try ctx.mul(x, x);
    stats.mul = 1;
    stats.guess = 1;
    try std.testing.expectEqual(stats, ctx.stats);

    const x_sqr_minus_y = try ctx.sub(x_sqr, y);
    stats.sub = 1;
    try std.testing.expectEqual(stats, ctx.stats);

    try ctx.eq(x_sqr_minus_y, ctx.zero());
    stats.equals = 1;
    try std.testing.expectEqual(stats, ctx.stats);

    // `(0) + (0)` is elided by the add-zero peephole.
    _ = try ctx.add(try ctx.constant(m(0)), try ctx.constant(m(0)));
    try std.testing.expectEqual(stats, ctx.stats);

    // `(1) + (1)` creates a gate.
    _ = try ctx.add(try ctx.constant(m(1)), try ctx.constant(m(1)));
    stats.add = 1;
    try std.testing.expectEqual(stats, ctx.stats);

    const y_inv = try ctx.inv(y);
    _ = try ctx.mul(x, y_inv);
    stats.inv = 1;
    stats.mul += 2;
    stats.guess += 1;
    stats.equals += 1;
    try std.testing.expectEqual(stats, ctx.stats);

    _ = try ctx.pointwiseMul(x, y);
    stats.pointwise_mul = 1;
    try std.testing.expectEqual(stats, ctx.stats);
    try std.testing.expect(try ctx.isCircuitValid());
}

test "ops: index-only peepholes add no gate" {
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    const zero = ctx.zero();
    const one = ctx.one();
    const x = try ctx.guess(m(42));
    const expected: Stats = .{ .outputs = 1, .guess = 1 };
    try std.testing.expectEqual(expected, ctx.stats);

    try std.testing.expectEqual(x, try ctx.add(zero, x));
    try std.testing.expectEqual(x, try ctx.add(x, zero));
    try std.testing.expectEqual(zero, try ctx.add(zero, zero));
    try std.testing.expectEqual(zero, try ctx.mul(zero, x));
    try std.testing.expectEqual(zero, try ctx.mul(x, zero));
    try std.testing.expectEqual(zero, try ctx.mul(zero, zero));
    try std.testing.expectEqual(x, try ctx.mul(one, x));
    try std.testing.expectEqual(x, try ctx.mul(x, one));
    try std.testing.expectEqual(one, try ctx.mul(one, one));
    try std.testing.expectEqual(expected, ctx.stats);

    // A different variable holding 0 or 1 is not elided: no value folding.
    const other_zero = try ctx.guess(m(0));
    _ = try ctx.add(x, other_zero);
    try std.testing.expectEqual(@as(usize, 1), ctx.circuit.add.items.len);
    // `sub` and `pointwise_mul` never elide.
    _ = try ctx.sub(x, zero);
    _ = try ctx.pointwiseMul(x, one);
    try std.testing.expectEqual(@as(usize, 1), ctx.circuit.sub.items.len);
    try std.testing.expectEqual(@as(usize, 1), ctx.circuit.pointwise_mul.items.len);
    try std.testing.expect(try ctx.isCircuitValid());
}

test "ops: permute sorts by the u coordinate and records the gate" {
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    var inputs: [3]context_mod.Var = undefined;
    for (&inputs, [_]u32{ 9, 3, 7 }) |*v, u_coord| v.* = try ctx.guess(q(u_coord, 0, u_coord, 0));
    const outputs = try ctx.permute(&inputs, ivalue.sortByUCoordinate(QM31));
    try testing.expectVars("[[6], [7], [8]]", outputs);
    for (outputs, [_]u32{ 3, 7, 9 }) |v, a| try std.testing.expectEqual(a, ctx.get(v).c0.a.v);
    try testing.expectCircuit(&ctx.circuit,
        \\([6, 7, 8]) = ([3, 4, 5])
        \\output [2]
        \\
    );
    try std.testing.expectEqual(@as(usize, 3), ctx.stats.permutation_inputs);
    // One QM31Ops row per permutation input and output.
    try std.testing.expectEqual(@as(usize, 6), ctx.circuit.nQm31OpsRows());
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
    try std.testing.expectEqual(null, try ctx.circuit.firstYieldViolation(gpa));
}
