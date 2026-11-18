//! Native degree-eight DEEP algebra. Conjugation is over QM31 (the outer
//! quadratic tower), not the legacy QM31-over-CM31 conjugation.
const circuit = @import("stwo_circuit_frontend");
const C = @import("common.zig");
const Shape = @import("shape.zig");
const F = C.F;
const Q = C.Q;
const Inner = C.Inner;
const Base = circuit.builder.wrappers.M31Wrapper(C.Var);
const Simd = circuit.builder.simd;
const BasePoints = circuit.stark_verifier.circle.Point(Simd.Simd);
const Batch = struct { imaginary: F, intercept: F, point: C.Point, weights: []const F, columns: []const [2]usize };

// Bound addition depth by ceil(log2(n)). The input holds temporary terms.
fn sum(terms: []F) F {
    var active = terms;
    while (active.len > 1) {
        const pairs = active.len / 2;
        for (0..pairs) |i| active[i] = active[2 * i].add(active[2 * i + 1]);
        if (active.len % 2 != 0) active[pairs] = active[active.len - 1];
        active = active[0 .. pairs + active.len % 2];
    }
    return if (active.len == 0) F.zero() else active[0];
}

pub fn friInput(ctx: *C.Context, plan: *const Shape.SamplePlan, oods: C.Point, sampled: []const []const []const F, alpha: F, points: BasePoints, queried: []const []const []const Base) ![]const F {
    const a = ctx.scratch();
    const powers = try a.alloc(F, plan.n_samples);
    for (powers, 0..) |*power, i| power.* = switch (i) {
        0 => F.one(),
        1 => alpha,
        else => if (i % 2 == 0) powers[i / 2].square() else powers[i / 2].mul(powers[i / 2 + 1]),
    };
    var max_terms: usize = 0;
    for (plan.batches) |batch| max_terms = @max(max_terms, batch.entries.len);
    const real_terms = try a.alloc(F, max_terms);
    const imag_terms = try a.alloc(F, max_terms);
    const batches = try a.alloc(Batch, plan.batches.len);
    for (batches, plan.batches) |*out, batch| {
        const point = if (batch.isOods()) oods else C.addPoint(oods, batch.shiftPoint());
        // Native DegenerateLine: every point has a nonzero imaginary Y.
        // Keep the inverse equation even when its hint is zero.
        const inv_y = point.y.c1.inv();
        try ctx.eq(try ctx.mul(point.y.c1.v, inv_y.v), ctx.one());
        // Over the quadratic tower, factor -2u out of every conjugate line.
        // Weights can be non-real, so project the sample halves before they
        // are multiplied by the shared imaginary and real coordinates of y.
        const re = real_terms[0..batch.entries.len];
        const im = imag_terms[0..batch.entries.len];
        const weights = try a.alloc(F, batch.entries.len);
        const columns = try a.alloc([2]usize, batch.entries.len);
        for (batch.entries, weights, columns, re, im) |entry, *weight, *column, *r, *j| {
            if (entry.tree >= sampled.len or entry.column >= sampled[entry.tree].len or
                entry.sample >= sampled[entry.tree][entry.column].len or entry.power >= powers.len) return error.ShapeMismatch;
            const value = sampled[entry.tree][entry.column][entry.sample];
            const power = powers[entry.power];
            r.* = power.mulInner(value.c0);
            j.* = power.mulInner(value.c1);
            weight.* = power;
            column.* = .{ entry.tree, entry.column };
        }
        const imaginary = sum(im);
        out.* = .{ .imaginary = imaginary, .intercept = imaginary.mulInner(point.y.c0).sub(sum(re).mulInner(point.y.c1)), .point = point, .weights = weights, .columns = columns };
    }
    const output = try a.alloc(F, points.x.len);
    for (output, 0..) |*out, query| {
        const x = Inner.wire(try Simd.unpackIdx(Q, ctx, points.x, query));
        const y = Inner.wire(try Simd.unpackIdx(Q, ctx, points.y, query));
        var answer = F.zero();
        for (batches) |batch| {
            const terms = real_terms[0..batch.weights.len];
            for (batch.weights, batch.columns, terms) |weight, col, *term| {
                if (col[0] >= queried.len or col[1] >= queried[col[0]].len or query >= queried[col[0]][col[1]].len) return error.ShapeMismatch;
                term.* = weight.mulInner(Inner.wire(queried[col[0]][col[1]][query].get()));
            }
            const p = batch.point;
            const numerator = sum(terms).mulInner(p.y.c1).add(batch.intercept).sub(batch.imaginary.mulInner(y));
            const denominator = p.x.c0.sub(x).mul(p.y.c1).sub(p.y.c0.sub(y).mul(p.x.c1));
            answer = answer.add(numerator.mulInner(denominator.inv()));
        }
        const minus_two_u = C.O{ .c0 = Q.zero(), .c1 = Q.one().add(Q.one()).neg() };
        out.* = answer.mul(F.fromOm31(minus_two_u));
    }
    try C.lane.check();
    return output;
}

test "recursive native DEEP matches independently weighted odd and empty sample batches" {
    const std = @import("std");
    const core = @import("stwo_core");
    const M = core.fields.m31.M31;
    const O = C.O;
    var channel = core.channel.raw_mod_m31.Om31Channel.init();
    const z = try core.circle.randomSecureFieldPointFor(O, &channel);
    const alpha = channel.drawSecureFelt();
    const w = core.circle.M31_CIRCLE_GEN;
    for ([_]usize{ 0, 1, 13, 32, 37, 13 }, 0..) |n, case| {
        var ctx = try C.Context.init(std.testing.allocator, 0);
        defer ctx.deinit();
        C.lane.begin(&ctx);
        defer C.lane.finish() catch unreachable;
        const a = ctx.scratch();
        const refs = try a.alloc(Shape.SampleRef, n);
        const sampled = try a.alloc([]const F, n);
        const opened = try a.alloc([]const Base, n);
        var expected = O.zero();
        for (refs, sampled, opened, 0..) |*ref, *s, *v, i| {
            const claim = channel.drawSecureFelt();
            const base = M.fromU64(i * 739 + 17);
            ref.* = .{ .tree = 0, .column = i, .sample = 0, .flat_column = i, .power = n - i - 1 };
            const sample = try a.alloc(F, 1);
            sample[0] = try F.guess(&ctx, claim);
            s.* = sample;
            const word = try a.alloc(Base, 1);
            word[0] = Base.newUnsafe(try ctx.guessM31(Q.fromBase(base)));
            v.* = word;
            const line = try core.constraints.quadraticConjugateLineCoeffs(O, z, claim, alpha.pow(@intCast(ref.power)));
            const d = core.constraints.quadraticLineDenominator(O, z, w);
            expected = expected.add(line.c.mulM31(base).sub(line.a.mulM31(w.y)).sub(line.b).mulInner(try d.inv()));
        }
        const plan = Shape.SamplePlan{ .batches = &.{.{ .entries = refs, .shift = .{ .v = 0 } }}, .n_samples = n };
        const got = try friInput(&ctx, &plan, .{ .x = try F.guess(&ctx, z.x), .y = try F.guess(&ctx, z.y) }, &.{sampled}, try F.guess(&ctx, alpha), .{ .x = try Simd.repeat(Q, &ctx, w.x, 1), .y = try Simd.repeat(Q, &ctx, w.y, 1) }, &.{opened});
        try std.testing.expectEqual(expected, got[0].value());
        const corrupt = case == 5;
        try C.eq(&ctx, got[0], try F.guess(&ctx, if (corrupt) expected.add(O.one()) else expected));
        // The original 37-column, single-query circuit emitted 2,461 operations.
        if (n == 37) try std.testing.expect(ctx.gate_counts.qm31_ops <= 750);
        try ctx.finalize(false);
        try std.testing.expectEqual(!corrupt, try ctx.isCircuitValid());
    }
}
