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
const Batch = struct { a: F, b: F, point: C.Point, weights: []const F, columns: []const [2]usize };

pub fn friInput(ctx: *C.Context, plan: *const Shape.SamplePlan, oods: C.Point, sampled: []const []const []const F, alpha: F, points: BasePoints, queried: []const []const []const Base) ![]const F {
    const a = ctx.scratch();
    const powers = try a.alloc(F, plan.n_samples);
    if (powers.len != 0) {
        powers[0] = F.one();
        for (powers[1..], 0..) |*power, i| power.* = powers[i].mul(alpha);
    }
    const batches = try a.alloc(Batch, plan.batches.len);
    for (batches, plan.batches) |*out, batch| {
        const point = if (batch.isOods()) oods else C.addPoint(oods, batch.shiftPoint());
        // Native DegenerateLine: every point has a nonzero imaginary Y.
        // Keep the inverse equation even when its hint is zero.
        const inv_y = point.y.c1.inv();
        try ctx.eq(try ctx.mul(point.y.c1.v, inv_y.v), ctx.one());
        const c = point.y.quadraticConjugate().sub(point.y);
        var sum_a = F.zero();
        var sum_b = F.zero();
        const weights = try a.alloc(F, batch.entries.len);
        const columns = try a.alloc([2]usize, batch.entries.len);
        for (batch.entries, weights, columns) |entry, *weight, *column| {
            if (entry.tree >= sampled.len or entry.column >= sampled[entry.tree].len or
                entry.sample >= sampled[entry.tree][entry.column].len or entry.power >= powers.len) return error.ShapeMismatch;
            const value = sampled[entry.tree][entry.column][entry.sample];
            const power = powers[entry.power];
            const av = value.quadraticConjugate().sub(value);
            const bv = value.mul(c).sub(av.mul(point.y));
            sum_a = sum_a.add(power.mul(av));
            sum_b = sum_b.add(power.mul(bv));
            weight.* = power.mul(c);
            column.* = .{ entry.tree, entry.column };
        }
        out.* = .{ .a = sum_a, .b = sum_b, .point = point, .weights = weights, .columns = columns };
    }
    const output = try a.alloc(F, points.x.len);
    for (output, 0..) |*out, query| {
        const x = Inner.wire(try Simd.unpackIdx(Q, ctx, points.x, query));
        const y = Inner.wire(try Simd.unpackIdx(Q, ctx, points.y, query));
        var answer = F.zero();
        for (batches) |batch| {
            var numerator = F.zero();
            for (batch.weights, batch.columns) |weight, col| {
                if (col[0] >= queried.len or col[1] >= queried[col[0]].len or query >= queried[col[0]][col[1]].len) return error.ShapeMismatch;
                numerator = numerator.add(weight.mulInner(Inner.wire(queried[col[0]][col[1]][query].get())));
            }
            numerator = numerator.sub(batch.a.mulInner(y).add(batch.b));
            const p = batch.point;
            const denominator = p.x.c0.sub(x).mul(p.y.c1).sub(p.y.c0.sub(y).mul(p.x.c1));
            answer = answer.add(numerator.mulInner(denominator.inv()));
        }
        out.* = answer;
    }
    try C.lane.check();
    return output;
}
