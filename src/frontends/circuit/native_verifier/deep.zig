//! The DEEP quotient at every query: port of `friAnswers` in
//! `core/pcs/quotients/fri_answers.zig` with the line coefficients and row
//! law of `core/pcs/quotients/row_evaluation.zig` and the sample batches of
//! `core/pcs/quotients/samples.zig` (precomputed in `shape.zig`).
//!
//! Natively, for sample batch `b` at point `P = (Px, Py)` (QM31) with
//! samples `(column_i, v_i, alpha^k_i)` and the query's M31 domain point
//! `(x, y)`:
//! - `complexConjugateLineCoeffs`: `a_i = alpha^k (conj(v_i) - v_i)`,
//!   `c_i = alpha^k (conj(Py) - Py)`, `b_i = alpha^k (v_i c - a Py)` (with the
//!   unscaled `a`, `c`); `sum_a = sum a_i`, `sum_b = sum b_i`;
//! - the batch numerator is `sum_i c_i column_i(x, y) - (sum_a y + sum_b)`;
//! - the denominator is the CM31 `(prx - x) piy - (pry - y) pix`, where
//!   `Px = prx + pix u` and `Py = pry + piy u`, and the row answer is
//!   `sum_b numerator_b / denominator_b`.
//!
//! In QM31 wires the denominator is computed as `D = (re(Px) - x) im(Py) -
//! (re(Py) - y) im(Px)`, which equals `denominator * u` (`im(z) = z's u part
//! times u`), so the row answer is `u * sum_b numerator_b / D_b`; `det = re(Px)
//! im(Py) - re(Py) im(Px)` is a per-batch constant and `D = det - im(Py) x +
//! im(Px) y`, as `denominatorValue`. The division proves `D != 0`, which also
//! covers the native `DegenerateLine` rejection of a batch point over CM31.
//! Random coefficient powers are assigned in the native sample order
//! (`SamplePlan`): `alpha^0` is the constant one.

const std = @import("std");
const core = @import("stwo_core");
const builder = @import("../builder/mod.zig");
const sv_circle = @import("../stark_verifier/circle.zig");
const shape_mod = @import("shape.zig");

const QM31 = core.fields.qm31.QM31;
const Var = builder.Var;
const Context = builder.Context;
const Error = builder.context.Error;
const ops = builder.ops;
const simd = builder.simd;
const Simd = simd.Simd;
const M31Wrapper = builder.wrappers.M31Wrapper;
const Point = sv_circle.Point;
const SamplePlan = shape_mod.SamplePlan;

pub const DeepError = Error || error{ShapeMismatch};

/// `re(z)`: the CM31 part of `z` (the `u` coordinates zeroed).
pub fn re(comptime V: type, ctx: *Context(V), z: Var) Error!Var {
    const mask = try ctx.constant(QM31.fromU32Unchecked(1, 1, 0, 0));
    return ctx.pointwiseMul(z, mask);
}

/// `oods + shift` for a constant M31 point `shift`: `(ox cx - oy cy, ox cy + oy cx)`.
pub fn addConstantPoint(comptime V: type, ctx: *Context(V), oods: Point(Var), shift: core.circle.CirclePointM31) Error!Point(Var) {
    const cx = try ctx.constant(QM31.fromBase(shift.x));
    const cy = try ctx.constant(QM31.fromBase(shift.y));
    const x = try ctx.sub(try ctx.mul(oods.x, cx), try ctx.mul(oods.y, cy));
    const y = try ctx.add(try ctx.mul(oods.x, cy), try ctx.mul(oods.y, cx));
    return .{ .x = x, .y = y };
}

/// The query-independent constants of one batch.
const BatchConstants = struct {
    sum_a: Var,
    sum_b: Var,
    det: Var,
    im_x: Var,
    im_y: Var,
    /// `c_i` and the sampled column of every entry.
    coefficients: []const Var,
    columns: []const [2]usize,
};

/// `alpha^0 .. alpha^(n - 1)`: the constant one, then repeated products
/// (`nextRandomPow` in `samples.zig` hands out `random_pow` then multiplies).
fn randomPowers(comptime V: type, ctx: *Context(V), alpha: Var, n: usize) Error![]Var {
    const powers = try ctx.scratch().alloc(Var, n);
    if (n == 0) return powers;
    powers[0] = ctx.one();
    for (powers[1..], 0..) |*power, i| power.* = try ctx.mul(powers[i], alpha);
    return powers;
}

fn batchConstants(
    comptime V: type,
    ctx: *Context(V),
    batch: shape_mod.Batch,
    oods: Point(Var),
    sampled_values: []const []const []const Var,
    powers: []const Var,
) Error!BatchConstants {
    const scratch = ctx.scratch();
    const point = if (batch.isOods()) oods else try addConstantPoint(V, ctx, oods, batch.shiftPoint());
    // `c = conj(Py) - Py`, shared by the batch's samples.
    const c_raw = try ctx.sub(try ops.conj(V, ctx, point.y), point.y);
    var sum_a = ctx.zero();
    var sum_b = ctx.zero();
    const coefficients = try scratch.alloc(Var, batch.entries.len);
    const columns = try scratch.alloc([2]usize, batch.entries.len);
    for (batch.entries, coefficients, columns) |entry, *coefficient, *column| {
        const value = sampled_values[entry.tree][entry.column][entry.sample];
        const power = powers[entry.power];
        const a_raw = try ctx.sub(try ops.conj(V, ctx, value), value);
        const b_raw = try ctx.sub(try ctx.mul(value, c_raw), try ctx.mul(a_raw, point.y));
        sum_a = try ctx.add(sum_a, try ctx.mul(power, a_raw));
        sum_b = try ctx.add(sum_b, try ctx.mul(power, b_raw));
        coefficient.* = try ctx.mul(power, c_raw);
        column.* = .{ entry.tree, entry.column };
    }
    const re_x = try re(V, ctx, point.x);
    const re_y = try re(V, ctx, point.y);
    const im_x = try ops.im(V, ctx, point.x);
    const im_y = try ops.im(V, ctx, point.y);
    const det = try ctx.sub(try ctx.mul(re_x, im_y), try ctx.mul(re_y, im_x));
    return .{ .sum_a = sum_a, .sum_b = sum_b, .det = det, .im_x = im_x, .im_y = im_y, .coefficients = coefficients, .columns = columns };
}

/// `friAnswers`: the DEEP quotient of every query (scratch-owned).
/// `sampled_values[t][c][s]` and `queried_values[t][c][q]` are the proof's;
/// `points` are the queries' lifting-domain points.
pub fn friInput(
    comptime V: type,
    ctx: *Context(V),
    plan: *const SamplePlan,
    oods: Point(Var),
    sampled_values: []const []const []const Var,
    deep_randomness: Var,
    points: Point(Simd),
    queried_values: []const []const []const M31Wrapper(Var),
) DeepError![]const Var {
    const scratch = ctx.scratch();
    const n_queries = points.x.len;
    const powers = try randomPowers(V, ctx, deep_randomness, plan.n_samples);
    const batches = try scratch.alloc(BatchConstants, plan.batches.len);
    for (batches, plan.batches) |*constants, batch| {
        for (batch.entries) |entry| {
            if (entry.tree >= queried_values.len or entry.column >= queried_values[entry.tree].len) return error.ShapeMismatch;
            if (queried_values[entry.tree][entry.column].len != n_queries) return error.ShapeMismatch;
        }
        constants.* = try batchConstants(V, ctx, batch, oods, sampled_values, powers);
    }

    const u = ctx.u();
    const out = try scratch.alloc(Var, n_queries);
    for (out, 0..) |*answer, q| {
        const x = try simd.unpackIdx(V, ctx, points.x, q);
        const y = try simd.unpackIdx(V, ctx, points.y, q);
        var accumulator = ctx.zero();
        for (batches) |batch| {
            const numerator = try batchNumerator(V, ctx, batch, queried_values, q, y);
            const denominator = try batchDenominator(V, ctx, batch, x, y);
            const quotient = try ctx.div(numerator, denominator);
            accumulator = try ctx.add(accumulator, quotient);
        }
        answer.* = try ctx.mul(accumulator, u);
    }
    return out;
}

/// `sum_i c_i column_i(q) - (sum_a y + sum_b)`: the batch numerator at
/// query `q` (`accumulateRowQuotients` plus `finalizeRowQuotients`).
fn batchNumerator(
    comptime V: type,
    ctx: *Context(V),
    batch: BatchConstants,
    queried_values: []const []const []const M31Wrapper(Var),
    q: usize,
    y: Var,
) Error!Var {
    var numerator = ctx.zero();
    for (batch.coefficients, batch.columns) |coefficient, column| {
        const value = queried_values[column[0]][column[1]][q].get();
        numerator = try ctx.add(numerator, try ctx.mul(coefficient, value));
    }
    const linear = try ctx.add(try ctx.mul(batch.sum_a, y), batch.sum_b);
    return ctx.sub(numerator, linear);
}

/// `det - im(Py) x + im(Px) y`: the native denominator times `u`
/// (`denominatorValue`).
fn batchDenominator(comptime V: type, ctx: *Context(V), batch: BatchConstants, x: Var, y: Var) Error!Var {
    const shifted = try ctx.sub(batch.det, try ctx.mul(batch.im_y, x));
    return ctx.add(shifted, try ctx.mul(batch.im_x, y));
}

test {
    _ = @import("deep_test.zig");
}

const M31 = core.fields.m31.M31;
const CM31 = core.fields.cm31.CM31;

test "deep: batch constants follow complexConjugateLineCoeffs and the denominator law" {
    const CirclePointM31 = core.circle.CirclePointM31;
    var ctx = try Context(QM31).init(std.testing.allocator, 0);
    defer ctx.deinit();
    const oods = core.circle.SECURE_FIELD_CIRCLE_GEN.mul(424_242);
    const alpha = QM31.fromU32Unchecked(3, 1, 4, 1);
    const values = [_]QM31{ QM31.fromU32Unchecked(5, 9, 2, 6), QM31.fromU32Unchecked(53, 58, 97, 93) };
    // One batch at `oods - step(5)` holding two samples with powers 1 and 2.
    const shift = core.circle.CirclePointIndex.subgroupGen(5).neg();
    const entries = [_]shape_mod.SampleRef{
        .{ .tree = 1, .column = 0, .sample = 0, .flat_column = 0, .power = 1 },
        .{ .tree = 1, .column = 1, .sample = 0, .flat_column = 1, .power = 2 },
    };
    const batch = shape_mod.Batch{ .shift = shift, .entries = &entries };
    const oods_wires: Point(Var) = .{ .x = try ctx.guess(oods.x), .y = try ctx.guess(oods.y) };
    const column_0 = [_]Var{try ctx.guess(values[0])};
    const column_1 = [_]Var{try ctx.guess(values[1])};
    const main = [_][]const Var{ &column_0, &column_1 };
    const sampled = [_][]const []const Var{ &.{}, &main };
    const powers = try randomPowers(QM31, &ctx, try ctx.guess(alpha), 3);
    const constants = try batchConstants(QM31, &ctx, batch, oods_wires, &sampled, powers);

    const shift_point: CirclePointM31 = shift.toPoint();
    const point = oods.add(.{ .x = QM31.fromBase(shift_point.x), .y = QM31.fromBase(shift_point.y) });
    var sum_a = QM31.zero();
    var sum_b = QM31.zero();
    for (values, 1..) |value, power| {
        const coeffs = try core.constraints.complexConjugateLineCoeffs(point, value, alpha.pow(@intCast(power)));
        sum_a = sum_a.add(coeffs.a);
        sum_b = sum_b.add(coeffs.b);
        try std.testing.expect(ctx.get(constants.coefficients[power - 1]).eql(coeffs.c));
    }
    try std.testing.expect(ctx.get(constants.sum_a).eql(sum_a));
    try std.testing.expect(ctx.get(constants.sum_b).eql(sum_b));

    // `D = det - im(Py) x + im(Px) y` is the native CM31 denominator times `u`.
    const domain_point = core.poly.circle.canonic.CanonicCoset.new(6).circleDomain().at(13);
    const x = try ctx.guess(QM31.fromBase(domain_point.x));
    const y = try ctx.guess(QM31.fromBase(domain_point.y));
    const d = try batchDenominator(QM31, &ctx, constants, x, y);
    const prx = point.x.c0;
    const pix = point.x.c1;
    const pry = point.y.c0;
    const piy = point.y.c1;
    const native = prx.sub(CM31.fromBase(domain_point.x)).mul(piy).sub(pry.sub(CM31.fromBase(domain_point.y)).mul(pix));
    const expected = (QM31{ .c0 = native, .c1 = CM31.zero() }).mul(builder.context.u_value);
    try std.testing.expect(ctx.get(d).eql(expected));
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}

test "deep: random powers start at the constant one" {
    var ctx = try Context(QM31).init(std.testing.allocator, 0);
    defer ctx.deinit();
    const alpha = QM31.fromU32Unchecked(7, 0, 0, 1);
    const powers = try randomPowers(QM31, &ctx, try ctx.guess(alpha), 4);
    try std.testing.expectEqual(ctx.one().idx, powers[0].idx);
    try std.testing.expect(ctx.get(powers[3]).eql(alpha.pow(3)));
    _ = M31.one();
}
