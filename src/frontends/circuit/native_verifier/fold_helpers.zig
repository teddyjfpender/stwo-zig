//! FRI folding helpers of the native verifier: verbatim copies of the
//! private helpers of `stark_verifier/fri.zig` (fold a coset, the twiddles of
//! the circle-to-line and line-to-line folds, translation to the coset base
//! point, the query-position check). They are duplicated on purpose: the
//! StarkWare-parity verifier keeps its helpers private and byte-pinned, and
//! nothing the native lane changes may move them.

const std = @import("std");
const core = @import("stwo_core");
const builder = @import("../builder/mod.zig");
const circle = @import("../stark_verifier/circle.zig");
const merkle = @import("../stark_verifier/merkle.zig");
const select_queries = @import("../stark_verifier/select_queries.zig");

const QM31 = core.fields.qm31.QM31;
const Var = builder.Var;
const Context = builder.Context;
const Error = builder.context.Error;
const simd = builder.simd;
const Simd = simd.Simd;
const Point = circle.Point;

/// `split_off(..n)` on a slice: returns the first `n` items and advances.
pub fn splitOff(comptime T: type, items: *[]const T, n: usize) []const T {
    std.debug.assert(items.len >= n);
    const head = items.*[0..n];
    items.* = items.*[n..];
    return head;
}

/// `fold_coset`: folds `2^n` coset values to one with `n` folds, fold `i`
/// using `twiddles_per_fold[i]` (length `2^(n-1-i)`) and `alphas[i]`.
pub fn foldCoset(comptime V: type, ctx: *Context(V), coset_values: []const Var, twiddles_per_fold: []const []Var, alphas: []const Var) Error!Var {
    std.debug.assert(coset_values.len == @as(usize, 1) << @intCast(twiddles_per_fold.len));
    std.debug.assert(alphas.len == twiddles_per_fold.len);
    const values = try ctx.scratch().dupe(Var, coset_values);
    for (alphas, twiddles_per_fold) |alpha, twiddles| {
        for (twiddles, 0..) |twiddle, j| {
            const even = values[2 * j];
            const odd = values[2 * j + 1];
            const g = try ctx.add(even, odd);
            const h = try ctx.mul(try ctx.sub(even, odd), twiddle);
            values[j] = try ctx.add(g, try ctx.mul(alpha, h));
        }
    }
    return values[0];
}

/// `validate_query_position_in_coset`: each query value equals the coset
/// value its low `step` bits select.
pub fn validateQueryPositionInCoset(
    comptime V: type,
    ctx: *Context(V),
    witness: []const Var,
    coset_size: usize,
    layer_values: []const Var,
    bits: []const []const Var,
) Error!void {
    const query_bits = try ctx.scratch().alloc(Var, bits.len);
    for (layer_values, 0..) |query_value, query_idx| {
        for (query_bits, bits) |*bit, bit_column| bit.* = bit_column[query_idx];
        const coset = witness[query_idx * coset_size ..][0..coset_size];
        const expected = try builder.select.selectByIndex(V, ctx, coset, query_bits);
        try ctx.eq(query_value, expected);
    }
}

/// `circle_compute_twiddles_from_base_point`: the y twiddles of the
/// circle-to-line fold, then the x twiddles of the line folds. The result is
/// `[fold][twiddle]`, each twiddle packed across queries.
pub fn circleComputeTwiddlesFromBasePoint(comptime V: type, ctx: *Context(V), base_point: Point(Simd), fold_step: usize) Error![]const []const Simd {
    std.debug.assert(fold_step > 0);
    const scratch = ctx.scratch();
    if (fold_step == 1) {
        const folds = try scratch.alloc([]const Simd, 1);
        const twiddle = try scratch.alloc(Simd, 1);
        twiddle[0] = try simd.inv(V, ctx, base_point.y);
        folds[0] = twiddle;
        return folds;
    }

    // The witness domain is a circle domain with a half coset of log size `fold_step - 1`.
    const coset_points = try circle.computeHalfCosetPoints(V, ctx, base_point, @intCast(fold_step - 1));
    if (coset_points.len > 1) try simd.markPartlyUsed(V, ctx, coset_points[coset_points.len - 1].y);

    const y_inverses = try scratch.alloc(Simd, coset_points.len);
    for (y_inverses, coset_points) |*y_inv, point| y_inv.* = try simd.inv(V, ctx, point.y);
    const folds = try scratch.alloc([]const Simd, fold_step);
    const first = try scratch.alloc(Simd, 2 * y_inverses.len);
    for (y_inverses, 0..) |y_inv, i| {
        first[2 * i] = y_inv;
        first[2 * i + 1] = try select_queries.negSimd(V, ctx, y_inv);
    }
    folds[0] = first;

    const x_coords = try scratch.alloc(Simd, coset_points.len);
    for (x_coords, coset_points) |*x, point| x.* = point.x;
    try computeXTwiddles(V, ctx, x_coords, folds[1..]);
    return folds;
}

/// `compute_x_twiddles`: `out.len` folds; each inverts the current x
/// coordinates, then (except the last) keeps every other one, doubled.
pub fn computeXTwiddles(comptime V: type, ctx: *Context(V), x_coords: []const Simd, out: [][]const Simd) Error!void {
    var xs = x_coords;
    for (out, 0..) |*fold, fold_idx| {
        const inverses = try ctx.scratch().alloc(Simd, xs.len);
        for (inverses, xs) |*x_inv, x| x_inv.* = try simd.inv(V, ctx, x);
        fold.* = inverses;
        // No unused gates in the last iteration.
        if (fold_idx != out.len - 1) {
            const next = try ctx.scratch().alloc(Simd, std.math.divCeil(usize, xs.len, 2) catch unreachable);
            for (next, 0..) |*x, i| x.* = try circle.doubleXSimd(V, ctx, xs[2 * i]);
            xs = next;
        }
    }
}

/// `compute_twiddles_from_base_point`: the x twiddles of a line-to-line
/// step.
pub fn computeTwiddlesFromBasePoint(comptime V: type, ctx: *Context(V), base_point: Point(Simd), fold_step: usize) Error![]const []const Simd {
    std.debug.assert(fold_step > 0);
    const coset_points = try circle.computeHalfCosetPoints(V, ctx, base_point, @intCast(fold_step));
    // The last half-coset point's y is not necessarily used (a single-point
    // half coset only happens for fold_step 1).
    if (coset_points.len > 1) try simd.markPartlyUsed(V, ctx, coset_points[coset_points.len - 1].y);
    const x_coords = try ctx.scratch().alloc(Simd, coset_points.len);
    for (x_coords, coset_points) |*x, point| x.* = point.x;
    const folds = try ctx.scratch().alloc([]const Simd, fold_step);
    try computeXTwiddles(V, ctx, x_coords, folds);
    return folds;
}

/// `circle_translate_to_base_point`: the circle bit negates `y`, the rest
/// are line bits.
pub fn circleTranslateToBasePoint(comptime V: type, ctx: *Context(V), point: Point(Simd), packed_bits: []const Simd) Error!Point(Simd) {
    const minus_y = try select_queries.negSimd(V, ctx, point.y);
    const selected: Point(Simd) = .{ .x = point.x, .y = try simd.select(V, ctx, packed_bits[0], point.y, minus_y) };
    return translateToBasePoint(V, ctx, selected, packed_bits[1..]);
}

/// `translate_to_base_point`: subtracts the generator of the subgroup of
/// size `2^(i+1)` from every lane whose bit `i` is set.
pub fn translateToBasePoint(comptime V: type, ctx: *Context(V), point: Point(Simd), packed_bits: []const Simd) Error!Point(Simd) {
    var base = point;
    for (packed_bits, 0..) |bit, i| {
        const generator = try circle.generatorPointSimd(V, ctx, i + 1, base.x.len);
        const point_if_bit = try circle.subPointsSimd(V, ctx, base, generator);
        base = .{
            .x = try simd.select(V, ctx, bit, base.x, point_if_bit.x),
            .y = try simd.select(V, ctx, bit, base.y, point_if_bit.y),
        };
    }
    return base;
}
