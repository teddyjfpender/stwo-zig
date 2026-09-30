//! In-circuit circle-group arithmetic: port of
//! `crates/stark_verifier/src/circle.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230).
//!
//! Points are over QM31 wires (`Point(Var)`) or over SIMD-packed M31 lanes
//! (`Point(Simd)`, one lane per query). Every function emits its builder
//! calls in the Rust `eval!` order.

const std = @import("std");
const core = @import("stwo_core");
const builder = @import("../builder/mod.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Var = builder.Var;
const Context = builder.Context;
const Error = builder.context.Error;
const simd = builder.simd;
const Simd = simd.Simd;
const wrappers = builder.wrappers;
const M31Wrapper = wrappers.M31Wrapper;

/// `CirclePoint<T>`.
pub fn Point(comptime T: type) type {
    return struct { x: T, y: T };
}

/// `double_x`: `2x^2 - 1`, the x-coordinate of `(x, y) + (x, y)`.
pub fn doubleX(comptime V: type, ctx: *Context(V), value: Var) Error!Var {
    const sqr = try ctx.mul(value, value);
    const twice = try ctx.add(sqr, sqr);
    return ctx.sub(twice, try ctx.constant(QM31.one()));
}

/// `double_x_simd`.
pub fn doubleXSimd(comptime V: type, ctx: *Context(V), value: Simd) Error!Simd {
    const sqr = try simd.mul(V, ctx, value, value);
    const twice = try simd.add(V, ctx, sqr, sqr);
    const one = try simd.one(V, ctx, value.len);
    return simd.sub(V, ctx, twice, one);
}

/// `double_point`: `p + p` over M31 wires.
pub fn doublePoint(comptime V: type, ctx: *Context(V), p: Point(M31Wrapper(Var))) Error!Point(M31Wrapper(Var)) {
    const xy = try ctx.mul(p.x.get(), p.y.get());
    const new_y = try ctx.add(xy, xy);
    return .{ .x = .newUnsafe(try doubleX(V, ctx, p.x.get())), .y = .newUnsafe(new_y) };
}

/// `double_point_simd`.
pub fn doublePointSimd(comptime V: type, ctx: *Context(V), p: Point(Simd)) Error!Point(Simd) {
    const xy = try simd.mul(V, ctx, p.x, p.y);
    const new_y = try simd.add(V, ctx, xy, xy);
    return .{ .x = try doubleXSimd(V, ctx, p.x), .y = new_y };
}

/// `repeated_double_point_simd`: `2^n_doubles * p`.
pub fn repeatedDoublePointSimd(comptime V: type, ctx: *Context(V), p: Point(Simd), n_doubles: usize) Error!Point(Simd) {
    var point = p;
    for (0..n_doubles) |_| point = try doublePointSimd(V, ctx, point);
    return point;
}

/// `add_points`.
pub fn addPoints(comptime V: type, ctx: *Context(V), p0: Point(Var), p1: Point(Var)) Error!Point(Var) {
    const x0x1 = try ctx.mul(p0.x, p1.x);
    const y0y1 = try ctx.mul(p0.y, p1.y);
    const x = try ctx.sub(x0x1, y0y1);
    const x0y1 = try ctx.mul(p0.x, p1.y);
    const y0x1 = try ctx.mul(p0.y, p1.x);
    const y = try ctx.add(x0y1, y0x1);
    return .{ .x = x, .y = y };
}

const PointOp = enum { add, sub };

/// `add_points_simd` and `sub_points_simd`: the four products first, then
/// the two coordinates.
fn combinePointsSimd(comptime V: type, ctx: *Context(V), comptime op: PointOp, p0: Point(Simd), p1: Point(Simd)) Error!Point(Simd) {
    const x0x1 = try simd.mul(V, ctx, p0.x, p1.x);
    const x0y1 = try simd.mul(V, ctx, p0.x, p1.y);
    const y0x1 = try simd.mul(V, ctx, p0.y, p1.x);
    const y0y1 = try simd.mul(V, ctx, p0.y, p1.y);
    return switch (op) {
        .add => .{ .x = try simd.sub(V, ctx, x0x1, y0y1), .y = try simd.add(V, ctx, x0y1, y0x1) },
        .sub => .{ .x = try simd.add(V, ctx, x0x1, y0y1), .y = try simd.sub(V, ctx, y0x1, x0y1) },
    };
}

/// `add_points_simd`.
pub fn addPointsSimd(comptime V: type, ctx: *Context(V), p0: Point(Simd), p1: Point(Simd)) Error!Point(Simd) {
    return combinePointsSimd(V, ctx, .add, p0, p1);
}

/// `sub_points_simd`.
pub fn subPointsSimd(comptime V: type, ctx: *Context(V), p0: Point(Simd), p1: Point(Simd)) Error!Point(Simd) {
    return combinePointsSimd(V, ctx, .sub, p0, p1);
}

/// `generator_point`: the generator of the subgroup of size `2^log_size`.
pub fn generatorPoint(log_size: usize) core.circle.CirclePointM31 {
    return core.circle.CirclePointIndex.subgroupGen(@intCast(log_size)).toPoint();
}

/// `generator_point_simd`: that generator repeated in `len` lanes.
pub fn generatorPointSimd(comptime V: type, ctx: *Context(V), log_size: usize, len: usize) Error!Point(Simd) {
    const pt = generatorPoint(log_size);
    const x = try simd.repeat(V, ctx, pt.x, len);
    return .{ .x = x, .y = try simd.repeat(V, ctx, pt.y, len) };
}

/// `coset_vanishing_poly`: `pi^(log_trace_size - 1)(x)`.
pub fn cosetVanishingPoly(comptime V: type, ctx: *Context(V), x: Var, log_trace_size: usize) Error!Var {
    std.debug.assert(log_trace_size >= 1);
    var value = x;
    for (0..log_trace_size - 1) |_| value = try doubleX(V, ctx, value);
    return value;
}

/// `denom_inverse`: the inverse of the trace coset's vanishing polynomial at
/// `x`, which must lie off the coset.
pub fn denomInverse(comptime V: type, ctx: *Context(V), x: Var, log_trace_size: usize) Error!Var {
    return ctx.inv(try cosetVanishingPoly(V, ctx, x, log_trace_size));
}

/// `compute_half_coset_points`: per lane, the first half of the coset of
/// size `2^log_size` starting at the base point, in bit-reversed order.
/// The result is scratch-owned.
pub fn computeHalfCosetPoints(comptime V: type, ctx: *Context(V), base_points: Point(Simd), log_size: u32) Error![]Point(Simd) {
    std.debug.assert(log_size > 0);
    const gen = try generatorPointSimd(V, ctx, log_size, base_points.x.len);
    const n_points = @as(usize, 1) << @intCast(log_size - 1);
    const points = try ctx.scratch().alloc(Point(Simd), n_points);
    points[0] = base_points;
    for (points[1..], 0..) |*point, i| point.* = try addPointsSimd(V, ctx, points[i], gen);
    core.utils.bitReverse(Point(Simd), points);
    return points;
}

test {
    _ = @import("circle_test.zig");
}
