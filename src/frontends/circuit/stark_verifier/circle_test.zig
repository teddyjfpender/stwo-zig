//! `crates/stark_verifier/src/circle_test.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230): the in-circuit circle
//! operations against the host group law.

const std = @import("std");
const core = @import("stwo_core");
const builder = @import("../builder/mod.zig");
const circle = @import("circle.zig");

const QM31 = core.fields.qm31.QM31;
const M31 = core.fields.m31.M31;
const CirclePointM31 = core.circle.CirclePointM31;
const Context = builder.Context(QM31);
const Var = builder.Var;
const Simd = builder.simd.Simd;
const qm31 = builder.ivalue.qm31FromU32s;

fn m31(value: u32) M31 {
    return M31.fromCanonical(value);
}

fn point(x: u32, y: u32) CirclePointM31 {
    return .{ .x = m31(x), .y = m31(y) };
}

const pt0 = point(102767539, 739428083);
const pt1 = point(1562688784, 946400219);
const pt2 = point(946122697, 337868966);
const pt3 = point(2104020285, 511427956);

/// `test_utils::simd_from_u32s`: one `new_var` per four values, zero-padded.
fn simdFromU32s(ctx: *Context, values: []const u32) !Simd {
    const n = std.math.divCeil(usize, values.len, 4) catch unreachable;
    const data = try ctx.scratch().alloc(Var, n);
    for (data, 0..) |*v, i| {
        var lanes = [_]u32{0} ** 4;
        for (0..4) |j| {
            if (4 * i + j < values.len) lanes[j] = values[4 * i + j];
        }
        v.* = try ctx.newVar(qm31(lanes[0], lanes[1], lanes[2], lanes[3]));
    }
    return .fromPacked(data, values.len);
}

fn pointsSimd(ctx: *Context, a: CirclePointM31, b: CirclePointM31) !circle.Point(Simd) {
    return .{ .x = try simdFromU32s(ctx, &.{ a.x.v, b.x.v }), .y = try simdFromU32s(ctx, &.{ a.y.v, b.y.v }) };
}

/// The one packed wire of a two-lane `Simd`: `QM31(CM31(a, b), 0)`.
fn expectLanes(ctx: *const Context, a: Simd, first: M31, second: M31) !void {
    try std.testing.expectEqual(@as(usize, 1), a.data.len);
    try std.testing.expect(ctx.get(a.data[0]).eql(QM31.fromM31(first, second, M31.zero(), M31.zero())));
}

fn expectValid(ctx: *Context) !void {
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}

test "circle: double_x and double_x_simd" {
    var ctx = try Context.init(std.testing.allocator, 0);
    defer ctx.deinit();
    const double0 = pt0.double();
    const double1 = pt1.double();

    const input = try ctx.guess(QM31.fromBase(pt0.x));
    try std.testing.expect(ctx.get(try circle.doubleX(QM31, &ctx, input)).eql(QM31.fromBase(double0.x)));

    const input_simd = try simdFromU32s(&ctx, &.{ pt0.x.v, pt1.x.v });
    const res = try circle.doubleXSimd(QM31, &ctx, input_simd);
    try std.testing.expectEqual(@as(usize, 2), res.len);
    // Upstream compares only the first CM31 (the two used lanes): the padding
    // lanes of `simd::one` are one, so `2·0 - 1` fills them with -1.
    const limbs = ctx.get(res.data[0]).toM31Array();
    try std.testing.expect(limbs[0].eql(double0.x) and limbs[1].eql(double1.x));
    try expectValid(&ctx);
}

test "circle: add_points over QM31" {
    var ctx = try Context.init(std.testing.allocator, 0);
    defer ctx.deinit();
    const a: core.circle.CirclePoint(QM31) = .{ .x = QM31.fromBase(m31(102767539)), .y = QM31.fromBase(m31(739428083)) };
    const b: core.circle.CirclePoint(QM31) = .{ .x = QM31.fromBase(m31(946122697)), .y = QM31.fromBase(m31(337868966)) };
    const a_var: circle.Point(Var) = .{ .x = try ctx.guess(a.x), .y = try ctx.guess(a.y) };
    const b_var: circle.Point(Var) = .{ .x = try ctx.guess(b.x), .y = try ctx.guess(b.y) };
    const res = try circle.addPoints(QM31, &ctx, a_var, b_var);
    const expected = a.add(b);
    try std.testing.expect(ctx.get(res.x).eql(expected.x));
    try std.testing.expect(ctx.get(res.y).eql(expected.y));
    try expectValid(&ctx);
}

test "circle: add_points_simd and sub_points_simd" {
    inline for (.{ true, false }) |adding| {
        var ctx = try Context.init(std.testing.allocator, 0);
        defer ctx.deinit();
        const first = try pointsSimd(&ctx, pt0, pt1);
        const second = try pointsSimd(&ctx, pt2, pt3);
        const res = if (adding)
            try circle.addPointsSimd(QM31, &ctx, first, second)
        else
            try circle.subPointsSimd(QM31, &ctx, first, second);
        const lane0 = if (adding) pt0.add(pt2) else pt0.sub(pt2);
        const lane1 = if (adding) pt1.add(pt3) else pt1.sub(pt3);
        try expectLanes(&ctx, res.x, lane0.x, lane1.x);
        try expectLanes(&ctx, res.y, lane0.y, lane1.y);
        try expectValid(&ctx);
    }
}

test "circle: double_point" {
    var ctx = try Context.init(std.testing.allocator, 0);
    defer ctx.deinit();
    const p: circle.Point(builder.wrappers.M31Wrapper(Var)) = .{
        .x = try builder.wrappers.guessM31(QM31, &ctx, builder.wrappers.m31Value(QM31, pt0.x)),
        .y = try builder.wrappers.guessM31(QM31, &ctx, builder.wrappers.m31Value(QM31, pt0.y)),
    };
    const res = try circle.doublePoint(QM31, &ctx, p);
    const expected = pt0.double();
    try std.testing.expect(ctx.get(res.x.get()).toM31Array()[0].eql(expected.x));
    try std.testing.expect(ctx.get(res.y.get()).toM31Array()[0].eql(expected.y));
}

test "circle: double_point_simd" {
    var ctx = try Context.init(std.testing.allocator, 0);
    defer ctx.deinit();
    const res = try circle.doublePointSimd(QM31, &ctx, try pointsSimd(&ctx, pt0, pt1));
    const xs = try builder.simd.unpack(QM31, &ctx, res.x);
    const ys = try builder.simd.unpack(QM31, &ctx, res.y);
    for ([_]CirclePointM31{ pt0.double(), pt1.double() }, xs, ys) |expected, x, y| {
        try std.testing.expect(ctx.get(x).toM31Array()[0].eql(expected.x));
        try std.testing.expect(ctx.get(y).toM31Array()[0].eql(expected.y));
    }
}
