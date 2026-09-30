//! `crates/stark_verifier/src/select_queries_test.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230).

const std = @import("std");
const core = @import("stwo_core");
const builder = @import("../builder/mod.zig");
const circle = @import("circle.zig");
const select_queries = @import("select_queries.zig");
const Channel = @import("channel.zig").Channel;

const QM31 = core.fields.qm31.QM31;
const M31 = core.fields.m31.M31;
const CirclePointM31 = core.circle.CirclePointM31;
const Context = builder.Context(QM31);
const Var = builder.Var;
const Simd = builder.simd.Simd;
const qm31 = builder.ivalue.qm31FromU32s;

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

/// `test_utils::packed_values` against `expected`.
fn expectPacked(ctx: *const Context, a: Simd, expected: []const QM31) !void {
    try std.testing.expectEqual(expected.len, a.data.len);
    for (a.data, expected) |v, e| try std.testing.expect(ctx.get(v).eql(e));
}

/// Lane `lane` of the first packed wire of `a`.
fn lane(ctx: *const Context, a: Simd, index: usize) M31 {
    return ctx.get(a.data[0]).toM31Array()[index];
}

fn expectValid(ctx: *Context) !void {
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}

test "select_queries: points lie on the canonic coset in bit-reversed order" {
    var ctx = try Context.init(std.testing.allocator, 0);
    defer ctx.deinit();
    const log_domain_size = 5;
    const input = try simdFromU32s(&ctx, &.{ 24, 25 });
    const queries = try select_queries.selectQueries(QM31, &ctx, input, log_domain_size);

    // The first point is on the circle and in the coset: doubling it
    // `log_domain_size` times gives `(-1, 0)`.
    const first: CirclePointM31 = .{ .x = lane(&ctx, queries.points.x, 0), .y = lane(&ctx, queries.points.y, 0) };
    try std.testing.expect(first.x.mul(first.x).add(first.y.mul(first.y)).eql(M31.one()));
    try std.testing.expect(first.repeatedDouble(log_domain_size).eql(.{ .x = M31.one().neg(), .y = M31.zero() }));

    // Index 24 = 0b11000: without the LSB, bit-reversed, 0b0011.
    const expected = circle.generatorPoint(log_domain_size + 1).add(circle.generatorPoint(log_domain_size - 1).mul(0b0011));
    try std.testing.expect(first.eql(expected));
    // Index 25 = 0b11001: the same, negated by the LSB.
    const second: CirclePointM31 = .{ .x = lane(&ctx, queries.points.x, 1), .y = lane(&ctx, queries.points.y, 1) };
    try std.testing.expect(second.eql(expected.neg()));
    try expectValid(&ctx);
}

test "select_queries: full selection from the channel regression" {
    var ctx = try Context.init(std.testing.allocator, 0);
    defer ctx.deinit();
    var channel: Channel = .{ .digest = .{
        .low = try ctx.constant(qm31(271333035, 1833401714, 819175623, 1270120203)),
        .high = try ctx.constant(qm31(1921341900, 364315769, 339695133, 365135865)),
    }, .n_draws = 0 };
    const n_queries = 3;
    const input = try select_queries.getQuerySelectionInputFromChannel(QM31, &ctx, &channel, n_queries);
    try std.testing.expectEqual(@as(usize, n_queries), input.len);
    try expectPacked(&ctx, input, &.{qm31(577837367, 1394565488, 1540262994, 293692251)});

    const queries = try select_queries.selectQueries(QM31, &ctx, input, 5);
    try std.testing.expectEqual(@as(usize, n_queries), queries.points.x.len);
    try std.testing.expectEqual(@as(usize, n_queries), queries.points.y.len);
    try expectPacked(&ctx, queries.points.x, &.{qm31(567259857, 1952787376, 194696271, 1133522282)});
    try expectPacked(&ctx, queries.points.y, &.{qm31(194696271, 1580223790, 567259857, 280947147)});
    const bits = [_]QM31{ qm31(1, 0, 0, 1), qm31(1, 0, 1, 1), qm31(1, 0, 0, 0), qm31(0, 0, 0, 1), qm31(1, 1, 1, 1) };
    try std.testing.expectEqual(bits.len, queries.bits.len);
    for (queries.bits, bits) |bit, expected| try expectPacked(&ctx, bit, &.{expected});
    try expectValid(&ctx);
}
