const std = @import("std");
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const B = E.PackedFields.PackedOmBase;
const S = E.PackedFields.PackedOmSecure;
fn dense(seed: usize) O {
    var c: [8]M = undefined;
    for (&c, 0..) |*v, i| v.* = M.fromCanonical(@intCast((seed * 7919 + i * 977 + 3) % core.fields.m31.Modulus));
    return O.fromM31Array(c);
}
test "active OM sixteen-row frontend multiplication preserves every coordinate" {
    var left: [E.LANES]O = undefined;
    var right: [E.LANES]O = undefined;
    for (&left, &right, 0..) |*x, *y, i| {
        x.* = if (i % 5 == 0) O.zero() else if (i % 5 == 1) O.one().neg() else dense(i + 17);
        y.* = if (i % 3 == 0) O.one() else dense(i + 91);
    }
    const actual = S.fromLanes(left).mul(S.fromLanes(right));
    for (left, right, 0..) |x, y, i| try std.testing.expectEqualDeep(x.mul(y), actual.lane(i));
}
test "OM pointer weighted-base accumulation preserves mixed outputs scale and count" {
    var powers: [6]O = undefined;
    for (&powers, 0..) |*p, i| p.* = dense(i + 101);
    var base: [3][E.LANES]M = undefined;
    for (&base, 0..) |*row, r| for (row, 0..) |*v, i| {
        v.* = if (i % 3 == 0) M.zero() else if (i % 3 == 1) M.one().neg() else M.fromCanonical(@intCast(i + 37 * r));
    };
    var secure: [2][E.LANES]O = undefined;
    for (&secure, 0..) |*row, r| for (row, 0..) |*v, i| {
        v.* = dense(i + 53 * r + 23);
    };
    var scales: [E.LANES]O = undefined;
    var random: [E.LANES]O = undefined;
    for (&scales, &random, 0..) |*scale, *r, i| {
        scale.* = if (i == 0) O.zero() else if (i == 1) O.one() else dense(i + 433);
        r.* = dense(i + 701);
    }
    for ([_]bool{ false, true }) |scaled| {
        const initial = dense(991);
        var accumulation = E.WeightedAccumulatorFor(B){ .powers = &powers, .accumulation = S.splat(initial) };
        var point = E.lane.PointAccumulator(S){ .random_coeff = S.fromLanes(random), .accumulation = S.splat(initial) };
        var values: [6]S = undefined;
        var sink = E.SinkFor(B){ .values = &values, .accumulator = &point, .weighted_accumulator = &accumulation, .scale = if (scaled) S.fromLanes(scales) else null };
        sink.emit(B.fromLanes(base[0]));
        sink.emit(S.fromLanes(secure[0]));
        sink.zeros(1);
        sink.emit(B.fromLanes(base[1]));
        sink.emit(S.fromLanes(secure[1]));
        sink.emit(B.fromLanes(base[2]));
        try std.testing.expectEqual(@as(usize, 6), sink.count);
        for (0..E.LANES) |i| {
            const residuals = [_]O{ O.fromBase(base[0][i]), secure[0][i], O.zero(), O.fromBase(base[1][i]), secure[1][i], O.fromBase(base[2][i]) };
            var expected = initial;
            var point_expected = initial;
            for (residuals, 0..) |value, j| {
                try std.testing.expectEqualDeep(value, values[j].lane(i));
                const effective = if (scaled) scales[i].mul(value) else value;
                expected = expected.add(powers[5 - j].mul(effective));
                point_expected = point_expected.mul(random[i]).add(effective);
            }
            try std.testing.expectEqualDeep(expected, accumulation.accumulation.lane(i));
            try std.testing.expectEqualDeep(point_expected, point.accumulation.lane(i));
        }
    }
}
