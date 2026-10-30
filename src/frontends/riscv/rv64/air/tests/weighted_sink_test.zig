const std = @import("std");
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const Q = E.Q;

test "weighted residual sink preserves Horner order, global offsets, scale and zero runs" {
    var prng = std.Random.DefaultPrng.init(0x5745494748544544);
    const rng = prng.random();
    const alpha = randomQ(rng);
    var values: [97]Q = undefined;
    for (&values, 0..) |*value, i| value.* = if (i % 3 == 0) E.q(@intCast(i)) else randomQ(rng);
    @memset(values[11..19], Q.zero());
    for ([_]usize{ 0, 7, 23 }) |offset| {
        var powers: [values.len]Q = undefined;
        var power = alpha.pow(offset);
        for (&powers) |*value| {
            value.* = power;
            power = power.mul(alpha);
        }
        for ([_]?Q{ null, Q.zero(), Q.one(), randomQ(rng) }) |scale| {
            var expected = core.air.accumulation.PointEvaluationAccumulator.init(alpha);
            var direct = E.WeightedAccumulator{ .powers = &powers };
            var buffered: [values.len]Q = undefined;
            var sink = E.Sink{ .values = &buffered, .accumulator = &expected, .weighted_accumulator = &direct, .scale = scale };
            for (values[0..11]) |value| sink.emit(value);
            sink.zeros(8);
            for (values[19..]) |value| sink.emit(value);
            try std.testing.expectEqual(values.len, sink.count);
            try std.testing.expect(direct.accumulation.eql(expected.finalize().mul(alpha.pow(offset))));
            for (values, buffered) |want, actual| try std.testing.expect(want.eql(actual));
        }
    }
}
fn randomQ(rng: std.Random) Q {
    const p = core.fields.m31.Modulus;
    return Q.fromU32Unchecked(rng.int(u32) % p, rng.int(u32) % p, rng.int(u32) % p, rng.int(u32) % p);
}
