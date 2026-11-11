//! Terminal expressions reuse the ORIGINAL arithmetic/frontier fraction
//! authority. The row masks must be authenticated on the lifted PCS domain.
const std = @import("std");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const N = A.crypto.bn254_tower.narrow;
const Frame = @import("authority.zig");
pub const laneWeightsFor = @import("../truth_local_gkr/projection.zig").laneWeightsFor;
pub fn fraction(comptime F: type, instance: Frame.Instance, view: anytype, public: E.CallSpanFor(E.ConstFor(F)), challenges: N.equations.ChallengesFor(E.ConstFor(F)), query: usize) !struct { F, E.SecureFor(F) } {
    if (query >= instance.queries()) return error.MillerLocalQuery;
    const Arith = N.equations.EquationsForField(.arithmetic, E.ConstFor(F));
    const Frontier = N.equations.EquationsForField(.frontier, E.ConstFor(F));
    return switch (instance.role) {
        .bytes => Arith.fraction(F, view, public, challenges, .range, query),
        .carries => Arith.fraction(F, view, public, challenges, .range, 98 + query),
        .arithmetic_ssa => Arith.fraction(F, view, public, challenges, .ssa, query),
        .frontier_ssa => Frontier.fraction(F, view, public, challenges, .ssa, query),
    };
}
pub fn evaluate(comptime F: type, instance: Frame.Instance, view: anytype, public: E.CallSpanFor(E.ConstFor(F)), challenges: N.equations.ChallengesFor(E.ConstFor(F)), weights: []const E.ConstFor(F)) !struct { E.SecureFor(F), E.SecureFor(F) } {
    if (weights.len != @as(usize, 1) << @intCast(instance.laneLog())) return error.MillerLocalProjectionShape;
    var numerator = E.SecureFor(F).zero();
    var denominator = E.SecureFor(F).zero();
    for (weights[0..instance.queries()], 0..) |weight, query| {
        const f = try fraction(F, instance, view, public, challenges, query);
        const eq = E.splatFor(F, weight);
        numerator = numerator.add(E.mulBaseFor(F, eq, f[0]));
        denominator = denominator.add(eq.mul(f[1]));
    }
    for (weights[instance.queries()..]) |weight| denominator = denominator.add(E.splatFor(F, weight));
    return .{ numerator, denominator };
}
test "Miller local GKR source terminal projections match native row fractions including padding" {
    const core = @import("stwo_core");
    const O = core.fields.om31.OM31;
    const allocator = std.testing.allocator;
    const input = [_]N.trace.Input{@splat(1)};
    var source = try N.trace.SourceForField(.arithmetic, O).init(allocator, &input, 7, 15);
    defer source.deinit();
    var channel = core.channel.poseidon2_m31.Om31ChannelV2.init();
    const ch = @import("native.zig").draw(&channel);
    const view = N.trace.SourceForField(.arithmetic, O).View{ .source = &source, .physical = 0 };
    const instances = try (Frame.Geometry{ .calls = 1, .first_id = 7, .arithmetic_log = 15, .frontier_log = 8 }).instances();
    for (instances[0..3]) |instance| {
        var point: [7]O = undefined;
        for (&point, 0..) |*value, i| value.* = O.fromBase(core.fields.m31.M31.fromCanonical(@intCast(i + 3)));
        const weights = try laneWeightsFor(O, allocator, point[0..instance.laneLog()]);
        defer allocator.free(weights);
        const actual = try evaluate(O, instance, &view, source.public(), ch, weights);
        var expected = [2]O{ O.zero(), O.zero() };
        for (weights, 0..) |weight, i| {
            if (i >= instance.queries()) {
                expected[1] = expected[1].add(weight);
            } else {
                var fnn: [1]O = undefined;
                var fdd: [1]O = undefined;
                switch (instance.role) {
                    .bytes => try source.fractionsAt(0, ch, .range, i, &fnn, &fdd),
                    .carries => try source.fractionsAt(0, ch, .range, 98 + i, &fnn, &fdd),
                    .arithmetic_ssa => try source.fractionsAt(0, ch, .ssa, i, &fnn, &fdd),
                    .frontier_ssa => unreachable,
                }
                expected[0] = expected[0].add(weight.mul(fnn[0]));
                expected[1] = expected[1].add(weight.mul(fdd[0]));
            }
        }
        try std.testing.expect(actual[0].eql(expected[0]));
        try std.testing.expect(actual[1].eql(expected[1]));
    }
}
