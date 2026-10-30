//! Independent finite-difference check of the declared polynomial degree.
const std = @import("std");
const E = @import("../evaluation.zig");
const relation = @import("../relations.zig");
const Q = E.Q;
const L = E.L;

test "rv64 AIR: domain and OODS constraint authority has declared degree at most four" {
    const a = std.testing.allocator;
    const width = L.fixed.COUNT + L.MAIN + 2 * L.INTERACTION;
    const base = try a.alloc(Q, width);
    defer a.free(base);
    const slope = try a.alloc(Q, width);
    defer a.free(slope);
    const values = try a.alloc(Q, width);
    defer a.free(values);
    const differences = try a.alloc(Q, 6 * 8192);
    defer a.free(differences);
    var random: u64 = 0x8dadbeef55;
    for (base, slope) |*b, *s| {
        b.* = draw(&random);
        s.* = draw(&random);
    }
    var challenges = relation.Challenges{ .offset = draw(&random), .coefficients = undefined };
    for (&challenges.coefficients) |*c| c.* = draw(&random);
    const expected = draw(&random);
    var count: usize = 0;
    for (0..6) |t| {
        for (values, base, slope) |*v, b, s| v.* = b.add(s.mul(E.q(@intCast(t))));
        const fixed: *const E.Fixed = values[0..L.fixed.COUNT];
        const main: *const E.Main = values[L.fixed.COUNT..][0..L.MAIN];
        const current: *const [L.INTERACTION]Q = values[L.fixed.COUNT + L.MAIN ..][0..L.INTERACTION];
        const previous: *const [L.INTERACTION]Q = values[L.fixed.COUNT + L.MAIN + L.INTERACTION ..][0..L.INTERACTION];
        var sink = E.Sink{ .values = differences[t * 8192 ..][0..8192] };
        const view = E.View{ .f = fixed, .m = main };
        E.local(view, &sink);
        relation.evaluate(view, current, previous, challenges, expected, &sink);
        count = sink.count;
        const Accumulator = @import("stwo_core").air.accumulation.PointEvaluationAccumulator;
        var buffered = Accumulator.init(challenges.offset);
        var streaming = Accumulator.init(challenges.offset);
        const scale = E.q(7);
        for (differences[t * 8192 ..][0..count]) |value| buffered.accumulate(value.mul(scale));
        var direct = E.Sink{ .values = null, .accumulator = &streaming, .scale = scale };
        E.local(view, &direct);
        relation.evaluate(view, current, previous, challenges, expected, &direct);
        try std.testing.expectEqual(count, direct.count);
        try std.testing.expect(buffered.finalize().eql(streaming.finalize()));
    }
    for (0..5) |order| for (0..5 - order) |t| for (0..count) |c| {
        differences[t * 8192 + c] = differences[(t + 1) * 8192 + c].sub(differences[t * 8192 + c]);
    };
    for (differences[0..count], 0..) |residual, i| if (!residual.isZero()) {
        std.debug.print("RV64 degree exceeds declared bound: constraint {d}\n", .{i});
        return error.InvalidRv64DegreeBound;
    };
}
fn draw(state: *u64) Q {
    var coordinates: [4]u32 = undefined;
    for (&coordinates) |*c| {
        state.* ^= state.* << 13;
        state.* ^= state.* >> 7;
        state.* ^= state.* << 17;
        c.* = @intCast(state.* % 2147483647);
    }
    return Q.fromU32Unchecked(coordinates[0], coordinates[1], coordinates[2], coordinates[3]);
}

test "rv64 AIR: zero runs preserve the pinned Horner recurrence and constraint positions" {
    const Accumulator = @import("stwo_core").air.accumulation.PointEvaluationAccumulator;
    for ([_]usize{ 0, 1, 2, 29, 80, 285, 2528, 5513 }) |count| {
        const alpha = Q.fromU32Unchecked(2, 3, 5, 7);
        var reference = Accumulator.init(alpha);
        var actual = Accumulator.init(alpha);
        reference.accumulate(Q.one());
        actual.accumulate(Q.one());
        for (0..count) |_| reference.accumulate(Q.zero());
        var sink = E.Sink{ .values = null, .accumulator = &actual, .scale = E.q(11) };
        sink.zeros(count);
        try std.testing.expectEqual(count, sink.count);
        reference.accumulate(E.q(17));
        sink.emit(E.q(17).mul(try E.q(11).inv()));
        try std.testing.expect(reference.finalize().eql(actual.finalize()));
    }
}
