const std = @import("std");
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const A = @import("alu.zig");
const P = @import("alu_lookup.zig");
const Q = E.Q;
const N = P.MAIN + 2 * P.INTERACTION + 2;
fn challenges() P.Challenges {
    var channel = core.channel.blake2s.Blake2sChannel{};
    var ch = P.Challenges{ .range16 = .{ .offset = channel.drawSecureFelt(), .coefficient = channel.drawSecureFelt() }, .function = .{ .offset = channel.drawSecureFelt(), .coefficients = undefined } };
    for (&ch.function.coefficients) |*v| v.* = channel.drawSecureFelt();
    return ch;
}
fn dense(x: u32) Q {
    return Q.fromU32Unchecked(x + 1, x + 3, x + 5, x + 7);
}
fn evaluate(input: *const [N]Q, ch: P.Challenges, claims: P.Claims) [P.CONSTRAINTS]Q {
    var result: [P.CONSTRAINTS]Q = undefined;
    var sink = E.Sink{ .values = &result };
    P.emitFor(Q, input[0..P.MAIN], input[P.MAIN..][0..P.INTERACTION], input[P.MAIN + P.INTERACTION ..][0..P.INTERACTION], input[N - 2], input[N - 1], claims, ch, &sink);
    std.debug.assert(sink.count == P.CONSTRAINTS);
    return result;
}
test "ALU48 joint polynomial is genuinely cubic at arbitrary extension points and preserves arithmetic" {
    const ch = challenges();
    const claims = P.Claims{ .range16 = dense(29), .function = dense(37) };
    var results: [5][P.CONSTRAINTS]Q = undefined;
    for (&results, 0..) |*values, t| {
        var input: [N]Q = undefined;
        for (&input, 0..) |*v, c| v.* = dense(@intCast(5 * c)).add(dense(@intCast(7 * c + 9)).mul(E.q(@intCast(t))));
        values.* = evaluate(&input, ch, claims);
        var original: [A.CONSTRAINTS]Q = undefined;
        var sink = E.Sink{ .values = &original };
        A.emitFor(Q, &P.rowFromColumnsFor(Q, input[0..P.MAIN]), &sink);
        try std.testing.expectEqualSlices(Q, &original, values[0..A.CONSTRAINTS]);
    }
    var cubic = false;
    for (0..P.CONSTRAINTS) |c| {
        var difference: [5]Q = undefined;
        for (&difference, results) |*v, row| v.* = row[c];
        for (0..4) |order| {
            for (0..4 - order) |i| difference[i] = difference[i + 1].sub(difference[i]);
            if (order == 2) cubic = cubic or !difference[0].isZero();
        }
        try std.testing.expect(difference[0].isZero());
    }
    try std.testing.expect(cubic);
}
test "ALU48 authenticates only combined physical claim and rejects unweighted poles" {
    const ch = challenges();
    var input: [N]Q = undefined;
    for (&input, 0..) |*v, i| v.* = dense(@intCast(3 * i));
    const claims = P.Claims{ .range16 = dense(17), .function = dense(23) };
    const shifted = P.Claims{ .range16 = claims.range16.add(Q.one()), .function = claims.function.sub(Q.one()) };
    try std.testing.expectEqualSlices(Q, &evaluate(&input, ch, claims), &evaluate(&input, ch, shifted));
    // No function inverse can disappear behind zero multiplicity, even on a
    // fully dormant row: the corresponding strict residual is exactly -1.
    @memset(&input, Q.zero());
    var row = try A.witness(.add, 0, 0);
    row.active = Q.zero();
    row.selectors[0] = Q.zero();
    @memcpy(input[0..A.LOCAL_MAIN], &P.rowToColumnsFor(Q, row));
    var range_claim = Q.zero();
    for (0..10) |i| {
        const dx = ch.range16.denominatorFor(Q, A.rangeValueFor(Q, &row, 2 * i));
        const dy = ch.range16.denominatorFor(Q, A.rangeValueFor(Q, &row, 2 * i + 1));
        const inverse = try dx.mul(dy).inv();
        for (inverse.toM31Array(), 0..) |value, c| input[P.MAIN + 4 * i + c] = Q.fromBase(value);
        range_claim = range_claim.add(dx.add(dy).mul(inverse));
    }
    input[N - 2] = Q.one();
    input[N - 1] = Q.one();
    var pole = ch;
    pole.function.offset = Q.zero();
    const bad = evaluate(&input, pole, .{ .range16 = range_claim, .function = Q.zero() });
    for (bad[0 .. A.CONSTRAINTS + 1 + 10]) |value| try std.testing.expect(value.isZero());
    try std.testing.expect(bad[A.CONSTRAINTS + 1 + 10].eql(Q.one().neg()));
    for (bad[A.CONSTRAINTS + 2 + 10 ..]) |value| try std.testing.expect(value.isZero());
}
