const std = @import("std");
const core = @import("stwo_core");
const E = @import("../evaluation.zig");
const A = @import("shift_word.zig");
const P = @import("shift_word_lookup.zig");
const Q = E.Q;
const N = P.MAIN + 2 * P.INTERACTION + 2;
fn challenges() P.Challenges {
    var channel = core.channel.blake2s.Blake2sChannel{};
    var ch = P.Challenges{ .shift = .{ .offset = channel.drawSecureFelt(), .coefficients = undefined }, .range16 = .{ .offset = channel.drawSecureFelt(), .coefficient = channel.drawSecureFelt() }, .function = .{ .offset = channel.drawSecureFelt(), .coefficients = undefined } };
    for (&ch.shift.coefficients) |*v| v.* = channel.drawSecureFelt();
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
test "SHIFT36 joint polynomial is genuinely cubic at arbitrary extension points and preserves arithmetic" {
    const ch = challenges();
    const claims = P.Claims{ .shift = dense(13), .range16 = dense(29), .function = dense(37) };
    var results: [5][P.CONSTRAINTS]Q = undefined;
    for (&results, 0..) |*values, t| {
        var input: [N]Q = undefined;
        for (&input, 0..) |*v, c| v.* = dense(@intCast(5 * c)).add(dense(@intCast(7 * c + 9)).mul(E.q(@intCast(t))));
        values.* = evaluate(&input, ch, claims);
        var original: [A.CONSTRAINTS]Q = undefined;
        var sink = E.Sink{ .values = &original };
        A.emitFor(Q, &A.rowFromColumnsFor(Q, input[0..P.MAIN]), &sink);
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
test "SHIFT36 authenticates only combined physical claim and rejects unweighted poles" {
    const ch = challenges();
    var input: [N]Q = undefined;
    for (&input, 0..) |*v, i| v.* = dense(@intCast(3 * i));
    const claims = P.Claims{ .shift = dense(11), .range16 = dense(17), .function = dense(23) };
    const shifted = P.Claims{ .shift = claims.shift, .range16 = claims.range16.add(Q.one()), .function = claims.function.sub(Q.one()) };
    try std.testing.expectEqualSlices(Q, &evaluate(&input, ch, claims), &evaluate(&input, ch, shifted));
    // No function inverse can disappear behind zero multiplicity, even on a
    // fully dormant row: the corresponding strict residual is exactly -1.
    @memset(&input, Q.zero());
    var row = A.witness(.sll, 0, 0);
    row.active = Q.zero();
    row.selectors[0] = Q.zero();
    row.offset = @splat(Q.zero());
    row.payload[0] = Q.zero();
    @memcpy(input[0..A.LOCAL_MAIN], &A.rowToColumnsFor(Q, &row));
    var range_claim = Q.zero();
    var shift_claim = Q.zero();
    for (0..7) |i| {
        const dx = P.unitDenominatorFor(Q, &row, 2 * i, ch);
        const dy = P.unitDenominatorFor(Q, &row, 2 * i + 1, ch);
        const inverse = try dx.mul(dy).inv();
        for (inverse.toM31Array(), 0..) |value, c| input[P.MAIN + 4 * i + c] = Q.fromBase(value);
        const x = try dx.inv();
        const y = try dy.inv();
        if (2 * i < 5) shift_claim = shift_claim.add(x) else range_claim = range_claim.add(x);
        if (2 * i + 1 < 5) shift_claim = shift_claim.add(y) else range_claim = range_claim.add(y);
    }
    input[N - 2] = Q.one();
    input[N - 1] = Q.one();
    var pole = ch;
    pole.function.offset = Q.zero();
    const bad = evaluate(&input, pole, .{ .shift = shift_claim, .range16 = range_claim, .function = Q.zero() });
    for (bad[0 .. A.CONSTRAINTS + 1 + 7]) |value| try std.testing.expect(value.isZero());
    try std.testing.expect(bad[A.CONSTRAINTS + 1 + 7].eql(Q.one().neg()));
    for (bad[A.CONSTRAINTS + 2 + 7 ..]) |value| try std.testing.expect(value.isZero());
}
