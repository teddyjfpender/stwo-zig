const std = @import("std");
const air = @import("policy_air.zig");
const E = @import("../evaluation.zig");
const policy = @import("policy.zig");
const Q = air.Q;
fn sample(n: u32) Q {
    return Q.fromU32Unchecked(n + 1, n + 3, n + 7, n + 11);
}
fn challenges() air.Challenges {
    var result = air.Challenges{ .bytes = sample(100), .policy = .{ .offset = sample(200), .coefficients = undefined }, .permit = .{ .offset = sample(300), .coefficients = undefined } };
    for (&result.policy.coefficients, 0..) |*value, i| value.* = sample(@intCast(400 + 17 * i));
    for (&result.permit.coefficients, 0..) |*value, i| value.* = sample(@intCast(800 + 19 * i));
    return result;
}
fn contributions(span: policy.Span, row: *const air.SecureRow, rel: air.Challenges) !air.Claims {
    var result: air.Claims = @splat(Q.zero());
    for (0..air.RANGES) |i| result[i / 3] = result[i / 3].add(try rel.bytes.sub(row[air.rangeField(i)]).inv());
    result[air.POLICY_SUM] = try rel.policy.denominator(air.policyTuple(row)).inv();
    result[air.PERMIT_SUM] = (try rel.permit.denominator(air.permitTuple(row, span)).inv()).neg();
    return result;
}
fn coordinates(values: air.Claims) [air.INTERACTION]Q {
    var result: [air.INTERACTION]Q = undefined;
    for (values, 0..) |value, i| for (value.toM31Array(), 0..) |limb, j| {
        result[4 * i + j] = Q.fromBase(limb);
    };
    return result;
}
fn evaluate(span: policy.Span, row: *const air.SecureRow, claims: air.Claims, rel: air.Challenges) ![air.CONSTRAINTS]Q {
    const current = coordinates(try contributions(span, row, rel));
    const previous = coordinates(claims);
    var result: [air.CONSTRAINTS]Q = undefined;
    var sink = E.Sink{ .values = &result };
    air.evaluate(span, Q.one(), Q.one(), row, &current, &previous, claims, rel, &sink);
    try std.testing.expectEqual(air.CONSTRAINTS, sink.count);
    return result;
}
fn zero(values: []const Q) bool {
    for (values) |value| if (!value.isZero()) return false;
    return true;
}

test "RV64 private RAM policy AIR: full-extension cyclic prefixes and bounds authenticate both spans" {
    const rel = challenges();
    var claims: air.Claims = undefined;
    for (&claims, 0..) |*value, i| value.* = sample(@intCast(1200 + 31 * i));
    for ([_]policy.Span{ .word8, .chunk512, .page4096 }) |span| {
        const row = try air.fill(span, std.math.maxInt(u64) - (span.bytes() - 1), .{ .first = std.math.maxInt(u64) - 4095, .last = std.math.maxInt(u64), .mask = 3 });
        var secure: air.SecureRow = undefined;
        for (&secure, row) |*value, base| value.* = Q.fromBase(base);
        try std.testing.expect(zero(&try evaluate(span, &secure, claims, rel)));
        var bad = secure;
        bad[air.ADDRESS + 7] = bad[air.ADDRESS + 7].sub(Q.one());
        try std.testing.expect(!zero(&try evaluate(span, &bad, claims, rel)));
        bad = secure;
        bad[air.READ] = E.q(2);
        try std.testing.expect(!zero(&try evaluate(span, &bad, claims, rel)));
        bad = secure;
        bad[air.ALIGN] = bad[air.ALIGN].add(Q.one());
        try std.testing.expect(!zero(&try evaluate(span, &bad, claims, rel)));
    }
}

test "RV64 private RAM policy AIR: byte256 carry alias needs a real closed range relation" {
    const rel = challenges();
    const base = try air.fill(.chunk512, 512, .{ .first = 0, .last = 1023, .mask = 3 });
    var honest: air.SecureRow = undefined;
    for (&honest, base) |*value, word| value.* = Q.fromBase(word);
    var bad = honest;
    bad[air.FROM_FIRST] = E.q(256);
    bad[air.FROM_FIRST + 1] = E.q(1);
    bad[air.CARRY_FROM] = Q.one();
    const claims: air.Claims = @splat(Q.zero());
    // All arithmetic AND caller prefix identities can hold with a fabricated
    // range claim; this must not be confused with closed table membership.
    try std.testing.expect(zero(&try evaluate(.chunk512, &bad, claims, rel)));
    const good_claims = try contributions(.chunk512, &honest, rel);
    const bad_claims = try contributions(.chunk512, &bad, rel);
    var good = Q.zero();
    var forged = Q.zero();
    for (0..air.BYTE_SUMS) |i| {
        good = good.add(good_claims[i]);
        forged = forged.add(bad_claims[i]);
    }
    try std.testing.expect(!good.eql(forged));
}

test "RV64 private RAM policy AIR: arbitrary-Q polynomial degree is at most four" {
    const rel = challenges();
    var claims: air.Claims = undefined;
    for (&claims, 0..) |*value, i| value.* = sample(@intCast(50 + i));
    for ([_]policy.Span{ .word8, .chunk512, .page4096 }) |span| {
        var evaluations: [6][air.CONSTRAINTS]Q = undefined;
        for (0..6) |step| {
            const t = E.q(@intCast(step));
            var main: air.SecureRow = undefined;
            var interaction: [air.INTERACTION]Q = undefined;
            var previous: [air.INTERACTION]Q = undefined;
            for (&main, 0..) |*value, i| value.* = sample(@intCast(i)).add(t.mul(sample(@intCast(100 + 2 * i))));
            for (&interaction, &previous, 0..) |*value, *prior, i| {
                value.* = sample(@intCast(500 + i)).add(t.mul(sample(@intCast(700 + 3 * i))));
                prior.* = sample(@intCast(900 + i)).add(t.mul(sample(@intCast(1100 + 5 * i))));
            }
            var sink = E.Sink{ .values = &evaluations[step] };
            air.evaluate(span, sample(13).add(t.mul(sample(19))), sample(23).add(t.mul(sample(29))), &main, &interaction, &previous, claims, rel, &sink);
        }
        for (0..5) |level| for (0..5 - level) |row| for (0..air.CONSTRAINTS) |column| {
            evaluations[row][column] = evaluations[row + 1][column].sub(evaluations[row][column]);
        };
        try std.testing.expect(zero(&evaluations[0]));
    }
}
