const std = @import("std");
const air = @import("node_air.zig");
const values = @import("values.zig");
const relation = @import("internal_relations.zig");
const E = @import("../evaluation.zig");
const Q = E.Q;
fn sample(n: u32) Q {
    return Q.fromU32Unchecked(n + 1, n + 3, n + 7, n + 11);
}
fn challenges() air.Challenges {
    var r = relation.Challenge{ .offset = sample(23), .coefficients = undefined };
    for (&r.coefficients, 0..) |*coefficient, i| coefficient.* = sample(@intCast(97 + i * 3));
    return .{ .ram = r.prepare(), .io = @import("chunk_air.zig").PermutationChallenge.init(sample(7), sample(11)), .bytes = sample(43) };
}
fn coordinates(claims: air.Claims) [air.INTERACTION]Q {
    var result: [air.INTERACTION]Q = undefined;
    for (claims, 0..) |claim, group| for (claim.toM31Array(), 0..) |limb, j| {
        result[group * 4 + j] = Q.fromBase(limb);
    };
    return result;
}
test "RV64 private node caller: linear inputs match qualified full-height hash and cyclic claims" {
    const a = std.testing.allocator;
    var recorder = values.Recorder{ .allocator = a };
    defer recorder.deinit();
    const left: values.Digest = @splat(17);
    const right: values.Digest = @splat(29);
    const digest = try values.hashNode(.chunk512, 54, left, right, &recorder);
    const base = try air.fill(55, 0, 0, true, left, right, recorder.calls.items[0..4]);
    var main: air.SecureRow = undefined;
    for (&main, base) |*value, word| value.* = Q.fromBase(word);
    const row = air.hashRow(&main);
    for (row.digest, digest) |actual, expected| try std.testing.expectEqualDeep(E.q(expected), actual);
    for (row.inputs, row.outputs, recorder.calls.items) |input, output, io| for (input, output, io.input, io.output) |in, out, expected_in, expected_out| {
        try std.testing.expectEqualDeep(Q.fromBase(expected_in), in);
        try std.testing.expectEqualDeep(Q.fromBase(expected_out), out);
    };
    const challenge = challenges();
    var claims: air.Claims = @splat(Q.zero());
    for (0..air.SUMS) |group| for (0..3) |slot| {
        const term = if (group < 2) air.ioTerm(&main, challenge.io, 3 * group + slot) else if (group < 4) air.nodeTerm(&main, &challenge.ram, 3 * (group - 2) + slot) else air.byteTerm(&main, challenge.bytes, 3 * (group - 4) + slot);
        if (!term.numerator.isZero()) claims[group] = claims[group].add(term.numerator.mul(try term.denominator.inv()));
    };
    const inter = coordinates(claims);
    const shape = air.Shape{ .nodes = 1, .log_size = 4 };
    const zero: air.SecureRow = @splat(Q.zero());
    for (0..16) |i| {
        var fixed: air.Fixed = undefined;
        for (&fixed, shape.fixedAt(i)) |*value, word| value.* = Q.fromBase(word);
        var residuals: [air.CONSTRAINTS]Q = undefined;
        var sink = E.Sink{ .values = &residuals };
        air.evaluate(shape, &fixed, if (i == 0) &main else &zero, if (i == 1) &main else &zero, &inter, &inter, claims, &challenge, &sink);
        try std.testing.expectEqual(air.CONSTRAINTS, sink.count);
        for (residuals) |residual| try std.testing.expect(residual.isZero());
    }
    // Full 64-bit addressing cannot alias via a dropped carry into byte seven.
    var malformed = base;
    malformed[air.INDEX_BYTES + 6] = @import("stwo_core").fields.m31.M31.fromCanonical(255);
    for (&main, malformed) |*value, word| value.* = Q.fromBase(word);
    var fixed: air.Fixed = .{ Q.one(), Q.zero(), Q.zero() };
    var residuals: [air.CONSTRAINTS]Q = undefined;
    var sink = E.Sink{ .values = &residuals };
    air.evaluate(shape, &fixed, &main, &zero, &inter, &inter, claims, &challenge, &sink);
    try std.testing.expect(!residuals[26].isZero());
}

test "RV64 private node caller: arbitrary QM31 coordinates retain degree four including reuse" {
    const shape = air.Shape{ .nodes = 1, .log_size = 4 };
    const challenge = challenges();
    const claims: air.Claims = @splat(sample(31));
    var evaluations: [6][air.CONSTRAINTS]Q = undefined;
    for (0..6) |step| {
        const t = E.q(@intCast(step));
        var main: air.SecureRow = undefined;
        var previous: air.SecureRow = undefined;
        var fixed: air.Fixed = undefined;
        var current: [air.INTERACTION]Q = undefined;
        var prior: [air.INTERACTION]Q = undefined;
        for (&main, &previous, 0..) |*field, *old, i| {
            field.* = sample(@intCast(101 + i)).add(t.mul(sample(@intCast(211 + i))));
            old.* = sample(@intCast(307 + i)).add(t.mul(sample(@intCast(419 + i))));
        }
        for (&fixed, 0..) |*field, i| field.* = sample(@intCast(503 + i)).add(t.mul(sample(@intCast(601 + i))));
        for (&current, &prior, 0..) |*field, *old, i| {
            field.* = sample(@intCast(701 + i)).add(t.mul(sample(@intCast(809 + i))));
            old.* = sample(@intCast(907 + i)).add(t.mul(sample(@intCast(1009 + i))));
        }
        var sink = E.Sink{ .values = &evaluations[step] };
        air.evaluate(shape, &fixed, &main, &previous, &current, &prior, claims, &challenge, &sink);
    }
    for (0..5) |level| for (0..5 - level) |row| for (0..air.CONSTRAINTS) |column| {
        evaluations[row][column] = evaluations[row + 1][column].sub(evaluations[row][column]);
    };
    for (evaluations[0]) |residual| try std.testing.expect(residual.isZero());
}
