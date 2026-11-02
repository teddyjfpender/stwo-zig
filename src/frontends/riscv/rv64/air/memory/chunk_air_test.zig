const std = @import("std");
const air = @import("chunk_air.zig");
const values = @import("values.zig");
const relation = @import("internal_relations.zig");
const E = @import("../evaluation.zig");
const Q = E.Q;
fn sample(n: u32) Q {
    return Q.fromU32Unchecked(n + 1, n + 3, n + 7, n + 11);
}
fn challenges() air.Challenges {
    var challenge = relation.Challenge{ .offset = sample(10), .coefficients = undefined };
    for (&challenge.coefficients, 0..) |*coefficient, i| coefficient.* = sample(@intCast(31 + 3 * i));
    return .{ .ram = challenge.prepare(), .io = air.PermutationChallenge.init(sample(50), sample(71)) };
}
fn coordinates(claims: air.Claims) [air.INTERACTION]Q {
    var result: [air.INTERACTION]Q = undefined;
    for (claims, 0..) |claim, i| for (claim.toM31Array(), 0..) |limb, j| {
        result[4 * i + j] = Q.fromBase(limb);
    };
    return result;
}
fn contributions(shape: air.Shape, fixed: *const air.Fixed, row: *const air.SecureRow, previous: *const air.SecureRow, challenge: *const air.Challenges) !air.Claims {
    var result: air.Claims = @splat(Q.zero());
    const io_weight = row[air.ACTIVE].mul(Q.one().sub(fixed[air.RESET]));
    if (!io_weight.isZero()) result[0] = io_weight.mul(try air.ioDenominator(shape, fixed, row, previous, challenge.io).inv()).neg();
    for (0..8) |slot| {
        const term = air.ramTerm(shape, fixed, row, previous, &challenge.ram, slot);
        if (!term.numerator.isZero()) result[1 + slot / 3] = result[1 + slot / 3].add(term.numerator.mul(try term.denominator.inv()));
    }
    return result;
}

test "RV64 private chunk caller: native transcript cyclic prefixes and zero reset agree over full QM31" {
    const a = std.testing.allocator;
    const challenge = challenges();
    const shape = air.Shape{ .geometry = .chunk512, .hashes = 1, .log_size = 6 };
    try shape.validate();
    var words: [64]u64 = undefined;
    for (&words, 0..) |*word, i| word.* = @as(u64, @intCast(i)) *% 0xfedc_ba98_7654_3211;
    var recorder = values.Recorder{ .allocator = a };
    defer recorder.deinit();
    const expected = try values.hashValues(.chunk512, &words, &recorder);
    var main: [64]air.SecureRow = @splat(@splat(Q.zero()));
    var fixed: [64]air.Fixed = undefined;
    for (&fixed, 0..) |*row, i| for (row, shape.fixedAt(i)) |*field, value| {
        field.* = Q.fromBase(value);
    };
    for (0..shape.activeRows()) |i| main[i][air.ACTIVE] = Q.one();
    for (recorder.calls.items, 0..) |call, i| {
        for (0..16) |lane| main[i][air.OUTPUT + lane] = Q.fromBase(call.output[lane]);
        for (0..7) |lane| main[i][air.PAYLOAD + lane] = Q.fromBase(call.input[lane]).sub(if (i == 0) Q.zero() else main[i - 1][air.OUTPUT + lane]);
        const derived = air.input(shape, &fixed[i], &main[i], &main[if (i == 0) 63 else i - 1]);
        for (derived, call.input) |actual, word| try std.testing.expectEqualDeep(Q.fromBase(word), actual);
    }
    const digest = air.digest(&main[37], &main[36]);
    for (digest, expected) |actual, word| try std.testing.expectEqualDeep(E.q(word), actual);
    var prefix: [64][air.INTERACTION]Q = undefined;
    var sums: air.Claims = @splat(Q.zero());
    for (&main, 0..) |*row, i| {
        const contribution = try contributions(shape, &fixed[i], row, &main[if (i == 0) 63 else i - 1], &challenge);
        for (&sums, contribution) |*sum, value| sum.* = sum.add(value);
        prefix[i] = coordinates(sums);
    }
    for (0..64) |i| {
        var residuals: [air.CONSTRAINTS]Q = undefined;
        var sink = E.Sink{ .values = &residuals };
        air.evaluate(shape, &fixed[i], &main[i], &main[if (i == 0) 63 else i - 1], &prefix[i], &prefix[if (i == 0) 63 else i - 1], sums, &challenge, &sink);
        try std.testing.expectEqual(air.CONSTRAINTS, sink.count);
        for (residuals) |residual| try std.testing.expect(residual.isZero());
    }
    var bad = main[38];
    bad[air.OUTPUT] = Q.one();
    var residuals: [air.CONSTRAINTS]Q = undefined;
    var sink = E.Sink{ .values = &residuals };
    air.evaluate(shape, &fixed[38], &bad, &main[37], &prefix[38], &prefix[37], sums, &challenge, &sink);
    var caught = false;
    for (residuals) |residual| caught = caught or !residual.isZero();
    try std.testing.expect(caught);
}

test "RV64 private chunk caller: reset and lookup polynomials have degree at most four at arbitrary Q" {
    const challenge = challenges();
    const claims: air.Claims = .{ sample(1), sample(3), sample(5), sample(7) };
    const shape = air.Shape{ .geometry = .chunk512, .hashes = 1, .log_size = 6 };
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
