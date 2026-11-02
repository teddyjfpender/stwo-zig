const std = @import("std");
const air = @import("cell_air.zig");
const relation = @import("internal_relations.zig");
const state = @import("../relations.zig");
const E = @import("../evaluation.zig");
const Q = E.Q;
fn sample(n: u32) Q {
    return Q.fromU32Unchecked(n + 1, n + 3, n + 7, n + 11);
}
fn challenges() air.Challenges {
    var r = relation.Challenge{ .offset = sample(23), .coefficients = undefined };
    for (&r.coefficients, 0..) |*coefficient, i| coefficient.* = sample(@intCast(97 + i * 3));
    var s = state.Challenges{ .offset = sample(53), .coefficients = undefined };
    for (&s.coefficients, 0..) |*coefficient, i| coefficient.* = sample(@intCast(199 + i * 5));
    return .{ .ram = r.prepare(), .state = s, .bytes = sample(43) };
}
fn coordinates(claims: air.Claims) [air.INTERACTION]Q {
    var result: [air.INTERACTION]Q = undefined;
    for (claims, 0..) |claim, group| for (claim.toM31Array(), 0..) |limb, j| {
        result[group * 4 + j] = Q.fromBase(limb);
    };
    return result;
}
fn term(shape: air.Shape, f: *const air.Fixed, main: *const air.SecureRow, ch: *const air.Challenges, group: usize, slot: usize) air.Term {
    return if (group < air.BYTE_SUMS) air.byteTerm(main, ch.bytes, group * 3 + slot) else if (group < air.HEADER_SUM) air.payloadTerm(f, main, &ch.ram, (group - air.BYTE_SUMS) * 3 + slot) else if (group == air.HEADER_SUM) (if (slot == 0) air.headerTerm(f, main, &ch.ram) else .{ .denominator = Q.one(), .numerator = Q.zero() }) else if (group == air.PERMIT_SUM) (if (slot == 0) air.permitTerm(shape, f, main, &ch.ram) else .{ .denominator = Q.one(), .numerator = Q.zero() }) else air.stateTerm(f, main, ch.state, slot);
}
test "RV64 private cell table: canonical 64-bit cells clocks and CPU state close without public RAM target" {
    const shape = air.Shape{ .geometry = .chunk512, .chunks = 1, .log_size = 6, .policy_mode = .chunk };
    const ch = challenges();
    const base: u64 = 0xffff_ffff_ffff_fe00;
    var rows: [64]air.SecureRow = undefined;
    var fixed: [64]air.Fixed = undefined;
    var prefix: [64][air.INTERACTION]Q = undefined;
    var claims: air.Claims = @splat(Q.zero());
    var expected = Q.zero();
    for (&rows, &fixed, &prefix, 0..) |*row, *f, *inter, i| {
        const before: u64 = @as(u64, @intCast(i)) *% 0xfedcba9876543211;
        const after = if (i == 7) before ^ 0x1234abcd9876 else before;
        const clock: u32 = if (i == 7 or i == 13) (1 << 24) - 4 else 0;
        const native = try air.fill(.chunk512, .{ .base = base, .before_id = 0, .after_id = 1, .changed = true, .before = before, .after = after, .terminal_clock = clock, .readable = true, .writable = true });
        for (row, native) |*field, m| field.* = Q.fromBase(m);
        for (f, shape.fixedAt(i)) |*field, m| field.* = Q.fromBase(m);
        for (0..air.SUMS) |group| for (0..3) |slot| {
            const t = term(shape, f, row, &ch, group, slot);
            if (!t.numerator.isZero()) claims[group] = claims[group].add(t.numerator.mul(try t.denominator.inv()));
        };
        inter.* = coordinates(claims);
        if (clock != 0) expected = expected.sub(try ch.state.denominator(state.boundaryTuple(1, base + 8 * i, 0, before, true, true)).inv()).add(try ch.state.denominator(state.boundaryTuple(1, base + 8 * i, clock, after, true, true)).inv());
    }
    try std.testing.expectEqualDeep(expected, claims[air.STATE_SUM]);
    for (0..64) |i| {
        var residuals: [air.CONSTRAINTS]Q = undefined;
        var sink = E.Sink{ .values = &residuals };
        const previous = (i + 63) % 64;
        air.evaluate(shape, &fixed[i], &rows[i], &rows[previous], &prefix[i], &prefix[previous], claims, &ch, &sink);
        try std.testing.expectEqual(air.CONSTRAINTS, sink.count);
        for (residuals) |value| try std.testing.expect(value.isZero());
    }
    var bad = rows[8];
    bad[air.AFTER] = bad[air.AFTER].add(Q.one());
    var residuals: [air.CONSTRAINTS]Q = undefined;
    var sink = E.Sink{ .values = &residuals };
    air.evaluate(shape, &fixed[8], &bad, &rows[7], &prefix[8], &prefix[7], claims, &ch, &sink);
    try std.testing.expect(!residuals[25].isZero());
    try std.testing.expectError(error.InvalidPrivateRamCell, air.fill(.chunk512, .{ .base = base, .before_id = 0, .after_id = 1, .changed = true, .before = 0, .after = 1, .terminal_clock = 0, .readable = true, .writable = true }));
}

test "RV64 private cell table: header rights and state polynomials retain degree four at arbitrary QM31" {
    const ch = challenges();
    const claims: air.Claims = @splat(sample(31));
    for ([_]air.PolicyMode{ .chunk, .word }) |mode| {
        const shape = air.Shape{ .geometry = .page4096, .chunks = 1, .log_size = 9, .policy_mode = mode };
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
            air.evaluate(shape, &fixed, &main, &previous, &current, &prior, claims, &ch, &sink);
        }
        for (0..5) |level| for (0..5 - level) |row| for (0..air.CONSTRAINTS) |column| {
            evaluations[row][column] = evaluations[row + 1][column].sub(evaluations[row][column]);
        };
        for (evaluations[0]) |value| try std.testing.expect(value.isZero());
    }
}
