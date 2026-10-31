const std = @import("std");
const E = @import("../evaluation.zig");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = E.Q;
const PB = E.PackedBase;
const PS = E.PackedSecure;
fn dense(value: u32) Q {
    return Q.fromM31Array(.{ M.fromCanonical(value), M.fromCanonical(value + 17), M.fromCanonical(value + 31), M.fromCanonical(value + 43) });
}
// Independent signed-integer extension product; deliberately avoids scalar
// QM31 aggregate multiplication as an oracle for optimized compiler tests.
fn oracleProduct(lhs: Q, rhs: Q) [4]u32 {
    const ll = lhs.toM31Array();
    const rr = rhs.toM31Array();
    const x0: i128 = ll[0].v;
    const x1: i128 = ll[1].v;
    const x2: i128 = ll[2].v;
    const x3: i128 = ll[3].v;
    const y0: i128 = rr[0].v;
    const y1: i128 = rr[1].v;
    const y2: i128 = rr[2].v;
    const y3: i128 = rr[3].v;
    const ac = x0 * y0 - x1 * y1;
    const ai = x0 * y1 + x1 * y0;
    const bd = x2 * y2 - x3 * y3;
    const bi = x2 * y3 + x3 * y2;
    const terms = [_]i128{ ac + 2 * bd - bi, ai + bd + 2 * bi, x0 * y2 - x1 * y3 + x2 * y0 - x3 * y1, x0 * y3 + x1 * y2 + x2 * y1 + x3 * y0 };
    var result: [4]u32 = undefined;
    for (terms, &result) |value, *out| out.* = @intCast(@mod(value, @as(i128, core.fields.m31.Modulus)));
    return result;
}
test "sixteen row packed fields preserve scalar base secure and mixed products" {
    var lhs: [16]M = undefined;
    var rhs: [16]M = undefined;
    var ql: [16]Q = undefined;
    var qr: [16]Q = undefined;
    for (0..16) |i| {
        lhs[i] = M.fromCanonical(if (i == 0) 0 else if (i == 1) core.fields.m31.Modulus - 1 else @intCast(i * 7381));
        rhs[i] = M.fromCanonical(if (i % 3 == 0) core.fields.m31.Modulus - 1 else @intCast(i + 1));
        ql[i] = dense(@intCast(i * 77 + 3));
        qr[i] = dense(@intCast(i * 911 + 13));
    }
    ql[0] = Q.zero();
    ql[1] = Q.one();
    ql[2] = Q.fromM31Array(@splat(M.fromCanonical(core.fields.m31.Modulus - 1)));
    qr[2] = Q.fromM31Array(.{ M.fromCanonical(core.fields.m31.Modulus - 1), M.zero(), M.fromCanonical(core.fields.m31.Modulus - 2), M.one() });
    const bl = PB.fromLanes(lhs);
    const br = PB.fromLanes(rhs);
    const sl = PS.fromLanes(ql);
    const sr = PS.fromLanes(qr);
    for (0..16) |i| {
        try std.testing.expect(bl.add(br).lane(i).eql(lhs[i].add(rhs[i])));
        try std.testing.expect(bl.sub(br).lane(i).eql(lhs[i].sub(rhs[i])));
        try std.testing.expect(bl.mul(br).lane(i).eql(lhs[i].mul(rhs[i])));
        try std.testing.expect(bl.neg().lane(i).eql(lhs[i].neg()));
        try std.testing.expect(sl.add(sr).lane(i).eql(ql[i].add(qr[i])));
        try std.testing.expect(sl.sub(sr).lane(i).eql(ql[i].sub(qr[i])));
        try std.testing.expect(sl.mul(sr).lane(i).eql(ql[i].mul(qr[i])));
        const independently_expected = oracleProduct(ql[i], qr[i]);
        for (sl.mul(sr).lane(i).toM31Array(), independently_expected) |actual, expected| try std.testing.expectEqual(expected, actual.v);
        try std.testing.expect(sl.mulBase(br).lane(i).eql(ql[i].mulM31(rhs[i])));
        try std.testing.expect(sl.neg().lane(i).eql(ql[i].neg()));
    }
    const coords = sl.coordinates();
    try std.testing.expect(sl.eql(PS.fromCoordinates(coords)));
    var unaligned: [18]M = @splat(M.fromCanonical(111));
    bl.store(unaligned[1..].ptr);
    try std.testing.expect(bl.eql(PB.load(unaligned[1..].ptr)));
    try std.testing.expectEqual(@as(u32, 111), unaligned[0].v);
    try std.testing.expectEqual(@as(u32, 111), unaligned[17].v);
}
test "mixed packed sink preserves reverse Horner powers scale capture and zero weights" {
    var base: [16]M = undefined;
    var secure: [16]Q = undefined;
    var scales: [16]Q = undefined;
    for (0..16) |i| {
        base[i] = M.fromCanonical(@intCast(7 * i + 5));
        secure[i] = dense(@intCast(13 * i + 19));
        scales[i] = dense(@intCast(23 * i + 7));
    }
    const b = PB.fromLanes(base);
    const s = PS.fromLanes(secure);
    const powers = [_]Q{ dense(2), dense(3), dense(5), dense(7), dense(11), dense(13) };
    for ([_]bool{ false, true }) |scaled| {
        var accumulator = E.PackedWeightedAccumulator{ .powers = &powers };
        var values: [6]PS = undefined;
        var sink = E.PackedSink{ .values = &values, .weighted_accumulator = &accumulator, .scale = if (scaled) PS.fromLanes(scales) else null };
        sink.emit(b);
        sink.emit(s);
        sink.zeros(2);
        sink.emit(b.neg());
        sink.emit(s.mulBase(b));
        try std.testing.expectEqual(@as(usize, 6), sink.count);
        try std.testing.expect(values[0].eql(PS.fromBase(b)));
        try std.testing.expect(values[1].eql(s));
        try std.testing.expect(values[2].isZero() and values[3].isZero());
        for (0..16) |i| {
            var old = E.WeightedAccumulator{ .powers = &powers };
            var scalar = E.Sink{ .values = null, .weighted_accumulator = &old, .scale = if (scaled) scales[i] else null };
            scalar.emit(Q.fromBase(base[i]));
            scalar.emit(secure[i]);
            scalar.zeros(2);
            scalar.emit(Q.fromBase(base[i].neg()));
            scalar.emit(secure[i].mulM31(base[i]));
            try std.testing.expect(accumulator.accumulation.lane(i).eql(old.accumulation));
        }
    }
}
test "packed affine denominators and coordinate assembly equal arbitrary OODS authority" {
    var rows: [4][16]M = undefined;
    var dense_rows: [4][16]Q = undefined;
    for (0..4) |c| for (0..16) |i| {
        rows[c][i] = M.fromCanonical(@intCast(c * 47 + i * 31));
        dense_rows[c][i] = dense(@intCast(c * 17 + i * 13));
    };
    var base: [4]PB = undefined;
    var secure: [4]PS = undefined;
    for (0..4) |c| {
        base[c] = PB.fromLanes(rows[c]);
        secure[c] = PS.fromLanes(dense_rows[c]);
    }
    const coefficients = [_]Q{ dense(7), dense(17), dense(29), dense(43) };
    const offset = dense(89);
    inline for ([_]bool{ false, true }) |subtract| {
        const packed_result = E.denominatorFor(PB, offset, &coefficients, &base, subtract);
        const packed_secure = E.denominatorFor(PS, offset, &coefficients, &secure, subtract);
        for (0..16) |i| {
            var expected = offset;
            var dense_expected = offset;
            for (0..4) |c| {
                const term = coefficients[c].mulM31(rows[c][i]);
                expected = if (subtract) expected.sub(term) else expected.add(term);
                const dense_term = coefficients[c].mul(dense_rows[c][i]);
                dense_expected = if (subtract) dense_expected.sub(dense_term) else dense_expected.add(dense_term);
            }
            try std.testing.expect(packed_result.lane(i).eql(expected));
            try std.testing.expect(packed_secure.lane(i).eql(dense_expected));
        }
    }
    const assembled = E.secureFromCoordinatesFor(PB, base);
    const dense_assembled = E.secureFromCoordinatesFor(PS, secure);
    for (0..16) |i| {
        const expected = Q.fromM31Array(.{ rows[0][i], rows[1][i], rows[2][i], rows[3][i] });
        const arbitrary = [_]Q{ dense_rows[0][i], dense_rows[1][i], dense_rows[2][i], dense_rows[3][i] };
        try std.testing.expect(assembled.lane(i).eql(expected));
        try std.testing.expect(dense_assembled.lane(i).eql(Q.fromPartialEvals(arbitrary)));
        try std.testing.expect(E.secureFor(Q, &arbitrary, 0).eql(Q.fromPartialEvals(arbitrary)));
    }
}
