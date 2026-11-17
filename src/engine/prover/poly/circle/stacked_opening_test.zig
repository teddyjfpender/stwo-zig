const std = @import("std");
const core = @import("stwo_core");
const poly = @import("poly.zig");
const stack = @import("stacked_opening.zig");
const Base = core.fields.m31.M31;
const Secure = core.fields.om31.OM31;
const BasePoint = core.circle.CirclePointM31;
const Point = core.circle.CirclePoint(Secure);
const alloc = std.testing.allocator;

fn extend(p: BasePoint) Point {
    return .{ .x = Secure.fromBase(p.x), .y = Secure.fromBase(p.y) };
}

fn oodsPoint() !Point {
    var coords: [8]Base = undefined;
    for (&coords, 0..) |*v, i| v.* = Base.fromCanonical(@intCast(23 + i * 7));
    const t = Secure.fromM31Array(coords);
    const reciprocal = try Secure.one().add(t.square()).inv();
    return .{ .x = Secure.one().sub(t.square()).mul(reciprocal), .y = t.add(t).mul(reciprocal) };
}

test "stacked Circle packing preserves adjacent coefficient pairs and refuses invalid storage before writing" {
    var source: [16]Base = undefined;
    for (&source, 0..) |*v, i| v.* = Base.fromCanonical(@intCast(i));
    var dest: [16]Base = undefined;
    try stack.pack(&source, 4, &dest);
    const expected = [_]u32{ 0, 1, 4, 5, 8, 9, 12, 13, 2, 3, 6, 7, 10, 11, 14, 15 };
    for (expected, dest) |v, actual| try std.testing.expectEqual(v, actual.toU32());
    const snapshot = dest;
    try std.testing.expectError(error.InvalidStackShape, stack.pack(&source, 3, &dest));
    try std.testing.expectError(error.InvalidStackShape, stack.pack(&source, 16, &dest));
    try std.testing.expectError(error.InvalidStackShape, stack.pack(source[0..12], 2, dest[0..12]));
    try std.testing.expectError(error.InvalidStackShape, stack.pack(&source, 4, dest[0..8]));
    try std.testing.expectError(error.OverlappingBuffers, stack.pack(dest[0..8], 2, dest[1..9]));
    try std.testing.expectEqualSlices(Base, &snapshot, &dest);
}

fn eval(c: []const Base, p: Point) !Secure {
    return (try poly.CircleCoefficients.initBorrowed(c)).evalAtPointFor(Secure, p);
}

// Independent lookup of each original polynomial and both original DEEP equations.
fn originalQuotient(p: BasePoint, sample_point: Point, value: Secure, sample: Secure) !Secure {
    const line = try core.constraints.quadraticConjugateLineCoeffs(Secure, sample_point, sample, Secure.one());
    const d = core.constraints.quadraticLineDenominator(Secure, sample_point, p);
    return value.mul(line.c).sub(line.a.mulM31(p.y)).sub(line.b).mulInner(try d.inv());
}

const Mutation = enum { none, sample, sibling, column_order };
fn checkDegree(comptime rows: usize, comptime width: usize, offset: i8, mutation: Mutation) !usize {
    const size = rows * width;
    const domain_log = std.math.log2_int(usize, 2 * size);
    const domain = core.poly.circle.canonic.CanonicCoset.new(domain_log).circleDomain();
    const sample_point = (try oodsPoint()).add(extend(core.circle.M31_CIRCLE_GEN.mul(915)).mulSigned(offset));
    var source: [width][rows]Base = undefined;
    var packed_coeffs: [size]Base = undefined;
    var samples: [width]Secure = undefined;
    for (&source, 0..) |*column, j| {
        for (column, 0..) |*c, i| c.* = Base.fromU64(1013 * (j + 2) * (i + 7) * (i + 3) + 17 * i * i + j);
        samples[j] = try eval(column, sample_point);
    }
    try stack.pack(std.mem.bytesAsSlice(Base, std.mem.asBytes(&source)), width, &packed_coeffs);
    switch (mutation) {
        .none, .sibling => {},
        .sample => samples[width - 1] = samples[width - 1].add(Secure.one()),
        .column_order => std.mem.swap(Secure, &samples[0], &samples[width - 1]),
    }
    var evaluations: [8][2 * size]Base = undefined;
    const half = try Base.fromCanonical(2).inv();
    for (0..2 * size) |row| {
        const p = domain.at(core.utils.bitReverseIndex(row, domain_log));
        const sibling = domain.at(core.utils.bitReverseIndex(row ^ 1, domain_log));
        try std.testing.expect(sibling.eql(p.conjugate()));
        const plus = (try eval(&packed_coeffs, extend(p))).toM31Array()[0];
        var minus = (try eval(&packed_coeffs, extend(sibling))).toM31Array()[0];
        if (mutation == .sibling and row == 4) minus = minus.add(Base.one());
        const result = try stack.quotient(p, plus, minus, sample_point, &samples);
        if (mutation == .none) {
            const folded = p.repeatedDouble(std.math.log2_int(usize, width));
            var expected = Secure.zero();
            for (source, samples, 0..) |column, sample, j| {
                const q0 = try originalQuotient(folded, sample_point, try eval(&column, extend(folded)), sample);
                const q1 = try originalQuotient(folded.conjugate(), sample_point, try eval(&column, extend(folded.conjugate())), sample);
                // Evaluate the low x-coordinate basis independently for this column.
                var weight = half;
                var x = p.x;
                var bits = j;
                while (bits != 0) : (bits >>= 1) {
                    if (bits & 1 != 0) weight = weight.mul(x);
                    x = BasePoint.doubleX(x);
                }
                const q = q0.add(q1).add(q0.sub(q1).mulM31(p.y.mul(try folded.y.inv())));
                expected = expected.add(q.mulM31(weight));
            }
            try std.testing.expect(expected.eql(result));
        }
        for (result.toM31Array(), 0..) |v, i| evaluations[i][row] = v;
    }
    var high: usize = 0;
    for (&evaluations) |*column| {
        const ev = try @import("evaluation.zig").CircleEvaluation.init(domain, column);
        var coefficients = try poly.interpolateFromEvaluation(alloc, ev);
        defer coefficients.deinit(alloc);
        for (coefficients.coeffs[size..]) |c| high += @intFromBool(!c.isZero());
    }
    return high;
}

test "stacked Circle sibling opening agrees with native DEEP and enforces the degree on shifted masks" {
    for ([_]i8{ -1, 0, 1 }) |offset| try std.testing.expectEqual(@as(usize, 0), try checkDegree(8, 4, offset, .none));
    try std.testing.expectEqual(@as(usize, 0), try checkDegree(2, 16, 0, .none));
    try std.testing.expectEqual(@as(usize, 0), try checkDegree(16, 2, 0, .none));
    inline for (.{ Mutation.sample, Mutation.sibling, Mutation.column_order }) |mutation|
        try std.testing.expect(try checkDegree(8, 4, 1, mutation) > 0);
}

test "stacked Circle refuses singular geometry and degenerate sample points" {
    const sample = [_]Secure{Secure.one()} ** 4;
    const p = core.circle.M31_CIRCLE_GEN;
    const invalid = BasePoint{ .x = Base.one(), .y = Base.one() };
    try std.testing.expectError(error.InvalidStackShape, stack.quotient(p, Base.zero(), Base.one(), try oodsPoint(), sample[0..3]));
    try std.testing.expectError(error.InvalidCirclePoint, stack.quotient(invalid, Base.zero(), Base.one(), try oodsPoint(), &sample));
    try std.testing.expectError(error.SingularFiber, stack.quotient(BasePoint.identity(), Base.zero(), Base.one(), try oodsPoint(), &sample));
    try std.testing.expectError(error.DegenerateLine, stack.quotient(p, Base.zero(), Base.one(), extend(p), &sample));
}
