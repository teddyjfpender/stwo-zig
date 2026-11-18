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

const Mutation = enum { none, sample, sibling, column_order, wrong_mask_domain, excessive_degree, widened_oods };
fn checkDegree(comptime rows: usize, comptime width: usize, comptime global_size: usize, comptime extra_log: u32, offset: i8, mutation: Mutation) !usize {
    const size = rows * width;
    const domain_log = std.math.log2_int(usize, 2 * global_size);
    const domain = core.poly.circle.canonic.CanonicCoset.new(domain_log).circleDomain();
    const global_log = domain_log - 1;
    const air_log = global_log - extra_log;
    const Layout = @import("stacked_layout.zig");
    const group = Layout.Group{ .first = 0, .log_width = @intCast(std.math.log2_int(usize, width)), .source_log = std.math.log2_int(usize, rows) };
    const lift = try group.lift(air_log, global_log);
    const global_step = core.poly.circle.canonic.CanonicCoset.new(air_log).step();
    const global_shift = extend(global_step.mulSigned(offset));
    const global_sample = (try oodsPoint()).add(global_shift);
    const sample_point = lift.samplePoint(global_sample);
    // Native two-mask columns repeat sample 1 at the periodicity point.
    const extended_step = core.poly.circle.canonic.CanonicCoset.new(air_log + 1).step();
    const period = extend(extended_step.repeatedDouble(group.source_log + 1));
    try std.testing.expect(sample_point.eql(lift.samplePoint(global_sample.add(period))));
    const receiver_point = if (mutation == .wrong_mask_domain) lift.samplePoint(try oodsPoint()).add(global_shift) else if (mutation == .widened_oods) global_sample.repeatedDouble(global_log - group.source_log) else sample_point;
    var source: [width][rows]Base = undefined;
    var packed_coeffs: [2 * size]Base = @splat(Base.zero());
    var samples: [width]Secure = undefined;
    for (&source, 0..) |*column, j| {
        for (column, 0..) |*c, i| c.* = Base.fromU64(1013 * (j + 2) * (i + 7) * (i + 3) + 17 * i * i + j);
        samples[j] = try eval(column, sample_point);
    }
    try stack.pack(std.mem.bytesAsSlice(Base, std.mem.asBytes(&source)), width, packed_coeffs[0..size]);
    switch (mutation) {
        .none, .sibling, .wrong_mask_domain, .widened_oods => {},
        .excessive_degree => packed_coeffs[size] = Base.one(),
        .sample => samples[width - 1] = samples[width - 1].add(Secure.one()),
        .column_order => std.mem.swap(Secure, &samples[0], &samples[width - 1]),
    }
    var evaluations: [8][2 * global_size]Base = undefined;
    const half = try Base.fromCanonical(2).inv();
    const raw_weight = (try oodsPoint()).x;
    for (0..2 * global_size) |row| {
        const p = lift.queryPoint(domain.at(core.utils.bitReverseIndex(row, domain_log)));
        const sibling = lift.queryPoint(domain.at(core.utils.bitReverseIndex(row ^ 1, domain_log)));
        try std.testing.expect(sibling.eql(p.conjugate()));
        const plus = (try eval(&packed_coeffs, extend(p))).toM31Array()[0];
        var minus = (try eval(&packed_coeffs, extend(sibling))).toM31Array()[0];
        if (mutation == .sibling and row == 4) minus = minus.add(Base.one());
        const result = try stack.quotient(p, plus, minus, receiver_point, &samples);
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
        const combined = result.add(raw_weight.mulM31(plus));
        for (combined.toM31Array(), 0..) |v, i| evaluations[i][row] = v;
    }
    var high: usize = 0;
    for (&evaluations) |*column| {
        const ev = try @import("evaluation.zig").CircleEvaluation.init(domain, column);
        var coefficients = try poly.interpolateFromEvaluation(alloc, ev);
        defer coefficients.deinit(alloc);
        for (coefficients.coeffs[global_size..]) |c| high += @intFromBool(!c.isZero());
    }
    return high;
}

test "stacked Circle sibling opening agrees with native DEEP and enforces the degree on shifted masks" {
    for ([_]i8{ -1, 0, 1 }) |offset| try std.testing.expectEqual(@as(usize, 0), try checkDegree(8, 4, 32, 0, offset, .none));
    try std.testing.expectEqual(@as(usize, 0), try checkDegree(2, 16, 32, 0, 0, .none));
    try std.testing.expectEqual(@as(usize, 0), try checkDegree(16, 2, 32, 0, 0, .none));
    inline for (.{ Mutation.sample, Mutation.sibling, Mutation.column_order }) |mutation|
        try std.testing.expect(try checkDegree(8, 4, 32, 0, 1, mutation) > 0);
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

test "stacked Circle lifted source masks normalize after the global shift and enforce the declared degree" {
    try std.testing.expectEqual(@as(usize, 0), try checkDegree(8, 4, 128, 0, -1, .none));
    try std.testing.expectEqual(@as(usize, 0), try checkDegree(4, 8, 64, 0, 2, .none));
    try std.testing.expect(try checkDegree(8, 4, 128, 0, -1, .wrong_mask_domain) > 0);
    try std.testing.expect(try checkDegree(8, 4, 128, 0, -1, .excessive_degree) > 0);
}

test "stacked Circle batches share query reductions with non-real weights and shifted masks" {
    const domain = core.poly.circle.canonic.CanonicCoset.new(8).circleDomain();
    const base_sample = try oodsPoint();
    const w0 = base_sample.x;
    const weights = [_]Secure{ w0, w0.square(), base_sample.y };
    const plus = [_]Base{ Base.fromCanonical(101), Base.fromCanonical(202), Base.fromCanonical(303) };
    const minus = [_]Base{ Base.fromCanonical(404), Base.fromCanonical(505), Base.fromCanonical(606) };
    var values: [24]Secure = undefined;
    for (&values, 0..) |*v, i| v.* = w0.mulM31(Base.fromU64(i + 13)).add(base_sample.y.square().mulM31(Base.fromU64(i * i + 1)));
    for ([_]usize{ 1, 2, 4, 8 }) |width| {
        const samples = values[0 .. width * weights.len];
        for ([_]i8{ -1, 0, 1 }) |shift| {
            const z = base_sample.add(extend(domain.half_coset.step.mulSigned(shift)));
            var prep = try stack.Batch.init(alloc, width, &weights, z, samples);
            defer prep.deinit(alloc);
            for (0..8) |i| {
                const query = domain.at(core.utils.bitReverseIndex(i, 8));
                var expected = Secure.zero();
                for (weights, plus, minus, 0..) |alpha, v, s, g| {
                    const q = if (width == 1) try originalQuotient(query, z, Secure.fromBase(v), samples[g]) else try stack.quotient(query, v, s, z, samples[g * width ..][0..width]);
                    expected = expected.add(alpha.mul(q));
                }
                try std.testing.expect(expected.eql(try prep.answer(query, &plus, &minus)));
                var changed = plus;
                changed[1] = changed[1].add(Base.one());
                try std.testing.expect(!expected.eql(try prep.answer(query, &changed, &minus)));
                changed = minus;
                changed[1] = changed[1].add(Base.one());
                try std.testing.expectEqual(width == 1, expected.eql(try prep.answer(query, &plus, &changed)));
            }
        }
    }
}

test "stacked Circle batch admission rejects mismatched extents and degeneracy" {
    const point = try oodsPoint();
    const alpha = [_]Secure{ point.y, point.x };
    const values = [_]Secure{point.y} ** 8;
    try std.testing.expectError(error.InvalidStackShape, stack.Batch.init(alloc, 0, &alpha, point, &values));
    try std.testing.expectError(error.InvalidStackShape, stack.Batch.init(alloc, 3, &alpha, point, &values));
    try std.testing.expectError(error.InvalidStackShape, stack.Batch.init(alloc, 4, alpha[0..0], point, values[0..0]));
    try std.testing.expectError(error.InvalidStackShape, stack.Batch.init(alloc, 4, &alpha, point, values[0..7]));
    try std.testing.expectError(error.DegenerateLine, stack.Batch.init(alloc, 4, &alpha, extend(core.circle.M31_CIRCLE_GEN), &values));
    var prep = try stack.Batch.init(alloc, 4, &alpha, point, &values);
    defer prep.deinit(alloc);
    const row = [_]Base{Base.one()} ** 2;
    try std.testing.expectError(error.InvalidStackShape, prep.answer(core.circle.M31_CIRCLE_GEN, row[0..1], &row));
    try std.testing.expectError(error.InvalidStackShape, prep.answer(core.circle.M31_CIRCLE_GEN, &row, row[0..1]));
    try std.testing.expectError(error.SingularFiber, prep.answer(BasePoint.identity(), &row, &row));
    try std.testing.expectError(error.InvalidCirclePoint, prep.answer(.{ .x = Base.one(), .y = Base.one() }, &row, &row));
}

test "stacked Circle batch owns its weights and releases its only preparation allocation" {
    const z = try oodsPoint();
    var weights = [_]Secure{ z.x, z.y };
    var values = [_]Secure{z.x} ** 8;
    var fail = std.testing.FailingAllocator.init(alloc, .{ .fail_index = 0 });
    try std.testing.expectError(error.OutOfMemory, stack.Batch.init(fail.allocator(), 4, &weights, z, &values));
    var prep = try stack.Batch.init(alloc, 4, &weights, z, &values);
    defer prep.deinit(alloc);
    const p = core.circle.M31_CIRCLE_GEN;
    const row = [_]Base{ Base.one(), Base.fromCanonical(73) };
    const expected = try prep.answer(p, &row, &row);
    @memset(&weights, Secure.zero());
    @memset(&values, Secure.zero());
    try std.testing.expect(expected.eql(try prep.answer(p, &row, &row)));
}

test "stacked Circle raised FRI height preserves original AIR samples and rejects excess degree" {
    try std.testing.expectEqual(@as(usize, 0), try checkDegree(8, 4, 32, 2, -1, .none));
    try std.testing.expect(try checkDegree(8, 4, 32, 2, -1, .widened_oods) > 0);
    try std.testing.expect(try checkDegree(8, 4, 32, 2, -1, .excessive_degree) > 0);
}
