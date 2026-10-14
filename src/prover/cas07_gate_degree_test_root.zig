//! Exact Gate-minimum-height source/own-quotient degree check for CAS07.
//! This algebraic counterexample is not an accepting PCS proof.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");

const M31 = core.fields.m31.M31;
const CM31 = core.fields.cm31.CM31;
const QM31 = core.fields.qm31.QM31;
const Point = core.circle.CirclePointM31;
const SecurePoint = core.circle.CirclePointQM31;
const SourceKind = enum { one, y, x, xy, x_squared };

fn sourceAt(kind: SourceKind, p: Point) M31 {
    return switch (kind) {
        .one => M31.one(),
        .y => p.y,
        .x => p.x,
        .xy => p.x.mul(p.y),
        .x_squared => p.x.square(),
    };
}

fn claimAt(kind: SourceKind, q: SecurePoint) QM31 {
    return switch (kind) {
        .one => QM31.one(),
        .y => q.y,
        .x => q.x,
        .xy => q.x.mul(q.y),
        .x_squared => q.x.square(),
    };
}

fn fitAffine(points: [16]Point, values: [16]CM31) ![3]CM31 {
    var matrix: [3][4]CM31 = undefined;
    for (0..3) |row| {
        matrix[row] = .{
            CM31.one(),                   CM31.fromBase(points[row].x),
            CM31.fromBase(points[row].y), values[row],
        };
    }
    for (0..3) |column| {
        var pivot = column;
        while (pivot < 3 and matrix[pivot][column].isZero()) : (pivot += 1) {}
        if (pivot == 3) return error.SingularRows;
        std.mem.swap([4]CM31, &matrix[pivot], &matrix[column]);
        const inverse = try matrix[column][column].inv();
        for (0..4) |j| matrix[column][j] = matrix[column][j].mul(inverse);
        for (0..3) |row| {
            if (row == column) continue;
            const factor = matrix[row][column];
            for (0..4) |j| matrix[row][j] = matrix[row][j].sub(factor.mul(matrix[column][j]));
        }
    }
    return .{ matrix[0][3], matrix[1][3], matrix[2][3] };
}

fn checkSource(
    allocator: std.mem.Allocator,
    kind: SourceKind,
    domain: core.poly.circle.domain.CircleDomain,
    sample: SecurePoint,
    source_bound_log: u32,
) !void {
    var points: [16]Point = undefined;
    var source: [16]M31 = undefined;
    for (0..16) |row| {
        const p = domain.at(core.utils.bitReverseIndex(row, 4));
        points[row] = p;
        source[row] = sourceAt(kind, p);
    }
    const claim = claimAt(kind, sample);
    const evaluation = try prover.poly.circle.CircleEvaluation.init(domain, &source);
    var polynomial = try prover.poly.circle.poly.interpolateFromEvaluation(allocator, evaluation);
    defer polynomial.deinit(allocator);
    try std.testing.expect(polynomial.evalAtPoint(sample).eql(claim));

    const half = M31.fromCanonical(1073741824);
    const admitted_slot: ?usize = switch (kind) {
        .one => 0,
        .y => 1,
        .x => 2,
        .xy => 3,
        .x_squared => null,
    };
    for (polynomial.coefficients(), 0..) |coefficient, slot| {
        const expected = if (admitted_slot) |one_slot|
            (if (slot == one_slot) M31.one() else M31.zero())
        else
            (if (slot == 0 or slot == 4) half else M31.zero());
        try std.testing.expect(coefficient.eql(expected));
    }
    const columns = [_][]const M31{&source};
    if (admitted_slot != null) {
        try prover.pcs.paired_two_height_experimental.validateSourceDegree(
            allocator,
            domain,
            &columns,
            source_bound_log,
        );
    } else {
        try std.testing.expectError(error.SourceDegreeExceeded, prover.pcs.paired_two_height_experimental.validateSourceDegree(
            allocator,
            domain,
            &columns,
            source_bound_log,
        ));
    }

    const x0 = sample.x.c0;
    const x1 = sample.x.c1;
    const y0 = sample.y.c0;
    const y1 = sample.y.c1;
    const scale = QM31.fromU32Unchecked(0, 0, 1, 0)
        .mulCM31(y1.neg().add(y1.neg()));
    const batch = try prover.pcs.paired_two_height_experimental.pairedHeight(
        allocator,
        domain,
        &columns,
        &.{claim},
        sample,
        .{ .batch = QM31.one() },
    );
    defer allocator.free(batch);
    var own: [16]CM31 = undefined;
    for (points, 0..) |p, row| {
        const interpolation = claim.c0.add(claim.c1.mul(
            try CM31.fromBase(p.y).sub(y0).div(y1),
        ));
        const denominator = x0.sub(CM31.fromBase(p.x)).mul(y1)
            .sub(y0.sub(CM31.fromBase(p.y)).mul(x1));
        try std.testing.expect(!denominator.isZero());
        own[row] = try CM31.fromBase(source[row]).sub(interpolation).div(denominator);
        const expected_native = QM31.fromBase(source[row]).add(scale.mulCM31(own[row]));
        try std.testing.expect(batch[row].eql(expected_native));
    }
    const quotient = try fitAffine(points, own);
    for (points, own) |p, actual| {
        const expected = quotient[0]
            .add(quotient[1].mulM31(p.x))
            .add(quotient[2].mulM31(p.y));
        try std.testing.expect(actual.eql(expected));
    }
    const edge = y1.mul(quotient[1]).add(x1.mul(quotient[2]));
    if (admitted_slot != null) {
        try std.testing.expect(edge.isZero());
    } else {
        // Exact fifth-coordinate obstruction y1*b+x1*c from S31 #230.
        try std.testing.expect(!edge.isZero());
        try std.testing.expect(quotient[0].eql(CM31.fromU32Unchecked(1777893936, 1429241158)));
        try std.testing.expect(quotient[1].eql(CM31.fromU32Unchecked(1978046109, 742432526)));
        try std.testing.expect(quotient[2].eql(CM31.fromU32Unchecked(1340263512, 1618953911)));
    }
}

test "CAS07 exact Gate roster has a low-degree quotient x-square edge counterexample" {
    var columns = [_]u16{0} ** core.pcs.transposed_merkle_sparse_heights_experimental.MAX_HEIGHTS;
    columns[0] = 51; // source log 20
    columns[2] = 8;
    columns[4] = 15;
    columns[6] = 8;
    columns[11] = 28;
    columns[12] = 8;
    columns[16] = 193; // source log 4, the smallest occupied Gate height
    const profile = core.pcs.paired_sparse_cascade_heights_experimental.Profile{
        .source = .{
            .largest_log_size = 20,
            .height_count = 17,
            .columns = columns,
            .query_count = 32,
        },
        .log_blowup = 2,
    };
    try profile.validate();
    try std.testing.expectEqual(@as(usize, 2), profile.terminalLength());
    const min_source_log = profile.source.largest_log_size -
        @as(u32, @intCast(profile.source.height_count - 1));
    const source_bound_log = min_source_log - profile.log_blowup;
    try std.testing.expectEqual(@as(u32, 4), min_source_log);
    try std.testing.expectEqual(@as(u32, 2), source_bound_log);

    const sample = core.circle.SECURE_FIELD_CIRCLE_GEN.mul(17);
    try std.testing.expect(sample.isOnCircle());
    try std.testing.expect(!sample.y.c1.isZero());
    const domain = core.poly.circle.canonic.CanonicCoset.new(min_source_log).circleDomain();
    for ([_]SourceKind{ .one, .y, .x, .xy, .x_squared }) |kind|
        try checkSource(std.testing.allocator, kind, domain, sample, source_bound_log);
}

// The formulas below are the CM31 specialization of
// S31.Gadgets.PcsFri.GateFourSlotNativeMap. They are independent of the
// native pairedHeight numerator and its coefficient builder.
fn fourSlotAt(coefficients: [4]M31, point: Point) M31 {
    return coefficients[0]
        .add(coefficients[1].mul(point.y))
        .add(coefficients[2].mul(point.x))
        .add(coefficients[3].mul(point.x).mul(point.y));
}

fn fourSlotClaim(coefficients: [4]M31, point: SecurePoint) QM31 {
    return QM31.fromBase(coefficients[0])
        .add(point.y.mulM31(coefficients[1]))
        .add(point.x.mulM31(coefficients[2]))
        .add(point.x.mul(point.y).mulM31(coefficients[3]));
}

test "CAS07 four-slot quotient coefficient map matches native H=1 witness for varied sources" {
    const allocator = std.testing.allocator;
    const domain = core.poly.circle.canonic.CanonicCoset.new(4).circleDomain();
    const tuples = [_][4]u32{
        .{ 0, 0, 0, 0 },
        .{ 1, 0, 0, 0 },
        .{ 0, 1, 0, 0 },
        .{ 0, 0, 1, 0 },
        .{ 0, 0, 0, 1 },
        .{ 3, 5, 7, 11 },
        .{ 2147483646, 19, 0, 37 },
        .{ 1234567, 7654321, 1111111, 3333333 },
    };
    for ([_]u32{ 17, 23 }) |sample_multiplier| {
        const point = core.circle.SECURE_FIELD_CIRCLE_GEN.mul(sample_multiplier);
        try std.testing.expect(point.isOnCircle());
        const x0 = point.x.c0;
        const x1 = point.x.c1;
        const y0 = point.y.c0;
        const y1 = point.y.c1;
        try std.testing.expect(!y1.isZero());
        const norm = x1.square().add(y1.square());
        try std.testing.expect(!norm.isZero());
        const determinant = x0.mul(y1).sub(y0.mul(x1));
        const u = QM31.fromU32Unchecked(0, 0, 1, 0);
        const scale = u.mulCM31(y1.neg().add(y1.neg()));
        for (tuples) |raw| {
            var coefficients: [4]M31 = undefined;
            for (raw, 0..) |value, i| coefficients[i] = M31.fromCanonical(value);
            var source: [16]M31 = undefined;
            for (&source, 0..) |*value, i| {
                const row = domain.at(core.utils.bitReverseIndex(i, 4));
                value.* = fourSlotAt(coefficients, row);
            }
            const columns = [_][]const M31{&source};
            try prover.pcs.paired_two_height_experimental.validateSourceDegree(
                allocator,
                domain,
                &columns,
                2,
            );
            const claim = fourSlotClaim(coefficients, point);
            const c0 = CM31.fromBase(coefficients[0]);
            const c1 = CM31.fromBase(coefficients[1]);
            const c2 = CM31.fromBase(coefficients[2]);
            const c3 = CM31.fromBase(coefficients[3]);
            const v0 = c0.add(c1.mul(y0)).add(c2.mul(x0))
                .add(c3.mul(x0.mul(y0).add(core.fields.qm31.R.mul(x1).mul(y1))));
            const v1 = c1.mul(y1).add(c2.mul(x1))
                .add(c3.mul(x0.mul(y1).add(x1.mul(y0))));
            try std.testing.expect(claim.eql(.{ .c0 = v0, .c1 = v1 }));

            const a = (try c2.neg().div(y1)).add(try c3.mul(determinant).mul(x1)
                .div(y1.mul(norm)));
            const b = try c3.mul(x1).div(norm);
            const c = try c3.neg().mul(y1).div(norm);
            try std.testing.expect(y1.mul(b).add(x1.mul(c)).isZero());

            const evaluation = try prover.poly.circle.CircleEvaluation.init(domain, &source);
            var polynomial = try prover.poly.circle.poly.interpolateFromEvaluation(allocator, evaluation);
            defer polynomial.deinit(allocator);
            try std.testing.expect(polynomial.evalAtPoint(point).eql(claim));
            const native = try prover.pcs.paired_two_height_experimental.pairedHeight(
                allocator,
                domain,
                &columns,
                &.{claim},
                point,
                .{ .batch = QM31.one() },
            );
            defer allocator.free(native);
            for (source, native, 0..) |value, actual, i| {
                const row = domain.at(core.utils.bitReverseIndex(i, 4));
                const row_x = CM31.fromBase(row.x);
                const row_y = CM31.fromBase(row.y);
                const affine = v0.add(v1.mul(try row_y.sub(y0).div(y1)));
                const line = x0.sub(row_x).mul(y1).sub(y0.sub(row_y).mul(x1));
                try std.testing.expect(!line.isZero());
                const mapped_quotient = a.add(b.mul(row_x)).add(c.mul(row_y));
                try std.testing.expect(CM31.fromBase(value).eql(
                    affine.add(line.mul(mapped_quotient)),
                ));
                const divided_quotient = try CM31.fromBase(value).sub(affine).div(line);
                try std.testing.expect(divided_quotient.eql(mapped_quotient));
                const expected_native = QM31.fromBase(value).add(scale.mulCM31(mapped_quotient));
                try std.testing.expect(actual.eql(expected_native));
            }
        }
    }
}
