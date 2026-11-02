const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const canonic = @import("stwo_core").poly.circle.canonic;
const prover_poly = @import("../poly/circle/poly.zig");
const prover_twiddles = @import("../poly/twiddles.zig");
const secure_column = @import("../secure_column.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;
const SecureColumnByCoords = secure_column.SecureColumnByCoords;

pub const ForField = @import("accumulation_family.zig").ForField;
const Default = ForField(QM31);
pub const AccumulationError = Default.AccumulationError;
pub const ColumnRequest = Default.ColumnRequest;
pub const ColumnAccumulator = Default.ColumnAccumulator;
pub const DomainEvaluationAccumulator = Default.DomainEvaluationAccumulator;
pub const generateSecurePowers = Default.generateSecurePowers;
const constantColumnValue = Default.constantColumnValue;

test "prover air accumulation: polynomial extension is allocated and resource accounted" {
    const allocator = std.testing.allocator;
    const values = [_]QM31{
        QM31.fromU32Unchecked(1, 0, 0, 0),
        QM31.fromU32Unchecked(2, 0, 0, 0),
        QM31.fromU32Unchecked(3, 0, 0, 0),
        QM31.fromU32Unchecked(4, 0, 0, 0),
    };
    var source = try SecureColumnByCoords.fromSecureSlice(allocator, &values);
    defer source.deinit(allocator);

    var accumulator = try DomainEvaluationAccumulator.init(
        allocator,
        QM31.fromU32Unchecked(7, 0, 0, 0),
        3,
        1,
    );
    defer accumulator.deinit();
    try accumulator.beginPolynomialExtensionV1();
    try accumulator.accumulateColumn(2, &source);
    accumulator.endPolynomialExtensionV1();
    try std.testing.expect(accumulator.hasPolynomialExtensions());
    // target secure column: 8 rows * 4 coords * 4B = 128B;
    // target twiddle pair: 8 base values * 4B = 32B;
    // conservative final output: another 128B.
    try std.testing.expectEqual(
        @as(usize, 288),
        try accumulator.polynomialExtensionResourceBytes(),
    );

    var caller_owned = try SecureColumnByCoords.uninitialized(allocator, 8);
    defer caller_owned.deinit(allocator);
    try std.testing.expectError(
        error.PolynomialExtensionRequiresAllocation,
        accumulator.finalizeInto(&caller_owned),
    );

    var extended = try accumulator.finalize();
    defer extended.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 8), extended.len());
    try std.testing.expect(!accumulator.hasPolynomialExtensions());
}

test "prover air accumulation: generate secure powers" {
    const alloc = std.testing.allocator;
    const alpha = QM31.fromU32Unchecked(2, 0, 0, 0);
    const powers = try generateSecurePowers(alloc, alpha, 4);
    defer alloc.free(powers);

    try std.testing.expect(powers[0].eql(QM31.one()));
    try std.testing.expect(powers[1].eql(alpha));
    try std.testing.expect(powers[2].eql(alpha.square()));
    try std.testing.expect(powers[3].eql(alpha.square().mul(alpha)));
}

test "prover air accumulation: lifted combination matches direct formula" {
    const alloc = std.testing.allocator;
    const alpha = QM31.fromU32Unchecked(3, 0, 0, 0);

    var acc = try DomainEvaluationAccumulator.init(
        alloc,
        alpha,
        3,
        2,
    );
    defer acc.deinit();

    const col_large_values = [_]QM31{
        QM31.fromU32Unchecked(1, 0, 0, 0),
        QM31.fromU32Unchecked(2, 0, 0, 0),
        QM31.fromU32Unchecked(3, 0, 0, 0),
        QM31.fromU32Unchecked(4, 0, 0, 0),
        QM31.fromU32Unchecked(5, 0, 0, 0),
        QM31.fromU32Unchecked(6, 0, 0, 0),
        QM31.fromU32Unchecked(7, 0, 0, 0),
        QM31.fromU32Unchecked(8, 0, 0, 0),
    };
    const col_small_values = [_]QM31{
        QM31.fromU32Unchecked(10, 0, 0, 0),
        QM31.fromU32Unchecked(20, 0, 0, 0),
        QM31.fromU32Unchecked(30, 0, 0, 0),
        QM31.fromU32Unchecked(40, 0, 0, 0),
    };

    var col_large = try SecureColumnByCoords.fromSecureSlice(alloc, col_large_values[0..]);
    defer col_large.deinit(alloc);
    var col_small = try SecureColumnByCoords.fromSecureSlice(alloc, col_small_values[0..]);
    defer col_small.deinit(alloc);

    // First column uses alpha^(2-1)=alpha, second uses alpha^0=1.
    try acc.accumulateColumn(3, &col_large);
    try acc.accumulateColumn(2, &col_small);

    var combined = try acc.finalize();
    defer combined.deinit(alloc);

    const combined_vec = try combined.toVec(alloc);
    defer alloc.free(combined_vec);

    const shift: u32 = 1;
    const shift_amt: std.math.Log2Int(usize) = @intCast(shift + 1);
    for (combined_vec, 0..) |value, position| {
        const idx_small = ((position >> shift_amt) << 1) + (position & 1);
        const expected = col_large_values[position].mul(alpha).add(col_small_values[idx_small]);
        try std.testing.expect(value.eql(expected));
    }
}

test "prover air accumulation: detects unused and missing coefficients" {
    const alloc = std.testing.allocator;
    const alpha = QM31.fromU32Unchecked(5, 0, 0, 0);

    var acc = try DomainEvaluationAccumulator.init(alloc, alpha, 2, 1);
    defer acc.deinit();

    const values = [_]QM31{
        QM31.fromU32Unchecked(1, 0, 0, 0),
        QM31.fromU32Unchecked(2, 0, 0, 0),
        QM31.fromU32Unchecked(3, 0, 0, 0),
        QM31.fromU32Unchecked(4, 0, 0, 0),
    };
    var col = try SecureColumnByCoords.fromSecureSlice(alloc, values[0..]);
    defer col.deinit(alloc);

    try std.testing.expectError(AccumulationError.UnusedCoefficients, acc.finalize());

    try acc.accumulateColumn(2, &col);
    try std.testing.expectError(AccumulationError.NotEnoughCoefficients, acc.accumulateColumn(2, &col));
}

test "prover air accumulation: columns API assigns tail coefficient chunks" {
    const alloc = std.testing.allocator;
    const alpha = QM31.fromU32Unchecked(2, 0, 0, 0);

    var acc = try DomainEvaluationAccumulator.init(alloc, alpha, 2, 3);
    defer acc.deinit();

    const requests = [_]ColumnRequest{
        .{ .log_size = 1, .n_cols = 2 },
        .{ .log_size = 2, .n_cols = 1 },
    };
    const cols = try acc.columns(alloc, requests[0..]);
    defer alloc.free(cols);

    try std.testing.expectEqual(@as(u32, 2), acc.logSize());
    try std.testing.expectEqual(@as(usize, 2), cols[0].random_coeff_powers.len);
    try std.testing.expectEqual(@as(usize, 1), cols[1].random_coeff_powers.len);
    try std.testing.expect(cols[0].random_coeff_powers[0].eql(alpha));
    try std.testing.expect(cols[0].random_coeff_powers[1].eql(alpha.square()));
    try std.testing.expect(cols[1].random_coeff_powers[0].eql(QM31.one()));

    var col0 = cols[0];
    var col1 = cols[1];
    col0.accumulate(0, QM31.fromU32Unchecked(7, 0, 0, 0));
    col0.accumulate(0, QM31.fromU32Unchecked(5, 0, 0, 0));
    col1.accumulate(3, QM31.fromU32Unchecked(9, 0, 0, 0));

    try std.testing.expect(col0.col.at(0).eql(QM31.fromU32Unchecked(12, 0, 0, 0)));
    try std.testing.expect(col1.col.at(3).eql(QM31.fromU32Unchecked(9, 0, 0, 0)));
}

test "prover air accumulation: finalize transfers sole max-domain bucket" {
    const alloc = std.testing.allocator;
    var acc = try DomainEvaluationAccumulator.init(
        alloc,
        QM31.fromU32Unchecked(3, 0, 0, 0),
        3,
        1,
    );
    defer acc.deinit();

    const cols = try acc.columns(alloc, &.{.{ .log_size = 3, .n_cols = 1 }});
    defer alloc.free(cols);
    var column = cols[0];
    for (0..8) |index| {
        column.accumulate(index, QM31.fromU32Unchecked(@intCast(index + 1), 0, 0, 0));
    }
    const original_ptr = column.col.columns[0].ptr;

    var out = try acc.finalize();
    defer out.deinit(alloc);
    try std.testing.expectEqual(original_ptr, out.columns[0].ptr);
    for (0..8) |index| {
        try std.testing.expect(out.at(index).eql(
            QM31.fromU32Unchecked(@intCast(index + 1), 0, 0, 0),
        ));
    }
}

test "prover air accumulation: merge combines sub_accumulations" {
    const alloc = std.testing.allocator;
    const alpha = QM31.fromU32Unchecked(3, 0, 0, 0);

    // Create two accumulators that accumulate into the same log_size bucket
    // using initForComponent with pre-assigned power indices.
    const total_constraints: usize = 2;
    const powers = try generateSecurePowers(alloc, alpha, total_constraints);
    defer alloc.free(powers);

    // Accumulator A gets power index 2 (will consume 1 -> lands at index 1 = alpha)
    var acc_a = try DomainEvaluationAccumulator.initForComponent(powers, alloc, 2, 2);
    defer acc_a.deinit();

    // Accumulator B gets power index 1 (will consume 1 -> lands at index 0 = 1)
    var acc_b = try DomainEvaluationAccumulator.initForComponent(powers, alloc, 2, 1);
    defer acc_b.deinit();

    const vals_a = [_]QM31{
        QM31.fromU32Unchecked(1, 0, 0, 0),
        QM31.fromU32Unchecked(2, 0, 0, 0),
        QM31.fromU32Unchecked(3, 0, 0, 0),
        QM31.fromU32Unchecked(4, 0, 0, 0),
    };
    const vals_b = [_]QM31{
        QM31.fromU32Unchecked(10, 0, 0, 0),
        QM31.fromU32Unchecked(20, 0, 0, 0),
        QM31.fromU32Unchecked(30, 0, 0, 0),
        QM31.fromU32Unchecked(40, 0, 0, 0),
    };

    var col_a = try SecureColumnByCoords.fromSecureSlice(alloc, vals_a[0..]);
    defer col_a.deinit(alloc);
    var col_b = try SecureColumnByCoords.fromSecureSlice(alloc, vals_b[0..]);
    defer col_b.deinit(alloc);

    try acc_a.accumulateColumn(2, &col_a);
    try acc_b.accumulateColumn(2, &col_b);

    // Merge B into A
    acc_a.merge(&acc_b);

    // After merge, force next_power_index = 0 for finalize
    acc_a.next_power_index = 0;
    var combined = try acc_a.finalize();
    defer combined.deinit(alloc);

    // Also compute the sequential reference
    var ref_acc = try DomainEvaluationAccumulator.init(alloc, alpha, 2, 2);
    defer ref_acc.deinit();
    try ref_acc.accumulateColumn(2, &col_a);
    try ref_acc.accumulateColumn(2, &col_b);
    var ref_combined = try ref_acc.finalize();
    defer ref_combined.deinit(alloc);

    // Compare
    const combined_vec = try combined.toVec(alloc);
    defer alloc.free(combined_vec);
    const ref_vec = try ref_combined.toVec(alloc);
    defer alloc.free(ref_vec);

    try std.testing.expectEqual(combined_vec.len, ref_vec.len);
    for (combined_vec, ref_vec) |c, r| {
        try std.testing.expect(c.eql(r));
    }
}

test "prover air accumulation: merge transfers ownership for empty slots" {
    const alloc = std.testing.allocator;
    const alpha = QM31.fromU32Unchecked(2, 0, 0, 0);

    const total_constraints: usize = 2;
    const powers = try generateSecurePowers(alloc, alpha, total_constraints);
    defer alloc.free(powers);

    // A writes to log_size 3, B writes to log_size 2 -> non-overlapping buckets
    var acc_a = try DomainEvaluationAccumulator.initForComponent(powers, alloc, 3, 2);
    defer acc_a.deinit();
    var acc_b = try DomainEvaluationAccumulator.initForComponent(powers, alloc, 3, 1);
    defer acc_b.deinit();

    const large_vals = [_]QM31{
        QM31.fromU32Unchecked(1, 0, 0, 0),
        QM31.fromU32Unchecked(2, 0, 0, 0),
        QM31.fromU32Unchecked(3, 0, 0, 0),
        QM31.fromU32Unchecked(4, 0, 0, 0),
        QM31.fromU32Unchecked(5, 0, 0, 0),
        QM31.fromU32Unchecked(6, 0, 0, 0),
        QM31.fromU32Unchecked(7, 0, 0, 0),
        QM31.fromU32Unchecked(8, 0, 0, 0),
    };
    const small_vals = [_]QM31{
        QM31.fromU32Unchecked(10, 0, 0, 0),
        QM31.fromU32Unchecked(20, 0, 0, 0),
        QM31.fromU32Unchecked(30, 0, 0, 0),
        QM31.fromU32Unchecked(40, 0, 0, 0),
    };

    var col_large = try SecureColumnByCoords.fromSecureSlice(alloc, large_vals[0..]);
    defer col_large.deinit(alloc);
    var col_small = try SecureColumnByCoords.fromSecureSlice(alloc, small_vals[0..]);
    defer col_small.deinit(alloc);

    try acc_a.accumulateColumn(3, &col_large);
    try acc_b.accumulateColumn(2, &col_small);

    // Merge B into A: A has log_size 3 only, B has log_size 2 only
    // So B's log_size=2 slot should be transferred to A.
    acc_a.merge(&acc_b);

    // B's slot should now be null (ownership transferred)
    try std.testing.expect(acc_b.sub_accumulations[2] == null);
    // A should now have both
    try std.testing.expect(acc_a.sub_accumulations[3] != null);
    try std.testing.expect(acc_a.sub_accumulations[2] != null);
}

test "prover air accumulation: constants match materialized columns after merge" {
    const alloc = std.testing.allocator;
    const alpha = QM31.fromU32Unchecked(3, 1, 0, 0);
    const value_a = QM31.fromU32Unchecked(7, 2, 1, 0);
    const value_b = QM31.fromU32Unchecked(11, 0, 4, 1);

    const powers = try generateSecurePowers(alloc, alpha, 2);
    defer alloc.free(powers);
    var acc_a = try DomainEvaluationAccumulator.initForComponent(powers, alloc, 3, 2);
    defer acc_a.deinit();
    var acc_b = try DomainEvaluationAccumulator.initForComponent(powers, alloc, 3, 1);
    defer acc_b.deinit();
    try acc_a.accumulateConstant(3, value_a);
    try acc_b.accumulateConstant(2, value_b);
    acc_a.merge(&acc_b);
    acc_a.next_power_index = 0;
    var combined = try acc_a.finalize();
    defer combined.deinit(alloc);

    var reference = try DomainEvaluationAccumulator.init(alloc, alpha, 3, 2);
    defer reference.deinit();
    const values_a = [_]QM31{value_a} ** 8;
    const values_b = [_]QM31{value_b} ** 4;
    var col_a = try SecureColumnByCoords.fromSecureSlice(alloc, &values_a);
    defer col_a.deinit(alloc);
    var col_b = try SecureColumnByCoords.fromSecureSlice(alloc, &values_b);
    defer col_b.deinit(alloc);
    try reference.accumulateColumn(3, &col_a);
    try reference.accumulateColumn(2, &col_b);
    var expected = try reference.finalize();
    defer expected.deinit(alloc);

    for (0..combined.len()) |row| {
        try std.testing.expect(combined.at(row).eql(expected.at(row)));
    }
}

test "prover air accumulation: constant columns bypass domain buckets" {
    const alloc = std.testing.allocator;
    const alpha = QM31.fromU32Unchecked(3, 1, 0, 0);
    const constant = QM31.fromU32Unchecked(7, 2, 1, 0);
    const constant_values = [_]QM31{constant} ** 8;
    const varying_values = [_]QM31{
        QM31.fromU32Unchecked(1, 0, 0, 0),
        QM31.fromU32Unchecked(2, 0, 0, 0),
        QM31.fromU32Unchecked(3, 0, 0, 0),
        QM31.fromU32Unchecked(4, 0, 0, 0),
        QM31.fromU32Unchecked(5, 0, 0, 0),
        QM31.fromU32Unchecked(6, 0, 0, 0),
        QM31.fromU32Unchecked(7, 0, 0, 0),
        QM31.fromU32Unchecked(8, 0, 0, 0),
    };
    var constant_column = try SecureColumnByCoords.fromSecureSlice(alloc, &constant_values);
    defer constant_column.deinit(alloc);
    var varying_column = try SecureColumnByCoords.fromSecureSlice(alloc, &varying_values);
    defer varying_column.deinit(alloc);

    try std.testing.expect(constantColumnValue(&constant_column).?.eql(constant));
    try std.testing.expectEqual(null, constantColumnValue(&varying_column));

    var acc = try DomainEvaluationAccumulator.init(alloc, alpha, 3, 2);
    defer acc.deinit();
    try acc.accumulateColumn(3, &constant_column);
    try std.testing.expect(acc.sub_accumulations[3] == null);
    try acc.accumulateColumn(3, &varying_column);
    try std.testing.expect(acc.sub_accumulations[3] != null);

    var combined = try acc.finalize();
    defer combined.deinit(alloc);
    for (0..combined.len()) |row| {
        const expected = constant.mul(alpha).add(varying_values[row]);
        try std.testing.expect(combined.at(row).eql(expected));
    }
}
