//! Contract tests for caller-owned, allocation-free domain finalization.

const std = @import("std");
const qm31 = @import("stwo_core").fields.qm31;
const accumulation = @import("accumulation.zig");
const secure_column = @import("../secure_column.zig");

const AccumulationError = accumulation.AccumulationError;
const DomainEvaluationAccumulator = accumulation.DomainEvaluationAccumulator;
const QM31 = qm31.QM31;
const SecureColumnByCoords = secure_column.SecureColumnByCoords;

fn expectSecureColumnBytesEqual(
    expected: *const SecureColumnByCoords,
    actual: *const SecureColumnByCoords,
) !void {
    try std.testing.expectEqual(expected.len(), actual.len());
    inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
        try std.testing.expectEqualSlices(
            u8,
            std.mem.sliceAsBytes(expected.columns[coordinate]),
            std.mem.sliceAsBytes(actual.columns[coordinate]),
        );
    }
}

fn accumulateMixedDomainFixture(
    accumulator: *DomainEvaluationAccumulator,
    large: *const SecureColumnByCoords,
    small: *const SecureColumnByCoords,
) !void {
    try accumulator.accumulateColumn(3, large);
    try accumulator.accumulateConstant(1, QM31.fromU32Unchecked(17, 19, 23, 29));
    try accumulator.accumulateColumn(2, small);
    try accumulator.accumulateConstant(3, QM31.fromU32Unchecked(31, 37, 41, 43));
}

test "prover air accumulation: finalizeInto is allocation-free and byte-identical" {
    const allocator = std.testing.allocator;
    const alpha = QM31.fromU32Unchecked(3, 5, 7, 11);
    const large_values = [_]QM31{
        QM31.fromU32Unchecked(1, 11, 21, 31),
        QM31.fromU32Unchecked(2, 12, 22, 32),
        QM31.fromU32Unchecked(3, 13, 23, 33),
        QM31.fromU32Unchecked(4, 14, 24, 34),
        QM31.fromU32Unchecked(5, 15, 25, 35),
        QM31.fromU32Unchecked(6, 16, 26, 36),
        QM31.fromU32Unchecked(7, 17, 27, 37),
        QM31.fromU32Unchecked(8, 18, 28, 38),
    };
    const small_values = [_]QM31{
        QM31.fromU32Unchecked(41, 51, 61, 71),
        QM31.fromU32Unchecked(42, 52, 62, 72),
        QM31.fromU32Unchecked(43, 53, 63, 73),
        QM31.fromU32Unchecked(44, 54, 64, 74),
    };
    var large = try SecureColumnByCoords.fromSecureSlice(allocator, &large_values);
    defer large.deinit(allocator);
    var small = try SecureColumnByCoords.fromSecureSlice(allocator, &small_values);
    defer small.deinit(allocator);

    var reference = try DomainEvaluationAccumulator.init(allocator, alpha, 3, 4);
    defer reference.deinit();
    try accumulateMixedDomainFixture(&reference, &large, &small);
    var expected = try reference.finalize();
    defer expected.deinit(allocator);

    var accumulator = try DomainEvaluationAccumulator.init(allocator, alpha, 3, 4);
    defer accumulator.deinit();
    try accumulateMixedDomainFixture(&accumulator, &large, &small);
    const large_bucket_ptr = accumulator.sub_accumulations[3].?.columns[0].ptr;
    const small_bucket_ptr = accumulator.sub_accumulations[2].?.columns[0].ptr;

    var actual = try SecureColumnByCoords.uninitialized(allocator, 8);
    defer actual.deinit(allocator);
    const output_ptr = actual.columns[0].ptr;

    var failing = std.testing.FailingAllocator.init(allocator, .{
        .fail_index = 0,
        .resize_fail_index = 0,
    });
    const retained_allocator = accumulator.allocator;
    {
        accumulator.allocator = failing.allocator();
        defer accumulator.allocator = retained_allocator;
        try accumulator.finalizeInto(&actual);
    }
    try std.testing.expectEqual(@as(usize, 0), failing.alloc_index);
    try std.testing.expectEqual(@as(usize, 0), failing.resize_index);
    try std.testing.expect(!failing.has_induced_failure);

    try expectSecureColumnBytesEqual(&expected, &actual);
    try std.testing.expectEqual(output_ptr, actual.columns[0].ptr);
    try std.testing.expectEqual(
        large_bucket_ptr,
        accumulator.sub_accumulations[3].?.columns[0].ptr,
    );
    try std.testing.expectEqual(
        small_bucket_ptr,
        accumulator.sub_accumulations[2].?.columns[0].ptr,
    );

    // `finalizeInto` is non-consuming: the accumulator remains valid and owns
    // the same buckets after writing into caller-owned storage.
    var replay = try accumulator.finalize();
    defer replay.deinit(allocator);
    try expectSecureColumnBytesEqual(&expected, &replay);
}

test "prover air accumulation: finalizeInto rejects wrong output shape unchanged" {
    const allocator = std.testing.allocator;
    var accumulator = try DomainEvaluationAccumulator.init(
        allocator,
        QM31.fromU32Unchecked(3, 1, 4, 1),
        2,
        1,
    );
    defer accumulator.deinit();

    const values = [_]QM31{
        QM31.fromU32Unchecked(1, 2, 3, 4),
        QM31.fromU32Unchecked(5, 6, 7, 8),
        QM31.fromU32Unchecked(9, 10, 11, 12),
        QM31.fromU32Unchecked(13, 14, 15, 16),
    };
    var column = try SecureColumnByCoords.fromSecureSlice(allocator, &values);
    defer column.deinit(allocator);
    try accumulator.accumulateColumn(2, &column);
    const bucket_ptr = accumulator.sub_accumulations[2].?.columns[0].ptr;

    var wrong_shape = try SecureColumnByCoords.uninitialized(allocator, 2);
    defer wrong_shape.deinit(allocator);
    const sentinel = QM31.fromU32Unchecked(101, 103, 107, 109);
    for (0..wrong_shape.len()) |row| wrong_shape.set(row, sentinel);

    try std.testing.expectError(
        AccumulationError.ShapeMismatch,
        accumulator.finalizeInto(&wrong_shape),
    );
    for (0..wrong_shape.len()) |row| {
        try std.testing.expect(wrong_shape.at(row).eql(sentinel));
    }
    try std.testing.expectEqual(
        bucket_ptr,
        accumulator.sub_accumulations[2].?.columns[0].ptr,
    );
}

test "prover air accumulation: finalizeInto rejects unused coefficients unchanged" {
    const allocator = std.testing.allocator;
    var accumulator = try DomainEvaluationAccumulator.init(
        allocator,
        QM31.fromU32Unchecked(3, 1, 4, 1),
        2,
        1,
    );
    defer accumulator.deinit();

    var output = try SecureColumnByCoords.uninitialized(allocator, 4);
    defer output.deinit(allocator);
    const sentinel = QM31.fromU32Unchecked(127, 131, 137, 139);
    for (0..output.len()) |row| output.set(row, sentinel);

    try std.testing.expectError(
        AccumulationError.UnusedCoefficients,
        accumulator.finalizeInto(&output),
    );
    for (0..output.len()) |row| {
        try std.testing.expect(output.at(row).eql(sentinel));
    }
    try std.testing.expectEqual(@as(usize, 1), accumulator.next_power_index);
}
