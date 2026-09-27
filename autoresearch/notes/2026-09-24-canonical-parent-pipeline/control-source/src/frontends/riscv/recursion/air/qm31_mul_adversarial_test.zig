const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const qm31_mul = @import("qm31_mul.zig");
const support = @import("test_support.zig");
const witness = @import("qm31_mul_witness.zig");

test "R-012 typed QM31 multiplication rejects every corrupted output coordinate" {
    var definition = try qm31_mul.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const honest = support.rowFor(
        QM31.fromU32Unchecked(17, 31, 257, 65_537),
        QM31.fromU32Unchecked(19, 37, 263, 65_539),
    );
    for (0..4) |coordinate| {
        var forged = honest;
        forged[8 + coordinate] = forged[8 + coordinate].add(M31.one());
        const values = try support.evaluateQm31Mul(
            std.testing.allocator,
            &definition,
            &forged,
        );
        defer std.testing.allocator.free(values);
        for (0..4) |constraint_index| {
            const value = support.constraintValue(
                &definition,
                values,
                constraint_index,
            );
            if (constraint_index == coordinate) {
                try std.testing.expect(!value.isZero());
            } else {
                try std.testing.expect(value.isZero());
            }
        }
    }
}

test "R-012 typed QM31 multiplication rejects stale products after operand mutation" {
    var definition = try qm31_mul.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const honest = support.rowFor(
        QM31.fromU32Unchecked(3, 5, 7, 11),
        QM31.fromU32Unchecked(13, 17, 19, 23),
    );
    for (0..8) |input_coordinate| {
        var forged = honest;
        forged[input_coordinate] = forged[input_coordinate].add(M31.one());
        const values = try support.evaluateQm31Mul(
            std.testing.allocator,
            &definition,
            &forged,
        );
        defer std.testing.allocator.free(values);
        var rejected = false;
        for (0..4) |constraint_index| {
            rejected = rejected or !support.constraintValue(
                &definition,
                values,
                constraint_index,
            ).isZero();
        }
        try std.testing.expect(rejected);
    }
}

test "R-012 witness binding and destination geometry fail before mutation" {
    var definition = try qm31_mul.build(std.testing.allocator, .generated);
    defer definition.deinit();
    var binding = try witness.WitnessBinding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);

    binding.slots[0].source = .b_0;
    try std.testing.expectError(
        error.InvalidWitnessBinding,
        witness.Executor.init(&definition, &binding),
    );

    const sentinel = M31.fromCanonical(0x5151);
    var storage: [witness.PHYSICAL_COLUMN_COUNT][2]M31 = undefined;
    var columns: [witness.PHYSICAL_COLUMN_COUNT][]M31 = undefined;
    for (&storage, &columns) |*column_storage, *column| {
        @memset(column_storage, sentinel);
        column.* = column_storage;
    }
    columns[11] = storage[11][0..1];
    try std.testing.expectError(
        error.InvalidTraceShape,
        executor.generateMainInto(&columns, &.{.{
            .a = QM31.one(),
            .b = QM31.one(),
        }}, 1),
    );
    for (storage) |column_storage| {
        for (column_storage) |value| try std.testing.expect(value.eql(sentinel));
    }
}

test "R-012 QM31 multiplication definition rejects detached metadata" {
    var definition = try qm31_mul.build(std.testing.allocator, .generated);
    defer definition.deinit();

    definition.expected[0] = definition.columns.a[0];
    try std.testing.expectError(
        error.InvalidQm31MulDefinition,
        definition.validate(),
    );
}
