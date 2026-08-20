//! Adversarial coverage for recursion QM31 add/sub/neg rows.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const full = @import("linear_ops.zig");
const full_relation = @import("linear_ops_relation.zig");
const support = @import("test_support.zig");
const witness = @import("linear_ops_witness.zig");

test "R-012 linear add and sub reject every committed-column mutation" {
    var definition = try full.build(std.testing.allocator, .generated);
    defer definition.deinit();
    inline for (.{ witness.Operation.add, witness.Operation.sub }) |operation| {
        const metadata = circuitMetadata(operation, 101 + 100 * @intFromEnum(operation));
        const honest = try witness.mainRow(.{
            .operation = operation,
            .lhs = QM31.fromU32Unchecked(3, 5, 7, 11),
            .rhs = QM31.fromU32Unchecked(13, 17, 19, 23),
            .circuit = metadata,
        });
        const preprocessed = witness.preprocessedRow(.{ .segment = .{
            .operation = operation,
            .circuit = metadata,
        } });
        for (0..witness.MAIN_COLUMN_COUNT) |column| {
            var forged = honest;
            forged[column] = forged[column].add(M31.one());
            try expectRejected(&definition, witness.logicalInputs(
                forged,
                preprocessed,
                .segment_leaf,
            ));
        }
    }
}

test "R-012 linear negation rejects every semantically live column mutation" {
    var definition = try full.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const metadata = circuitMetadata(.neg, 311);
    const honest = try witness.mainRow(.{
        .operation = .neg,
        .lhs = QM31.fromU32Unchecked(29, 31, 37, 41),
        .circuit = metadata,
    });
    const preprocessed = witness.preprocessedRow(.{ .segment = .{
        .operation = .neg,
        .circuit = metadata,
    } });
    const live_columns = [_]usize{
        0,  1, 2,  3,  4,  5,  6,  7,
        8,  9, 10, 11, 16, 17, 18, 19,
        20,
    };
    for (live_columns) |column| {
        var forged = honest;
        forged[column] = forged[column].add(M31.one());
        try expectRejected(&definition, witness.logicalInputs(
            forged,
            preprocessed,
            .segment_leaf,
        ));
    }
    // Negation deliberately has no right-hand relation edge. Its four RHS
    // limbs are semantically dead in the AIR and therefore canonicalized by
    // the only admitted witness writer instead of adding redundant roots.
    for (12..16) |column| {
        var unused = honest;
        unused[column] = unused[column].add(M31.one());
        try expectSatisfied(&definition, witness.logicalInputs(
            unused,
            preprocessed,
            .segment_leaf,
        ));
    }
}

test "R-012 linear rows reject flag schedule and proof-kind substitution" {
    var definition = try full.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const selected = circuitMetadata(.add, 401);
    const wrong = circuitMetadata(.sub, 801);
    const main = try witness.mainRow(.{
        .operation = .add,
        .lhs = QM31.fromU32Unchecked(2, 3, 5, 7),
        .rhs = QM31.fromU32Unchecked(11, 13, 17, 19),
        .circuit = selected,
    });
    const schedules = witness.PreprocessedRow{
        .segment = .{ .operation = .add, .circuit = selected },
        .binary = .{ .operation = .sub, .circuit = wrong },
    };
    const honest = witness.preprocessedRow(schedules);
    for (0..9) |column| {
        var forged = honest;
        forged[column] = forged[column].add(M31.one());
        try expectRejected(&definition, witness.logicalInputs(
            main,
            forged,
            .segment_leaf,
        ));
    }
    try expectRejected(&definition, witness.logicalInputs(main, honest, .binary_node));
    try expectRejected(&definition, witness.logicalInputs(main, honest, .empty_leaf));

    var multi_hot = main;
    multi_hot[@intFromEnum(witness.MainSource.is_sub)] = M31.one();
    try expectRejected(&definition, witness.logicalInputs(
        multi_hot,
        honest,
        .segment_leaf,
    ));
    var no_operation = main;
    no_operation[@intFromEnum(witness.MainSource.is_add)] = M31.zero();
    try expectRejected(&definition, witness.logicalInputs(
        no_operation,
        honest,
        .segment_leaf,
    ));
}

test "R-012 linear witness canonicalizes negation and rejects invalid rows atomically" {
    const metadata = circuitMetadata(.neg, 503);
    try std.testing.expectError(error.InvalidTraceRow, witness.mainRow(.{
        .operation = .neg,
        .lhs = QM31.one(),
        .rhs = QM31.one(),
        .circuit = metadata,
    }));
    var invalid_metadata = metadata;
    invalid_metadata.rhs_id = M31.one();
    try std.testing.expectError(error.InvalidTraceRow, witness.mainRow(.{
        .operation = .neg,
        .lhs = QM31.one(),
        .circuit = invalid_metadata,
    }));

    var definition = try full.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const binding = try witness.Binding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    const sentinel = M31.fromCanonical(0x6161);
    var storage: [witness.MAIN_COLUMN_COUNT][2]M31 = undefined;
    var columns: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    initializeColumns(witness.MAIN_COLUMN_COUNT, &storage, &columns, sentinel);
    try std.testing.expectError(error.InvalidTraceRow, executor.generateMainInto(
        &columns,
        &.{
            .{
                .operation = .add,
                .lhs = QM31.one(),
                .rhs = QM31.one(),
                .circuit = circuitMetadata(.add, 601),
            },
            .{
                .operation = .neg,
                .lhs = QM31.one(),
                .rhs = QM31.one(),
                .circuit = metadata,
            },
        },
        1,
    ));
    try expectSentinel(witness.MAIN_COLUMN_COUNT, &storage, sentinel);
}

test "R-012 linear interaction plan binds RHS liveness and odd final batch" {
    var definition = try full.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const plan = try full_relation.authenticate(&definition);
    const add = try witness.mainRow(.{
        .operation = .add,
        .lhs = QM31.fromU32Unchecked(2, 3, 5, 7),
        .rhs = QM31.fromU32Unchecked(11, 13, 17, 19),
        .circuit = circuitMetadata(.add, 701),
    });
    const neg = try witness.mainRow(.{
        .operation = .neg,
        .lhs = QM31.fromU32Unchecked(23, 29, 31, 37),
        .circuit = circuitMetadata(.neg, 801),
    });
    const add_entries = try plan.entries(&definition, add);
    const neg_entries = try plan.entries(&definition, neg);
    try std.testing.expect(add_entries[1].numerator.eql(QM31.one().neg()));
    try std.testing.expect(neg_entries[1].numerator.isZero());
    try std.testing.expectEqual(@as(?u8, 1), plan.compiled.batches[0].second);
    try std.testing.expectEqual(@as(?u8, null), plan.compiled.batches[1].second);

    var forged = plan;
    forged.compiled.events[1].weight = .{ .input = 0 };
    try std.testing.expectError(error.EventPlanMismatch, forged.validateAgainst(&definition));
    forged = plan;
    forged.compiled.batches[1].second = 0;
    try std.testing.expectError(error.BatchPlanMismatch, forged.validateAgainst(&definition));

    const rows = [_]full_relation.Row{ add, neg };
    const challenge = full_relation.Challenge.dummy();
    var interaction = try plan.generateInteraction(
        std.testing.allocator,
        &definition,
        &rows,
        1,
        challenge,
    );
    defer interaction.deinit(std.testing.allocator);
    interaction.columns[7][0] = interaction.columns[7][0].add(M31.one());
    try std.testing.expectError(
        error.InteractionColumnMismatch,
        plan.validateInteraction(
            std.testing.allocator,
            &definition,
            &rows,
            1,
            challenge,
            &interaction,
        ),
    );
}

test "R-012 linear bindings and preprocessing shapes fail before mutation" {
    var definition = try full.build(std.testing.allocator, .generated);
    defer definition.deinit();
    var binding = try witness.Binding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    binding.main[3].source = .is_sub;
    try std.testing.expectError(
        error.InvalidWitnessBinding,
        witness.Executor.init(&definition, &binding),
    );
    binding = try witness.Binding.canonical(&definition);
    binding.preprocessed[0].source = .segment_is_add;
    try std.testing.expectError(
        error.InvalidWitnessBinding,
        witness.Executor.init(&definition, &binding),
    );

    const sentinel = M31.fromCanonical(0x7171);
    var storage: [witness.PREPROCESSED_COLUMN_COUNT][2]M31 = undefined;
    var columns: [witness.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
    initializeColumns(witness.PREPROCESSED_COLUMN_COUNT, &storage, &columns, sentinel);
    columns[0] = storage[0][0..1];
    try std.testing.expectError(
        error.InvalidTraceShape,
        executor.generatePreprocessedInto(&columns, &.{.{}}, 1),
    );
    try expectSentinel(witness.PREPROCESSED_COLUMN_COUNT, &storage, sentinel);
}

fn expectSatisfied(
    definition: *const full.Definition,
    inputs: [full.LOGICAL_INPUT_COUNT]M31,
) !void {
    const values = try support.evaluateArena(std.testing.allocator, &definition.arena, &inputs);
    defer std.testing.allocator.free(values);
    for (0..full.DIRECT_CONSTRAINT_COUNT) |index| {
        try std.testing.expect(support.constraintAt(
            &definition.arena,
            &definition.constraints,
            values,
            index,
        ).isZero());
    }
}

fn expectRejected(
    definition: *const full.Definition,
    inputs: [full.LOGICAL_INPUT_COUNT]M31,
) !void {
    const values = try support.evaluateArena(std.testing.allocator, &definition.arena, &inputs);
    defer std.testing.allocator.free(values);
    for (0..full.DIRECT_CONSTRAINT_COUNT) |index| {
        if (!support.constraintAt(
            &definition.arena,
            &definition.constraints,
            values,
            index,
        ).isZero()) return;
    }
    return error.TestUnexpectedResult;
}

fn initializeColumns(
    comptime count: usize,
    storage: *[count][2]M31,
    columns: *[count][]M31,
    sentinel: M31,
) void {
    for (storage, columns) |*column_storage, *column| {
        @memset(column_storage, sentinel);
        column.* = column_storage;
    }
}

fn expectSentinel(
    comptime count: usize,
    storage: *const [count][2]M31,
    sentinel: M31,
) !void {
    for (storage) |column| {
        for (column) |value| try std.testing.expect(value.eql(sentinel));
    }
}

fn circuitMetadata(operation: witness.Operation, seed: u32) witness.CircuitMetadata {
    return .{
        .circuit_id = M31.fromCanonical(seed),
        .node_id = M31.fromCanonical(seed + 1),
        .lhs_id = M31.fromCanonical(seed + 2),
        .rhs_id = if (operation == .neg) M31.zero() else M31.fromCanonical(seed + 3),
        .uses = M31.fromCanonical(seed + 4),
    };
}
