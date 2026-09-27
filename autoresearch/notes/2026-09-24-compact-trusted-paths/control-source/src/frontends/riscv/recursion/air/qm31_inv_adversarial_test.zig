//! Mutation-complete defensive evidence for recursion QM31 inversion.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const relation = @import("../../air/lang/relation.zig");
const full = @import("qm31_inv.zig");
const full_relation = @import("qm31_inv_relation.zig");
const support = @import("test_support.zig");
const witness = @import("qm31_inv_witness.zig");

test "R-012 QM31 inversion rejects every committed-column mutation" {
    var definition = try full.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const metadata = circuitMetadata(101);
    const honest = try witness.mainRow(.{
        .a = QM31.fromU32Unchecked(3, 5, 7, 11),
        .circuit = metadata,
    });
    const preprocessed = witness.preprocessedRow(.{ .segment = metadata });
    try expectSatisfied(&definition, witness.logicalInputs(
        honest,
        preprocessed,
        .segment_leaf,
    ));
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

test "R-012 QM31 inversion rejects selected schedule and proof-kind substitution" {
    var definition = try full.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const selected = circuitMetadata(211);
    const wrong = circuitMetadata(711);
    const main = try witness.mainRow(.{
        .a = QM31.fromU32Unchecked(13, 17, 19, 23),
        .circuit = selected,
    });
    const schedules = witness.PreprocessedRow{
        .segment = selected,
        .binary = wrong,
    };
    const honest = witness.preprocessedRow(schedules);
    for (0..5) |column| {
        var forged = honest;
        forged[column] = forged[column].add(M31.one());
        try expectRejected(&definition, witness.logicalInputs(
            main,
            forged,
            .segment_leaf,
        ));
    }
    try expectRejected(&definition, witness.logicalInputs(
        main,
        honest,
        .binary_node,
    ));
    try expectRejected(&definition, witness.logicalInputs(
        main,
        honest,
        .empty_leaf,
    ));
}

test "R-012 QM31 inversion wire entries bind order schema role weight and tuple" {
    var definition = try full.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const plan = try full_relation.authenticate(&definition);
    const metadata = circuitMetadata(307);
    const row = try witness.mainRow(.{
        .a = QM31.fromU32Unchecked(29, 31, 37, 41),
        .circuit = metadata,
    });
    const honest = try plan.entries(&definition, row);
    try plan.validateEntries(&definition, row, honest);
    try std.testing.expect(honest[0].numerator.eql(QM31.one().neg()));
    try std.testing.expect(honest[1].numerator.eql(QM31.fromBase(metadata.uses)));

    var forged = honest;
    forged[0].ordinal = 1;
    try std.testing.expectError(
        error.EntryOrderMismatch,
        plan.validateEntries(&definition, row, forged),
    );
    forged = honest;
    forged[0].schema = relation.id(.bitwise);
    try std.testing.expectError(
        error.EntrySchemaMismatch,
        plan.validateEntries(&definition, row, forged),
    );
    forged = honest;
    forged[0].schema_version += 1;
    try std.testing.expectError(
        error.EntrySchemaMismatch,
        plan.validateEntries(&definition, row, forged),
    );
    forged = honest;
    forged[0].role = .emit;
    try std.testing.expectError(
        error.EntryRoleMismatch,
        plan.validateEntries(&definition, row, forged),
    );
    forged = honest;
    forged[0].arity -= 1;
    try std.testing.expectError(
        error.EntryArityMismatch,
        plan.validateEntries(&definition, row, forged),
    );
    forged = honest;
    forged[0].numerator = forged[0].numerator.add(QM31.one());
    try std.testing.expectError(
        error.EntryNumeratorMismatch,
        plan.validateEntries(&definition, row, forged),
    );
    forged = honest;
    forged[0].values[5] = forged[0].values[5].add(QM31.one());
    try std.testing.expectError(
        error.EntryTupleMismatch,
        plan.validateEntries(&definition, row, forged),
    );
}

test "R-012 QM31 inversion interaction plan rejects every authority mutation" {
    var definition = try full.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const plan = try full_relation.authenticate(&definition);

    var forged = plan;
    forged.compiled.format_version += 1;
    try std.testing.expectError(error.FormatVersionMismatch, forged.validateAgainst(&definition));
    forged = plan;
    forged.compiled.semantic_digest[0] ^= 1;
    try std.testing.expectError(error.BindingSealMismatch, forged.validateAgainst(&definition));
    forged = plan;
    forged.compiled.events[0].value_columns[0] += 1;
    try std.testing.expectError(error.EventPlanMismatch, forged.validateAgainst(&definition));
    forged = plan;
    forged.compiled.events[1].weight = .{ .input = 0 };
    try std.testing.expectError(error.EventPlanMismatch, forged.validateAgainst(&definition));
    forged = plan;
    forged.compiled.events[0].role = .emit;
    try std.testing.expectError(error.EventPlanMismatch, forged.validateAgainst(&definition));
    forged = plan;
    forged.compiled.batches[0].second = null;
    try std.testing.expectError(error.BatchPlanMismatch, forged.validateAgainst(&definition));

    definition.events.output_weight = definition.main.in_circuit;
    try std.testing.expectError(error.InvalidQm31InvDefinition, definition.validate());
}

test "R-012 QM31 inversion interaction rejects columns claims closure and geometry" {
    var definition = try full.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const plan = try full_relation.authenticate(&definition);
    const rows = [_]full_relation.Row{
        try witness.mainRow(.{
            .a = QM31.fromU32Unchecked(2, 3, 5, 7),
            .circuit = circuitMetadata(401),
        }),
        try witness.mainRow(.{ .a = QM31.fromU32Unchecked(11, 13, 17, 19) }),
    };
    const challenge = full_relation.Challenge.dummy();
    var interaction = try plan.generateInteraction(
        std.testing.allocator,
        &definition,
        &rows,
        2,
        challenge,
    );
    defer interaction.deinit(std.testing.allocator);
    try plan.validateInteraction(
        std.testing.allocator,
        &definition,
        &rows,
        2,
        challenge,
        &interaction,
    );

    interaction.columns[0][0] = interaction.columns[0][0].add(M31.one());
    try std.testing.expectError(
        error.InteractionColumnMismatch,
        plan.validateInteraction(
            std.testing.allocator,
            &definition,
            &rows,
            2,
            challenge,
            &interaction,
        ),
    );
    interaction.columns[0][0] = interaction.columns[0][0].sub(M31.one());
    interaction.claims.sums[0] = interaction.claims.sums[0].add(QM31.one());
    try std.testing.expectError(
        error.ClaimMismatch,
        plan.validateInteraction(
            std.testing.allocator,
            &definition,
            &rows,
            2,
            challenge,
            &interaction,
        ),
    );
    interaction.claims.sums[0] = interaction.claims.sums[0].sub(QM31.one());
    var short = interaction;
    short.columns[0] = short.columns[0][0 .. short.columns[0].len - 1];
    try std.testing.expectError(
        error.InteractionGeometryMismatch,
        plan.validateInteraction(
            std.testing.allocator,
            &definition,
            &rows,
            2,
            challenge,
            &short,
        ),
    );
    const claims = interaction.claims;
    try claims.verifyClosure(claims.total().neg());
    try std.testing.expectError(
        error.RelationSumNonZero,
        claims.verifyClosure(claims.total().neg().add(QM31.one())),
    );
    const too_many = [_]full_relation.Row{rows[0]} ** 5;
    try std.testing.expectError(
        error.InvalidTraceShape,
        plan.generateInteraction(
            std.testing.allocator,
            &definition,
            &too_many,
            2,
            challenge,
        ),
    );
}

test "R-012 QM31 inversion bindings and destination shapes fail before mutation" {
    var definition = try full.build(std.testing.allocator, .generated);
    defer definition.deinit();
    var binding = try witness.Binding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    binding.main[0].source = .a_0;
    try std.testing.expectError(
        error.InvalidWitnessBinding,
        witness.Executor.init(&definition, &binding),
    );
    binding = try witness.Binding.canonical(&definition);
    binding.preprocessed[0].source = .segment_circuit_id;
    try std.testing.expectError(
        error.InvalidWitnessBinding,
        witness.Executor.init(&definition, &binding),
    );
    binding = try witness.Binding.canonical(&definition);
    std.mem.swap(@TypeOf(binding.parameters[0]), &binding.parameters[0], &binding.parameters[1]);
    try std.testing.expectError(
        error.InvalidWitnessBinding,
        witness.Executor.init(&definition, &binding),
    );

    const sentinel = M31.fromCanonical(0x5151);
    var main_storage: [witness.MAIN_COLUMN_COUNT][2]M31 = undefined;
    var main_columns: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    initializeColumns(witness.MAIN_COLUMN_COUNT, &main_storage, &main_columns, sentinel);
    main_columns[main_columns.len - 1] = main_storage[main_storage.len - 1][0..1];
    try std.testing.expectError(
        error.InvalidTraceShape,
        executor.generateMainInto(&main_columns, &.{.{ .a = QM31.one() }}, 1),
    );
    try expectSentinel(witness.MAIN_COLUMN_COUNT, &main_storage, sentinel);

    var preprocessing_storage: [witness.PREPROCESSED_COLUMN_COUNT][2]M31 = undefined;
    var preprocessing_columns: [witness.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
    initializeColumns(
        witness.PREPROCESSED_COLUMN_COUNT,
        &preprocessing_storage,
        &preprocessing_columns,
        sentinel,
    );
    preprocessing_columns[0] = preprocessing_storage[0][0..1];
    try std.testing.expectError(
        error.InvalidTraceShape,
        executor.generatePreprocessedInto(&preprocessing_columns, &.{.{}}, 1),
    );
    try expectSentinel(
        witness.PREPROCESSED_COLUMN_COUNT,
        &preprocessing_storage,
        sentinel,
    );
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

fn circuitMetadata(seed: u32) witness.CircuitMetadata {
    return .{
        .circuit_id = M31.fromCanonical(seed),
        .node_id = M31.fromCanonical(seed + 1),
        .lhs_id = M31.fromCanonical(seed + 2),
        .uses = M31.fromCanonical(seed + 3),
    };
}
