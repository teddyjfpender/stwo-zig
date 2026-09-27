const std = @import("std");
const stwo_core = @import("stwo_core");
const m31 = stwo_core.fields.m31;
const M31 = m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const degree = @import("../../air/lang/degree.zig");
const digest = @import("../../air/lang/digest.zig");
const static_profile = @import("../../air/lang/static_profile.zig");
const full = @import("qm31_inv.zig");
const full_relation = @import("qm31_inv_relation.zig");
const support = @import("test_support.zig");
const witness = @import("qm31_inv_witness.zig");

test "R-012 QM31 inversion has exact macro-expanded compiler geometry" {
    var definition = try full.build(std.testing.allocator, .generated);
    defer definition.deinit();
    try std.testing.expectEqual(@as(usize, 14), definition.main.physical().len);
    try std.testing.expectEqual(@as(usize, 15), definition.preprocessed.physical().len);
    try std.testing.expectEqual(@as(usize, 12), definition.constraints.len);
    try std.testing.expectEqual(@as(usize, 2), definition.events.ordered().len);
    var degrees = try degree.analyze(std.testing.allocator, &definition.arena);
    defer degrees.deinit();
    try std.testing.expectEqual(
        @as(degree.Degree, full.MAXIMUM_CONSTRAINT_DEGREE),
        degrees.maximumConstraintDegree(),
    );
    const identity = try digest.computeIdentity(&definition.arena);
    try std.testing.expectEqual(digest.typed_effect_format_version, identity.format_version);
    try std.testing.expectEqualStrings(
        full.SEMANTIC_DIGEST_HEX,
        &std.fmt.bytesToHex(identity.bytes, .lower),
    );
    const binding = try witness.Binding.canonical(&definition);
    _ = try witness.Executor.init(&definition, &binding);
    try std.testing.expectEqualStrings(
        witness.BINDING_DIGEST_HEX,
        &std.fmt.bytesToHex(binding.identityDigest(), .lower),
    );
    const plan = try full_relation.authenticate(&definition);
    try plan.validateAgainst(&definition);
}

test "R-012 QM31 inversion static profile is exact and closed" {
    var definition = try full.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const profile = try static_profile.collect(
        std.testing.allocator,
        &definition.arena,
        .{
            .physical_main_columns = full.PHYSICAL_MAIN_COLUMN_COUNT,
            .lookup_layout = .{
                .batch_size = full.LOOKUP_BATCH_SIZE,
                .interaction_coordinates_per_batch = 4,
            },
        },
    );
    try profile.validate();
    try std.testing.expectEqual(@as(?u32, 14), profile.physical_main_columns);
    try std.testing.expectEqual(@as(u32, 32), profile.logical_input_nodes);
    try std.testing.expectEqual(@as(u32, 12), profile.constraint_roots);
    try std.testing.expectEqual(@as(u32, 2), profile.lookup_events);
    try std.testing.expectEqual(@as(?u32, 1), profile.lookup_batches);
    try std.testing.expectEqual(@as(?u32, 4), profile.interaction_columns);
    try std.testing.expectEqual(@as(u32, 3), profile.maximum_logical_constraint_degree);
    try std.testing.expectEqual(@as(?u32, 2), profile.maximum_lookup_numerator_degree);
    try std.testing.expectEqual(@as(?u32, 3), profile.maximum_modeled_interaction_degree);
    try std.testing.expectEqual(@as(u32, 106), profile.expression_dag_nodes);
    try std.testing.expectEqual(@as(u32, 146), profile.expression_dag_edges);
    try std.testing.expectEqual(@as(u32, 18), profile.expression_dag_shared_nodes);
    try std.testing.expectEqual(@as(u32, 9), profile.expression_dag_max_fanout);
    try std.testing.expectEqual(@as(u32, 0), profile.nodes_outside_constraint_effect_closure);
    try std.testing.expectEqualStrings(
        full.STATIC_PROFILE_DIGEST_HEX,
        &std.fmt.bytesToHex(profile.profile_digest, .lower),
    );
}

test "R-012 QM31 inversion witness and schedule agree across all proof kinds" {
    var definition = try full.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const metadata = circuitMetadata(101);
    const wrong = circuitMetadata(701);
    const invocation = witness.Invocation{
        .a = QM31.fromU32Unchecked(3, 5, 7, 11),
        .circuit = metadata,
    };
    const main = try witness.mainRow(invocation);
    try std.testing.expect(QM31.fromM31Array(main[1..5].*).mul(
        QM31.fromM31Array(main[5..9].*),
    ).eql(QM31.one()));
    for (std.enums.values(witness.ProofKind)) |kind| {
        var schedules = witness.PreprocessedRow{
            .segment = wrong,
            .binary = wrong,
            .empty = wrong,
        };
        switch (kind) {
            .segment_leaf => schedules.segment = metadata,
            .binary_node => schedules.binary = metadata,
            .empty_leaf => schedules.empty = metadata,
        }
        try expectSatisfied(&definition, witness.logicalInputs(
            main,
            witness.preprocessedRow(schedules),
            kind,
        ));
    }

    var prng = std.Random.DefaultPrng.init(0x4930_3132_514d_3331);
    const random = prng.random();
    for (0..256) |_| {
        var value = randomQm31(random);
        if (value.isZero()) value = QM31.one();
        const standalone = try witness.mainRow(.{ .a = value });
        try expectSatisfied(&definition, witness.logicalInputs(
            standalone,
            witness.preprocessedRow(.{}),
            .segment_leaf,
        ));
    }
}

test "R-012 QM31 inversion direct writers are exact padded and failure-atomic" {
    var definition = try full.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const binding = try witness.Binding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    const metadata = circuitMetadata(211);
    const invocations = [_]witness.Invocation{
        .{ .a = QM31.one(), .circuit = metadata },
        .{ .a = QM31.fromU32Unchecked(17, 19, 23, 29) },
    };
    const schedules = [_]witness.PreprocessedRow{
        .{ .segment = metadata },
        .{ .empty = circuitMetadata(311) },
    };
    var main_storage: [witness.MAIN_COLUMN_COUNT][4]M31 = undefined;
    var main_columns: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&main_storage, &main_columns) |*storage, *column| column.* = storage;
    var preprocessing_storage: [witness.PREPROCESSED_COLUMN_COUNT][4]M31 = undefined;
    var preprocessing_columns: [witness.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
    for (&preprocessing_storage, &preprocessing_columns) |*storage, *column| column.* = storage;
    try executor.generateMainInto(&main_columns, &invocations, 2);
    try executor.generatePreprocessedInto(&preprocessing_columns, &schedules, 2);
    for (invocations, 0..) |invocation, row| {
        const expected = try witness.mainRow(invocation);
        for (main_columns, expected) |column, value| {
            try std.testing.expect(column[row].eql(value));
        }
    }
    for (schedules, 0..) |schedule, row| {
        const expected = witness.preprocessedRow(schedule);
        for (preprocessing_columns, expected) |column, value| {
            try std.testing.expect(column[row].eql(value));
        }
    }
    for (main_columns) |column| for (column[2..]) |value| try std.testing.expect(value.isZero());
    for (preprocessing_columns) |column| for (column[2..]) |value| try std.testing.expect(value.isZero());

    const sentinel = M31.fromCanonical(0x5151);
    for (&main_storage) |*column| @memset(column, sentinel);
    try std.testing.expectError(
        error.InvalidTraceRow,
        executor.generateMainInto(&main_columns, &.{.{ .a = QM31.zero() }}, 2),
    );
    for (main_storage) |column| for (column) |value| try std.testing.expect(value.eql(sentinel));
}

test "R-012 QM31 inversion relation entries and interaction are compiler-derived" {
    var definition = try full.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const plan = try full_relation.authenticate(&definition);
    const metadata = circuitMetadata(401);
    const rows = [_]full_relation.Row{
        try witness.mainRow(.{
            .a = QM31.fromU32Unchecked(2, 3, 5, 7),
            .circuit = metadata,
        }),
        try witness.mainRow(.{ .a = QM31.fromU32Unchecked(11, 13, 17, 19) }),
    };
    const entries = try plan.entries(&definition, rows[0]);
    try plan.validateEntries(&definition, rows[0], entries);
    try std.testing.expect(entries[0].numerator.eql(QM31.one().neg()));
    try std.testing.expect(entries[1].numerator.eql(QM31.fromBase(metadata.uses)));
    try std.testing.expect(entries[0].values[1].eql(QM31.fromBase(metadata.lhs_id)));
    try std.testing.expect(entries[1].values[1].eql(QM31.fromBase(metadata.node_id)));
    const challenge = full_relation.Challenge.dummy();
    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    {
        var interaction = try plan.generateInteraction(
            measured.allocator(),
            &definition,
            &rows,
            2,
            challenge,
        );
        defer interaction.deinit(measured.allocator());
        try plan.validateInteraction(
            std.testing.allocator,
            &definition,
            &rows,
            2,
            challenge,
            &interaction,
        );
        try std.testing.expect(measured.alloc_index <= 4);
        try interaction.claims.verifyClosure(interaction.claims.total().neg());
    }
    try std.testing.expectEqual(measured.allocated_bytes, measured.freed_bytes);
}

test "R-012 QM31 inversion construction and interaction release every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        buildFailureCase,
        .{},
    );
    var definition = try full.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const plan = try full_relation.authenticate(&definition);
    const rows = [_]full_relation.Row{try witness.mainRow(.{
        .a = QM31.fromU32Unchecked(3, 5, 7, 11),
    })};
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        interactionFailureCase,
        .{ &definition, &plan, &rows },
    );
}

fn buildFailureCase(allocator: std.mem.Allocator) !void {
    var definition = try full.build(allocator, .generated);
    defer definition.deinit();
}

fn interactionFailureCase(
    allocator: std.mem.Allocator,
    definition: *const full.Definition,
    plan: *const full_relation.Plan,
    rows: []const full_relation.Row,
) !void {
    var interaction = try plan.generateInteraction(
        allocator,
        definition,
        rows,
        1,
        full_relation.Challenge.dummy(),
    );
    defer interaction.deinit(allocator);
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

fn circuitMetadata(seed: u32) witness.CircuitMetadata {
    return .{
        .circuit_id = M31.fromCanonical(seed),
        .node_id = M31.fromCanonical(seed + 1),
        .lhs_id = M31.fromCanonical(seed + 2),
        .uses = M31.fromCanonical(seed + 3),
    };
}

fn randomQm31(random: std.Random) QM31 {
    return QM31.fromM31(
        randomM31(random),
        randomM31(random),
        randomM31(random),
        randomM31(random),
    );
}

fn randomM31(random: std.Random) M31 {
    return M31.fromCanonical(random.int(u32) % m31.Modulus);
}
