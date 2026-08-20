const std = @import("std");
const stwo_core = @import("stwo_core");
const m31 = stwo_core.fields.m31;
const M31 = m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const degree = @import("../../air/lang/degree.zig");
const digest = @import("../../air/lang/digest.zig");
const static_profile = @import("../../air/lang/static_profile.zig");
const full = @import("linear_ops.zig");
const full_relation = @import("linear_ops_relation.zig");
const support = @import("test_support.zig");
const witness = @import("linear_ops_witness.zig");

test "R-012 linear operations have exact macro-expanded compiler geometry" {
    var definition = try full.build(std.testing.allocator, .generated);
    defer definition.deinit();
    try std.testing.expectEqual(@as(usize, 21), definition.main.physical().len);
    try std.testing.expectEqual(@as(usize, 27), definition.preprocessed.physical().len);
    try std.testing.expectEqual(@as(usize, 18), definition.constraints.len);
    try std.testing.expectEqual(@as(usize, 3), definition.events.ordered().len);
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

test "R-012 linear operations static profile is exact and closed" {
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
    try std.testing.expectEqual(@as(?u32, 21), profile.physical_main_columns);
    try std.testing.expectEqual(@as(u32, 51), profile.logical_input_nodes);
    try std.testing.expectEqual(@as(u32, 18), profile.constraint_roots);
    try std.testing.expectEqual(@as(u32, 3), profile.lookup_events);
    try std.testing.expectEqual(@as(?u32, 2), profile.lookup_batches);
    try std.testing.expectEqual(@as(?u32, 8), profile.interaction_columns);
    try std.testing.expectEqual(@as(u32, 3), profile.maximum_logical_constraint_degree);
    try std.testing.expectEqual(@as(?u32, 1), profile.maximum_lookup_numerator_degree);
    try std.testing.expectEqual(@as(?u32, 3), profile.maximum_modeled_interaction_degree);
    try std.testing.expectEqual(@as(u32, 157), profile.expression_dag_nodes);
    try std.testing.expectEqual(@as(u32, 210), profile.expression_dag_edges);
    try std.testing.expectEqual(@as(u32, 16), profile.expression_dag_shared_nodes);
    try std.testing.expectEqual(@as(u32, 12), profile.expression_dag_max_fanout);
    try std.testing.expectEqual(@as(u32, 0), profile.nodes_outside_constraint_effect_closure);
    try std.testing.expectEqualStrings(
        full.STATIC_PROFILE_DIGEST_HEX,
        &std.fmt.bytesToHex(profile.profile_digest, .lower),
    );
}

test "R-012 linear operation witnesses satisfy every operation and proof kind" {
    var definition = try full.build(std.testing.allocator, .generated);
    defer definition.deinit();
    for (std.enums.values(witness.Operation)) |operation| {
        const selected = circuitMetadata(operation, 101);
        const wrong = circuitMetadata(.add, 701);
        const invocation = witness.Invocation{
            .operation = operation,
            .lhs = QM31.fromU32Unchecked(3, 5, 7, 11),
            .rhs = if (operation == .neg)
                QM31.zero()
            else
                QM31.fromU32Unchecked(13, 17, 19, 23),
            .circuit = selected,
        };
        const main = try witness.mainRow(invocation);
        for (std.enums.values(witness.ProofKind)) |kind| {
            var schedules = witness.PreprocessedRow{
                .segment = .{ .operation = .add, .circuit = wrong },
                .binary = .{ .operation = .add, .circuit = wrong },
                .empty = .{ .operation = .add, .circuit = wrong },
            };
            switch (kind) {
                .segment_leaf => schedules.segment = .{
                    .operation = operation,
                    .circuit = selected,
                },
                .binary_node => schedules.binary = .{
                    .operation = operation,
                    .circuit = selected,
                },
                .empty_leaf => schedules.empty = .{
                    .operation = operation,
                    .circuit = selected,
                },
            }
            try expectSatisfied(&definition, witness.logicalInputs(
                main,
                witness.preprocessedRow(schedules),
                kind,
            ));
        }
    }
}

test "R-012 linear operation arithmetic agrees with randomized QM31 corpus" {
    var definition = try full.build(std.testing.allocator, .generated);
    defer definition.deinit();
    var prng = std.Random.DefaultPrng.init(0x4c49_4e45_4152_3031);
    const random = prng.random();
    for (0..256) |index| {
        const operation: witness.Operation = @enumFromInt(index % 3);
        const circuit = circuitMetadata(operation, @intCast(1000 + index * 7));
        const invocation = witness.Invocation{
            .operation = operation,
            .lhs = randomQm31(random),
            .rhs = if (operation == .neg) QM31.zero() else randomQm31(random),
            .circuit = circuit,
        };
        const main = try witness.mainRow(invocation);
        try std.testing.expect(QM31.fromM31Array(main[16..20].*).eql(
            operation.apply(invocation.lhs, invocation.rhs),
        ));
        try expectSatisfied(&definition, witness.logicalInputs(
            main,
            witness.preprocessedRow(.{ .segment = .{
                .operation = operation,
                .circuit = circuit,
            } }),
            .segment_leaf,
        ));
    }
}

test "R-012 linear operation direct writers are exact padded and allocation-free" {
    var definition = try full.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const binding = try witness.Binding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    const invocations = [_]witness.Invocation{
        .{
            .operation = .add,
            .lhs = QM31.fromU32Unchecked(2, 3, 5, 7),
            .rhs = QM31.fromU32Unchecked(11, 13, 17, 19),
            .circuit = circuitMetadata(.add, 211),
        },
        .{
            .operation = .sub,
            .lhs = QM31.fromU32Unchecked(23, 29, 31, 37),
            .rhs = QM31.fromU32Unchecked(41, 43, 47, 53),
            .circuit = circuitMetadata(.sub, 311),
        },
        .{
            .operation = .neg,
            .lhs = QM31.fromU32Unchecked(59, 61, 67, 71),
            .circuit = circuitMetadata(.neg, 411),
        },
    };
    const preprocessing = [_]witness.PreprocessedRow{
        .{ .segment = .{ .operation = .add, .circuit = invocations[0].circuit } },
        .{ .binary = .{ .operation = .sub, .circuit = invocations[1].circuit } },
        .{ .empty = .{ .operation = .neg, .circuit = invocations[2].circuit } },
    };
    var main_storage: [witness.MAIN_COLUMN_COUNT][4]M31 = undefined;
    var main_columns: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&main_storage, &main_columns) |*storage, *column| column.* = storage;
    var preprocessing_storage: [witness.PREPROCESSED_COLUMN_COUNT][4]M31 = undefined;
    var preprocessing_columns: [witness.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
    for (&preprocessing_storage, &preprocessing_columns) |*storage, *column| column.* = storage;
    try executor.generateMainInto(&main_columns, &invocations, 2);
    try executor.generatePreprocessedInto(&preprocessing_columns, &preprocessing, 2);
    for (invocations, 0..) |invocation, row| {
        const expected = try witness.mainRow(invocation);
        for (main_columns, expected) |column, value| try std.testing.expect(column[row].eql(value));
    }
    for (preprocessing, 0..) |schedule, row| {
        const expected = witness.preprocessedRow(schedule);
        for (preprocessing_columns, expected) |column, value| {
            try std.testing.expect(column[row].eql(value));
        }
    }
    for (main_columns) |column| try std.testing.expect(column[3].isZero());
    for (preprocessing_columns) |column| try std.testing.expect(column[3].isZero());
}

test "R-012 linear wire entries and pair batching preserve exact operation weights" {
    var definition = try full.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const plan = try full_relation.authenticate(&definition);
    const rows = [_]full_relation.Row{
        try witness.mainRow(.{
            .operation = .add,
            .lhs = QM31.fromU32Unchecked(2, 3, 5, 7),
            .rhs = QM31.fromU32Unchecked(11, 13, 17, 19),
            .circuit = circuitMetadata(.add, 501),
        }),
        try witness.mainRow(.{
            .operation = .sub,
            .lhs = QM31.fromU32Unchecked(23, 29, 31, 37),
            .rhs = QM31.fromU32Unchecked(41, 43, 47, 53),
            .circuit = circuitMetadata(.sub, 601),
        }),
        try witness.mainRow(.{
            .operation = .neg,
            .lhs = QM31.fromU32Unchecked(59, 61, 67, 71),
            .circuit = circuitMetadata(.neg, 701),
        }),
    };
    const add_entries = try plan.entries(&definition, rows[0]);
    try plan.validateEntries(&definition, rows[0], add_entries);
    try std.testing.expect(add_entries[0].numerator.eql(QM31.one().neg()));
    try std.testing.expect(add_entries[1].numerator.eql(QM31.one().neg()));
    try std.testing.expect(add_entries[2].numerator.eql(QM31.fromBase(rows[0][20])));
    try std.testing.expect(add_entries[0].values[1].eql(QM31.fromBase(rows[0][6])));
    try std.testing.expect(add_entries[1].values[1].eql(QM31.fromBase(rows[0][7])));
    try std.testing.expect(add_entries[2].values[1].eql(QM31.fromBase(rows[0][2])));
    const neg_entries = try plan.entries(&definition, rows[2]);
    try std.testing.expect(neg_entries[1].numerator.isZero());
    for (neg_entries[1].values[2..]) |value| try std.testing.expect(value.isZero());

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
        try std.testing.expect(measured.alloc_index <= 5);
        try interaction.claims.verifyClosure(interaction.claims.total().neg());
    }
    try std.testing.expectEqual(measured.allocated_bytes, measured.freed_bytes);
}

test "R-012 linear construction and interaction release every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        buildFailureCase,
        .{},
    );
    var definition = try full.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const plan = try full_relation.authenticate(&definition);
    const rows = [_]full_relation.Row{try witness.mainRow(.{
        .operation = .add,
        .lhs = QM31.one(),
        .rhs = QM31.one(),
        .circuit = circuitMetadata(.add, 801),
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

fn circuitMetadata(operation: witness.Operation, seed: u32) witness.CircuitMetadata {
    return .{
        .circuit_id = M31.fromCanonical(seed),
        .node_id = M31.fromCanonical(seed + 1),
        .lhs_id = M31.fromCanonical(seed + 2),
        .rhs_id = if (operation == .neg) M31.zero() else M31.fromCanonical(seed + 3),
        .uses = M31.fromCanonical(seed + 4),
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
