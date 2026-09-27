const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const degree = @import("../../air/lang/degree.zig");
const digest = @import("../../air/lang/digest.zig");
const static_profile = @import("../../air/lang/static_profile.zig");
const full = @import("qm31_mul_full.zig");
const full_relation = @import("qm31_mul_full_relation.zig");
const standalone = @import("qm31_mul.zig");
const support = @import("test_support.zig");
const witness = @import("qm31_mul_full_witness.zig");

test "R-012 full typed QM31 multiplication has exact compiler-owned geometry" {
    var definition = try full.build(std.testing.allocator, .generated);
    defer definition.deinit();

    try std.testing.expectEqual(
        @as(usize, 19),
        definition.main.physical().len,
    );
    try std.testing.expectEqual(
        @as(usize, 18),
        definition.preprocessed.physical().len,
    );
    try std.testing.expectEqual(@as(usize, 13), definition.constraints.len);
    try std.testing.expectEqual(@as(usize, 3), definition.events.ordered().len);
    var degrees = try degree.analyze(std.testing.allocator, &definition.arena);
    defer degrees.deinit();
    try std.testing.expectEqual(
        @as(degree.Degree, full.MAXIMUM_CONSTRAINT_DEGREE),
        degrees.maximumConstraintDegree(),
    );

    const identity = try digest.computeIdentity(&definition.arena);
    try std.testing.expectEqual(
        digest.typed_effect_format_version,
        identity.format_version,
    );
    try std.testing.expectEqualStrings(
        full.SEMANTIC_DIGEST_HEX,
        &std.fmt.bytesToHex(identity.bytes, .lower),
    );

    const binding = try witness.Binding.canonical(&definition);
    try std.testing.expectEqualStrings(
        witness.BINDING_DIGEST_HEX,
        &std.fmt.bytesToHex(binding.identityDigest(), .lower),
    );

    const relation_plan = try full_relation.authenticate(&definition);
    try relation_plan.validateAgainst(&definition);
}

test "R-012 full typed QM31 multiplication static profile is compiler-derived" {
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
    try std.testing.expectEqual(@as(?u32, 19), profile.physical_main_columns);
    try std.testing.expectEqual(@as(u32, 40), profile.logical_input_nodes);
    try std.testing.expectEqual(@as(u32, 13), profile.constraint_roots);
    try std.testing.expectEqual(@as(u32, 3), profile.effects);
    try std.testing.expectEqual(@as(u32, 3), profile.lookup_events);
    try std.testing.expectEqual(@as(?u32, 2), profile.lookup_batches);
    try std.testing.expectEqual(@as(?u32, 8), profile.interaction_columns);
    try std.testing.expectEqual(@as(u32, 3), profile.maximum_logical_value_degree);
    try std.testing.expectEqual(@as(u32, 3), profile.maximum_logical_constraint_degree);
    try std.testing.expectEqual(@as(?u32, 2), profile.maximum_lookup_numerator_degree);
    try std.testing.expectEqual(@as(?u32, 1), profile.maximum_lookup_denominator_degree);
    try std.testing.expectEqual(@as(?u32, 3), profile.maximum_modeled_interaction_degree);
    try std.testing.expectEqual(@as(u32, 124), profile.expression_dag_nodes);
    try std.testing.expectEqual(@as(u32, 166), profile.expression_dag_edges);
    try std.testing.expectEqual(@as(u32, 18), profile.expression_dag_shared_nodes);
    try std.testing.expectEqual(@as(u32, 10), profile.expression_dag_max_fanout);
    try std.testing.expectEqual(@as(u32, 124), profile.constraint_effect_reachable_nodes);
    try std.testing.expectEqual(@as(u32, 0), profile.nodes_outside_constraint_effect_closure);
    try std.testing.expectEqualStrings(
        full.STATIC_PROFILE_DIGEST_HEX,
        &std.fmt.bytesToHex(profile.profile_digest, .lower),
    );
}

test "R-012 full QM31 schedule selects only the verifier-owned proof kind" {
    var definition = try full.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const metadata = circuitMetadata(101);
    const wrong = circuitMetadata(701);
    const invocation = witness.Invocation{
        .a = QM31.fromU32Unchecked(3, 5, 7, 11),
        .b = QM31.fromU32Unchecked(13, 17, 19, 23),
        .circuit = metadata,
    };
    const main = witness.mainRow(invocation);
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
        const inputs = witness.logicalInputs(
            main,
            witness.preprocessedRow(schedules),
            kind,
        );
        const values = try support.evaluateArena(
            std.testing.allocator,
            &definition.arena,
            &inputs,
        );
        defer std.testing.allocator.free(values);
        try expectAllConstraintsZero(&definition, values);
    }
}

test "R-012 full QM31 standalone rows preserve the arithmetic substrate" {
    var definition = try full.build(std.testing.allocator, .generated);
    defer definition.deinit();
    var substrate = try standalone.build(std.testing.allocator, .generated);
    defer substrate.deinit();
    const invocation = witness.Invocation{
        .a = QM31.fromU32Unchecked(29, 31, 37, 41),
        .b = QM31.fromU32Unchecked(43, 47, 53, 59),
    };
    const main = witness.mainRow(invocation);
    const substrate_row = support.rowFor(invocation.a, invocation.b);
    try std.testing.expectEqualSlices(M31, &substrate_row, main[1..13]);

    for (std.enums.values(witness.ProofKind)) |kind| {
        const inputs = witness.logicalInputs(
            main,
            witness.preprocessedRow(.{}),
            kind,
        );
        const values = try support.evaluateArena(
            std.testing.allocator,
            &definition.arena,
            &inputs,
        );
        defer std.testing.allocator.free(values);
        try expectAllConstraintsZero(&definition, values);
    }
}

test "R-012 full QM31 direct main and preprocessing writers are exact and padded" {
    var definition = try full.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const binding = try witness.Binding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    const metadata = circuitMetadata(17);
    const invocations = [_]witness.Invocation{
        .{
            .a = QM31.fromU32Unchecked(1, 2, 3, 4),
            .b = QM31.fromU32Unchecked(5, 6, 7, 8),
            .circuit = metadata,
        },
        .{
            .a = QM31.fromU32Unchecked(11, 13, 17, 19),
            .b = QM31.fromU32Unchecked(23, 29, 31, 37),
        },
    };
    const schedules = [_]witness.PreprocessedRow{
        .{ .segment = metadata, .binary = circuitMetadata(117) },
        .{ .empty = circuitMetadata(217) },
    };
    const sentinel = M31.fromCanonical(0x5151);
    var main_storage: [witness.MAIN_COLUMN_COUNT][4]M31 = undefined;
    var main_columns: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    for (&main_storage, &main_columns) |*storage, *column| {
        @memset(storage, sentinel);
        column.* = storage;
    }
    var preprocessed_storage: [witness.PREPROCESSED_COLUMN_COUNT][4]M31 = undefined;
    var preprocessed_columns: [witness.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
    for (&preprocessed_storage, &preprocessed_columns) |*storage, *column| {
        @memset(storage, sentinel);
        column.* = storage;
    }
    try executor.generateMainInto(&main_columns, &invocations, 2);
    try executor.generatePreprocessedInto(&preprocessed_columns, &schedules, 2);

    for (invocations, 0..) |invocation, row| {
        const expected = witness.mainRow(invocation);
        for (main_columns, expected) |column, value| {
            try std.testing.expect(column[row].eql(value));
        }
    }
    for (schedules, 0..) |schedule, row| {
        const expected = witness.preprocessedRow(schedule);
        for (preprocessed_columns, expected) |column, value| {
            try std.testing.expect(column[row].eql(value));
        }
    }
    for (main_columns) |column| {
        for (column[invocations.len..]) |padding| try std.testing.expect(padding.isZero());
    }
    for (preprocessed_columns) |column| {
        for (column[schedules.len..]) |padding| try std.testing.expect(padding.isZero());
    }
}

test "R-012 full QM31 construction and interaction clean up allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        buildFailureCase,
        .{},
    );

    var definition = try full.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const plan = try full_relation.authenticate(&definition);
    const rows = [_]full_relation.Row{
        witness.mainRow(.{
            .a = QM31.fromU32Unchecked(2, 3, 5, 7),
            .b = QM31.fromU32Unchecked(11, 13, 17, 19),
            .circuit = circuitMetadata(43),
        }),
        witness.mainRow(.{
            .a = QM31.fromU32Unchecked(23, 29, 31, 37),
            .b = QM31.fromU32Unchecked(41, 43, 47, 53),
        }),
    };
    const challenge = full_relation.Challenge.dummy();
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        interactionFailureCase,
        .{ &definition, &plan, &rows, challenge },
    );
}

test "R-012 full QM31 interaction allocation shape stays cache-bounded" {
    var definition = try full.build(std.testing.allocator, .generated);
    defer definition.deinit();
    const plan = try full_relation.authenticate(&definition);
    const rows = [_]full_relation.Row{witness.mainRow(.{
        .a = QM31.fromU32Unchecked(3, 5, 7, 11),
        .b = QM31.fromU32Unchecked(13, 17, 19, 23),
        .circuit = circuitMetadata(61),
    })};
    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    {
        var interaction = try plan.generateInteraction(
            measured.allocator(),
            &definition,
            &rows,
            2,
            full_relation.Challenge.dummy(),
        );
        defer interaction.deinit(measured.allocator());
        // One SoA pair buffer, two cumulative columns, one contiguous final
        // column slab, and one placement table. There is no per-batch copy and
        // no allocator call per interaction coordinate.
        try std.testing.expect(measured.alloc_index <= 5);
    }
    try std.testing.expectEqual(measured.allocated_bytes, measured.freed_bytes);
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
    challenge: full_relation.Challenge,
) !void {
    var interaction = try plan.generateInteraction(
        allocator,
        definition,
        rows,
        2,
        challenge,
    );
    defer interaction.deinit(allocator);
    try plan.validateInteraction(
        allocator,
        definition,
        rows,
        2,
        challenge,
        &interaction,
    );
}

fn expectAllConstraintsZero(
    definition: *const full.Definition,
    values: []const M31,
) !void {
    for (0..full.DIRECT_CONSTRAINT_COUNT) |index| {
        try std.testing.expect(
            support.constraintAt(
                &definition.arena,
                &definition.constraints,
                values,
                index,
            ).isZero(),
        );
    }
}

fn circuitMetadata(seed: u32) witness.CircuitMetadata {
    return .{
        .circuit_id = M31.fromCanonical(seed),
        .node_id = M31.fromCanonical(seed + 1),
        .lhs_id = M31.fromCanonical(seed + 2),
        .rhs_id = M31.fromCanonical(seed + 3),
        .uses = M31.fromCanonical(seed + 4),
    };
}
