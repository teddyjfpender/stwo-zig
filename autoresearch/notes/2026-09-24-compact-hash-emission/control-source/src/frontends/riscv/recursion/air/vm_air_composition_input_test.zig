const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const degree = @import("../../air/lang/degree.zig");
const digest = @import("../../air/lang/digest.zig");
const relation = @import("../../air/lang/relation.zig");
const static_profile = @import("../../air/lang/static_profile.zig");
const component = @import("vm_air_composition_input.zig");
const interaction_mod = @import("vm_air_composition_input_relation.zig");
const support = @import("test_support.zig");
const universal = @import("universal_challenges.zig");
const witness = @import("vm_air_composition_input_witness.zig");

test "R-012 VM AIR composition input preserves exact Stark-V row-18 geometry" {
    const regenerated = try component.computeSemanticDigest(std.testing.allocator);
    try std.testing.expectEqualStrings(
        component.SEMANTIC_DIGEST_HEX,
        &std.fmt.bytesToHex(regenerated, .lower),
    );
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    try std.testing.expectEqual(@as(usize, 2), definition.main.physical().len);
    try std.testing.expectEqual(@as(usize, 22), definition.preprocessed.physical().len);
    try std.testing.expectEqual(@as(usize, 9), definition.parameters.physical().len);
    try std.testing.expectEqual(@as(usize, 7), definition.constraints.len);
    try std.testing.expectEqual(@as(usize, 9), definition.events.len);
    var degrees = try degree.analyze(std.testing.allocator, &definition.arena);
    defer degrees.deinit();
    try std.testing.expectEqual(
        @as(degree.Degree, component.MAXIMUM_CONSTRAINT_DEGREE),
        degrees.maximumConstraintDegree(),
    );
    const identity = try digest.computeIdentity(&definition.arena);
    try std.testing.expectEqualStrings(
        component.SEMANTIC_DIGEST_HEX,
        &std.fmt.bytesToHex(identity.bytes, .lower),
    );
    const plan = try interaction_mod.authenticate(&definition);
    const binding = try witness.Binding.canonical(&definition);
    const binding_digest = binding.identityDigest();
    try std.testing.expectEqualStrings(
        witness.BINDING_DIGEST_HEX,
        &std.fmt.bytesToHex(binding_digest, .lower),
    );
    _ = try witness.Executor.init(&definition, &binding);
    try std.testing.expectEqual(@as(usize, 5), interaction_mod.Runtime.BATCH_COUNT);
    try std.testing.expectEqual(@as(usize, 20), interaction_mod.Runtime.INTERACTION_COLUMN_COUNT);
    const domains = [_]relation.Domain{
        .recursion_verifier_input_word,
        .recursion_verifier_input_word,
        .recursion_verifier_input_word,
        .recursion_relation_challenge_word,
        .recursion_verifier_randomness_word,
        .recursion_verifier_randomness_word,
        .recursion_statement_word,
        .recursion_wire,
        .recursion_verifier_input_word,
    };
    const roles = [_]relation.Role{
        .consume, .consume, .consume, .consume,
        .consume, .consume, .consume, .emit,
        .consume,
    };
    for (plan.events, domains, roles) |event, domain, role| {
        try std.testing.expectEqual(domain, event.domain);
        try std.testing.expectEqual(role, event.role);
    }
}

test "R-012 VM AIR composition input static profile is exact and closed" {
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const profile = try static_profile.collect(std.testing.allocator, &definition.arena, .{
        .physical_main_columns = component.PHYSICAL_MAIN_COLUMN_COUNT,
        .lookup_layout = .{
            .batch_size = component.LOOKUP_BATCH_SIZE,
            .interaction_coordinates_per_batch = 4,
        },
    });
    try profile.validate();
    try std.testing.expectEqual(@as(u32, 33), profile.logical_input_nodes);
    try std.testing.expectEqual(@as(u32, 7), profile.constraint_roots);
    try std.testing.expectEqual(@as(u32, 9), profile.lookup_events);
    try std.testing.expectEqual(@as(?u32, 5), profile.lookup_batches);
    try std.testing.expectEqual(@as(?u32, 20), profile.interaction_columns);
    try std.testing.expectEqual(@as(u32, 3), profile.maximum_logical_constraint_degree);
    try std.testing.expectEqual(@as(?u32, 4), profile.maximum_modeled_interaction_degree);
    try std.testing.expectEqual(@as(u32, 71), profile.expression_dag_nodes);
    try std.testing.expectEqual(@as(u32, 72), profile.expression_dag_edges);
    try std.testing.expectEqual(@as(u32, 19), profile.expression_dag_shared_nodes);
    try std.testing.expectEqual(@as(u32, 0), profile.nodes_outside_constraint_effect_closure);
    try std.testing.expectEqualStrings(
        component.STATIC_PROFILE_DIGEST_HEX,
        &std.fmt.bytesToHex(profile.profile_digest, .lower),
    );
}

test "R-012 VM AIR composition schedule derives exact preprocessed columns" {
    var preprocessing = try fixturePreprocessed(std.testing.allocator);
    defer preprocessing.deinit();
    try preprocessing.validate();
    try std.testing.expectEqual(@as(usize, 17), witness.inputCount(preprocessing.rows));
    const sampled = preprocessing.rows[1].values();
    try std.testing.expectEqual(@as(u32, 1), sampled[0].toU32());
    try std.testing.expectEqual(@as(u32, 1), sampled[1].toU32());
    try std.testing.expectEqual(@as(u32, 1), sampled[13].toU32());
    try std.testing.expectEqual(@as(u32, witness.SEGMENT_VERIFIER_ID), sampled[18].toU32());
    const transcript_claimed = preprocessing.rows[6].values();
    try std.testing.expectEqual(@as(u32, 1), transcript_claimed[2].toU32());
    try std.testing.expectEqual(@as(u32, 1), transcript_claimed[13].toU32());
    try std.testing.expectEqual(@as(u32, 1), transcript_claimed[21].toU32());
    try std.testing.expectEqual(@as(u32, 7), transcript_claimed[10].toU32());
    try std.testing.expectEqual(@as(u32, 2), transcript_claimed[11].toU32());
    const recursion_claimed = preprocessing.rows[12].values();
    try std.testing.expectEqual(@as(u32, 1), recursion_claimed[2].toU32());
    try std.testing.expectEqual(@as(u32, 1), recursion_claimed[14].toU32());
    try std.testing.expectEqual(@as(u32, 1), recursion_claimed[20].toU32());
    try std.testing.expectEqual(@as(u32, 21), recursion_claimed[18].toU32());
    try std.testing.expectEqual(@as(u32, 2), recursion_claimed[19].toU32());
    const constant = preprocessing.rows[17].values();
    try std.testing.expectEqual(@as(u32, 1), constant[12].toU32());
    const output = preprocessing.rows[20].values();
    try std.testing.expectEqual(@as(u32, 1), output[12].toU32());
}

test "R-012 VM AIR composition inputs and anchors satisfy all universal modes" {
    var preprocessing = try fixturePreprocessed(std.testing.allocator);
    defer preprocessing.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try interaction_mod.authenticate(&definition);

    for (std.enums.values(witness.ProofKind)) |kind| {
        const values = fixtureValues(kind);
        for (preprocessing.rows, values) |row, value| {
            const logical = try witness.logicalRow(row, value, kind);
            try expectSatisfied(&definition, logical);
        }
    }

    const segment_values = fixtureValues(.segment_leaf);
    const vm_entries = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        try witness.logicalRow(preprocessing.rows[1], segment_values[1], .segment_leaf),
    );
    try std.testing.expect(vm_entries[0].numerator.eql(QM31.one().neg()));
    try std.testing.expect(vm_entries[7].numerator.eql(QM31.fromBase(
        M31.fromCanonical(preprocessing.rows[1].use_count),
    )));
    const transcript_entries = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        try witness.logicalRow(preprocessing.rows[6], segment_values[6], .segment_leaf),
    );
    try std.testing.expect(transcript_entries[8].numerator.eql(QM31.one().neg()));
    const binary_values = fixtureValues(.binary_node);
    const claimed_entries = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        try witness.logicalRow(preprocessing.rows[12], binary_values[12], .binary_node),
    );
    try std.testing.expect(claimed_entries[1].numerator.isZero());
    try std.testing.expect(claimed_entries[2].numerator.eql(QM31.one().neg()));
}

test "R-012 VM AIR composition direct writers are padded and failure atomic" {
    var preprocessing = try fixturePreprocessed(std.testing.allocator);
    defer preprocessing.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const binding = try witness.Binding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    const size = @as(usize, 1) << @intCast(preprocessing.log_size);
    const main_storage = try std.testing.allocator.alloc(M31, witness.MAIN_COLUMN_COUNT * size);
    defer std.testing.allocator.free(main_storage);
    var main_columns: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    splitColumns(witness.MAIN_COLUMN_COUNT, size, main_storage, &main_columns);
    const values = fixtureValues(.binary_node);
    try executor.generateMainInto(&preprocessing, &main_columns, &values, .binary_node);
    for (preprocessing.rows, values, 0..) |row, value, index| {
        const expected = try witness.mainRow(row, value, .binary_node);
        for (main_columns, expected) |column, item| try std.testing.expect(column[index].eql(item));
    }
    for (main_columns) |column| for (column[preprocessing.rows.len..]) |value|
        try std.testing.expect(value.isZero());

    const pp_storage = try std.testing.allocator.alloc(
        M31,
        witness.PREPROCESSED_COLUMN_COUNT * size,
    );
    defer std.testing.allocator.free(pp_storage);
    var pp_columns: [witness.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
    splitColumns(witness.PREPROCESSED_COLUMN_COUNT, size, pp_storage, &pp_columns);
    try executor.generatePreprocessedInto(&preprocessing, &pp_columns);
    for (preprocessing.rows, 0..) |row, index| {
        const expected = row.values();
        for (pp_columns, expected) |column, item| try std.testing.expect(column[index].eql(item));
    }

    const sentinel = M31.fromCanonical(0x5151);
    @memset(main_storage, sentinel);
    var invalid = values;
    invalid[7] = M31.zero();
    try std.testing.expectError(
        error.InvalidWitnessValue,
        executor.generateMainInto(&preprocessing, &main_columns, &invalid, .binary_node),
    );
    for (main_storage) |value| try std.testing.expect(value.eql(sentinel));

    invalid = values;
    invalid[17] = M31.one();
    try std.testing.expectError(
        error.InvalidWitnessValue,
        executor.generateMainInto(&preprocessing, &main_columns, &invalid, .binary_node),
    );
    for (main_storage) |value| try std.testing.expect(value.eql(sentinel));

    var short_columns = main_columns;
    short_columns[1] = short_columns[1][0 .. size - 1];
    try std.testing.expectError(
        error.InvalidTraceShape,
        executor.generateMainInto(&preprocessing, &short_columns, &values, .binary_node),
    );
    for (main_storage) |value| try std.testing.expect(value.eql(sentinel));

    var duplicate_columns = main_columns;
    duplicate_columns[1] = duplicate_columns[0];
    try std.testing.expectError(
        error.AliasedDestination,
        executor.generateMainInto(&preprocessing, &duplicate_columns, &values, .binary_node),
    );
    for (main_storage) |value| try std.testing.expect(value.eql(sentinel));

    const aliased_values = main_storage[0..SCHEDULE.len];
    for (aliased_values, values) |*target, value| target.* = value;
    const before_alias = aliased_values[0..SCHEDULE.len].*;
    try std.testing.expectError(
        error.AliasedInput,
        executor.generateMainInto(&preprocessing, &main_columns, aliased_values, .binary_node),
    );
    for (aliased_values, before_alias) |value, expected| try std.testing.expect(value.eql(expected));
}

test "R-012 VM AIR composition schedule is sealed and rejects malformed authority" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        preprocessingFailureCase,
        .{},
    );
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        componentFailureCase,
        .{},
    );
    var preprocessing = try fixturePreprocessed(std.testing.allocator);
    defer preprocessing.deinit();
    preprocessing.rows[1].node_id += 1;
    try std.testing.expectError(error.AuthorityMismatch, preprocessing.validate());

    var duplicate = SCHEDULE;
    duplicate[2].classification = duplicate[1].classification;
    try std.testing.expectError(
        error.DuplicateInputSource,
        witness.Preprocessed.initForTesting(std.testing.allocator, &duplicate),
    );
    var no_anchor = SCHEDULE[0..17].*;
    try std.testing.expectError(
        error.MissingCircuitAnchor,
        witness.Preprocessed.initForTesting(std.testing.allocator, &no_anchor),
    );
    var bad_order = SCHEDULE;
    std.mem.swap(witness.Row, &bad_order[0], &bad_order[17]);
    try std.testing.expectError(
        error.InvalidScheduleOrder,
        witness.Preprocessed.initForTesting(std.testing.allocator, &bad_order),
    );
    var bad_anchor_mode = SCHEDULE;
    bad_anchor_mode[17].classification = .{ .constant_anchor = .ALL };
    bad_anchor_mode[18].classification = .{ .output_anchor = .ALL };
    try std.testing.expectError(
        error.AnchorModeMismatch,
        witness.Preprocessed.initForTesting(std.testing.allocator, &bad_anchor_mode),
    );
    var noncanonical = SCHEDULE;
    noncanonical[1].fixed_value[0] = 1;
    try std.testing.expectError(
        error.InvalidInputSource,
        witness.Preprocessed.initForTesting(std.testing.allocator, &noncanonical),
    );
    var missing_child = SCHEDULE;
    missing_child[10].classification = recursion(.{ .statement_word = 10 });
    try std.testing.expectError(
        error.RecursionSelectorCountMismatch,
        witness.Preprocessed.initForTesting(std.testing.allocator, &missing_child),
    );
    var bad_anchor_order = SCHEDULE;
    std.mem.swap(witness.Row, &bad_anchor_order[17], &bad_anchor_order[18]);
    try std.testing.expectError(
        error.InvalidScheduleOrder,
        witness.Preprocessed.initForTesting(std.testing.allocator, &bad_anchor_order),
    );

    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    {
        var measured_preprocessing = try fixturePreprocessed(measured.allocator());
        defer measured_preprocessing.deinit();
        try std.testing.expectEqual(@as(usize, 1), measured.alloc_index);
    }
    try std.testing.expectEqual(measured.allocated_bytes, measured.freed_bytes);

    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    var binding = try witness.Binding.canonical(&definition);
    binding.preprocessed[0].source = .node_id;
    try std.testing.expectError(
        error.InvalidWitnessBinding,
        witness.Executor.init(&definition, &binding),
    );
}

test "R-012 VM AIR composition interaction is cache bounded and failure atomic" {
    var preprocessing = try fixturePreprocessed(std.testing.allocator);
    defer preprocessing.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try interaction_mod.authenticate(&definition);
    const values = fixtureValues(.binary_node);
    var rows: [SCHEDULE.len]interaction_mod.Row = undefined;
    for (&rows, preprocessing.rows, values) |*target, row, value| {
        target.* = try witness.logicalRow(row, value, .binary_node);
    }
    const relations = universal.UniversalRelations.dummy();
    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    {
        var interaction = try plan.generateInteraction(
            measured.allocator(),
            &definition.arena,
            component.SEMANTIC_DIGEST,
            definition.events,
            &rows,
            preprocessing.log_size,
            &relations,
        );
        defer interaction.deinit(measured.allocator());
        try std.testing.expect(measured.alloc_index <= 5);
        try plan.validateInteraction(
            std.testing.allocator,
            &definition.arena,
            component.SEMANTIC_DIGEST,
            definition.events,
            &rows,
            preprocessing.log_size,
            &relations,
            &interaction,
        );
        interaction.storage[0] = interaction.storage[0].add(M31.one());
        try std.testing.expectError(
            error.InteractionColumnMismatch,
            plan.validateInteraction(
                std.testing.allocator,
                &definition.arena,
                component.SEMANTIC_DIGEST,
                definition.events,
                &rows,
                preprocessing.log_size,
                &relations,
                &interaction,
            ),
        );
    }
    try std.testing.expectEqual(measured.allocated_bytes, measured.freed_bytes);
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        interactionFailureCase,
        .{ &definition, &plan, &rows, preprocessing.log_size, &relations },
    );
}

const SCHEDULE = [_]witness.Row{
    .{ .classification = .{ .vm_input = .segment_selector }, .circuit_id = 7, .node_id = 0, .use_count = 1 },
    .{ .classification = .{ .vm_input = .{ .sampled_value = .{ .item_index = 2, .word_index = 3 } } }, .circuit_id = 7, .node_id = 2, .use_count = 2 },
    .{ .classification = .{ .vm_input = .{ .claimed_sum = .{ .item_index = 1, .word_index = 0 } } }, .circuit_id = 7, .node_id = 4, .use_count = 3 },
    .{ .classification = .{ .vm_input = .{ .relation_challenge = .{ .challenge = 3, .word_index = 7 } } }, .circuit_id = 7, .node_id = 6, .use_count = 1 },
    .{ .classification = .{ .vm_input = .{ .composition_randomness = 2 } }, .circuit_id = 7, .node_id = 8, .use_count = 1 },
    .{ .classification = .{ .vm_input = .{ .oods_point = 1 } }, .circuit_id = 7, .node_id = 10, .use_count = 1 },
    .{ .classification = .{ .vm_input = .{ .transcript_claimed_sum = .{ .item_index = 7, .word_index = 2 } } }, .circuit_id = 7, .node_id = 12, .use_count = 1 },
    .{ .classification = recursion(.parent_binary_selector), .circuit_id = 9, .node_id = 0, .use_count = 1 },
    .{ .classification = recursion(.{ .child_kind_selector = .segment_leaf }), .circuit_id = 9, .node_id = 2, .use_count = 1 },
    .{ .classification = recursion(.{ .child_kind_selector = .binary_node }), .circuit_id = 9, .node_id = 4, .use_count = 1 },
    .{ .classification = recursion(.{ .child_kind_selector = .empty_leaf }), .circuit_id = 9, .node_id = 6, .use_count = 1 },
    .{ .classification = recursion(.{ .sampled_value = .{ .item_index = 4, .word_index = 2 } }), .circuit_id = 9, .node_id = 8, .use_count = 2 },
    .{ .classification = recursion(.{ .claimed_sum = .{ .item_index = 5, .word_index = 1 } }), .circuit_id = 9, .node_id = 10, .use_count = 2 },
    .{ .classification = recursion(.{ .relation_challenge = .{ .challenge = 46, .word_index = 6 } }), .circuit_id = 9, .node_id = 12, .use_count = 1 },
    .{ .classification = recursion(.{ .composition_randomness = 3 }), .circuit_id = 9, .node_id = 14, .use_count = 1 },
    .{ .classification = recursion(.{ .oods_point = 0 }), .circuit_id = 9, .node_id = 16, .use_count = 1 },
    .{ .classification = recursion(.{ .statement_word = 411 }), .circuit_id = 9, .node_id = 18, .use_count = 4 },
    .{ .classification = .{ .constant_anchor = .SEGMENT }, .circuit_id = 7, .node_id = 20, .use_count = 3, .fixed_value = .{ 7, 8, 9, 10 } },
    .{ .classification = .{ .output_anchor = .SEGMENT }, .circuit_id = 7, .node_id = 22, .use_count = 0 },
    .{ .classification = .{ .constant_anchor = .BINARY }, .circuit_id = 9, .node_id = 20, .use_count = 2, .fixed_value = .{ 11, 12, 13, 14 } },
    .{ .classification = .{ .output_anchor = .BINARY }, .circuit_id = 9, .node_id = 22, .use_count = 0 },
};

fn recursion(source: witness.RecursionSource) witness.Classification {
    return .{ .recursion_input = .{
        .verifier_id = 21,
        .statement_scope = 2,
        .source = source,
    } };
}

fn fixturePreprocessed(allocator: std.mem.Allocator) !witness.Preprocessed {
    return witness.Preprocessed.initForTesting(allocator, &SCHEDULE);
}

fn fixtureValues(kind: witness.ProofKind) [SCHEDULE.len]M31 {
    var result = [_]M31{M31.zero()} ** SCHEDULE.len;
    for (SCHEDULE, 0..) |row, index| result[index] = switch (row.classification) {
        .vm_input => |source_value| if (kind != .segment_leaf)
            M31.zero()
        else switch (source_value) {
            .segment_selector => M31.one(),
            else => M31.fromCanonical(@intCast(100 + index)),
        },
        .recursion_input => |input| if (kind != .binary_node)
            M31.zero()
        else switch (input.source) {
            .parent_binary_selector => M31.one(),
            .child_kind_selector => |child_kind| M31.fromCanonical(@intFromBool(child_kind == .segment_leaf)),
            else => M31.fromCanonical(@intCast(100 + index)),
        },
        .constant_anchor, .output_anchor => M31.zero(),
    };
    return result;
}

fn expectSatisfied(
    definition: *const component.Definition,
    inputs: [component.LOGICAL_INPUT_COUNT]M31,
) !void {
    const values = try support.evaluateArena(std.testing.allocator, &definition.arena, &inputs);
    defer std.testing.allocator.free(values);
    for (0..component.DIRECT_CONSTRAINT_COUNT) |index| {
        try std.testing.expect(support.constraintAt(
            &definition.arena,
            &definition.constraints,
            values,
            index,
        ).isZero());
    }
}

fn preprocessingFailureCase(allocator: std.mem.Allocator) !void {
    var preprocessing = try witness.Preprocessed.initForTesting(allocator, &SCHEDULE);
    defer preprocessing.deinit();
}

fn componentFailureCase(allocator: std.mem.Allocator) !void {
    var definition = try component.build(allocator);
    defer definition.deinit();
}

fn interactionFailureCase(
    allocator: std.mem.Allocator,
    definition: *const component.Definition,
    plan: *const interaction_mod.Plan,
    rows: []const interaction_mod.Row,
    log_size: u32,
    relations: *const universal.UniversalRelations,
) !void {
    var result = try plan.generateInteraction(
        allocator,
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        rows,
        log_size,
        relations,
    );
    defer result.deinit(allocator);
}

fn splitColumns(
    comptime count: usize,
    size: usize,
    storage: []M31,
    columns: *[count][]M31,
) void {
    for (columns, 0..) |*column, index| column.* = storage[index * size ..][0..size];
}
