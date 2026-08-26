const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const degree = @import("../../air/lang/degree.zig");
const digest = @import("../../air/lang/digest.zig");
const relation = @import("../../air/lang/relation.zig");
const static_profile = @import("../../air/lang/static_profile.zig");
const component = @import("statement_input.zig");
const interaction_mod = @import("statement_input_relation.zig");
const support = @import("test_support.zig");
const universal = @import("universal_challenges.zig");
const witness = @import("statement_input_witness.zig");

test "R-012 statement input preserves exact Stark-V row-10 geometry and seal" {
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    try std.testing.expectEqual(@as(usize, 2), definition.main.physical().len);
    try std.testing.expectEqual(@as(usize, 7), definition.preprocessed.physical().len);
    try std.testing.expectEqual(@as(usize, 5), definition.parameters.physical().len);
    try std.testing.expectEqual(@as(usize, 2), definition.constraints.len);
    try std.testing.expectEqual(@as(usize, 4), definition.events.ordered().len);
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
    _ = try witness.Executor.init(&definition, &binding);
    try std.testing.expectEqualStrings(
        witness.BINDING_DIGEST_HEX,
        &std.fmt.bytesToHex(binding.identityDigest(), .lower),
    );
    try std.testing.expectEqual(@as(usize, 2), interaction_mod.Runtime.BATCH_COUNT);
    try std.testing.expectEqual(@as(usize, 8), interaction_mod.Runtime.INTERACTION_COLUMN_COUNT);
    try std.testing.expectEqual(relation.Domain.recursion_verifier_input_word, plan.events[0].domain);
    try std.testing.expectEqual(relation.Domain.recursion_statement_word, plan.events[1].domain);
    try std.testing.expectEqual(relation.Domain.recursion_statement_word, plan.events[2].domain);
    try std.testing.expectEqual(relation.Role.consume, plan.events[0].role);
    try std.testing.expectEqual(relation.Role.emit, plan.events[3].role);
}

test "R-012 statement input static profile is exact and closed" {
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
    try std.testing.expectEqual(@as(u32, 14), profile.logical_input_nodes);
    try std.testing.expectEqual(@as(u32, 2), profile.constraint_roots);
    try std.testing.expectEqual(@as(u32, 4), profile.lookup_events);
    try std.testing.expectEqual(@as(?u32, 2), profile.lookup_batches);
    try std.testing.expectEqual(@as(?u32, 8), profile.interaction_columns);
    try std.testing.expectEqual(@as(u32, 3), profile.maximum_logical_constraint_degree);
    try std.testing.expectEqual(@as(?u32, 3), profile.maximum_modeled_interaction_degree);
    try std.testing.expectEqual(@as(u32, 24), profile.expression_dag_nodes);
    try std.testing.expectEqual(@as(u32, 18), profile.expression_dag_edges);
    try std.testing.expectEqual(@as(u32, 4), profile.expression_dag_shared_nodes);
    try std.testing.expectEqual(@as(u32, 0), profile.nodes_outside_constraint_effect_closure);
    try std.testing.expectEqualStrings(
        component.STATIC_PROFILE_DIGEST_HEX,
        &std.fmt.bytesToHex(profile.profile_digest, .lower),
    );
}

test "R-012 statement input routes exact words in every universal mode" {
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator);
    defer preprocessing.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try interaction_mod.authenticate(&definition);
    var words = fixtureWords();
    var right = fixtureWords();
    var parent = fixtureWords();
    right[7] = M31.fromCanonical(777);
    parent[7] = M31.fromCanonical(888);
    const cases = [_]witness.StatementWitness{
        .{ .segment_leaf = &words },
        .{ .binary_node = .{ .left = &words, .right = &right, .parent = &parent } },
        .{ .empty_leaf = {} },
    };

    for (cases) |statement_value| {
        const offsets = [_]usize{
            7,
            component.CANONICAL_WORD_COUNT + 7,
            2 * component.CANONICAL_WORD_COUNT + 7,
            3 * component.CANONICAL_WORD_COUNT + 7,
        };
        for (offsets) |offset| {
            const logical = try witness.logicalRow(preprocessing.rows[offset], statement_value);
            try expectSatisfied(&definition, logical);
            const entries = try plan.entries(
                &definition.arena,
                component.SEMANTIC_DIGEST,
                definition.events.ordered(),
                logical,
            );
            const row = preprocessing.rows[offset];
            const authenticated = switch (statement_value.proofKind()) {
                .segment_leaf => row.segment_mask == 1,
                .binary_node => row.binary_mask == 1,
                .empty_leaf => false,
            };
            const active = authenticated or
                (statement_value.proofKind() == .binary_node and
                    row.derived_parent_mask == 1);
            try std.testing.expectEqual(authenticated, !entries[0].numerator.isZero());
            const scoped_weight: u32 = if (statement_value.proofKind() == .binary_node and
                row.binary_mask == 1)
                2
            else
                @intFromBool(active);
            try std.testing.expect(entries[1].numerator.eql(
                QM31.fromU32Unchecked(scoped_weight, 0, 0, 0),
            ));
            try std.testing.expectEqual(
                active and row.segment_mask == 1,
                !entries[2].numerator.isZero(),
            );
            try std.testing.expectEqual(
                active and row.segment_mask == 1,
                !entries[3].numerator.isZero(),
            );
        }
    }
    try std.testing.expectEqual(
        component.CANONICAL_WORD_COUNT,
        preprocessing.activeWordCount(.segment_leaf),
    );
    try std.testing.expectEqual(
        3 * component.CANONICAL_WORD_COUNT,
        preprocessing.activeWordCount(.binary_node),
    );
    try std.testing.expectEqual(@as(usize, 0), preprocessing.activeWordCount(.empty_leaf));
}

test "R-012 statement input direct writers are exact padded allocation-free and atomic" {
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator);
    defer preprocessing.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const binding = try witness.Binding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    var words = fixtureWords();
    const statement_value = witness.StatementWitness{ .segment_leaf = &words };
    const size = @as(usize, 1) << @intCast(preprocessing.log_size);
    const main_storage = try std.testing.allocator.alloc(M31, witness.MAIN_COLUMN_COUNT * size);
    defer std.testing.allocator.free(main_storage);
    var main_columns: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    splitColumns(witness.MAIN_COLUMN_COUNT, size, main_storage, &main_columns);
    try executor.generateMainInto(&preprocessing, &main_columns, statement_value);
    for (preprocessing.rows, 0..) |row, index| {
        const expected = try witness.mainRow(row, statement_value);
        for (main_columns, expected) |column, value| try std.testing.expect(column[index].eql(value));
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
        for (pp_columns, row.values()) |column, value|
            try std.testing.expect(column[index].eql(value));
    }

    const snapshot = try std.testing.allocator.dupe(M31, main_storage);
    defer std.testing.allocator.free(snapshot);
    main_columns[1] = main_columns[0];
    try std.testing.expectError(
        error.AliasedDestination,
        executor.generateMainInto(&preprocessing, &main_columns, statement_value),
    );
    try std.testing.expectEqualSlices(M31, snapshot, main_storage);
}

test "R-012 statement input schedule mutation and allocation failures reject cleanly" {
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
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator);
    defer preprocessing.deinit();
    preprocessing.rows[0].word_index += 1;
    try std.testing.expectError(error.AuthorityMismatch, preprocessing.validate());

    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    var binding = try witness.Binding.canonical(&definition);
    binding.main[0].source = .value;
    try std.testing.expectError(
        error.InvalidWitnessBinding,
        witness.Executor.init(&definition, &binding),
    );
}

test "R-012 statement input interaction stays cache bounded and failure atomic" {
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator);
    defer preprocessing.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try interaction_mod.authenticate(&definition);
    const events = definition.events.ordered();
    var words = fixtureWords();
    const statement_value = witness.StatementWitness{ .binary_node = .{
        .left = &words,
        .right = &words,
        .parent = &words,
    } };
    const rows = [_]interaction_mod.Row{
        try witness.logicalRow(preprocessing.rows[0], statement_value),
        try witness.logicalRow(preprocessing.rows[component.CANONICAL_WORD_COUNT], statement_value),
        try witness.logicalRow(preprocessing.rows[2 * component.CANONICAL_WORD_COUNT], statement_value),
        try witness.logicalRow(preprocessing.rows[3 * component.CANONICAL_WORD_COUNT], statement_value),
    };
    const relations = universal.UniversalRelations.dummy();
    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    {
        var interaction = try plan.generateInteraction(
            measured.allocator(),
            &definition.arena,
            component.SEMANTIC_DIGEST,
            events,
            &rows,
            2,
            &relations,
        );
        defer interaction.deinit(measured.allocator());
        try std.testing.expect(measured.alloc_index <= 5);
        try plan.validateInteraction(
            std.testing.allocator,
            &definition.arena,
            component.SEMANTIC_DIGEST,
            events,
            &rows,
            2,
            &relations,
            &interaction,
        );
    }
    try std.testing.expectEqual(measured.allocated_bytes, measured.freed_bytes);
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        interactionFailureCase,
        .{ &definition, &plan, &rows, &relations },
    );
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

fn fixtureWords() witness.StatementWords {
    var words: witness.StatementWords = undefined;
    for (&words, 0..) |*word, index| word.* = M31.fromCanonical(@intCast(index + 1));
    return words;
}

fn preprocessingFailureCase(allocator: std.mem.Allocator) !void {
    var value = try witness.Preprocessed.init(allocator);
    defer value.deinit();
}

fn componentFailureCase(allocator: std.mem.Allocator) !void {
    var value = try component.build(allocator);
    defer value.deinit();
}

fn interactionFailureCase(
    allocator: std.mem.Allocator,
    definition: *const component.Definition,
    plan: *const interaction_mod.Plan,
    rows: []const interaction_mod.Row,
    relations: *const universal.UniversalRelations,
) !void {
    var result = try plan.generateInteraction(
        allocator,
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events.ordered(),
        rows,
        2,
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
