const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const degree = @import("../../air/lang/degree.zig");
const digest = @import("../../air/lang/digest.zig");
const relation = @import("../../air/lang/relation.zig");
const static_profile = @import("../../air/lang/static_profile.zig");
const input_component = @import("statement_input.zig");
const input_interaction = @import("statement_input_relation.zig");
const input_witness = @import("statement_input_witness.zig");
const component = @import("statement_semantics_input.zig");
const interaction_mod = @import("statement_semantics_input_relation.zig");
const support = @import("test_support.zig");
const universal = @import("universal_challenges.zig");
const witness = @import("statement_semantics_input_witness.zig");

test "R-012 statement semantics input preserves exact Stark-V row-11 geometry and seal" {
    const unchecked_identity = try component.semanticIdentity(std.testing.allocator);
    try std.testing.expectEqualStrings(
        component.SEMANTIC_DIGEST_HEX,
        &std.fmt.bytesToHex(unchecked_identity.bytes, .lower),
    );
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    try std.testing.expectEqual(@as(usize, 4), definition.main.physical().len);
    try std.testing.expectEqual(@as(usize, 13), definition.preprocessed.physical().len);
    try std.testing.expectEqual(@as(usize, 4), definition.parameters.physical().len);
    try std.testing.expectEqual(@as(usize, 6), definition.constraints.len);
    try std.testing.expectEqual(@as(usize, 3), definition.events.ordered().len);
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
    try std.testing.expectEqual(relation.Domain.recursion_statement_word, plan.events[0].domain);
    try std.testing.expectEqual(relation.Domain.recursion_wire, plan.events[1].domain);
    try std.testing.expectEqual(relation.Domain.range_check_8_8, plan.events[2].domain);
    try std.testing.expectEqual(relation.Role.request, plan.events[2].role);
}

test "R-012 statement semantics input static profile is exact and closed" {
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
    try std.testing.expectEqual(@as(u32, 21), profile.logical_input_nodes);
    try std.testing.expectEqual(@as(u32, 6), profile.constraint_roots);
    try std.testing.expectEqual(@as(u32, 3), profile.lookup_events);
    try std.testing.expectEqual(@as(?u32, 2), profile.lookup_batches);
    try std.testing.expectEqual(@as(?u32, 8), profile.interaction_columns);
    try std.testing.expectEqual(@as(u32, 4), profile.maximum_logical_constraint_degree);
    try std.testing.expectEqual(@as(?u32, 4), profile.maximum_modeled_interaction_degree);
    try std.testing.expectEqual(@as(u32, 45), profile.expression_dag_nodes);
    try std.testing.expectEqual(@as(u32, 44), profile.expression_dag_edges);
    try std.testing.expectEqual(@as(u32, 9), profile.expression_dag_shared_nodes);
    try std.testing.expectEqual(@as(u32, 0), profile.nodes_outside_constraint_effect_closure);
    try std.testing.expectEqualStrings(
        component.STATIC_PROFILE_DIGEST_HEX,
        &std.fmt.bytesToHex(profile.profile_digest, .lower),
    );
}

test "R-012 canonical statement integer classification is exact" {
    var count: usize = 0;
    for (0..input_component.CANONICAL_WORD_COUNT) |index| {
        count += @intFromBool(witness.isIntegerWord(index));
    }
    try std.testing.expectEqual(@as(usize, 288), count);
    try std.testing.expect(!witness.isIntegerWord(214));
    try std.testing.expect(!witness.isIntegerWord(19 + 67));
}

test "R-012 statement semantics inputs satisfy every source class in all modes" {
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
        const parent_integer = 5;
        const entries = try plan.entries(
            &definition.arena,
            component.SEMANTIC_DIGEST,
            definition.events.ordered(),
            try witness.logicalRow(
                preprocessing.rows[parent_integer],
                values[parent_integer],
                kind,
            ),
        );
        try std.testing.expect(entries[0].numerator.eql(QM31.one().neg()));
        try std.testing.expect(entries[1].numerator.eql(QM31.fromBase(
            M31.fromCanonical(preprocessing.rows[parent_integer].use_count),
        )));
        try std.testing.expect(entries[2].numerator.eql(QM31.one().neg()));
        try std.testing.expect(entries[2].values[0].eql(QM31.fromBase(M31.fromCanonical(0xcd))));
        try std.testing.expect(entries[2].values[1].eql(QM31.fromBase(M31.fromCanonical(0xab))));
    }
    try std.testing.expectEqual(@as(usize, 2), preprocessing.activeStatementCount(.segment_leaf));
    try std.testing.expectEqual(@as(usize, 2), preprocessing.activeStatementCount(.binary_node));
    try std.testing.expectEqual(@as(usize, 1), preprocessing.activeStatementCount(.empty_leaf));
}

test "R-012 statement semantics direct writers are exact padded and failure atomic" {
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

    const sentinel = M31.fromCanonical(0x5151);
    @memset(main_storage, sentinel);
    var invalid_selector = values;
    invalid_selector[1] = M31.zero();
    try std.testing.expectError(
        error.InvalidSelectorValue,
        executor.generateMainInto(&preprocessing, &main_columns, &invalid_selector, .binary_node),
    );
    for (main_storage) |value| try std.testing.expect(value.eql(sentinel));

    var invalid_integer = fixtureValues(.segment_leaf);
    invalid_integer[3] = M31.fromCanonical(1 << 16);
    try std.testing.expectError(
        error.IntegerWordOutOfRange,
        executor.generateMainInto(&preprocessing, &main_columns, &invalid_integer, .segment_leaf),
    );
    for (main_storage) |value| try std.testing.expect(value.eql(sentinel));
}

test "R-012 statement semantics schedule is sealed and construction releases failures" {
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
    preprocessing.rows[3].statement_scope = input_component.RIGHT_STATEMENT_SCOPE;
    try std.testing.expectError(error.AuthorityMismatch, preprocessing.validate());

    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    var binding = try witness.Binding.canonical(&definition);
    binding.preprocessed[0].source = .node_id;
    try std.testing.expectError(
        error.InvalidWitnessBinding,
        witness.Executor.init(&definition, &binding),
    );
}

test "R-012 statement semantics interaction is cache bounded and failure atomic" {
    var preprocessing = try fixturePreprocessed(std.testing.allocator);
    defer preprocessing.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try interaction_mod.authenticate(&definition);
    const values = fixtureValues(.segment_leaf);
    var rows: [BINDINGS.len]interaction_mod.Row = undefined;
    for (&rows, preprocessing.rows, values) |*target, row, value| {
        target.* = try witness.logicalRow(row, value, .segment_leaf);
    }
    const relations = universal.UniversalRelations.dummy();
    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    {
        var interaction = try plan.generateInteraction(
            measured.allocator(),
            &definition.arena,
            component.SEMANTIC_DIGEST,
            definition.events.ordered(),
            &rows,
            4,
            &relations,
        );
        defer interaction.deinit(measured.allocator());
        try std.testing.expect(measured.alloc_index <= 5);
        try plan.validateInteraction(
            std.testing.allocator,
            &definition.arena,
            component.SEMANTIC_DIGEST,
            definition.events.ordered(),
            &rows,
            4,
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
                definition.events.ordered(),
                &rows,
                4,
                &relations,
                &interaction,
            ),
        );
    }
    try std.testing.expectEqual(measured.allocated_bytes, measured.freed_bytes);
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        interactionFailureCase,
        .{ &definition, &plan, &rows, &relations },
    );
}

test "R-012 row-10 scoped emission closes against row-11 consumption" {
    var input_preprocessing = try input_witness.Preprocessed.init(std.testing.allocator);
    defer input_preprocessing.deinit();
    var semantics_preprocessing = try fixturePreprocessed(std.testing.allocator);
    defer semantics_preprocessing.deinit();
    var input_definition = try input_component.build(std.testing.allocator);
    defer input_definition.deinit();
    var semantics_definition = try component.build(std.testing.allocator);
    defer semantics_definition.deinit();
    const first_plan = try input_interaction.authenticate(&input_definition);
    const second_plan = try interaction_mod.authenticate(&semantics_definition);
    var words = [_]M31{M31.zero()} ** input_component.CANONICAL_WORD_COUNT;
    words[201] = M31.fromCanonical(0x1234);
    const statement_value = input_witness.StatementWitness{ .segment_leaf = &words };
    const first_entries = try first_plan.entries(
        &input_definition.arena,
        input_component.SEMANTIC_DIGEST,
        input_definition.events.ordered(),
        try input_witness.logicalRow(input_preprocessing.rows[201], statement_value),
    );
    const values = fixtureValues(.segment_leaf);
    const second_entries = try second_plan.entries(
        &semantics_definition.arena,
        component.SEMANTIC_DIGEST,
        semantics_definition.events.ordered(),
        try witness.logicalRow(
            semantics_preprocessing.rows[3],
            values[3],
            .segment_leaf,
        ),
    );
    try std.testing.expectEqual(relation.Domain.recursion_statement_word, first_entries[1].domain);
    try std.testing.expectEqual(relation.Domain.recursion_statement_word, second_entries[0].domain);
    try std.testing.expect(first_entries[1].numerator.add(second_entries[0].numerator).isZero());
    try std.testing.expectEqual(first_entries[1].arity, second_entries[0].arity);
    for (first_entries[1].values, second_entries[0].values) |lhs, rhs|
        try std.testing.expect(lhs.eql(rhs));
}

const BINDINGS = [_]witness.InputBinding{
    .{ .node_id = 0, .use_count = 1, .source = .{ .selector = .segment_leaf } },
    .{ .node_id = 2, .use_count = 1, .source = .{ .selector = .binary_node } },
    .{ .node_id = 4, .use_count = 1, .source = .{ .selector = .empty_leaf } },
    .{ .node_id = 7, .use_count = 2, .source = .{ .statement = .{
        .scope = input_component.SEGMENT_STATEMENT_SCOPE,
        .index = 201,
        .active_kinds = .SEGMENT,
    } } },
    .{ .node_id = 9, .use_count = 3, .source = .{ .statement = .{
        .scope = input_component.LEFT_STATEMENT_SCOPE,
        .index = 0,
        .active_kinds = .BINARY,
    } } },
    .{ .node_id = 11, .use_count = 4, .source = .{ .statement = .{
        .scope = input_component.PARENT_STATEMENT_SCOPE,
        .index = 201,
        .active_kinds = .ALL,
    } } },
    .{ .node_id = 14, .use_count = 2, .source = .{ .private = .LEAVES } },
};

fn fixturePreprocessed(allocator: std.mem.Allocator) !witness.Preprocessed {
    return witness.Preprocessed.init(allocator, 17, &BINDINGS);
}

fn fixtureValues(kind: witness.ProofKind) [BINDINGS.len]M31 {
    const selectors = kind.selectors();
    return .{
        selectors[0],
        selectors[1],
        selectors[2],
        if (kind == .segment_leaf) M31.fromCanonical(0x1234) else M31.zero(),
        if (kind == .binary_node) M31.fromCanonical(60) else M31.zero(),
        M31.fromCanonical(0xabcd),
        if (kind == .binary_node) M31.zero() else M31.fromCanonical(7),
    };
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
    var preprocessing = try witness.Preprocessed.init(allocator, 17, &BINDINGS);
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
    relations: *const universal.UniversalRelations,
) !void {
    var result = try plan.generateInteraction(
        allocator,
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events.ordered(),
        rows,
        4,
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
