//! Exactness, authority, mutation, and performance gates for row 21.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const degree = @import("../../air/lang/degree.zig");
const digest = @import("../../air/lang/digest.zig");
const relation = @import("../../air/lang/relation.zig");
const static_profile = @import("../../air/lang/static_profile.zig");
const types = @import("../../air/lang/types.zig");
const component = @import("query_mapping.zig");
const interaction_mod = @import("query_mapping_relation.zig");
const support = @import("test_support.zig");
const universal = @import("universal_challenges.zig");
const witness = @import("query_mapping_witness.zig");

const VM_TREES = [_]u32{ 12, 11, 10, 9 };
const VM_FRI = [_]u32{ 4, 2 };
const RECURSION_TREES = [_]u32{ 10, 9, 8, 7 };
const RECURSION_FRI = [_]u32{ 2, 4 };
const VM_PROFILE = witness.LaneProfile{
    .query_count = 2,
    .lifting_log_size = 12,
    .tree_heights = &VM_TREES,
    .fri_fold_widths = &VM_FRI,
};
const RECURSION_PROFILE = witness.LaneProfile{
    .query_count = 2,
    .lifting_log_size = 10,
    .tree_heights = &RECURSION_TREES,
    .fri_fold_widths = &RECURSION_FRI,
};
const ROW_COUNT: usize = 60;

test "R-012 query mapping preserves exact Stark-V row-21 geometry and seal" {
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    try std.testing.expectEqual(@as(usize, 34), definition.main.physical().len);
    try std.testing.expectEqual(@as(usize, 69), definition.preprocessed.physical().len);
    try std.testing.expectEqual(@as(usize, 2), definition.parameters.physical().len);
    try std.testing.expectEqual(@as(usize, 36), definition.constraints.len);
    try std.testing.expectEqual(@as(usize, 2), definition.events.len);
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
    try std.testing.expectEqual(@as(usize, 1), interaction_mod.Runtime.BATCH_COUNT);
    try std.testing.expectEqual(@as(usize, 4), interaction_mod.Runtime.INTERACTION_COLUMN_COUNT);
    try std.testing.expectEqual(relation.Domain.recursion_query_bits, plan.events[0].domain);
    try std.testing.expectEqual(relation.Role.consume, plan.events[0].role);
    try std.testing.expectEqual(relation.Domain.recursion_query_position, plan.events[1].domain);
    try std.testing.expectEqual(relation.Role.emit, plan.events[1].role);
}

test "R-012 query mapping static profile is exact" {
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
    try std.testing.expectEqual(@as(u32, 105), profile.logical_input_nodes);
    try std.testing.expectEqual(@as(u32, 36), profile.constraint_roots);
    try std.testing.expectEqual(@as(u32, 2), profile.lookup_events);
    try std.testing.expectEqual(@as(?u32, 1), profile.lookup_batches);
    try std.testing.expectEqual(@as(?u32, 4), profile.interaction_columns);
    try std.testing.expectEqual(@as(u32, 3), profile.maximum_logical_constraint_degree);
    try std.testing.expectEqual(@as(?u32, 3), profile.maximum_modeled_interaction_degree);
}

test "R-012 query mapping derives every canonical route and binds row-20 profile" {
    const reference = try fixtureReference();
    try reference.validate();
    const bits_reference = try reference.queryBitsReference();
    try bits_reference.validate();
    try std.testing.expectEqual(@as(u32, 10), try VM_PROFILE.useCount());
    try std.testing.expectEqual(@as(u32, 10), bits_reference.vm.useCount());
    try std.testing.expectEqual(VM_PROFILE.lifting_log_size, bits_reference.vm.lifting_log_size);
    try std.testing.expectEqual(
        RECURSION_PROFILE.lifting_log_size,
        bits_reference.recursion.lifting_log_size,
    );

    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, reference);
    defer preprocessing.deinit();
    try preprocessing.validateAgainst(reference);
    try std.testing.expectEqual(@as(usize, ROW_COUNT), preprocessing.rows.len);
    try std.testing.expectEqual(@as(u32, 6), preprocessing.log_size);

    const first = preprocessing.rows[0];
    try std.testing.expectEqual(witness.QueryPositionKind.trace_tree, first.kind);
    try std.testing.expectEqual(@as(u32, 0), first.item);
    try std.testing.expectEqual(@as(u32, 0), first.query);
    try std.testing.expectEqual(@as(u32, 1), first.position_weights[0]);
    try std.testing.expectEqual(@as(u32, 2), first.position_weights[1]);

    const deep = preprocessing.rows[4];
    try std.testing.expectEqual(witness.QueryPositionKind.deep, deep.kind);
    const fold = preprocessing.rows[5];
    try std.testing.expectEqual(witness.QueryPositionKind.fri_fold, fold.kind);
    try std.testing.expectEqual(@as(u32, 1), fold.offset_weights[0]);
    try std.testing.expectEqual(@as(u32, 2), fold.offset_weights[1]);
    const merkle = preprocessing.rows[6];
    try std.testing.expectEqual(witness.QueryPositionKind.fri_merkle, merkle.kind);
    try std.testing.expectEqual(@as(u32, 1), merkle.position_weights[2]);
    const last = preprocessing.rows[9];
    try std.testing.expectEqual(witness.QueryPositionKind.last_layer, last.kind);

    preprocessing.rows[0].position_weights[0] = 7;
    try std.testing.expectError(
        error.AuthorityMismatch,
        preprocessing.validateAgainst(reference),
    );
}

test "R-012 query mapping witnesses and constraints cover every universal mode" {
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const reference = try fixtureReference();
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, reference);
    defer preprocessing.deinit();
    const queries = fixtureQueries();
    const cases = [_]witness.QueryWitness{
        .{ .segment_leaf = &queries.vm },
        .{ .binary_node = .{ .left = &queries.left, .right = &queries.right } },
        .{ .empty_leaf = {} },
    };
    const sample_rows = [_]usize{ 0, 5, 9, 20, 25, 29, 40, 45, 49 };
    for (cases) |query_witness| for (sample_rows) |index| {
        const row = preprocessing.rows[index];
        const logical = try witness.logicalRow(row, query_witness);
        try expectSatisfied(&definition, logical);
        const expected_active = switch (query_witness.proofKind()) {
            .segment_leaf => row.verifier_id == witness.SEGMENT_VERIFIER_ID,
            .binary_node => row.verifier_id != witness.SEGMENT_VERIFIER_ID,
            .empty_leaf => false,
        };
        try std.testing.expectEqual(
            @as(u32, @intFromBool(expected_active)),
            logical[0].toU32(),
        );
    };

    const active = try witness.logicalRow(
        preprocessing.rows[5],
        .{ .segment_leaf = &queries.vm },
    );
    // Query bits are lookup-bound rather than locally boolean; a zero-weight
    // source bit can therefore be changed without violating a direct root.
    // Mutate the committed outputs and a route-significant bit here, while the
    // relation tuple gate below covers all 31 bit coordinates.
    for ([_]usize{ 0, 1, 2, 3, 4, 5 }) |column| {
        var forged = active;
        forged[column] = forged[column].add(M31.one());
        try expectRejected(&definition, forged);
    }
}

test "R-012 query mapping preserves exact route tuples and multiplicities" {
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try interaction_mod.authenticate(&definition);
    const reference = try fixtureReference();
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, reference);
    defer preprocessing.deinit();
    const queries = fixtureQueries();
    const logical = try witness.logicalRow(
        preprocessing.rows[5],
        .{ .segment_leaf = &queries.vm },
    );
    const entries = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        logical,
    );
    try std.testing.expect(entries[0].numerator.eql(QM31.one().neg()));
    try std.testing.expect(entries[1].numerator.eql(QM31.one()));
    try std.testing.expect(entries[1].values[0].eql(QM31.fromBase(M31.zero())));
    try std.testing.expect(entries[1].values[1].eql(QM31.fromBase(M31.fromCanonical(
        @intFromEnum(witness.QueryPositionKind.fri_fold),
    ))));
    try std.testing.expect(entries[1].values[2].eql(QM31.fromBase(M31.zero())));
    try std.testing.expect(entries[1].values[3].eql(QM31.fromBase(M31.zero())));
    try std.testing.expect(entries[1].values[4].eql(QM31.fromBase(logical[1])));
    try std.testing.expect(entries[1].values[5].eql(QM31.fromBase(logical[2])));

    // Every bit is lookup-bound even when its route weight is zero. This is
    // the cross-component rigidity that direct roots alone cannot provide.
    for (0..component.M31_BIT_COUNT) |bit| {
        var forged = logical;
        forged[3 + bit] = forged[3 + bit].add(M31.one());
        const forged_entries = try plan.entries(
            &definition.arena,
            component.SEMANTIC_DIGEST,
            definition.events,
            forged,
        );
        try std.testing.expect(!forged_entries[0].values[2 + bit].eql(
            entries[0].values[2 + bit],
        ));
    }
}

test "R-012 query mapping direct writers are padded allocation-free and atomic" {
    const reference = try fixtureReference();
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, reference);
    defer preprocessing.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const binding = try witness.Binding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    const queries = fixtureQueries();
    const query_witness = witness.QueryWitness{ .binary_node = .{
        .left = &queries.left,
        .right = &queries.right,
    } };
    const size = @as(usize, 1) << @intCast(preprocessing.log_size);

    const preprocessed_storage = try std.testing.allocator.alloc(
        M31,
        witness.PREPROCESSED_COLUMN_COUNT * size,
    );
    defer std.testing.allocator.free(preprocessed_storage);
    var preprocessed_columns: [witness.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
    splitColumns(
        witness.PREPROCESSED_COLUMN_COUNT,
        size,
        preprocessed_storage,
        &preprocessed_columns,
    );
    try executor.generatePreprocessedInto(&preprocessing, reference, &preprocessed_columns);

    const main_storage = try std.testing.allocator.alloc(M31, witness.MAIN_COLUMN_COUNT * size);
    defer std.testing.allocator.free(main_storage);
    var main_columns: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    splitColumns(witness.MAIN_COLUMN_COUNT, size, main_storage, &main_columns);
    try executor.generateMainInto(&preprocessing, reference, &main_columns, query_witness);
    for (preprocessing.rows, 0..) |row, index| {
        const expected = (try witness.mainRow(row, query_witness)).values();
        for (main_columns, expected) |column, value|
            try std.testing.expect(column[index].eql(value));
    }
    for (main_columns) |column| for (column[preprocessing.rows.len..]) |value|
        try std.testing.expect(value.isZero());

    const sentinel = M31.fromCanonical(12345);
    @memset(main_storage, sentinel);
    var short_columns = main_columns;
    short_columns[0] = short_columns[0][0 .. size - 1];
    try std.testing.expectError(
        error.InvalidTraceShape,
        executor.generateMainInto(&preprocessing, reference, &short_columns, query_witness),
    );
    for (main_storage) |value| try std.testing.expect(value.eql(sentinel));

    var duplicate_columns = main_columns;
    duplicate_columns[1] = duplicate_columns[0];
    try std.testing.expectError(
        error.AliasedDestination,
        executor.generateMainInto(&preprocessing, reference, &duplicate_columns, query_witness),
    );
    for (main_storage) |value| try std.testing.expect(value.eql(sentinel));
}

test "R-012 query-mapping interaction remains five-allocation bounded" {
    const reference = try fixtureReference();
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, reference);
    defer preprocessing.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try interaction_mod.authenticate(&definition);
    const queries = fixtureQueries();
    const query_witness = witness.QueryWitness{ .binary_node = .{
        .left = &queries.left,
        .right = &queries.right,
    } };
    var rows: [ROW_COUNT]interaction_mod.Row = undefined;
    for (&rows, preprocessing.rows) |*target, row|
        target.* = try witness.logicalRow(row, query_witness);
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
        try std.testing.expectEqual(@as(usize, 5), measured.alloc_index);
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
    }
    try std.testing.expectEqual(measured.allocated_bytes, measured.freed_bytes);
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        interactionFailureCase,
        .{ &definition, &plan, &rows, preprocessing.log_size, &relations },
    );
}

test "R-012 query-mapping construction releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        componentFailureCase,
        .{},
    );
    const reference = try fixtureReference();
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        preprocessingFailureCase,
        .{reference},
    );
}

fn fixtureReference() !witness.Reference {
    return witness.Reference.seal(VM_PROFILE, RECURSION_PROFILE);
}

const QueryFixture = struct {
    vm: [2]M31,
    left: [2]M31,
    right: [2]M31,
};

fn fixtureQueries() QueryFixture {
    return .{
        .vm = .{ M31.zero(), M31.fromCanonical(183) },
        .left = .{ M31.fromCanonical(77), M31.fromCanonical(88) },
        .right = .{ M31.fromCanonical(99), M31.fromCanonical(0x7fff_fffe) },
    };
}

fn expectSatisfied(
    definition: *const component.Definition,
    inputs: [component.LOGICAL_INPUT_COUNT]M31,
) !void {
    const values = try support.evaluateArena(std.testing.allocator, &definition.arena, &inputs);
    defer std.testing.allocator.free(values);
    for (definition.constraints) |constraint_id| {
        const constraint = definition.arena.constraint(constraint_id).?;
        try std.testing.expect(values[types.idIndex(constraint.root)].isZero());
    }
}

fn expectRejected(
    definition: *const component.Definition,
    inputs: [component.LOGICAL_INPUT_COUNT]M31,
) !void {
    const values = try support.evaluateArena(std.testing.allocator, &definition.arena, &inputs);
    defer std.testing.allocator.free(values);
    for (definition.constraints) |constraint_id| {
        const constraint = definition.arena.constraint(constraint_id).?;
        if (!values[types.idIndex(constraint.root)].isZero()) return;
    }
    return error.TestExpectedConstraintFailure;
}

fn componentFailureCase(allocator: std.mem.Allocator) !void {
    var definition = try component.build(allocator);
    defer definition.deinit();
}

fn preprocessingFailureCase(
    allocator: std.mem.Allocator,
    reference: witness.Reference,
) !void {
    var preprocessing = try witness.Preprocessed.init(allocator, reference);
    defer preprocessing.deinit();
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
