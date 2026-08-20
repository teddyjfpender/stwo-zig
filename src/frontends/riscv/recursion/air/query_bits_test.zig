//! Exactness, canonicality, mutation, and performance gates for row 20.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const degree = @import("../../air/lang/degree.zig");
const digest = @import("../../air/lang/digest.zig");
const relation = @import("../../air/lang/relation.zig");
const static_profile = @import("../../air/lang/static_profile.zig");
const types = @import("../../air/lang/types.zig");
const component = @import("query_bits.zig");
const interaction_mod = @import("query_bits_relation.zig");
const support = @import("test_support.zig");
const universal = @import("universal_challenges.zig");
const witness = @import("query_bits_witness.zig");

const VM_PROFILE = witness.LaneProfile{
    .query_count = 2,
    .lifting_log_size = 12,
    .trace_tree_count = 4,
    .fri_layer_count = 2,
};
const RECURSION_PROFILE = witness.LaneProfile{
    .query_count = 2,
    .lifting_log_size = 10,
    .trace_tree_count = 4,
    .fri_layer_count = 2,
};
const ROW_COUNT: usize = 6;

test "R-012 query bits preserves exact Stark-V row-20 geometry and seal" {
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    try std.testing.expectEqual(@as(usize, 34), definition.main.physical().len);
    try std.testing.expectEqual(@as(usize, 6), definition.preprocessed.physical().len);
    try std.testing.expectEqual(@as(usize, 34), definition.parameters.physical().len);
    try std.testing.expectEqual(@as(usize, 67), definition.constraints.len);
    try std.testing.expectEqual(@as(usize, 33), definition.events.len);
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
    try std.testing.expectEqual(@as(usize, 17), interaction_mod.Runtime.BATCH_COUNT);
    try std.testing.expectEqual(@as(usize, 68), interaction_mod.Runtime.INTERACTION_COLUMN_COUNT);
    try std.testing.expectEqual(
        relation.Domain.recursion_verifier_randomness_word,
        plan.events[0].domain,
    );
    try std.testing.expectEqual(relation.Role.consume, plan.events[0].role);
    try std.testing.expectEqual(relation.Domain.recursion_query_bits, plan.events[1].domain);
    try std.testing.expectEqual(relation.Role.emit, plan.events[1].role);
    for (plan.events[2..]) |event| {
        try std.testing.expectEqual(relation.Domain.recursion_query_bit_value, event.domain);
        try std.testing.expectEqual(relation.Role.emit, event.role);
    }
}

test "R-012 query bits static profile is exact and closed" {
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
    try std.testing.expectEqual(@as(u32, 74), profile.logical_input_nodes);
    try std.testing.expectEqual(@as(u32, 67), profile.constraint_roots);
    try std.testing.expectEqual(@as(u32, 33), profile.lookup_events);
    try std.testing.expectEqual(@as(?u32, 17), profile.lookup_batches);
    try std.testing.expectEqual(@as(?u32, 68), profile.interaction_columns);
    try std.testing.expectEqual(@as(u32, 3), profile.maximum_logical_constraint_degree);
    // The generic profiler conservatively assigns degree one to every input;
    // the native adapter treats the trailing projection masks as verifier-owned
    // scalars, so they add no trace-polynomial degree or quotient blowup.
    try std.testing.expectEqual(@as(?u32, 5), profile.maximum_modeled_interaction_degree);
    try std.testing.expectEqual(@as(u32, 363), profile.expression_dag_nodes);
    try std.testing.expectEqual(@as(u32, 462), profile.expression_dag_edges);
    try std.testing.expectEqual(@as(u32, 38), profile.expression_dag_shared_nodes);
    // The reference macro declares row_mask for fixed-table geometry, but its
    // active expression intentionally uses the disjoint lane masks directly.
    try std.testing.expectEqual(@as(u32, 1), profile.nodes_outside_constraint_effect_closure);
    try std.testing.expectEqualStrings(
        component.STATIC_PROFILE_DIGEST_HEX,
        &std.fmt.bytesToHex(profile.profile_digest, .lower),
    );
}

test "R-012 query profile derives exact use counts and canonical lane order" {
    const reference = try fixtureReference();
    try reference.validate();
    try std.testing.expectEqual(@as(u32, 10), try VM_PROFILE.useCount());
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, reference);
    defer preprocessing.deinit();
    try preprocessing.validateAgainst(reference);
    try std.testing.expectEqual(@as(usize, ROW_COUNT), preprocessing.rows.len);
    try std.testing.expectEqual(@as(u32, 4), preprocessing.log_size);
    const expected_ids = [_]u32{ 0, 0, 1, 1, 2, 2 };
    const expected_queries = [_]u32{ 0, 1, 0, 1, 0, 1 };
    for (preprocessing.rows, expected_ids, expected_queries) |row, verifier_id, query| {
        try std.testing.expectEqual(verifier_id, row.verifier_id);
        try std.testing.expectEqual(query, row.query);
        try std.testing.expectEqual(@as(u32, 10), row.use_count);
    }

    var mutated = reference;
    mutated.vm.fri_layer_count += 1;
    try std.testing.expectError(error.AuthorityMismatch, mutated.validate());
    preprocessing.rows[0].use_count += 1;
    try std.testing.expectError(
        error.AuthorityMismatch,
        preprocessing.validateAgainst(reference),
    );
}

test "R-012 query bit witnesses and constraints cover every universal mode" {
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

    for (cases) |query_witness| {
        const parameters = try witness.parameterValues(reference, query_witness.proofKind());
        for (preprocessing.rows) |row| {
            const logical = try witness.logicalRow(row, query_witness, parameters);
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
            if (!expected_active) {
                for (logical[1..component.PHYSICAL_MAIN_COLUMN_COUNT]) |value|
                    try std.testing.expect(value.isZero());
            }
        }
    }

    const active = try witness.logicalRow(
        preprocessing.rows[1],
        .{ .segment_leaf = &queries.vm },
        try witness.parameterValues(reference, .segment_leaf),
    );
    for (0..component.PHYSICAL_MAIN_COLUMN_COUNT) |column| {
        var forged = active;
        forged[column] = forged[column].add(M31.one());
        try expectRejected(&definition, forged);
    }
}

test "R-012 query bits reject the all-ones alias of M31 zero" {
    const reference = try fixtureReference();
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, reference);
    defer preprocessing.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const queries = fixtureQueries();
    var forged = try witness.logicalRow(
        preprocessing.rows[0],
        .{ .segment_leaf = &queries.vm },
        try witness.parameterValues(reference, .segment_leaf),
    );
    forged[1] = M31.zero();
    forged[2] = M31.zero();
    for (forged[3 .. 3 + component.M31_BIT_COUNT]) |*bit| bit.* = M31.one();
    const values = try support.evaluateArena(std.testing.allocator, &definition.arena, &forged);
    defer std.testing.allocator.free(values);
    try std.testing.expect(support.constraintAt(
        &definition.arena,
        &definition.constraints,
        values,
        component.DIRECT_CONSTRAINT_COUNT - 2,
    ).isZero());
    try std.testing.expect(!support.constraintAt(
        &definition.arena,
        &definition.constraints,
        values,
        component.DIRECT_CONSTRAINT_COUNT - 1,
    ).isZero());
}

test "R-012 query bits relation weights preserve exact shared multiplicities" {
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try interaction_mod.authenticate(&definition);
    const reference = try fixtureReference();
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, reference);
    defer preprocessing.deinit();
    const queries = fixtureQueries();
    const logical = try witness.logicalRow(
        preprocessing.rows[1],
        .{ .segment_leaf = &queries.vm },
        try witness.parameterValues(reference, .segment_leaf),
    );
    const entries = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        logical,
    );
    try std.testing.expect(entries[0].numerator.eql(QM31.one().neg()));
    try std.testing.expect(entries[1].numerator.eql(QM31.fromBase(M31.fromCanonical(10))));
    for (entries[2..]) |entry|
        try std.testing.expect(entry.numerator.eql(QM31.fromBase(M31.fromCanonical(2))));
    try std.testing.expect(entries[0].values[4].eql(QM31.fromBase(queries.vm[1])));
    for (0..component.M31_BIT_COUNT) |bit| {
        const expected = M31.fromCanonical((queries.vm[1].toU32() >> @intCast(bit)) & 1);
        try std.testing.expect(entries[1].values[2 + bit].eql(QM31.fromBase(expected)));
        const projected = if (bit < VM_PROFILE.lifting_log_size) expected else M31.zero();
        try std.testing.expect(entries[2 + bit].values[3].eql(QM31.fromBase(projected)));
    }

    const inactive = try witness.logicalRow(
        preprocessing.rows[1],
        .{ .empty_leaf = {} },
        try witness.parameterValues(reference, .empty_leaf),
    );
    const inactive_entries = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        inactive,
    );
    for (inactive_entries) |entry| try std.testing.expect(entry.numerator.isZero());
}

test "R-012 raw query high bits authenticate without aliasing projected positions" {
    const reference = try fixtureReference();
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, reference);
    defer preprocessing.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try interaction_mod.authenticate(&definition);

    const low_word: u32 = 0b101101;
    const high_bit: usize = 20;
    var low_queries = fixtureQueries();
    low_queries.vm[0] = M31.fromCanonical(low_word);
    var high_queries = low_queries;
    high_queries.vm[0] = M31.fromCanonical(low_word | (@as(u32, 1) << high_bit));
    const low = try witness.logicalRow(
        preprocessing.rows[0],
        .{ .segment_leaf = &low_queries.vm },
        try witness.parameterValues(reference, .segment_leaf),
    );
    const high = try witness.logicalRow(
        preprocessing.rows[0],
        .{ .segment_leaf = &high_queries.vm },
        try witness.parameterValues(reference, .segment_leaf),
    );
    const low_entries = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        low,
    );
    const high_entries = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        high,
    );

    // The transcript word and full row-20 bit vector retain the high bit, so
    // two raw challenges that map to one domain position never alias at the
    // Fiat--Shamir boundary.
    try std.testing.expect(!low_entries[0].values[4].eql(high_entries[0].values[4]));
    try std.testing.expect(!low_entries[1].values[2 + high_bit].eql(
        high_entries[1].values[2 + high_bit],
    ));

    // Individual PCS/FRI inputs are the explicitly projected position bits.
    // All low bits agree and the authenticated high-bit difference is zero on
    // both sides of that typed boundary.
    for (0..component.M31_BIT_COUNT) |bit| {
        try std.testing.expect(low_entries[2 + bit].values[3].eql(
            high_entries[2 + bit].values[3],
        ));
    }
    try std.testing.expect(high_entries[2 + high_bit].values[3].isZero());

    const parameters = try witness.parameterValues(reference, .segment_leaf);
    for (parameters[3..], 0..) |mask, bit| {
        try std.testing.expectEqual(
            @as(u32, @intFromBool(bit < VM_PROFILE.lifting_log_size)),
            mask.toU32(),
        );
    }
    var profile_mutation = reference;
    profile_mutation.vm.lifting_log_size += 1;
    try std.testing.expectError(error.AuthorityMismatch, profile_mutation.validate());
}

test "R-012 query bit direct writers are padded allocation-free and atomic" {
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

    try std.testing.expectError(
        error.QueryCountMismatch,
        executor.generateMainInto(
            &preprocessing,
            reference,
            &main_columns,
            .{ .segment_leaf = queries.vm[0..1] },
        ),
    );
    for (main_storage) |value| try std.testing.expect(value.eql(sentinel));
}

test "R-012 query-bit interaction remains five-allocation bounded at 17 batches" {
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
    const parameters = try witness.parameterValues(reference, .binary_node);
    var rows: [ROW_COUNT]interaction_mod.Row = undefined;
    for (&rows, preprocessing.rows) |*target, row|
        target.* = try witness.logicalRow(row, query_witness, parameters);
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

test "R-012 query-bit construction releases every allocation failure" {
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
