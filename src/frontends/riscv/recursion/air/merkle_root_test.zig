//! Exactness, ownership, mutation, and performance gates for row 22.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const degree = @import("../../air/lang/degree.zig");
const digest = @import("../../air/lang/digest.zig");
const relation = @import("../../air/lang/relation.zig");
const static_profile = @import("../../air/lang/static_profile.zig");
const types = @import("../../air/lang/types.zig");
const component = @import("merkle_root.zig");
const interaction_mod = @import("merkle_root_relation.zig");
const support = @import("test_support.zig");
const universal = @import("universal_challenges.zig");
const witness = @import("merkle_root_witness.zig");

const VM_PROFILE = witness.LaneProfile{
    .query_count = 2,
    .trace_tree_count = 4,
    .fri_layer_count = 2,
};
const RECURSION_PROFILE = VM_PROFILE;
const ROW_COUNT: usize = 18;

test "R-012 Merkle root preserves exact Stark-V row-22 geometry and seal" {
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    try std.testing.expectEqual(@as(usize, 9), definition.main.physical().len);
    try std.testing.expectEqual(@as(usize, 8), definition.preprocessed.physical().len);
    try std.testing.expectEqual(@as(usize, 2), definition.parameters.physical().len);
    try std.testing.expectEqual(@as(usize, 9), definition.constraints.len);
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
    const binding = try witness.Binding.canonical(&definition);
    _ = try witness.Executor.init(&definition, &binding);
    try std.testing.expectEqualStrings(
        witness.BINDING_DIGEST_HEX,
        &std.fmt.bytesToHex(binding.identityDigest(), .lower),
    );

    const plan = try interaction_mod.authenticate(&definition);
    try std.testing.expectEqual(@as(usize, 5), interaction_mod.Runtime.BATCH_COUNT);
    try std.testing.expectEqual(@as(usize, 20), interaction_mod.Runtime.INTERACTION_COLUMN_COUNT);
    for (plan.events[0..8]) |event| {
        try std.testing.expectEqual(relation.Domain.recursion_verifier_input_word, event.domain);
        try std.testing.expectEqual(relation.Role.consume, event.role);
    }
    try std.testing.expectEqual(relation.Domain.recursion_merkle_node, plan.events[8].domain);
    try std.testing.expectEqual(relation.Role.emit, plan.events[8].role);
}

test "R-012 Merkle-root profile and namespaced tree geometry are exact" {
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
    try std.testing.expectEqual(@as(u32, 19), profile.logical_input_nodes);
    try std.testing.expectEqual(@as(u32, 9), profile.constraint_roots);
    try std.testing.expectEqual(@as(u32, 9), profile.lookup_events);
    try std.testing.expectEqual(@as(?u32, 5), profile.lookup_batches);
    try std.testing.expectEqual(@as(?u32, 20), profile.interaction_columns);
    try std.testing.expectEqual(@as(u32, 3), profile.maximum_logical_constraint_degree);

    const reference = try fixtureReference();
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, reference);
    defer preprocessing.deinit();
    try preprocessing.validateAgainst(reference);
    try std.testing.expectEqual(@as(usize, ROW_COUNT), preprocessing.rows.len);
    try std.testing.expectEqual(@as(u32, 5), preprocessing.log_size);
    try std.testing.expectEqual(@as(u32, 0), preprocessing.rows[0].tree_id);
    try std.testing.expectEqual(
        witness.FRI_TREE_OFFSET,
        preprocessing.rows[4].tree_id,
    );
    try std.testing.expectEqual(
        witness.VERIFIER_TREE_STRIDE,
        preprocessing.rows[6].tree_id,
    );
    try std.testing.expectEqual(
        2 * witness.VERIFIER_TREE_STRIDE + witness.FRI_TREE_OFFSET + 1,
        preprocessing.rows[17].tree_id,
    );
    preprocessing.rows[0].path_count += 1;
    try std.testing.expectError(
        error.AuthorityMismatch,
        preprocessing.validateAgainst(reference),
    );
}

test "R-012 Merkle-root witnesses and constraints cover every universal mode" {
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const reference = try fixtureReference();
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, reference);
    defer preprocessing.deinit();
    const roots = fixtureRoots();
    const cases = [_]witness.RootWitness{
        .{ .segment_leaf = roots.vmSet() },
        .{ .binary_node = .{ .left = roots.leftSet(), .right = roots.rightSet() } },
        .{ .empty_leaf = {} },
    };
    for (cases) |root_witness| for (preprocessing.rows) |row| {
        const logical = try witness.logicalRow(row, root_witness);
        try expectSatisfied(&definition, logical);
        const expected_active = switch (root_witness.proofKind()) {
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
        preprocessing.rows[0],
        .{ .segment_leaf = roots.vmSet() },
    );
    // Digest words are relation-bound, while the enabler is locally bound.
    var forged_enabler = active;
    forged_enabler[0] = forged_enabler[0].add(M31.one());
    try expectRejected(&definition, forged_enabler);
    const plan = try interaction_mod.authenticate(&definition);
    const honest_entries = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        active,
    );
    for (1..component.PHYSICAL_MAIN_COLUMN_COUNT) |column| {
        var forged = active;
        forged[column] = forged[column].add(M31.one());
        const forged_entries = try plan.entries(
            &definition.arena,
            component.SEMANTIC_DIGEST,
            definition.events,
            forged,
        );
        try std.testing.expect(!forged_entries[column - 1].values[4].eql(
            honest_entries[column - 1].values[4],
        ));
    }
}

test "R-012 Merkle-root relation binds all digest words and path multiplicity" {
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try interaction_mod.authenticate(&definition);
    const reference = try fixtureReference();
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, reference);
    defer preprocessing.deinit();
    const roots = fixtureRoots();
    const logical = try witness.logicalRow(
        preprocessing.rows[0],
        .{ .segment_leaf = roots.vmSet() },
    );
    const entries = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        logical,
    );
    for (entries[0..8], 0..) |entry, index| {
        try std.testing.expect(entry.numerator.eql(QM31.one().neg()));
        try std.testing.expect(entry.values[4].eql(QM31.fromBase(
            M31.fromCanonical(roots.vm_trace[0][index]),
        )));
    }
    try std.testing.expect(entries[8].numerator.eql(QM31.fromBase(M31.fromCanonical(2))));
    try std.testing.expect(entries[8].values[0].eql(QM31.fromBase(M31.zero())));
    for (0..component.DIGEST_WORD_COUNT) |index| {
        try std.testing.expect(entries[8].values[3 + index].eql(
            QM31.fromBase(M31.fromCanonical(roots.vm_trace[0][index])),
        ));
    }
}

test "R-012 Merkle-root direct writers are padded allocation-free and atomic" {
    const reference = try fixtureReference();
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, reference);
    defer preprocessing.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const binding = try witness.Binding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    const roots = fixtureRoots();
    const root_witness = witness.RootWitness{ .binary_node = .{
        .left = roots.leftSet(),
        .right = roots.rightSet(),
    } };
    const size = @as(usize, 1) << @intCast(preprocessing.log_size);

    const preprocessed_storage = try std.testing.allocator.alloc(
        M31,
        witness.PREPROCESSED_COLUMN_COUNT * size,
    );
    defer std.testing.allocator.free(preprocessed_storage);
    var preprocessed_columns: [witness.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
    splitColumns(witness.PREPROCESSED_COLUMN_COUNT, size, preprocessed_storage, &preprocessed_columns);
    try executor.generatePreprocessedInto(&preprocessing, reference, &preprocessed_columns);

    const main_storage = try std.testing.allocator.alloc(M31, witness.MAIN_COLUMN_COUNT * size);
    defer std.testing.allocator.free(main_storage);
    var main_columns: [witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    splitColumns(witness.MAIN_COLUMN_COUNT, size, main_storage, &main_columns);
    try executor.generateMainInto(&preprocessing, reference, &main_columns, root_witness);
    for (preprocessing.rows, 0..) |row, index| {
        const expected = (try witness.mainRow(row, root_witness)).values();
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
        executor.generateMainInto(&preprocessing, reference, &short_columns, root_witness),
    );
    for (main_storage) |value| try std.testing.expect(value.eql(sentinel));
}

test "R-012 Merkle-root interaction remains five-allocation bounded" {
    const reference = try fixtureReference();
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, reference);
    defer preprocessing.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try interaction_mod.authenticate(&definition);
    const roots = fixtureRoots();
    const root_witness = witness.RootWitness{ .binary_node = .{
        .left = roots.leftSet(),
        .right = roots.rightSet(),
    } };
    var rows: [ROW_COUNT]interaction_mod.Row = undefined;
    for (&rows, preprocessing.rows) |*target, row|
        target.* = try witness.logicalRow(row, root_witness);
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

test "R-012 Merkle-root construction releases every allocation failure" {
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

const RootFixture = struct {
    vm_trace: [4]witness.Digest,
    vm_fri: [2]witness.Digest,
    left_trace: [4]witness.Digest,
    left_fri: [2]witness.Digest,
    right_trace: [4]witness.Digest,
    right_fri: [2]witness.Digest,

    fn vmSet(self: *const RootFixture) witness.RootSet {
        return .{ .trace = &self.vm_trace, .fri = &self.vm_fri };
    }
    fn leftSet(self: *const RootFixture) witness.RootSet {
        return .{ .trace = &self.left_trace, .fri = &self.left_fri };
    }
    fn rightSet(self: *const RootFixture) witness.RootSet {
        return .{ .trace = &self.right_trace, .fri = &self.right_fri };
    }
};

fn fixtureRoots() RootFixture {
    var result: RootFixture = undefined;
    var seed: u32 = 1;
    inline for (std.meta.fields(RootFixture)) |field| {
        for (&@field(result, field.name)) |*value| {
            for (value) |*word| {
                word.* = seed;
                seed += 1;
            }
        }
    }
    return result;
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

fn preprocessingFailureCase(allocator: std.mem.Allocator, reference: witness.Reference) !void {
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
