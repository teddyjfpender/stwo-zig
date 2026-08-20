//! Exactness and end-to-end typed coupling gates for row 23.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const degree = @import("../../air/lang/degree.zig");
const digest = @import("../../air/lang/digest.zig");
const static_profile = @import("../../air/lang/static_profile.zig");
const types = @import("../../air/lang/types.zig");
const fixed_profile = @import("../fixed_profile.zig");
const protocol = @import("../protocol.zig");
const channel = @import("../poseidon2_channel.zig");
const component = @import("trace_merkle.zig");
const interaction_mod = @import("trace_merkle_relation.zig");
const query_mapping = @import("query_mapping_witness.zig");
const schedule = @import("verifier_schedule.zig");
const support = @import("test_support.zig");
const universal = @import("universal_challenges.zig");
const witness = @import("trace_merkle_witness.zig");

const TREE_0 = [_]u32{ 6, 4, 4, 5, 6, 7, 8, 8, 3, 9 };
const TREE_1 = [_]u32{9};
const TREE_2 = [_]u32{ 8, 7 };
const TREE_3 = [_]u32{ 9, 6 };
const TREES = [_]witness.TreeProfile{
    .{ .height = 9, .column_log_sizes = &TREE_0 },
    .{ .height = 9, .column_log_sizes = &TREE_1 },
    .{ .height = 9, .column_log_sizes = &TREE_2 },
    .{ .height = 9, .column_log_sizes = &TREE_3 },
};
const FRI = [_]u32{ 4, 4 };
const PROFILE = witness.LaneProfile{
    .query_count = protocol.FRI_QUERY_COUNT,
    .lifting_log_size = 9,
    .trees = &TREES,
    .fri_fold_widths = &FRI,
};
const ROW_COUNT: usize = 5 * protocol.FRI_QUERY_COUNT;

test "R-012 trace Merkle preserves exact Stark-V row-23 geometry and seal" {
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    try std.testing.expectEqual(@as(usize, 42), definition.main.physical().len);
    try std.testing.expectEqual(@as(usize, 41), definition.preprocessed.physical().len);
    try std.testing.expectEqual(@as(usize, 4), definition.parameters.physical().len);
    try std.testing.expectEqual(@as(usize, 66), definition.constraints.len);
    try std.testing.expectEqual(@as(usize, 14), definition.events.len);
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
    try std.testing.expectEqual(@as(usize, 7), interaction_mod.Runtime.BATCH_COUNT);
    try std.testing.expectEqual(@as(usize, 28), interaction_mod.Runtime.INTERACTION_COLUMN_COUNT);
    try std.testing.expectEqual(@as(usize, 14), plan.events.len);
}

test "R-012 trace Merkle static profile is exact" {
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
    try std.testing.expectEqual(@as(u32, 87), profile.logical_input_nodes);
    try std.testing.expectEqual(@as(u32, 66), profile.constraint_roots);
    try std.testing.expectEqual(@as(u32, 14), profile.lookup_events);
    try std.testing.expectEqual(@as(?u32, 7), profile.lookup_batches);
    try std.testing.expectEqual(@as(?u32, 28), profile.interaction_columns);
    try std.testing.expectEqual(@as(u32, 4), profile.maximum_logical_constraint_degree);
}

test "R-012 trace Merkle preprocessing binds stable leaf order and control plan" {
    var fixtures = try Fixtures.init();
    defer fixtures.deinit();
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, fixtures.reference);
    defer preprocessing.deinit();
    try preprocessing.validateAgainstAuthority(fixtures.reference);
    try std.testing.expectEqual(@as(usize, 3 * ROW_COUNT), preprocessing.rows.len);
    try std.testing.expectEqual(@as(u32, 12), preprocessing.log_size);
    const first = preprocessing.rows[0];
    try std.testing.expectEqual(@as(u32, 1), first.first);
    try std.testing.expectEqual(@as(u32, 0), first.last);
    // Stable ascending log-size order, with original index breaking ties.
    const expected_columns = [_]u32{ 8, 1, 2, 3, 0, 4, 5, 6 };
    for (first.chunks, expected_columns) |chunk, expected_column|
        try std.testing.expectEqual(expected_column, chunk.column);
    try std.testing.expectEqual(@as(u32, 1), preprocessing.rows[1].last);
    try std.testing.expectEqual(@as(u32, 7), preprocessing.rows[1].chunks[0].column);
    try std.testing.expectEqual(@as(u32, 9), preprocessing.rows[1].chunks[1].column);
    try std.testing.expectEqual(@as(u32, 1), preprocessing.rows[1].chunks[2].constant);
    try std.testing.expectEqual(@as(u32, 22), first.control_tag);
    try std.testing.expectEqual(@as(u32, 0), first.control_args[0]);
    try std.testing.expectEqual(@as(u32, 0), first.control_args[1]);
    try std.testing.expectEqual(@as(u32, 9), first.control_args[2]);

    const mapping = try query_mapping.Reference.seal(
        mappingProfile(),
        mappingProfile(),
    );
    try fixtures.reference.validateQueryMapping(mapping);
    var forged_mapping = mapping;
    forged_mapping.vm.lifting_log_size += 1;
    forged_mapping.authority_digest = (try query_mapping.Reference.seal(
        forged_mapping.vm,
        forged_mapping.recursion,
    )).authority_digest;
    try std.testing.expectError(
        error.AuthorityMismatch,
        fixtures.reference.validateQueryMapping(forged_mapping),
    );

    preprocessing.rows[0].chunks[0].column = 7;
    try std.testing.expectError(
        error.AuthorityMismatch,
        preprocessing.validateAgainst(fixtures.reference),
    );
}

test "R-012 trace Merkle materializes exact Poseidon state and all modes" {
    var fixtures = try Fixtures.init();
    defer fixtures.deinit();
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, fixtures.reference);
    defer preprocessing.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    var data = try OpeningFixture.init(std.testing.allocator);
    defer data.deinit();
    const cases = [_]witness.OpeningWitness{
        .{ .segment_leaf = data.vm },
        .{ .binary_node = .{ .left = data.left, .right = data.right } },
        .{ .empty_leaf = {} },
    };
    const sample_rows = [_]usize{ 0, ROW_COUNT, 2 * ROW_COUNT };
    for (cases) |opening| for (sample_rows) |row_index| {
        const logical = try witness.logicalRow(
            fixtures.reference,
            &preprocessing,
            row_index,
            opening,
        );
        try expectSatisfied(&definition, logical);
    };
    const active = try witness.logicalRow(
        fixtures.reference,
        &preprocessing,
        0,
        .{ .segment_leaf = data.vm },
    );
    try std.testing.expectEqual(@as(u32, 1), active[0].toU32());
    try std.testing.expectEqual(@as(u32, 0), active[1].toU32());
    try std.testing.expectEqual(@as(u32, witness.LEAF_TAG), active[17].toU32());
    try std.testing.expectEqual(data.vm.queried_values[8 * protocol.FRI_QUERY_COUNT], active[18]);
    try std.testing.expectEqual(data.vm.queried_values[protocol.FRI_QUERY_COUNT], active[19]);
    try std.testing.expectEqual(data.vm.queried_values[2 * protocol.FRI_QUERY_COUNT], active[20]);

    const empty = try witness.logicalRow(
        fixtures.reference,
        &preprocessing,
        0,
        .{ .empty_leaf = {} },
    );
    for (empty[0..component.PHYSICAL_MAIN_COLUMN_COUNT]) |value|
        try std.testing.expect(value.isZero());
}

test "R-012 trace Merkle relation tuples bind Poseidon values route leaf and control" {
    var fixtures = try Fixtures.init();
    defer fixtures.deinit();
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, fixtures.reference);
    defer preprocessing.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try interaction_mod.authenticate(&definition);
    var data = try OpeningFixture.init(std.testing.allocator);
    defer data.deinit();
    const logical = try witness.logicalRow(
        fixtures.reference,
        &preprocessing,
        0,
        .{ .segment_leaf = data.vm },
    );
    const entries = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        logical,
    );
    try std.testing.expect(entries[0].numerator.eql(QM31.one().neg()));
    for (entries[1..9]) |entry| try std.testing.expect(entry.numerator.eql(QM31.one()));
    try std.testing.expect(entries[9].numerator.isZero());
    try std.testing.expect(entries[10].numerator.eql(QM31.one()));
    try std.testing.expect(entries[11].numerator.isZero());
    try std.testing.expect(entries[12].numerator.isZero());
    try std.testing.expect(entries[13].numerator.isZero());

    const final_logical = try witness.logicalRow(
        fixtures.reference,
        &preprocessing,
        1,
        .{ .segment_leaf = data.vm },
    );
    const final_entries = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        final_logical,
    );
    try std.testing.expect(final_entries[9].numerator.eql(QM31.one().neg()));
    try std.testing.expect(final_entries[10].numerator.isZero());
    try std.testing.expect(final_entries[11].numerator.eql(QM31.one().neg()));
    try std.testing.expect(final_entries[12].numerator.eql(QM31.one().neg()));
    try std.testing.expect(final_entries[13].numerator.eql(QM31.one().neg()));
    // The first sponge row's authenticated state output is exactly the second
    // row's authenticated state input. This is the multistep chain that the
    // original one-step fixture could not exercise.
    try std.testing.expectEqual(entries[10].arity, final_entries[9].arity);
    for (
        entries[10].values[0..entries[10].arity],
        final_entries[9].values[0..final_entries[9].arity],
    ) |emitted, consumed| try std.testing.expect(emitted.eql(consumed));
}

test "R-012 trace Merkle direct writers are allocation-free padded and failure atomic" {
    var fixtures = try Fixtures.init();
    defer fixtures.deinit();
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, fixtures.reference);
    defer preprocessing.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const binding = try witness.Binding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    var data = try OpeningFixture.init(std.testing.allocator);
    defer data.deinit();
    const opening = witness.OpeningWitness{ .segment_leaf = data.vm };
    const size = @as(usize, 1) << @intCast(preprocessing.log_size);

    const preprocessed_storage = try std.testing.allocator.alloc(
        M31,
        component.PREPROCESSED_COLUMN_COUNT * size,
    );
    defer std.testing.allocator.free(preprocessed_storage);
    var preprocessed_columns: [component.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
    splitColumns(
        component.PREPROCESSED_COLUMN_COUNT,
        size,
        preprocessed_storage,
        &preprocessed_columns,
    );
    try executor.generatePreprocessedInto(
        &preprocessing,
        fixtures.reference,
        &preprocessed_columns,
    );
    for (preprocessing.rows, 0..) |row, row_index| {
        const expected = row.values();
        for (preprocessed_columns, expected) |column, value|
            try std.testing.expect(column[row_index].eql(value));
    }
    for (preprocessed_columns) |column| for (column[preprocessing.rows.len..]) |value|
        try std.testing.expect(value.isZero());

    const storage = try std.testing.allocator.alloc(M31, component.PHYSICAL_MAIN_COLUMN_COUNT * size);
    defer std.testing.allocator.free(storage);
    var columns: [component.PHYSICAL_MAIN_COLUMN_COUNT][]M31 = undefined;
    splitColumns(component.PHYSICAL_MAIN_COLUMN_COUNT, size, storage, &columns);
    try executor.generateMainInto(&preprocessing, fixtures.reference, &columns, opening);
    for (columns) |column| for (column[preprocessing.rows.len..]) |value|
        try std.testing.expect(value.isZero());

    const sentinel = M31.fromCanonical(12345);
    @memset(storage, sentinel);
    var short_columns = columns;
    short_columns[0] = short_columns[0][0 .. size - 1];
    try std.testing.expectError(
        error.InvalidTraceShape,
        executor.generateMainInto(
            &preprocessing,
            fixtures.reference,
            &short_columns,
            opening,
        ),
    );
    for (storage) |value| try std.testing.expect(value.eql(sentinel));

    var aliased_columns = columns;
    aliased_columns[1] = aliased_columns[0];
    try std.testing.expectError(
        error.AliasedDestination,
        executor.generateMainInto(
            &preprocessing,
            fixtures.reference,
            &aliased_columns,
            opening,
        ),
    );
    for (storage) |value| try std.testing.expect(value.eql(sentinel));

    const aliased_opening = witness.OpeningWitness{ .segment_leaf = .{
        .queried_values = storage[0..data.vm.queried_values.len],
        .raw_queries = data.vm.raw_queries,
    } };
    try std.testing.expectError(
        error.AliasedInput,
        executor.generateMainInto(
            &preprocessing,
            fixtures.reference,
            &columns,
            aliased_opening,
        ),
    );
    for (storage) |value| try std.testing.expect(value.eql(sentinel));
}

test "R-012 trace Merkle interaction stays five allocations and failure atomic" {
    var fixtures = try Fixtures.init();
    defer fixtures.deinit();
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, fixtures.reference);
    defer preprocessing.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    var data = try OpeningFixture.init(std.testing.allocator);
    defer data.deinit();
    const opening = witness.OpeningWitness{ .segment_leaf = data.vm };

    const plan = try interaction_mod.authenticate(&definition);
    const row = try witness.logicalRow(fixtures.reference, &preprocessing, 0, opening);
    const rows = [_]interaction_mod.Row{row};
    const relations = universal.UniversalRelations.dummy();
    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    {
        var interaction = try plan.generateInteraction(
            measured.allocator(),
            &definition.arena,
            component.SEMANTIC_DIGEST,
            definition.events,
            &rows,
            witness.MIN_LOG_SIZE,
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
            witness.MIN_LOG_SIZE,
            &relations,
            &interaction,
        );
    }
    try std.testing.expectEqual(measured.allocated_bytes, measured.freed_bytes);
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        interactionFailureCase,
        .{ &definition, &plan, &rows, witness.MIN_LOG_SIZE, &relations },
    );
}

test "R-012 trace Merkle construction releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        componentFailureCase,
        .{},
    );
    var fixtures = try Fixtures.init();
    defer fixtures.deinit();
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        preprocessingFailureCase,
        .{fixtures.reference},
    );
}

const Fixtures = struct {
    shape: fixed_profile.ProofShapeV1,
    vm_plan: schedule.Plan,
    recursion_plan: schedule.Plan,
    reference: witness.Reference,

    fn init() !Fixtures {
        const shape = try testShape();
        const vm_spec = try schedule.ProgramSpec.init(.vm, 47, 1, 1, 47);
        const recursion_spec = try schedule.ProgramSpec.init(.recursion, 47, 0, 1, 47);
        var vm_plan = try schedule.Plan.init(std.testing.allocator, vm_spec, shape);
        errdefer vm_plan.deinit();
        var recursion_plan = try schedule.Plan.init(std.testing.allocator, recursion_spec, shape);
        errdefer recursion_plan.deinit();
        return .{
            .shape = shape,
            .vm_plan = vm_plan,
            .recursion_plan = recursion_plan,
            .reference = try witness.Reference.seal(
                PROFILE,
                &vm_plan,
                PROFILE,
                &recursion_plan,
            ),
        };
    }

    fn deinit(self: *Fixtures) void {
        self.vm_plan.deinit();
        self.recursion_plan.deinit();
        self.* = undefined;
    }
};

const OpeningFixture = struct {
    allocator: std.mem.Allocator,
    vm_values: []M31,
    left_values: []M31,
    right_values: []M31,
    vm_queries: []M31,
    left_queries: []M31,
    right_queries: []M31,
    vm: witness.OpeningSet,
    left: witness.OpeningSet,
    right: witness.OpeningSet,

    fn init(allocator: std.mem.Allocator) !OpeningFixture {
        const value_count = try PROFILE.queriedValueCount();
        const all = try allocator.alloc(M31, 3 * value_count + 3 * protocol.FRI_QUERY_COUNT);
        errdefer allocator.free(all);
        for (all, 0..) |*value, index| value.* = M31.fromCanonical(@intCast(index + 1));
        const vm_values = all[0..value_count];
        const left_values = all[value_count..][0..value_count];
        const right_values = all[2 * value_count ..][0..value_count];
        const queries = all[3 * value_count ..];
        const vm_queries = queries[0..protocol.FRI_QUERY_COUNT];
        const left_queries = queries[protocol.FRI_QUERY_COUNT..][0..protocol.FRI_QUERY_COUNT];
        const right_queries = queries[2 * protocol.FRI_QUERY_COUNT ..][0..protocol.FRI_QUERY_COUNT];
        return .{
            .allocator = allocator,
            .vm_values = vm_values,
            .left_values = left_values,
            .right_values = right_values,
            .vm_queries = vm_queries,
            .left_queries = left_queries,
            .right_queries = right_queries,
            .vm = .{ .queried_values = vm_values, .raw_queries = vm_queries },
            .left = .{ .queried_values = left_values, .raw_queries = left_queries },
            .right = .{ .queried_values = right_values, .raw_queries = right_queries },
        };
    }

    fn deinit(self: *OpeningFixture) void {
        self.allocator.free(self.vm_values.ptr[0 .. 3 * self.vm_values.len + 3 * self.vm_queries.len]);
        self.* = undefined;
    }
};

fn mappingProfile() query_mapping.LaneProfile {
    return .{
        .query_count = PROFILE.query_count,
        .lifting_log_size = PROFILE.lifting_log_size,
        .tree_heights = &.{ 9, 9, 9, 9 },
        .fri_fold_widths = PROFILE.fri_fold_widths,
    };
}

fn testShape() !fixed_profile.ProofShapeV1 {
    const fri = try fixed_profile.FriSchedule.init(8, protocol.PCS_CONFIG.fri_config);
    return .{
        .air_program_id = channel.hashBytes("trace-merkle-air", 0x5450),
        .preprocessing_id = channel.hashBytes("trace-merkle-preprocessed", 0x5450),
        .table_layout_id = channel.hashBytes("trace-merkle-layout", 0x5450),
        .table_count = 15,
        .claimed_sum_count = 1,
        .sampled_value_count = 1,
        .preprocessed_column_count = 10,
        .tree_column_counts = .{ 10, 1, 2, 2 },
        .tree_heights = .{ 9, 9, 9, 9 },
        .column_log_degree = 8,
        .proof_wire_bytes = 1,
        .fri = fri,
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
    var interaction = try plan.generateInteraction(
        allocator,
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        rows,
        log_size,
        relations,
    );
    defer interaction.deinit(allocator);
}

fn splitColumns(
    comptime count: usize,
    size: usize,
    storage: []M31,
    columns: *[count][]M31,
) void {
    for (columns, 0..) |*column, index| column.* = storage[index * size ..][0..size];
}
