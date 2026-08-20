//! Exactness, schedule, mutation, and performance gates for row 25.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const degree = @import("../../air/lang/degree.zig");
const digest = @import("../../air/lang/digest.zig");
const relation = @import("../../air/lang/relation.zig");
const static_profile = @import("../../air/lang/static_profile.zig");
const types = @import("../../air/lang/types.zig");
const component = @import("fri_merkle_leaf.zig");
const interaction_mod = @import("fri_merkle_leaf_relation.zig");
const merkle_root = @import("merkle_root_witness.zig");
const query_mapping = @import("query_mapping_witness.zig");
const support = @import("test_support.zig");
const universal = @import("universal_challenges.zig");
const witness = @import("fri_merkle_leaf_witness.zig");

const LAYERS = [_]witness.LayerProfile{
    .{ .width = 16, .tree_height = 7 },
    .{ .width = 4, .tree_height = 3 },
    .{ .width = 2, .tree_height = 3 },
};
const PROFILE = witness.LaneProfile{
    .query_count = 2,
    .lifting_log_size = 9,
    .layers = &LAYERS,
};
const FOLD_WIDTHS = [_]u32{ 16, 4, 2 };
const TRACE_HEIGHTS = [_]u32{9};
const ROWS_PER_LANE: usize = 34;
const TOTAL_ROWS: usize = 3 * ROWS_PER_LANE;

test "R-012 FRI Merkle leaf preserves row-25 semantics with one cubic materialization" {
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    try std.testing.expectEqual(@as(usize, 43), definition.main.physical().len);
    try std.testing.expectEqual(@as(usize, 48), definition.preprocessed.physical().len);
    try std.testing.expectEqual(@as(usize, 3), definition.parameters.physical().len);
    try std.testing.expectEqual(@as(usize, 67), definition.constraints.len);
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
    const domains = [_]relation.Domain{
        .poseidon2_io,
        .recursion_fri_merkle_value_word,
        .recursion_fri_merkle_value_word,
        .recursion_fri_merkle_value_word,
        .recursion_fri_merkle_value_word,
        .recursion_fri_merkle_value_word,
        .recursion_fri_merkle_value_word,
        .recursion_fri_merkle_value_word,
        .recursion_fri_merkle_value_word,
        .recursion_fri_merkle_leaf_state,
        .recursion_fri_merkle_leaf_state,
        .recursion_fri_merkle_route,
        .recursion_merkle_node,
        .recursion_fri_merkle_local_root,
    };
    for (plan.events, domains) |event, domain| try std.testing.expectEqual(domain, event.domain);
}

test "R-012 FRI Merkle leaf static profile is exact and closed" {
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
    try std.testing.expectEqual(@as(u32, 94), profile.logical_input_nodes);
    try std.testing.expectEqual(@as(u32, 67), profile.constraint_roots);
    try std.testing.expectEqual(@as(u32, 14), profile.lookup_events);
    try std.testing.expectEqual(@as(?u32, 7), profile.lookup_batches);
    try std.testing.expectEqual(@as(?u32, 28), profile.interaction_columns);
    try std.testing.expectEqual(@as(u32, 4), profile.maximum_logical_constraint_degree);
    try std.testing.expectEqual(
        @as(?u32, 4),
        profile.maximum_modeled_interaction_degree,
    );
    // The generic profiler treats verifier scalars as trace-degree inputs.
    // The concrete adapter injects them as constants, reducing this
    // conservative four to the audited cubic protocol bound.
    try std.testing.expectEqual(
        @as(u32, 3),
        component.LOWERED_MAXIMUM_CONSTRAINT_DEGREE,
    );
    // Stark-V carries the shared row mask and local-root classification in
    // preprocessing even though the leaf AIR uses the two endpoint masks.
    // Keep that source-exact redundancy visible instead of silently pruning it.
    try std.testing.expectEqual(@as(u32, 2), profile.nodes_outside_constraint_effect_closure);
}

test "R-012 FRI Merkle leaf schedule binds packing routing and endpoint ownership" {
    const reference = try fixtureReference();
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, reference);
    defer preprocessing.deinit();
    try preprocessing.validateAgainstAuthority(reference);
    try std.testing.expectEqual(@as(usize, TOTAL_ROWS), preprocessing.rows.len);
    try std.testing.expectEqual(@as(u32, 7), preprocessing.log_size);
    const first = preprocessing.rows[0];
    try std.testing.expectEqual(@as(u32, 4), first.leaf_count);
    try std.testing.expectEqual(@as(u32, 0), first.local_root_mask);
    try std.testing.expectEqual(@as(u32, 0), first.packed_index);
    try std.testing.expectEqual(@as(u32, 1), first.first);
    try std.testing.expectEqual(@as(u32, 0), first.last);
    try std.testing.expectEqual(@as(u32, 0), first.chunks[0].offset);
    try std.testing.expectEqual(@as(u32, 0), first.chunks[0].word);
    try std.testing.expectEqual(@as(u32, 1), first.chunks[4].offset);
    try std.testing.expectEqual(@as(u32, 0), first.chunks[4].word);
    const endpoint = preprocessing.rows[2];
    try std.testing.expectEqual(@as(u32, 1), endpoint.last);
    try std.testing.expectEqual(@as(u32, 1), endpoint.merkle_endpoint_mask);
    try std.testing.expectEqual(@as(u32, 0), endpoint.local_root_endpoint_mask);
    try std.testing.expectEqual(@as(u32, 1), endpoint.chunks[0].constant);
    const local = preprocessing.rows[24];
    try std.testing.expectEqual(@as(u32, 1), local.leaf_count);
    try std.testing.expectEqual(@as(u32, 1), local.local_root_mask);
    try std.testing.expectEqual(@as(u32, 1), preprocessing.rows[26].local_root_endpoint_mask);
    const narrow = preprocessing.rows[30];
    try std.testing.expectEqual(@as(u32, 2), narrow.leaf_count);
    try std.testing.expectEqual(@as(u32, 7), narrow.position_shift);
    try std.testing.expectEqual(@as(u32, 2), narrow.position_bits);

    const mapping = try query_mapping.Reference.seal(mappingProfile(), mappingProfile());
    try reference.validateQueryMapping(mapping);
    const roots = try merkle_root.Reference.seal(rootProfile(), rootProfile());
    try reference.validateMerkleRoots(roots);

    preprocessing.rows[0].position_shift += 1;
    try std.testing.expectError(
        error.AuthorityMismatch,
        preprocessing.validateAgainst(reference),
    );
}

test "R-012 FRI Merkle leaf materializes exact chained states in every universal mode" {
    const reference = try fixtureReference();
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, reference);
    defer preprocessing.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    var openings = try OpeningFixture.init(std.testing.allocator);
    defer openings.deinit();
    const cases = [_]witness.OpeningWitness{
        .{ .segment_leaf = openings.opening(0) },
        .{ .binary_node = .{ .left = openings.opening(1), .right = openings.opening(2) } },
        .{ .empty_leaf = {} },
    };
    const sample_rows = [_]usize{ 0, 2, 24, 26, 30, ROWS_PER_LANE, 2 * ROWS_PER_LANE };
    for (cases) |opening| for (sample_rows) |row_index| {
        const logical = try witness.logicalRow(reference, &preprocessing, row_index, opening);
        try expectSatisfied(&definition, logical);
    };
    const active = try witness.logicalRow(
        reference,
        &preprocessing,
        0,
        .{ .segment_leaf = openings.opening(0) },
    );
    try std.testing.expectEqual(@as(u32, 1), active[0].toU32());
    try std.testing.expectEqual(@as(u32, witness.LEAF_TAG), active[18].toU32());
    try std.testing.expectEqual(openings.layers[0][0].values[0], active[19]);
    try std.testing.expectEqual(openings.layers[0][0].values[4], active[23]);
    const final = try witness.logicalRow(
        reference,
        &preprocessing,
        2,
        .{ .segment_leaf = openings.opening(0) },
    );
    const expected_position = (openings.raw[0][0].toU32() >> 4) & 0x1f;
    try std.testing.expectEqual(expected_position, final[1].toU32());
    try std.testing.expectEqual(expected_position * 4, final[2].toU32());
    const empty = try witness.logicalRow(
        reference,
        &preprocessing,
        0,
        .{ .empty_leaf = {} },
    );
    for (empty[0..component.PHYSICAL_MAIN_COLUMN_COUNT]) |value|
        try std.testing.expect(value.isZero());
}

test "R-012 FRI Merkle leaf relations bind chain values route and endpoints" {
    const reference = try fixtureReference();
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, reference);
    defer preprocessing.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try interaction_mod.authenticate(&definition);
    var openings = try OpeningFixture.init(std.testing.allocator);
    defer openings.deinit();
    const opening = witness.OpeningWitness{ .segment_leaf = openings.opening(0) };
    const first = try witness.logicalRow(reference, &preprocessing, 0, opening);
    const first_entries = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        first,
    );
    try std.testing.expect(first_entries[0].numerator.eql(QM31.one().neg()));
    for (first_entries[1..9]) |entry| try std.testing.expect(entry.numerator.eql(QM31.one()));
    try std.testing.expect(first_entries[9].numerator.isZero());
    try std.testing.expect(first_entries[10].numerator.eql(QM31.one()));
    for (first_entries[11..]) |entry| try std.testing.expect(entry.numerator.isZero());

    const middle = try witness.logicalRow(reference, &preprocessing, 1, opening);
    const middle_entries = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        middle,
    );
    try std.testing.expectEqual(first_entries[10].arity, middle_entries[9].arity);
    for (
        first_entries[10].values[0..first_entries[10].arity],
        middle_entries[9].values[0..middle_entries[9].arity],
    ) |emitted, consumed| try std.testing.expect(emitted.eql(consumed));

    const endpoint = try witness.logicalRow(reference, &preprocessing, 2, opening);
    const endpoint_entries = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        endpoint,
    );
    try std.testing.expect(endpoint_entries[9].numerator.eql(QM31.one().neg()));
    try std.testing.expect(endpoint_entries[10].numerator.isZero());
    try std.testing.expect(endpoint_entries[11].numerator.eql(QM31.one().neg()));
    try std.testing.expect(endpoint_entries[12].numerator.eql(QM31.one().neg()));
    try std.testing.expect(endpoint_entries[13].numerator.isZero());

    const local_endpoint = try witness.logicalRow(reference, &preprocessing, 26, opening);
    const local_entries = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        local_endpoint,
    );
    try std.testing.expect(local_entries[12].numerator.isZero());
    try std.testing.expect(local_entries[13].numerator.eql(QM31.one().neg()));
}

test "R-012 FRI Merkle leaf writers are allocation-free padded and atomic" {
    const reference = try fixtureReference();
    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var preprocessing = try witness.Preprocessed.init(measured.allocator(), reference);
    defer preprocessing.deinit();
    try std.testing.expectEqual(@as(usize, 1), measured.alloc_index);
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const binding = try witness.Binding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    var openings = try OpeningFixture.init(std.testing.allocator);
    defer openings.deinit();
    const opening = witness.OpeningWitness{ .binary_node = .{
        .left = openings.opening(1),
        .right = openings.opening(2),
    } };
    const size = @as(usize, 1) << @intCast(preprocessing.log_size);
    const pp_storage = try std.testing.allocator.alloc(
        M31,
        component.PREPROCESSED_COLUMN_COUNT * size,
    );
    defer std.testing.allocator.free(pp_storage);
    var pp_columns: [component.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
    splitColumns(component.PREPROCESSED_COLUMN_COUNT, size, pp_storage, &pp_columns);
    const before_pp = measured.alloc_index;
    try executor.generatePreprocessedInto(&preprocessing, reference, &pp_columns);
    try std.testing.expectEqual(before_pp, measured.alloc_index);

    const storage = try std.testing.allocator.alloc(M31, component.PHYSICAL_MAIN_COLUMN_COUNT * size);
    defer std.testing.allocator.free(storage);
    var columns: [component.PHYSICAL_MAIN_COLUMN_COUNT][]M31 = undefined;
    splitColumns(component.PHYSICAL_MAIN_COLUMN_COUNT, size, storage, &columns);
    const before_main = measured.alloc_index;
    try executor.generateMainInto(&preprocessing, reference, &columns, opening);
    try std.testing.expectEqual(before_main, measured.alloc_index);
    for (columns) |column| for (column[preprocessing.rows.len..]) |value|
        try std.testing.expect(value.isZero());

    const sentinel = M31.fromCanonical(12345);
    @memset(storage, sentinel);
    var short = columns;
    short[0] = short[0][0 .. size - 1];
    try std.testing.expectError(
        error.InvalidTraceShape,
        executor.generateMainInto(&preprocessing, reference, &short, opening),
    );
    for (storage) |value| try std.testing.expect(value.eql(sentinel));
    var duplicate = columns;
    duplicate[1] = duplicate[0];
    try std.testing.expectError(
        error.AliasedDestination,
        executor.generateMainInto(&preprocessing, reference, &duplicate, opening),
    );
    for (storage) |value| try std.testing.expect(value.eql(sentinel));
}

test "R-012 FRI Merkle leaf interaction and construction are failure atomic" {
    const reference = try fixtureReference();
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, reference);
    defer preprocessing.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try interaction_mod.authenticate(&definition);
    var openings = try OpeningFixture.init(std.testing.allocator);
    defer openings.deinit();
    const logical = try witness.logicalRow(
        reference,
        &preprocessing,
        0,
        .{ .segment_leaf = openings.opening(0) },
    );
    const rows = [_]interaction_mod.Row{logical};
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
    }
    try std.testing.expectEqual(measured.allocated_bytes, measured.freed_bytes);
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        interactionFailureCase,
        .{ &definition, &plan, &rows, witness.MIN_LOG_SIZE, &relations },
    );
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        componentFailureCase,
        .{},
    );
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        preprocessingFailureCase,
        .{reference},
    );
}

const OpeningFixture = struct {
    allocator: std.mem.Allocator,
    storage: []M31,
    raw: [3][]M31,
    layers: [3][3]witness.LayerOpening,

    fn init(allocator: std.mem.Allocator) !OpeningFixture {
        const words_per_lane = 2 + 2 * (16 + 4 + 2) * 4;
        const storage = try allocator.alloc(M31, 3 * words_per_lane);
        errdefer allocator.free(storage);
        for (storage, 0..) |*value, index| value.* = M31.fromCanonical(@intCast(index + 1));
        var result = OpeningFixture{
            .allocator = allocator,
            .storage = storage,
            .raw = undefined,
            .layers = undefined,
        };
        for (0..3) |lane| {
            const lane_storage = storage[lane * words_per_lane ..][0..words_per_lane];
            result.raw[lane] = lane_storage[0..2];
            var cursor: usize = 2;
            for (&result.layers[lane], LAYERS) |*target, profile_layer| {
                const count = 2 * @as(usize, profile_layer.width) * 4;
                target.* = .{
                    .width = profile_layer.width,
                    .values = lane_storage[cursor..][0..count],
                };
                cursor += count;
            }
        }
        return result;
    }

    fn deinit(self: *OpeningFixture) void {
        self.allocator.free(self.storage);
        self.* = undefined;
    }

    fn opening(self: *const OpeningFixture, lane: usize) witness.OpeningSet {
        return .{ .raw_queries = self.raw[lane], .layers = &self.layers[lane] };
    }
};

fn fixtureReference() !witness.Reference {
    return witness.Reference.seal(PROFILE, PROFILE);
}

fn mappingProfile() query_mapping.LaneProfile {
    return .{
        .query_count = PROFILE.query_count,
        .lifting_log_size = PROFILE.lifting_log_size,
        .tree_heights = &TRACE_HEIGHTS,
        .fri_fold_widths = &FOLD_WIDTHS,
    };
}

fn rootProfile() merkle_root.LaneProfile {
    return .{
        .query_count = PROFILE.query_count,
        .trace_tree_count = TRACE_HEIGHTS.len,
        .fri_layer_count = LAYERS.len,
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
