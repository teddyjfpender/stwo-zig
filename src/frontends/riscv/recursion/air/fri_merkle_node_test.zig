//! Exactness, schedule, mutation, and hot-path gates for row 26.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const degree = @import("../../air/lang/degree.zig");
const digest = @import("../../air/lang/digest.zig");
const relation = @import("../../air/lang/relation.zig");
const static_profile = @import("../../air/lang/static_profile.zig");
const types = @import("../../air/lang/types.zig");
const component = @import("fri_merkle_node.zig");
const interaction_mod = @import("fri_merkle_node_relation.zig");
const support = @import("test_support.zig");
const universal = @import("universal_challenges.zig");
const witness = @import("fri_merkle_node_witness.zig");

const LAYERS = [_]witness.leaf.LayerProfile{
    .{ .width = 16, .tree_height = 7 },
    .{ .width = 4, .tree_height = 3 },
    .{ .width = 2, .tree_height = 3 },
};
const PROFILE = witness.leaf.LaneProfile{
    .query_count = 2,
    .lifting_log_size = 9,
    .layers = &LAYERS,
};
const ROWS_PER_LANE: usize = 8;
const TOTAL_ROWS: usize = 3 * ROWS_PER_LANE;

test "R-012 FRI Merkle node preserves exact Stark-V row-26 geometry and seal" {
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    try std.testing.expectEqual(@as(usize, 34), definition.main.physical().len);
    try std.testing.expectEqual(@as(usize, 6), definition.preprocessed.physical().len);
    try std.testing.expectEqual(@as(usize, 2), definition.parameters.physical().len);
    try std.testing.expectEqual(@as(usize, 34), definition.constraints.len);
    try std.testing.expectEqual(@as(usize, 5), definition.events.len);
    var degrees = try degree.analyze(std.testing.allocator, &definition.arena);
    defer degrees.deinit();
    try std.testing.expectEqual(
        @as(degree.Degree, component.MAXIMUM_CONSTRAINT_DEGREE),
        degrees.maximumConstraintDegree(),
    );
    const identity_value = try digest.computeIdentity(&definition.arena);
    try std.testing.expectEqualStrings(
        component.SEMANTIC_DIGEST_HEX,
        &std.fmt.bytesToHex(identity_value.bytes, .lower),
    );
    const binding = try witness.Binding.canonical(&definition);
    _ = try witness.Executor.init(&definition, &binding);
    try std.testing.expectEqualStrings(
        witness.BINDING_DIGEST_HEX,
        &std.fmt.bytesToHex(binding.identityDigest(), .lower),
    );
    const plan = try interaction_mod.authenticate(&definition);
    try std.testing.expectEqual(@as(usize, 3), interaction_mod.Runtime.BATCH_COUNT);
    try std.testing.expectEqual(@as(usize, 12), interaction_mod.Runtime.INTERACTION_COLUMN_COUNT);
    const domains = [_]relation.Domain{
        .poseidon2_io,
        .recursion_merkle_node,
        .recursion_fri_merkle_local_root,
        .recursion_merkle_node,
        .recursion_merkle_node,
    };
    for (plan.events, domains) |event, domain| try std.testing.expectEqual(domain, event.domain);
}

test "R-012 FRI Merkle node static profile is exact" {
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
    try std.testing.expectEqual(@as(u32, 42), profile.logical_input_nodes);
    try std.testing.expectEqual(@as(u32, 34), profile.constraint_roots);
    try std.testing.expectEqual(@as(u32, 5), profile.lookup_events);
    try std.testing.expectEqual(@as(?u32, 3), profile.lookup_batches);
    try std.testing.expectEqual(@as(?u32, 12), profile.interaction_columns);
    try std.testing.expectEqual(@as(u32, 3), profile.maximum_logical_constraint_degree);
}

test "R-012 FRI Merkle node schedule is bottom-up and authority sealed" {
    const reference = try fixtureReference();
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, reference);
    defer preprocessing.deinit();
    try preprocessing.validateAgainstAuthority(reference);
    try std.testing.expectEqual(@as(usize, TOTAL_ROWS), preprocessing.rows.len);
    try std.testing.expectEqual(@as(u32, 5), preprocessing.log_size);
    try std.testing.expectEqual(@as(u32, 6), preprocessing.rows[0].depth);
    try std.testing.expectEqual(@as(u32, 0), preprocessing.rows[0].relative_index);
    try std.testing.expectEqual(@as(u32, 0), preprocessing.rows[0].local_root_mask);
    try std.testing.expectEqual(@as(u32, 1), preprocessing.rows[1].relative_index);
    try std.testing.expectEqual(@as(u32, 5), preprocessing.rows[2].depth);
    try std.testing.expectEqual(@as(u32, 1), preprocessing.rows[2].local_root_mask);
    try std.testing.expectEqual(@as(u32, 4), preprocessing.rows[0].position_shift);
    try std.testing.expectEqual(@as(u32, 5), preprocessing.rows[0].position_bits);

    preprocessing.rows[0].relative_index = 1;
    try std.testing.expectError(
        error.AuthorityMismatch,
        preprocessing.validateAgainst(reference),
    );
}

test "R-012 FRI Merkle node materializes exact subtree linkage in every mode" {
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
    const sample_rows = [_]usize{ 0, 1, 2, ROWS_PER_LANE, 2 * ROWS_PER_LANE };
    for (cases) |opening| for (sample_rows) |row_index| {
        const logical = try witness.logicalRow(reference, &preprocessing, row_index, opening);
        try expectSatisfied(&definition, logical);
    };
    const opening = witness.OpeningWitness{ .segment_leaf = openings.opening(0) };
    const left_parent = try witness.logicalRow(reference, &preprocessing, 0, opening);
    const right_parent = try witness.logicalRow(reference, &preprocessing, 1, opening);
    const root = try witness.logicalRow(reference, &preprocessing, 2, opening);
    try std.testing.expectEqual(@as(u32, 1), left_parent[0].toU32());
    try std.testing.expectEqual(@as(u32, 0), left_parent[1].toU32());
    try std.testing.expectEqual(@as(u32, 1), right_parent[1].toU32());
    for (0..component.DIGEST_WORD_COUNT) |index| {
        try std.testing.expectEqual(left_parent[18 + index], root[2 + index]);
        try std.testing.expectEqual(right_parent[18 + index], root[10 + index]);
    }
    const empty = try witness.logicalRow(
        reference,
        &preprocessing,
        0,
        .{ .empty_leaf = {} },
    );
    for (empty[0..component.PHYSICAL_MAIN_COLUMN_COUNT]) |value|
        try std.testing.expect(value.isZero());
}

test "R-012 FRI Merkle node relation tuples close parent and child ownership" {
    const reference = try fixtureReference();
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, reference);
    defer preprocessing.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try interaction_mod.authenticate(&definition);
    var openings = try OpeningFixture.init(std.testing.allocator);
    defer openings.deinit();
    const opening = witness.OpeningWitness{ .segment_leaf = openings.opening(0) };
    const branch = try witness.logicalRow(reference, &preprocessing, 0, opening);
    const branch_entries = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        branch,
    );
    try std.testing.expect(branch_entries[0].numerator.eql(QM31.one().neg()));
    try std.testing.expect(branch_entries[1].numerator.eql(QM31.one().neg()));
    try std.testing.expect(branch_entries[2].numerator.isZero());
    try std.testing.expect(branch_entries[3].numerator.eql(QM31.one()));
    try std.testing.expect(branch_entries[4].numerator.eql(QM31.one()));

    const root = try witness.logicalRow(reference, &preprocessing, 2, opening);
    const root_entries = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        root,
    );
    try std.testing.expect(root_entries[1].numerator.isZero());
    try std.testing.expect(root_entries[2].numerator.eql(QM31.one().neg()));
    try std.testing.expectEqual(branch_entries[1].arity, root_entries[3].arity);
    for (
        branch_entries[1].values[0..branch_entries[1].arity],
        root_entries[3].values[0..root_entries[3].arity],
    ) |owned_parent, consumed_child| try std.testing.expect(owned_parent.eql(consumed_child));
}

test "R-012 FRI Merkle node writers are allocation-free padded and atomic" {
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

test "R-012 FRI Merkle node construction and interaction release every failure" {
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
    layers: [3][LAYERS.len]witness.leaf.LayerOpening,

    fn init(allocator: std.mem.Allocator) !OpeningFixture {
        const words_per_lane = PROFILE.query_count +
            PROFILE.query_count * (16 + 4 + 2) * witness.leaf.SECURE_WORD_COUNT;
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
            result.raw[lane] = lane_storage[0..PROFILE.query_count];
            var cursor: usize = PROFILE.query_count;
            for (&result.layers[lane], LAYERS) |*target, profile_layer| {
                const count = PROFILE.query_count * @as(usize, profile_layer.width) *
                    witness.leaf.SECURE_WORD_COUNT;
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
