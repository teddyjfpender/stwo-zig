//! Exactness, control-coupling, mutation, and hot-path gates for row 27.

const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const degree = @import("../../air/lang/degree.zig");
const digest = @import("../../air/lang/digest.zig");
const relation = @import("../../air/lang/relation.zig");
const static_profile = @import("../../air/lang/static_profile.zig");
const types = @import("../../air/lang/types.zig");
const fixed_profile = @import("../fixed_profile.zig");
const protocol = @import("../protocol.zig");
const channel = @import("../poseidon2_channel.zig");
const component = @import("fri_merkle_anchor.zig");
const interaction_mod = @import("fri_merkle_anchor_relation.zig");
const node_witness = @import("fri_merkle_node_witness.zig");
const schedule = @import("verifier_schedule.zig");
const support = @import("test_support.zig");
const universal = @import("universal_challenges.zig");
const witness = @import("fri_merkle_anchor_witness.zig");

const LAYERS = [_]witness.leaf.LayerProfile{
    .{ .width = 16, .tree_height = 7 },
    .{ .width = 16, .tree_height = 3 },
};
const PROFILE = witness.leaf.LaneProfile{
    .query_count = 2,
    .lifting_log_size = 9,
    .layers = &LAYERS,
};
const ROWS_PER_LANE: usize = PROFILE.query_count * LAYERS.len;
const TOTAL_ROWS: usize = 3 * ROWS_PER_LANE;

test "R-012 FRI Merkle anchor preserves exact Stark-V row-27 geometry and seal" {
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    try std.testing.expectEqual(@as(usize, 10), definition.main.physical().len);
    try std.testing.expectEqual(@as(usize, 15), definition.preprocessed.physical().len);
    try std.testing.expectEqual(@as(usize, 3), definition.parameters.physical().len);
    try std.testing.expectEqual(@as(usize, 10), definition.constraints.len);
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
        .recursion_query_position,
        .recursion_merkle_node,
        .recursion_fri_merkle_local_root,
        .recursion_fri_merkle_route,
        .recursion_step,
    };
    for (plan.events, domains) |event, domain| try std.testing.expectEqual(domain, event.domain);
}

test "R-012 FRI Merkle anchor static profile is exact" {
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
    try std.testing.expectEqual(@as(u32, 28), profile.logical_input_nodes);
    try std.testing.expectEqual(@as(u32, 10), profile.constraint_roots);
    try std.testing.expectEqual(@as(u32, 5), profile.lookup_events);
    try std.testing.expectEqual(@as(?u32, 3), profile.lookup_batches);
    try std.testing.expectEqual(@as(?u32, 12), profile.interaction_columns);
    try std.testing.expectEqual(@as(u32, 3), profile.maximum_logical_constraint_degree);
}

test "R-012 FRI Merkle anchor schedule binds exact verifier-control rows" {
    var fixtures = try Fixtures.init(std.testing.allocator);
    defer fixtures.deinit();
    var preprocessing = try witness.Preprocessed.init(
        std.testing.allocator,
        fixtures.reference,
        &fixtures.vm_plan,
        &fixtures.recursion_plan,
    );
    defer preprocessing.deinit();
    try preprocessing.validateAgainstAuthority(
        fixtures.reference,
        &fixtures.vm_plan,
        &fixtures.recursion_plan,
    );
    try std.testing.expectEqual(@as(usize, TOTAL_ROWS), preprocessing.rows.len);
    try std.testing.expectEqual(@as(u32, 4), preprocessing.log_size);
    const first = preprocessing.rows[0];
    try std.testing.expectEqual(@as(u32, 0), first.layer);
    try std.testing.expectEqual(@as(u32, 0), first.query);
    try std.testing.expectEqual(@as(u32, 5), first.path_depth);
    try std.testing.expectEqual(@as(u32, 4), first.leaf_count);
    try std.testing.expectEqual(@as(u32, 24), first.control_tag);
    try std.testing.expectEqual([4]u32{ 0, 0, 5, 16 }, first.control_args);
    try std.testing.expectEqual(@as(u32, 4), first.position_shift);
    try std.testing.expectEqual(@as(u32, 5), first.position_bits);
    const next_layer = preprocessing.rows[2];
    try std.testing.expectEqual(@as(u32, 1), next_layer.layer);
    try std.testing.expectEqual(@as(u32, 1), next_layer.path_depth);
    try std.testing.expectEqual(@as(u32, 8), next_layer.position_shift);

    preprocessing.rows[0].control_sequence += 1;
    try std.testing.expectError(
        error.AuthorityMismatch,
        preprocessing.validateAgainst(
            fixtures.reference,
            &fixtures.vm_plan,
            &fixtures.recursion_plan,
        ),
    );
}

test "R-012 FRI Merkle anchor root equals typed node root in every mode" {
    var fixtures = try Fixtures.init(std.testing.allocator);
    defer fixtures.deinit();
    var preprocessing = try witness.Preprocessed.init(
        std.testing.allocator,
        fixtures.reference,
        &fixtures.vm_plan,
        &fixtures.recursion_plan,
    );
    defer preprocessing.deinit();
    var node_preprocessing = try node_witness.Preprocessed.init(
        std.testing.allocator,
        fixtures.reference,
    );
    defer node_preprocessing.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    var openings = try OpeningFixture.init(std.testing.allocator);
    defer openings.deinit();
    const cases = [_]witness.OpeningWitness{
        .{ .segment_leaf = openings.opening(0) },
        .{ .binary_node = .{ .left = openings.opening(1), .right = openings.opening(2) } },
        .{ .empty_leaf = {} },
    };
    const sample_rows = [_]usize{ 0, ROWS_PER_LANE, 2 * ROWS_PER_LANE };
    for (cases) |opening| for (sample_rows) |row_index| {
        const logical = try witness.logicalRow(
            fixtures.reference,
            &preprocessing,
            &fixtures.vm_plan,
            &fixtures.recursion_plan,
            row_index,
            opening,
        );
        try expectSatisfied(&definition, logical);
    };
    const opening = witness.OpeningWitness{ .segment_leaf = openings.opening(0) };
    const anchor = try witness.logicalRow(
        fixtures.reference,
        &preprocessing,
        &fixtures.vm_plan,
        &fixtures.recursion_plan,
        0,
        opening,
    );
    const node_root = try node_witness.logicalRow(
        fixtures.reference,
        &node_preprocessing,
        2,
        opening,
    );
    try std.testing.expectEqual(@as(u32, 1), anchor[0].toU32());
    for (0..component.DIGEST_WORD_COUNT) |index|
        try std.testing.expectEqual(node_root[18 + index], anchor[2 + index]);

    const empty = try witness.logicalRow(
        fixtures.reference,
        &preprocessing,
        &fixtures.vm_plan,
        &fixtures.recursion_plan,
        0,
        .{ .empty_leaf = {} },
    );
    for (empty[0..component.PHYSICAL_MAIN_COLUMN_COUNT]) |value|
        try std.testing.expect(value.isZero());
}

test "R-012 FRI Merkle anchor relations close route root and control ownership" {
    var fixtures = try Fixtures.init(std.testing.allocator);
    defer fixtures.deinit();
    var preprocessing = try witness.Preprocessed.init(
        std.testing.allocator,
        fixtures.reference,
        &fixtures.vm_plan,
        &fixtures.recursion_plan,
    );
    defer preprocessing.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try interaction_mod.authenticate(&definition);
    var openings = try OpeningFixture.init(std.testing.allocator);
    defer openings.deinit();
    const logical = try witness.logicalRow(
        fixtures.reference,
        &preprocessing,
        &fixtures.vm_plan,
        &fixtures.recursion_plan,
        0,
        .{ .segment_leaf = openings.opening(0) },
    );
    const entries = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        logical,
    );
    try std.testing.expect(entries[0].numerator.eql(QM31.one().neg()));
    try std.testing.expect(entries[1].numerator.eql(QM31.one().neg()));
    try std.testing.expect(entries[2].numerator.eql(QM31.one()));
    // The terminal global path and the first local FRI node meet at one exact
    // `(tree, depth, position, digest)` tuple.
    try std.testing.expect(entries[1].values[1].eql(QM31.fromBase(logical[17])));
    try std.testing.expect(entries[1].values[2].eql(QM31.fromBase(logical[1])));
    try std.testing.expect(entries[2].values[1].eql(QM31.fromBase(logical[17])));
    try std.testing.expect(entries[2].values[2].eql(QM31.fromBase(logical[1])));
    for (0..component.DIGEST_WORD_COUNT) |word| {
        try std.testing.expect(entries[1].values[3 + word].eql(entries[2].values[3 + word]));
    }
    try std.testing.expect(entries[3].numerator.eql(QM31.fromBase(M31.fromCanonical(4))));
    try std.testing.expect(entries[4].numerator.eql(QM31.one().neg()));
}

test "R-012 FRI Merkle anchor writers are allocation-free padded and atomic" {
    var fixtures = try Fixtures.init(std.testing.allocator);
    defer fixtures.deinit();
    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var preprocessing = try witness.Preprocessed.init(
        measured.allocator(),
        fixtures.reference,
        &fixtures.vm_plan,
        &fixtures.recursion_plan,
    );
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
    try executor.generatePreprocessedInto(
        &preprocessing,
        fixtures.reference,
        &fixtures.vm_plan,
        &fixtures.recursion_plan,
        &pp_columns,
    );
    try std.testing.expectEqual(before_pp, measured.alloc_index);

    const storage = try std.testing.allocator.alloc(M31, component.PHYSICAL_MAIN_COLUMN_COUNT * size);
    defer std.testing.allocator.free(storage);
    var columns: [component.PHYSICAL_MAIN_COLUMN_COUNT][]M31 = undefined;
    splitColumns(component.PHYSICAL_MAIN_COLUMN_COUNT, size, storage, &columns);
    const before_main = measured.alloc_index;
    try executor.generateMainInto(
        &preprocessing,
        fixtures.reference,
        &fixtures.vm_plan,
        &fixtures.recursion_plan,
        &columns,
        opening,
    );
    try std.testing.expectEqual(before_main, measured.alloc_index);
    for (columns) |column| for (column[preprocessing.rows.len..]) |value|
        try std.testing.expect(value.isZero());

    const sentinel = M31.fromCanonical(12345);
    @memset(storage, sentinel);
    var duplicate = columns;
    duplicate[1] = duplicate[0];
    try std.testing.expectError(
        error.AliasedDestination,
        executor.generateMainInto(
            &preprocessing,
            fixtures.reference,
            &fixtures.vm_plan,
            &fixtures.recursion_plan,
            &duplicate,
            opening,
        ),
    );
    for (storage) |value| try std.testing.expect(value.eql(sentinel));
}

test "R-012 FRI Merkle anchor construction and interaction release every failure" {
    var fixtures = try Fixtures.init(std.testing.allocator);
    defer fixtures.deinit();
    var preprocessing = try witness.Preprocessed.init(
        std.testing.allocator,
        fixtures.reference,
        &fixtures.vm_plan,
        &fixtures.recursion_plan,
    );
    defer preprocessing.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try interaction_mod.authenticate(&definition);
    var openings = try OpeningFixture.init(std.testing.allocator);
    defer openings.deinit();
    const logical = try witness.logicalRow(
        fixtures.reference,
        &preprocessing,
        &fixtures.vm_plan,
        &fixtures.recursion_plan,
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
}

const Fixtures = struct {
    reference: witness.Reference,
    vm_plan: schedule.Plan,
    recursion_plan: schedule.Plan,

    fn init(allocator: std.mem.Allocator) !Fixtures {
        const shape = try testShape();
        var vm_plan = try schedule.Plan.init(
            allocator,
            try schedule.ProgramSpec.init(.vm, 3, 2, 3, 2),
            shape,
        );
        errdefer vm_plan.deinit();
        return .{
            .reference = try witness.Reference.seal(PROFILE, PROFILE),
            .vm_plan = vm_plan,
            .recursion_plan = try schedule.Plan.init(
                allocator,
                try schedule.ProgramSpec.init(.recursion, 3, 0, 3, 2),
                shape,
            ),
        };
    }

    fn deinit(self: *Fixtures) void {
        self.recursion_plan.deinit();
        self.vm_plan.deinit();
        self.* = undefined;
    }
};

const OpeningFixture = struct {
    allocator: std.mem.Allocator,
    storage: []M31,
    raw: [3][]M31,
    layers: [3][LAYERS.len]witness.leaf.LayerOpening,

    fn init(allocator: std.mem.Allocator) !OpeningFixture {
        const words_per_lane = PROFILE.query_count +
            PROFILE.query_count * (16 + 16) * witness.leaf.SECURE_WORD_COUNT;
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

fn testShape() !fixed_profile.ProofShapeV1 {
    const fri = try fixed_profile.FriSchedule.init(8, protocol.PCS_CONFIG.fri_config);
    return .{
        .air_program_id = channel.hashBytes("fri-anchor-air", 0x5450),
        .preprocessing_id = channel.hashBytes("fri-anchor-preprocessing", 0x5450),
        .table_layout_id = channel.hashBytes("fri-anchor-layout", 0x5450),
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
