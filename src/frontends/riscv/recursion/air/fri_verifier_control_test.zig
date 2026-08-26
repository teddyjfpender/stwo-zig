//! Exact schedule, cross-component closure, mutation, and hot-path gates for row 28.

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
const component = @import("fri_verifier_control.zig");
const interaction_mod = @import("fri_verifier_control_relation.zig");
const mapping_component = @import("query_mapping.zig");
const mapping_witness = @import("query_mapping_witness.zig");
const schedule = @import("verifier_schedule.zig");
const support = @import("test_support.zig");
const universal = @import("universal_challenges.zig");
const witness = @import("fri_verifier_control_witness.zig");

const TREE_HEIGHTS = [_]u32{ 9, 9, 9, 9 };
const FRI_FOLD_WIDTHS = [_]u32{ 16, 16 };
const PROFILE = mapping_witness.LaneProfile{
    .query_count = protocol.FRI_QUERY_COUNT,
    .lifting_log_size = 9,
    .tree_heights = &TREE_HEIGHTS,
    .fri_fold_widths = &FRI_FOLD_WIDTHS,
};
const ROWS_PER_LANE: usize = protocol.FRI_QUERY_COUNT * (FRI_FOLD_WIDTHS.len + 2);
const TOTAL_ROWS: usize = 3 * ROWS_PER_LANE;
const MAPPING_ROWS_PER_QUERY: usize = TREE_HEIGHTS.len + 2 * FRI_FOLD_WIDTHS.len + 2;

test "R-012 FRI verifier control preserves exact Stark-V row-28 geometry and seal" {
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    try std.testing.expectEqual(@as(usize, 3), definition.main.physical().len);
    try std.testing.expectEqual(@as(usize, 15), definition.preprocessed.physical().len);
    try std.testing.expectEqual(@as(usize, 4), definition.parameters.physical().len);
    try std.testing.expectEqual(@as(usize, 6), definition.constraints.len);
    try std.testing.expectEqual(@as(usize, 4), definition.events.len);
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
    try std.testing.expectEqual(@as(usize, 2), interaction_mod.Runtime.BATCH_COUNT);
    try std.testing.expectEqual(@as(usize, 8), interaction_mod.Runtime.INTERACTION_COLUMN_COUNT);
    const domains = [_]relation.Domain{
        .recursion_step,
        .recursion_query_position,
        .recursion_fri_verifier_route_word,
        .recursion_fri_verifier_route_word,
    };
    const roles = [_]relation.Role{ .consume, .consume, .emit, .emit };
    for (plan.events, domains, roles) |event, domain, role| {
        try std.testing.expectEqual(domain, event.domain);
        try std.testing.expectEqual(role, event.role);
    }
}

test "R-012 FRI verifier control static profile is exact and closed" {
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
    try std.testing.expectEqual(@as(u32, 22), profile.logical_input_nodes);
    try std.testing.expectEqual(@as(u32, 6), profile.constraint_roots);
    try std.testing.expectEqual(@as(u32, 4), profile.lookup_events);
    try std.testing.expectEqual(@as(?u32, 2), profile.lookup_batches);
    try std.testing.expectEqual(@as(?u32, 8), profile.interaction_columns);
    try std.testing.expectEqual(@as(u32, 3), profile.maximum_logical_constraint_degree);
    try std.testing.expectEqual(@as(?u32, 4), profile.maximum_modeled_interaction_degree);
    try std.testing.expectEqual(@as(u32, 0), profile.nodes_outside_constraint_effect_closure);
}

test "R-012 FRI verifier control binds exact plan coordinates and cold schedule authority" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const reference = try fixture.reference();
    try reference.validateAuthority();
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, reference);
    defer preprocessing.deinit();
    try preprocessing.validateAgainstAuthority(reference);
    try std.testing.expectEqual(@as(usize, TOTAL_ROWS), preprocessing.rows.len);
    try std.testing.expectEqual(@as(u32, 12), preprocessing.log_size);

    const deep = preprocessing.rows[0];
    try std.testing.expectEqual(@as(u32, 0), deep.route_mask);
    try std.testing.expectEqual(@as(u32, 0), deep.offset_output_mask);
    try std.testing.expectEqual(@as(u32, 0), deep.query);
    try std.testing.expectEqual(@as(u32, 23), deep.tag);
    try std.testing.expectEqual(@as(u32, 0), deep.args[0]);

    const fold_0 = preprocessing.rows[protocol.FRI_QUERY_COUNT];
    try std.testing.expectEqual(@as(u32, 1), fold_0.route_mask);
    try std.testing.expectEqual(@as(u32, 1), fold_0.offset_output_mask);
    try std.testing.expectEqual(@as(u32, @intFromEnum(mapping_witness.QueryPositionKind.fri_fold)), fold_0.route_kind);
    try std.testing.expectEqual(@as(u32, 0), fold_0.item);
    try std.testing.expectEqual(@as(u32, 0), fold_0.query);
    try std.testing.expectEqual(@as(u32, 25), fold_0.tag);
    try std.testing.expectEqual([4]u32{ 0, 0, 16, 0 }, fold_0.args);

    const fold_1 = preprocessing.rows[2 * protocol.FRI_QUERY_COUNT];
    try std.testing.expectEqual(@as(u32, 1), fold_1.item);
    try std.testing.expectEqual([4]u32{ 1, 0, 16, 0 }, fold_1.args);
    const last = preprocessing.rows[3 * protocol.FRI_QUERY_COUNT];
    try std.testing.expectEqual(@as(u32, @intFromEnum(mapping_witness.QueryPositionKind.last_layer)), last.route_kind);
    try std.testing.expectEqual(@as(u32, 26), last.tag);
    try std.testing.expectEqual([4]u32{ 0, 0, 0, 0 }, last.args);

    preprocessing.rows[0].sequence += 1;
    try std.testing.expectError(error.AuthorityMismatch, preprocessing.validateAgainst(reference));
}

test "R-012 FRI verifier control hot seal is immutable while cold seal detects plan mutation" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const reference = try fixture.reference();
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, reference);
    defer preprocessing.deinit();

    fixture.vm_plan.steps[0] = .bind_statement;
    // The proof-time path consumes only the independently sealed row table and
    // therefore does not need to allocate to recompute the full plan digest.
    try preprocessing.validateAgainst(reference);
    try std.testing.expectError(
        error.ScheduleDigestMismatch,
        preprocessing.validateAgainstAuthority(reference),
    );
}

test "R-012 FRI verifier control exactly consumes typed query mapping positions" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const reference = try fixture.reference();
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, reference);
    defer preprocessing.deinit();
    const mapping_reference = try reference.mappingReference();
    var mapping_preprocessing = try mapping_witness.Preprocessed.init(
        std.testing.allocator,
        mapping_reference,
    );
    defer mapping_preprocessing.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const queries = queryFixture();
    const query_witness = mapping_witness.QueryWitness{ .segment_leaf = &queries.vm };

    const query: usize = 7;
    const control_index = protocol.FRI_QUERY_COUNT + query;
    const mapping_index = query * MAPPING_ROWS_PER_QUERY + TREE_HEIGHTS.len + 1;
    const control_row = try witness.logicalRow(
        reference,
        &preprocessing,
        control_index,
        query_witness,
    );
    const mapping_row = try mapping_witness.logicalRow(
        mapping_preprocessing.rows[mapping_index],
        query_witness,
    );
    try std.testing.expectEqual(mapping_row[1], control_row[1]);
    try std.testing.expectEqual(mapping_row[2], control_row[2]);
    try expectSatisfied(&definition, control_row);

    const empty = try witness.logicalRow(
        reference,
        &preprocessing,
        control_index,
        .{ .empty_leaf = {} },
    );
    try std.testing.expectEqual(@as(u32, 1), empty[0].toU32());
    try std.testing.expect(empty[1].isZero());
    try std.testing.expect(empty[2].isZero());
}

test "R-012 FRI verifier control relation signs and route-word fields are exact" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const reference = try fixture.reference();
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, reference);
    defer preprocessing.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try interaction_mod.authenticate(&definition);
    const queries = queryFixture();
    const query_witness = mapping_witness.QueryWitness{ .segment_leaf = &queries.vm };

    const logical = try witness.logicalRow(
        reference,
        &preprocessing,
        protocol.FRI_QUERY_COUNT,
        query_witness,
    );
    try expectSatisfied(&definition, logical);
    const entries = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        logical,
    );
    try std.testing.expect(entries[0].numerator.eql(QM31.one().neg()));
    try std.testing.expect(entries[1].numerator.eql(QM31.one().neg()));
    try std.testing.expect(entries[2].numerator.eql(QM31.one()));
    try std.testing.expect(entries[3].numerator.eql(QM31.one()));
    try std.testing.expect(entries[2].values[4].eql(QM31.fromBase(M31.fromCanonical(witness.POSITION_FIELD))));
    try std.testing.expect(entries[2].values[5].eql(QM31.fromBase(logical[1])));
    try std.testing.expect(entries[3].values[4].eql(QM31.fromBase(M31.fromCanonical(witness.OFFSET_FIELD))));
    try std.testing.expect(entries[3].values[5].eql(QM31.fromBase(logical[2])));

    const deep = try witness.logicalRow(reference, &preprocessing, 0, query_witness);
    const deep_entries = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        deep,
    );
    try std.testing.expect(deep_entries[0].numerator.eql(QM31.one().neg()));
    for (deep_entries[1..]) |entry| try std.testing.expect(entry.numerator.isZero());

    const inactive = try witness.logicalRow(
        reference,
        &preprocessing,
        ROWS_PER_LANE,
        query_witness,
    );
    try expectSatisfied(&definition, inactive);
    const inactive_entries = try plan.entries(
        &definition.arena,
        component.SEMANTIC_DIGEST,
        definition.events,
        inactive,
    );
    for (inactive_entries) |entry| try std.testing.expect(entry.numerator.isZero());
}

test "R-012 FRI verifier control writers are allocation-free padded and atomic" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const reference = try fixture.reference();
    var measured = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var preprocessing = try witness.Preprocessed.init(measured.allocator(), reference);
    defer preprocessing.deinit();
    try std.testing.expectEqual(@as(usize, 1), measured.alloc_index);
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const binding = try witness.Binding.canonical(&definition);
    const executor = try witness.Executor.init(&definition, &binding);
    const queries = queryFixture();
    const query_witness = mapping_witness.QueryWitness{ .binary_node = .{
        .left = &queries.left,
        .right = &queries.right,
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
    try executor.generateMainInto(&preprocessing, reference, &columns, query_witness);
    try std.testing.expectEqual(before_main, measured.alloc_index);
    for (columns) |column| for (column[preprocessing.rows.len..]) |value|
        try std.testing.expect(value.isZero());

    const sentinel = M31.fromCanonical(12345);
    @memset(storage, sentinel);
    var duplicate = columns;
    duplicate[1] = duplicate[0];
    try std.testing.expectError(
        error.AliasedDestination,
        executor.generateMainInto(&preprocessing, reference, &duplicate, query_witness),
    );
    for (storage) |value| try std.testing.expect(value.eql(sentinel));
}

test "R-012 FRI verifier control construction and interaction release every failure" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const reference = try fixture.reference();
    var preprocessing = try witness.Preprocessed.init(std.testing.allocator, reference);
    defer preprocessing.deinit();
    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try interaction_mod.authenticate(&definition);
    const queries = queryFixture();
    const logical = try witness.logicalRow(
        reference,
        &preprocessing,
        protocol.FRI_QUERY_COUNT,
        .{ .segment_leaf = &queries.vm },
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

const Fixture = struct {
    vm_plan: schedule.Plan,
    recursion_plan: schedule.Plan,

    fn init(allocator: std.mem.Allocator) !Fixture {
        const shape = try testShape();
        var vm_plan = try schedule.Plan.init(
            allocator,
            try schedule.ProgramSpec.init(.vm, 3, 2, 3, 2),
            shape,
        );
        errdefer vm_plan.deinit();
        return .{
            .vm_plan = vm_plan,
            .recursion_plan = try schedule.Plan.init(
                allocator,
                try schedule.ProgramSpec.init(.recursion, 3, 0, 3, 2),
                shape,
            ),
        };
    }

    fn reference(self: *const Fixture) !witness.Reference {
        return witness.Reference.seal(
            .{ .plan = &self.vm_plan, .mapping = PROFILE },
            .{ .plan = &self.recursion_plan, .mapping = PROFILE },
        );
    }

    fn deinit(self: *Fixture) void {
        self.recursion_plan.deinit();
        self.vm_plan.deinit();
        self.* = undefined;
    }
};

const QueryFixture = struct {
    vm: [protocol.FRI_QUERY_COUNT]M31,
    left: [protocol.FRI_QUERY_COUNT]M31,
    right: [protocol.FRI_QUERY_COUNT]M31,
};

fn queryFixture() QueryFixture {
    var result: QueryFixture = undefined;
    for (&result.vm, &result.left, &result.right, 0..) |*vm, *left, *right, index| {
        vm.* = M31.fromCanonical(@intCast(index * 17 + 3));
        left.* = M31.fromCanonical(@intCast(index * 19 + 5));
        right.* = M31.fromCanonical(@intCast(index * 23 + 7));
    }
    return result;
}

fn testShape() !fixed_profile.ProofShapeV1 {
    const fri = try fixed_profile.FriSchedule.init(8, protocol.PCS_CONFIG.fri_config);
    return .{
        .air_program_id = channel.hashBytes("fri-control-air", 0x5450),
        .preprocessing_id = channel.hashBytes("fri-control-preprocessing", 0x5450),
        .table_layout_id = channel.hashBytes("fri-control-layout", 0x5450),
        .table_count = 15,
        .claimed_sum_count = 1,
        .sampled_value_count = 1,
        .preprocessed_column_count = 10,
        .tree_column_counts = .{ 10, 1, 2, 2 },
        .tree_heights = TREE_HEIGHTS,
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

comptime {
    _ = mapping_component.LOGICAL_INPUT_COUNT;
}
