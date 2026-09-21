const std = @import("std");
const channel = @import("../poseidon2_channel.zig");
const fixed_profile = @import("../fixed_profile.zig");
const protocol = @import("../protocol.zig");
const control = @import("fri_verifier_control_heterogeneous_v2.zig");
const control_base = @import("fri_verifier_control_witness.zig");
const fri_base = @import("fri_merkle_leaf_witness.zig");
const fri = @import("fri_merkle_reference_heterogeneous_v2.zig");
const fri_rows = @import("fri_merkle_rows_heterogeneous_v2.zig");
const mapping_base = @import("query_mapping_witness.zig");
const mapping = @import("query_mapping_witness_heterogeneous_v2.zig");
const roots_base = @import("merkle_root_witness.zig");
const roots = @import("merkle_root_witness_heterogeneous_v2.zig");
const schedule = @import("verifier_schedule.zig");

const VM_TRACE_HEIGHTS = [_]u32{ 9, 9, 9, 9 };
const LEFT_TRACE_HEIGHTS = [_]u32{ 10, 10, 10 };
const RIGHT_TRACE_HEIGHTS = [_]u32{ 11, 11, 10, 11, 9 };
const VM_FOLDS = [_]u32{ 4, 4 };
const LEFT_FOLDS = [_]u32{ 4, 4 };
const RIGHT_FOLDS = [_]u32{ 8, 4 };
const VM_LAYERS = [_]fri_base.LayerProfile{
    .{ .width = 4, .tree_height = 7 },
    .{ .width = 4, .tree_height = 5 },
};
const LEFT_LAYERS = [_]fri_base.LayerProfile{
    .{ .width = 4, .tree_height = 8 },
    .{ .width = 4, .tree_height = 6 },
};
const RIGHT_LAYERS = [_]fri_base.LayerProfile{
    .{ .width = 8, .tree_height = 9 },
    .{ .width = 4, .tree_height = 6 },
};

test "R-012 heterogeneous FRI profiles bind independent roots and mappings" {
    var mapping_reference = try mapping.Reference.seal(
        mappingProfile(2, 9, &VM_TRACE_HEIGHTS, &VM_FOLDS),
        mappingProfile(3, 10, &LEFT_TRACE_HEIGHTS, &LEFT_FOLDS),
        mappingProfile(5, 11, &RIGHT_TRACE_HEIGHTS, &RIGHT_FOLDS),
    );
    var root_reference = try roots.Reference.seal(
        rootProfile(2, 4, 2),
        rootProfile(3, 3, 2),
        rootProfile(5, 5, 2),
    );
    const fri_reference = try fri.Reference.seal(
        friProfile(2, 9, &VM_LAYERS),
        friProfile(3, 10, &LEFT_LAYERS),
        friProfile(5, 11, &RIGHT_LAYERS),
    );
    try fri_reference.validateQueryMapping(&mapping_reference);
    try fri_reference.validateMerkleRoots(&root_reference);
    try std.testing.expect(
        mapping_reference.lanes[1].profile.tree_heights[0] !=
            mapping_reference.lanes[2].profile.tree_heights[0],
    );

    var preprocessing = try roots.Preprocessed.init(std.testing.allocator, &root_reference);
    defer preprocessing.deinit();
    try preprocessing.validateAgainstAuthority(&root_reference);
    try std.testing.expectEqual(@as(usize, 6 + 5 + 7), preprocessing.rows.len);
    try std.testing.expectEqual(@as(u32, 3), preprocessing.rows[6].path_count);
    try std.testing.expectEqual(@as(u32, 5), preprocessing.rows[11].path_count);

    var leaf_rows = try fri_rows.Preprocessed(.leaf).init(
        std.testing.allocator,
        &fri_reference,
        .none,
    );
    defer leaf_rows.deinit();
    try leaf_rows.validateAgainstAuthority(&fri_reference, .none);
    try std.testing.expectEqual(@as(usize, 75), leaf_rows.rows.len);

    var node_rows = try fri_rows.Preprocessed(.node).init(
        std.testing.allocator,
        &fri_reference,
        .none,
    );
    defer node_rows.deinit();
    try node_rows.validateAgainstAuthority(&fri_reference, .none);
    try std.testing.expectEqual(@as(usize, 5), node_rows.rows.len);
}

test "R-012 heterogeneous FRI profiles reject lane swaps and resealed rows" {
    var reference = try roots.Reference.seal(
        rootProfile(2, 4, 2),
        rootProfile(3, 3, 2),
        rootProfile(5, 5, 2),
    );
    var preprocessing = try roots.Preprocessed.init(std.testing.allocator, &reference);
    defer preprocessing.deinit();

    const retained = reference.lanes[2];
    reference.lanes[2] = reference.lanes[1];
    try std.testing.expectError(
        error.InvalidHeterogeneousMerkleRootAuthority,
        reference.validate(),
    );
    reference.lanes[2] = retained;

    preprocessing.rows[11].path_count += 1;
    preprocessing.authority_sha256 = preprocessing.computedAuthoritySha256();
    try std.testing.expectError(
        error.InvalidHeterogeneousMerkleRootAuthority,
        preprocessing.validateAgainstAuthority(&reference),
    );

    const fri_reference = try fri.Reference.seal(
        friProfile(2, 9, &VM_LAYERS),
        friProfile(3, 10, &LEFT_LAYERS),
        friProfile(5, 11, &RIGHT_LAYERS),
    );
    var leaf_rows = try fri_rows.Preprocessed(.leaf).init(
        std.testing.allocator,
        &fri_reference,
        .none,
    );
    defer leaf_rows.deinit();
    leaf_rows.rows[0].query += 1;
    leaf_rows.authority_sha256 = leaf_rows.computedAuthoritySha256();
    try std.testing.expectError(
        error.AuthorityMismatch,
        leaf_rows.validateAgainstAuthority(&fri_reference, .none),
    );
}

test "R-012 heterogeneous FRI control and anchor bind all three schedules" {
    var vm_plan = try testPlan(.vm, "fri-v2-vm", 8, 4, 2);
    defer vm_plan.deinit();
    // A binary parent may verify a native VM leaf on one edge and a recursive
    // node on the other. Lane identity, not child schedule schema, selects the
    // left/right routing namespace.
    var left_plan = try testPlan(.vm, "fri-v2-left", 9, 5, 2);
    defer left_plan.deinit();
    var right_plan = try testPlan(.recursion, "fri-v2-right", 10, 5, 3);
    defer right_plan.deinit();

    var mapping_reference = try mapping.Reference.seal(
        mappingProfile(2, 9, &VM_TRACE_HEIGHTS, &VM_FOLDS),
        mappingProfile(3, 10, &LEFT_TRACE_HEIGHTS, &LEFT_FOLDS),
        mappingProfile(5, 11, &RIGHT_TRACE_HEIGHTS, &RIGHT_FOLDS),
    );
    const control_reference = try control.Reference.seal(
        controlLane(&vm_plan, mapping_reference.lanes[0].profile),
        controlLane(&left_plan, mapping_reference.lanes[1].profile),
        controlLane(&right_plan, mapping_reference.lanes[2].profile),
    );
    try control_reference.validateMapping(&mapping_reference);

    var control_rows = try control.Preprocessed.init(
        std.testing.allocator,
        &control_reference,
    );
    defer control_rows.deinit();
    try control_rows.validateAgainstAuthority(&control_reference);
    try std.testing.expectEqual(@as(u32, 0), control_rows.rows[0].verifier_id);
    const left_start = try control_base.rowsForLane(control_reference.lanes[0].mapping);
    try std.testing.expectEqual(@as(u32, 1), control_rows.rows[left_start].verifier_id);

    const fri_reference = try fri.Reference.seal(
        friProfile(2, 9, &VM_LAYERS),
        friProfile(3, 10, &LEFT_LAYERS),
        friProfile(5, 11, &RIGHT_LAYERS),
    );
    var anchors = try fri_rows.Preprocessed(.anchor).init(
        std.testing.allocator,
        &fri_reference,
        .{ .anchor = .{ &vm_plan, &left_plan, &right_plan } },
    );
    defer anchors.deinit();
    try anchors.validateAgainstAuthority(
        &fri_reference,
        .{ .anchor = .{ &vm_plan, &left_plan, &right_plan } },
    );
    try std.testing.expectEqual(@as(usize, 20), anchors.rows.len);

    control_rows.rows[left_start].query += 1;
    control_rows.authority_sha256 = control_rows.computedAuthoritySha256();
    try std.testing.expectError(
        error.AuthorityMismatch,
        control_rows.validateAgainstAuthority(&control_reference),
    );
}

fn mappingProfile(
    query_count: u32,
    lifting: u32,
    heights: []const u32,
    folds: []const u32,
) mapping_base.LaneProfile {
    return .{
        .query_count = query_count,
        .lifting_log_size = lifting,
        .tree_heights = heights,
        .fri_fold_widths = folds,
    };
}

fn rootProfile(query_count: u32, trees: u32, layers: u32) roots_base.LaneProfile {
    return .{
        .query_count = query_count,
        .trace_tree_count = trees,
        .fri_layer_count = layers,
    };
}

fn friProfile(
    query_count: u32,
    lifting: u32,
    layers: []const fri_base.LayerProfile,
) fri_base.LaneProfile {
    return .{
        .query_count = query_count,
        .lifting_log_size = lifting,
        .layers = layers,
    };
}

fn controlLane(
    plan: *const schedule.Plan,
    profile: mapping_base.LaneProfile,
) control_base.Lane {
    return .{ .plan = plan, .mapping = profile };
}

fn testPlan(
    schema: schedule.Schema,
    shape_name: []const u8,
    column_log_degree: u32,
    last_layer_log: u32,
    fold_step: u32,
) !schedule.Plan {
    var fri_config = protocol.PCS_CONFIG.fri_config;
    fri_config.log_blowup_factor = 1;
    fri_config.log_last_layer_degree_bound = last_layer_log;
    fri_config.fold_step = fold_step;
    const lifting = column_log_degree + fri_config.log_blowup_factor;
    return schedule.Plan.initShape(
        std.testing.allocator,
        try schedule.ProgramSpec.init(schema, 3, 2, 3, 2),
        .{
            .protocol_id = protocol.protocolId(),
            .shape_id = channel.hashBytes(shape_name, 0x4652_5632),
            .interaction_pow_bits = 10,
            .pcs_pow_bits = 16,
            .query_count = if (column_log_degree == 8)
                2
            else if (column_log_degree == 9)
                3
            else
                5,
            .table_count = 3,
            .claimed_sum_count = 2,
            .sampled_value_count = 7,
            .tree_heights = [_]u32{lifting} ** fixed_profile.TREE_COUNT,
            .fri = try fixed_profile.FriSchedule.init(column_log_degree, fri_config),
        },
    );
}
