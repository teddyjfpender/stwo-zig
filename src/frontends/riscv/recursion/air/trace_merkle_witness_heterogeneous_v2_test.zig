const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;
const channel = @import("../poseidon2_channel.zig");
const fixed_profile = @import("../fixed_profile.zig");
const protocol = @import("../protocol.zig");
const component = @import("trace_merkle.zig");
const mapping_base = @import("query_mapping_witness.zig");
const mapping_v2 = @import("query_mapping_witness_heterogeneous_v2.zig");
const base = @import("trace_merkle_witness.zig");
const subject = @import("trace_merkle_witness_heterogeneous_v2.zig");
const schedule = @import("verifier_schedule.zig");

const VM_LOGS_0 = [_]u32{ 8, 7, 6 };
const VM_LOGS_1 = [_]u32{8};
const VM_LOGS_2 = [_]u32{ 8, 5 };
const VM_LOGS_3 = [_]u32{8};
const LEFT_LOGS_0 = [_]u32{ 8, 7, 6, 5 };
const LEFT_LOGS_1 = [_]u32{8};
const LEFT_LOGS_2 = [_]u32{ 8, 7 };
const LEFT_LOGS_3 = [_]u32{8};
const RIGHT_LOGS_0 = [_]u32{ 8, 7, 6, 5, 4, 4 };
const RIGHT_LOGS_1 = [_]u32{ 8, 6 };
const RIGHT_LOGS_2 = [_]u32{ 8, 7, 5 };
const RIGHT_LOGS_3 = [_]u32{8};
const FOLDS = [_]u32{ 4, 4 };
const RIGHT_FOLDS = [_]u32{ 8, 4 };
const VM_HEIGHTS = [_]u32{ 9, 9, 9, 9 };
const LEFT_HEIGHTS = [_]u32{ 9, 9, 9, 9 };
const RIGHT_HEIGHTS = [_]u32{ 10, 10, 9, 10 };

const VM_TREES = [_]base.TreeProfile{
    .{ .height = 9, .column_log_sizes = &VM_LOGS_0 },
    .{ .height = 9, .column_log_sizes = &VM_LOGS_1 },
    .{ .height = 9, .column_log_sizes = &VM_LOGS_2 },
    .{ .height = 9, .column_log_sizes = &VM_LOGS_3 },
};
const LEFT_TREES = [_]base.TreeProfile{
    .{ .height = 9, .column_log_sizes = &LEFT_LOGS_0 },
    .{ .height = 9, .column_log_sizes = &LEFT_LOGS_1 },
    .{ .height = 9, .column_log_sizes = &LEFT_LOGS_2 },
    .{ .height = 9, .column_log_sizes = &LEFT_LOGS_3 },
};
const RIGHT_TREES = [_]base.TreeProfile{
    .{ .height = 10, .column_log_sizes = &RIGHT_LOGS_0 },
    .{ .height = 10, .column_log_sizes = &RIGHT_LOGS_1 },
    .{ .height = 9, .column_log_sizes = &RIGHT_LOGS_2 },
    .{ .height = 10, .column_log_sizes = &RIGHT_LOGS_3 },
};

const VM_PROFILE = laneProfile(9, &VM_TREES, &FOLDS);
const LEFT_PROFILE = laneProfile(9, &LEFT_TREES, &FOLDS);
const RIGHT_PROFILE = laneProfile(10, &RIGHT_TREES, &RIGHT_FOLDS);

test "R-012 trace Merkle V2 binds independently shaped child lanes" {
    var plans = try Plans.init(std.testing.allocator);
    defer plans.deinit();
    var reference = try makeReference(&plans);
    var preprocessing = try subject.Preprocessed.init(
        std.testing.allocator,
        &reference,
        &plans.vm,
        &plans.left,
        &plans.right,
    );
    defer preprocessing.deinit();

    try preprocessing.validateAgainstAuthority(
        &reference,
        &plans.vm,
        &plans.left,
        &plans.right,
    );
    const mapping = try mapping_v2.Reference.seal(
        mappingProfile(9, &VM_HEIGHTS, &FOLDS),
        mappingProfile(9, &LEFT_HEIGHTS, &FOLDS),
        mappingProfile(10, &RIGHT_HEIGHTS, &RIGHT_FOLDS),
    );
    try reference.validateQueryMapping(&mapping);
    try std.testing.expect(
        reference.lanes[1].profile.queriedValueCount() catch unreachable !=
            reference.lanes[2].profile.queriedValueCount() catch unreachable,
    );
    try std.testing.expect(
        !std.meta.eql(
            reference.lanes[1].schedule_digest,
            reference.lanes[2].schedule_digest,
        ),
    );
    try std.testing.expectEqual(
        try rowCount(VM_PROFILE) + try rowCount(LEFT_PROFILE) + try rowCount(RIGHT_PROFILE),
        preprocessing.rows.len,
    );

    const left_start = try rowCount(VM_PROFILE);
    const right_start = left_start + try rowCount(LEFT_PROFILE);
    try std.testing.expectEqual(base.LEFT_RECURSION_VERIFIER_ID, preprocessing.rows[left_start].verifier_id);
    try std.testing.expectEqual(base.RIGHT_RECURSION_VERIFIER_ID, preprocessing.rows[right_start].verifier_id);
    try std.testing.expectEqual(@as(u32, LEFT_LOGS_0.len), activeChunkCount(preprocessing.rows[left_start]));
    try std.testing.expectEqual(@as(u32, RIGHT_LOGS_0.len), activeChunkCount(preprocessing.rows[right_start]));

    var definition = try component.build(std.testing.allocator);
    defer definition.deinit();
    const binding = try base.Binding.canonical(&definition);
    const executor = try base.Executor.init(&definition, &binding);
    const prepared = try preprocessing.prepare(
        &reference,
        &plans.vm,
        &plans.left,
        &plans.right,
    );
    const size = @as(usize, 1) << @intCast(preprocessing.log_size);
    var storage = try std.testing.allocator.alloc(
        M31,
        base.PREPROCESSED_COLUMN_COUNT * size,
    );
    defer std.testing.allocator.free(storage);
    var columns: [base.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
    for (&columns, 0..) |*column, index|
        column.* = storage[index * size ..][0..size];
    try preprocessing.generatePreprocessedInto(
        &reference,
        &plans.vm,
        &plans.left,
        &plans.right,
        prepared,
        &executor,
        &columns,
    );
    try std.testing.expectEqual(M31.fromCanonical(base.RIGHT_RECURSION_VERIFIER_ID), columns[3][right_start]);
}

test "R-012 trace Merkle V2 rejects lane order schedule and row mutations" {
    var plans = try Plans.init(std.testing.allocator);
    defer plans.deinit();
    var reference = try makeReference(&plans);
    var preprocessing = try subject.Preprocessed.init(
        std.testing.allocator,
        &reference,
        &plans.vm,
        &plans.left,
        &plans.right,
    );
    defer preprocessing.deinit();

    try std.testing.expectError(
        error.ControlStepMismatch,
        reference.validateAgainst(&plans.vm, &plans.right, &plans.left),
    );

    reference.lanes[2].schedule_digest[0] ^= 1;
    try std.testing.expectError(
        error.InvalidHeterogeneousTraceAuthority,
        reference.validateAgainst(&plans.vm, &plans.left, &plans.right),
    );
    reference.lanes[2].schedule_digest[0] ^= 1;

    const right_start = try rowCount(VM_PROFILE) + try rowCount(LEFT_PROFILE);
    var forged = try preprocessing.prepare(
        &reference,
        &plans.vm,
        &plans.left,
        &plans.right,
    );
    preprocessing.rows[right_start].tree_height -= 1;
    preprocessing.authority_sha256 = preprocessing.computedAuthoritySha256();
    forged.authority_sha256 = preprocessing.authority_sha256;
    try preprocessing.validateAgainst(
        &reference,
        &plans.vm,
        &plans.left,
        &plans.right,
    );
    try std.testing.expectError(
        error.AuthorityMismatch,
        preprocessing.validatePrepared(
            &reference,
            &plans.vm,
            &plans.left,
            &plans.right,
            forged,
        ),
    );
}

const Plans = struct {
    vm: schedule.Plan,
    left: schedule.Plan,
    right: schedule.Plan,

    fn init(allocator: std.mem.Allocator) !Plans {
        var vm = try plan(allocator, .vm, 1, VM_PROFILE, 9);
        errdefer vm.deinit();
        var left = try plan(allocator, .recursion, 2, LEFT_PROFILE, 13);
        errdefer left.deinit();
        return .{
            .vm = vm,
            .left = left,
            .right = try plan(allocator, .recursion, 3, RIGHT_PROFILE, 19),
        };
    }

    fn deinit(self: *Plans) void {
        self.right.deinit();
        self.left.deinit();
        self.vm.deinit();
        self.* = undefined;
    }
};

fn makeReference(plans: *const Plans) !subject.Reference {
    return subject.Reference.seal(
        VM_PROFILE,
        &plans.vm,
        LEFT_PROFILE,
        &plans.left,
        RIGHT_PROFILE,
        &plans.right,
    );
}

fn plan(
    allocator: std.mem.Allocator,
    schema: schedule.Schema,
    seed: u32,
    profile: base.LaneProfile,
    sampled_value_count: u32,
) !schedule.Plan {
    const tree_counts = [fixed_profile.TREE_COUNT]u32{
        @intCast(profile.trees[0].column_log_sizes.len),
        @intCast(profile.trees[1].column_log_sizes.len),
        @intCast(profile.trees[2].column_log_sizes.len),
        @intCast(profile.trees[3].column_log_sizes.len),
    };
    var table_count: u32 = 0;
    for (tree_counts) |count| table_count += count;
    const fri = try fixed_profile.FriSchedule.init(
        profile.lifting_log_size - protocol.PCS_CONFIG.fri_config.log_blowup_factor,
        protocol.PCS_CONFIG.fri_config,
    );
    const shape = fixed_profile.ProofShapeV1{
        .air_program_id = channel.hashBytes(std.mem.asBytes(&seed), 0x5452_4102),
        .preprocessing_id = channel.hashBytes(std.mem.asBytes(&seed), 0x5452_5002),
        .table_layout_id = channel.hashBytes(std.mem.asBytes(&seed), 0x5452_4c02),
        .table_count = table_count,
        .claimed_sum_count = seed + 1,
        .sampled_value_count = sampled_value_count,
        .preprocessed_column_count = tree_counts[0],
        .tree_column_counts = tree_counts,
        .tree_heights = .{
            profile.trees[0].height,
            profile.trees[1].height,
            profile.trees[2].height,
            profile.trees[3].height,
        },
        .column_log_degree = profile.lifting_log_size - 1,
        .proof_wire_bytes = 1_024 + seed,
        .fri = fri,
    };
    return schedule.Plan.init(
        allocator,
        try schedule.ProgramSpec.init(
            schema,
            sampled_value_count,
            @intFromBool(schema == .vm),
            3 + seed,
            sampled_value_count,
        ),
        shape,
    );
}

fn laneProfile(
    lifting_log_size: u32,
    tree_profiles: []const base.TreeProfile,
    fold_widths: []const u32,
) base.LaneProfile {
    return .{
        .query_count = protocol.FRI_QUERY_COUNT,
        .lifting_log_size = lifting_log_size,
        .trees = tree_profiles,
        .fri_fold_widths = fold_widths,
    };
}

fn mappingProfile(
    lifting_log_size: u32,
    tree_heights: []const u32,
    fold_widths: []const u32,
) mapping_base.LaneProfile {
    return .{
        .query_count = protocol.FRI_QUERY_COUNT,
        .lifting_log_size = lifting_log_size,
        .tree_heights = tree_heights,
        .fri_fold_widths = fold_widths,
    };
}

fn rowCount(profile: base.LaneProfile) !usize {
    var result: usize = 0;
    for (profile.trees) |tree| result += try std.math.divCeil(
        usize,
        tree.column_log_sizes.len + 1,
        component.RATE,
    ) * profile.query_count;
    return result;
}

fn activeChunkCount(row: base.Row) u32 {
    var result: u32 = 0;
    for (row.chunks) |chunk| result += chunk.source_mask;
    return result;
}
