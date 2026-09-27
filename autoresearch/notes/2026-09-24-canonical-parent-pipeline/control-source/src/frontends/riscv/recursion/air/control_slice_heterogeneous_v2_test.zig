const std = @import("std");

const fixed_profile = @import("../fixed_profile.zig");
const channel = @import("../poseidon2_channel.zig");
const protocol = @import("../protocol.zig");
const subject = @import("control_slice_heterogeneous_v2.zig");
const schedule = @import("verifier_schedule.zig");

test "R-012 heterogeneous control V2 retains distinct child schedules" {
    var plans = try Plans.init(std.testing.allocator);
    defer plans.deinit();
    var value = try makePreprocessed(std.testing.allocator, &plans);
    defer value.deinit();

    try value.validateAgainst(&plans.vm, &plans.left, &plans.right);
    try std.testing.expectEqual(@as(usize, 16), value.rows.len);
    try std.testing.expectEqual(@as(usize, 4), try value.activeStepCount(.segment_leaf));
    try std.testing.expectEqual(@as(usize, 12), try value.activeStepCount(.binary_node));
    try std.testing.expectEqual(@as(usize, 0), try value.activeStepCount(.empty_leaf));

    for (value.rows[0..4]) |row|
        try std.testing.expectEqual(@as(u32, 0), row.verifier_id);
    for (value.rows[4..9]) |row|
        try std.testing.expectEqual(@as(u32, 1), row.verifier_id);
    for (value.rows[9..16]) |row|
        try std.testing.expectEqual(@as(u32, 2), row.verifier_id);
    try std.testing.expectEqual(@as(u32, 14), value.rows[8].tag);
    try std.testing.expectEqual(@as(u32, 11), value.rows[8].args[0]);
    try std.testing.expectEqual(@as(u32, 14), value.rows[15].tag);
    try std.testing.expectEqual(@as(u32, 17), value.rows[15].args[0]);
    try std.testing.expect(!std.meta.eql(
        value.lanes[1].schedule_digest,
        value.lanes[2].schedule_digest,
    ));
}

test "R-012 heterogeneous control V2 rejects lane and retained mutations" {
    var plans = try Plans.init(std.testing.allocator);
    defer plans.deinit();
    var value = try makePreprocessed(std.testing.allocator, &plans);
    defer value.deinit();

    try std.testing.expectError(
        error.SchemaMismatch,
        value.validateAgainst(&plans.vm, &plans.right, &plans.left),
    );

    value.lanes[2].sampled_value_count += 1;
    try std.testing.expectError(
        error.SampledValueCountMismatch,
        value.validateAgainst(&plans.vm, &plans.left, &plans.right),
    );
    value.lanes[2].sampled_value_count -= 1;

    value.rows[9].tag += 1;
    try std.testing.expectError(
        error.ScheduleAuthorityMismatch,
        value.validateAgainst(&plans.vm, &plans.left, &plans.right),
    );
    value.rows[9].tag -= 1;

    value.authority_sha256[0] ^= 1;
    try std.testing.expectError(
        error.InvalidHeterogeneousControlAuthority,
        value.validateAgainst(&plans.vm, &plans.left, &plans.right),
    );
}

test "R-012 heterogeneous control V2 identity binds left-right order" {
    var plans = try Plans.init(std.testing.allocator);
    defer plans.deinit();
    var ordered = try makePreprocessed(std.testing.allocator, &plans);
    defer ordered.deinit();
    var reversed = try subject.CompositionPreprocessedV2.init(
        std.testing.allocator,
        &plans.vm,
        3,
        7,
        &plans.right,
        6,
        17,
        &plans.left,
        4,
        11,
    );
    defer reversed.deinit();
    try std.testing.expect(!std.mem.eql(
        u8,
        &ordered.authority_sha256,
        &reversed.authority_sha256,
    ));
}

test "R-012 heterogeneous control V2 admits a native leaf beside a recursive child" {
    var plans = try Plans.init(std.testing.allocator);
    defer plans.deinit();
    const native_shape = try testShape(4, 13, 9, .{ 8, 6, 5, 4 });
    var native = try schedule.Plan.init(
        std.testing.allocator,
        try schedule.ProgramSpec.init(.vm, 4, 3, 5, 3),
        native_shape,
    );
    defer native.deinit();

    var value = try subject.CompositionPreprocessedV2.init(
        std.testing.allocator,
        &plans.vm,
        3,
        7,
        &native,
        5,
        13,
        &plans.right,
        6,
        17,
    );
    defer value.deinit();
    try value.validateAgainst(&plans.vm, &native, &plans.right);
    try std.testing.expectEqual(schedule.Schema.vm, native.schema);
    try std.testing.expectEqual(schedule.Schema.recursion, plans.right.schema);

    try std.testing.expectError(
        error.SchemaMismatch,
        subject.CompositionPreprocessedV2.init(
            std.testing.allocator,
            &plans.left,
            4,
            11,
            &native,
            5,
            13,
            &plans.right,
            6,
            17,
        ),
    );
}

const Plans = struct {
    vm: schedule.Plan,
    left: schedule.Plan,
    right: schedule.Plan,

    fn init(allocator: std.mem.Allocator) !Plans {
        const vm_shape = try testShape(1, 7, 8, .{ 4, 4, 4, 4 });
        const left_shape = try testShape(2, 11, 9, .{ 5, 4, 4, 4 });
        const right_shape = try testShape(3, 17, 10, .{ 6, 5, 4, 4 });
        var vm = try schedule.Plan.init(
            allocator,
            try schedule.ProgramSpec.init(.vm, 3, 2, 3, 2),
            vm_shape,
        );
        errdefer vm.deinit();
        var left = try schedule.Plan.init(
            allocator,
            try schedule.ProgramSpec.init(.recursion, 3, 0, 4, 2),
            left_shape,
        );
        errdefer left.deinit();
        return .{
            .vm = vm,
            .left = left,
            .right = try schedule.Plan.init(
                allocator,
                try schedule.ProgramSpec.init(.recursion, 3, 0, 6, 2),
                right_shape,
            ),
        };
    }

    fn deinit(self: *Plans) void {
        self.right.deinit();
        self.left.deinit();
        self.vm.deinit();
        self.* = undefined;
    }
};

fn makePreprocessed(
    allocator: std.mem.Allocator,
    plans: *const Plans,
) !subject.CompositionPreprocessedV2 {
    return subject.CompositionPreprocessedV2.init(
        allocator,
        &plans.vm,
        3,
        7,
        &plans.left,
        4,
        11,
        &plans.right,
        6,
        17,
    );
}

fn testShape(
    seed: u32,
    sampled_value_count: u32,
    column_log_degree: u32,
    tree_column_counts: [fixed_profile.TREE_COUNT]u32,
) !fixed_profile.ProofShapeV1 {
    const fri = try fixed_profile.FriSchedule.init(
        column_log_degree,
        protocol.PCS_CONFIG.fri_config,
    );
    const height = column_log_degree +
        protocol.PCS_CONFIG.fri_config.log_blowup_factor;
    var table_count: u32 = 0;
    for (tree_column_counts) |count| table_count += count;
    return .{
        .air_program_id = channel.hashBytes(
            std.mem.asBytes(&seed),
            0x4832_4101,
        ),
        .preprocessing_id = channel.hashBytes(
            std.mem.asBytes(&seed),
            0x4832_5001,
        ),
        .table_layout_id = channel.hashBytes(
            std.mem.asBytes(&seed),
            0x4832_4c01,
        ),
        .table_count = table_count,
        .claimed_sum_count = 4 + seed,
        .sampled_value_count = sampled_value_count,
        .preprocessed_column_count = tree_column_counts[0],
        .tree_column_counts = tree_column_counts,
        .tree_heights = .{ height, height, height, height },
        .column_log_degree = column_log_degree,
        .proof_wire_bytes = 1_024 + seed,
        .fri = fri,
    };
}
