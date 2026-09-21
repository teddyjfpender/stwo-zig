const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const tail = @import("recursive_temporal_secure_tree_tail_v1.zig");
const topology = @import("recursive_temporal_topology_v1.zig");

const recursion = frontend.recursion;
const channel = recursion.poseidon2_channel;
const span = recursion.span_statement;

test "secure tree tail audits exact 23 empty H1 and 127 upper products" {
    std.testing.refAllDeclsRecursive(tail);
    const topology_plan = try topology.TopologyPlanV1.init(try job(210));
    var schedule = try topology.BreadthFirstScheduleV1.create(
        std.testing.allocator,
        topology_plan,
    );
    defer schedule.deinit();

    const geometry = try tail.auditGeometry(&schedule);
    try geometry.validate();
    try std.testing.expectEqual(@as(u16, 23), geometry.empty_h1_task_count);
    try std.testing.expectEqual(@as(u16, 127), geometry.upper_task_count);
    try std.testing.expectEqual(@as(u16, 101), geometry.upper_real_task_count);
    try std.testing.expectEqual(@as(u16, 19), geometry.upper_empty_task_count);
    try std.testing.expectEqual(@as(u16, 7), geometry.upper_mixed_task_count);

    try std.testing.expectEqual(@as(u64, 105), schedule.tasks[105].ordinal);
    try std.testing.expectEqual(@as(u8, 1), schedule.tasks[105].parent_height);
    try std.testing.expectEqual(topology.NodeKindV1.empty, schedule.tasks[105].left_kind);
    try std.testing.expectEqual(@as(u64, 127), schedule.tasks[127].ordinal);
    try std.testing.expectEqual(topology.NodeKindV1.empty, schedule.tasks[127].right_kind);
    try std.testing.expectEqual(@as(u8, 2), schedule.tasks[128].parent_height);
    try std.testing.expectEqual(@as(u64, 180), schedule.tasks[180].ordinal);
    try std.testing.expectEqual(topology.NodeKindV1.real, schedule.tasks[180].left_kind);
    try std.testing.expectEqual(topology.NodeKindV1.empty, schedule.tasks[180].right_kind);
    try std.testing.expectEqual(@as(u8, 8), schedule.tasks[254].parent_height);
    try std.testing.expectEqual(topology.NodeKindV1.real, schedule.tasks[254].left_kind);
    try std.testing.expectEqual(topology.NodeKindV1.mixed, schedule.tasks[254].right_kind);

    var forged = geometry;
    forged.upper_empty_task_count -= 1;
    try std.testing.expectError(
        error.InvalidSecureTreeTailGeometry,
        forged.validate(),
    );
}

test "secure tree tail product schedule rejects order kind and capture mutations" {
    var plan = try syntheticPlan(std.testing.allocator);
    try plan.validateCustody();
    try std.testing.expectEqual(
        tail.TaskClassV1.empty_h1,
        plan.tasks[0].task_class,
    );
    try std.testing.expectEqual(@as(u16, 105), plan.tasks[0].global_ordinal);
    try std.testing.expectEqual(
        tail.TaskClassV1.upper,
        plan.tasks[tail.EMPTY_H1_TASK_COUNT].task_class,
    );
    try std.testing.expectEqual(
        @as(u16, 128),
        plan.tasks[tail.EMPTY_H1_TASK_COUNT].global_ordinal,
    );
    for (plan.tasks[tail.EMPTY_H1_TASK_COUNT..]) |task|
        try std.testing.expect(task.requires_child_composition_capture);
    try std.testing.expect(!plan.upper_execution_available);
    try std.testing.expect(!plan.secure_child_composition_capture_available);

    var forged_capture = plan;
    forged_capture.tasks[tail.EMPTY_H1_TASK_COUNT]
        .requires_child_composition_capture = false;
    tail.testing.resealTask(
        &forged_capture.tasks[tail.EMPTY_H1_TASK_COUNT],
    );
    tail.testing.resealPlan(&forged_capture);
    try std.testing.expectError(
        error.InvalidSecureTreeTailTask,
        forged_capture.validateCustody(),
    );

    var forged_order = plan;
    forged_order.tasks[tail.EMPTY_H1_TASK_COUNT + 9].global_ordinal += 1;
    tail.testing.resealTask(
        &forged_order.tasks[tail.EMPTY_H1_TASK_COUNT + 9],
    );
    tail.testing.resealPlan(&forged_order);
    try std.testing.expectError(
        error.InvalidSecureTreeTailTask,
        forged_order.validateCustody(),
    );

    // Global ordinal 180 is the first mixed upper product.
    var forged_kind = plan;
    const mixed_tail_index = tail.EMPTY_H1_TASK_COUNT + (180 - 128);
    forged_kind.tasks[mixed_tail_index].parent_kind = .real;
    tail.testing.resealTask(&forged_kind.tasks[mixed_tail_index]);
    tail.testing.resealPlan(&forged_kind);
    try std.testing.expectError(
        error.InvalidSecureTreeTailTask,
        forged_kind.validateCustody(),
    );

    plan.identity_sha256[0] ^= 1;
    try std.testing.expectError(
        error.InvalidSecureTreeTailPlan,
        plan.validateCustody(),
    );
}

test "empty H1 admission is task bound and remains nonproduction" {
    const plan = try syntheticPlan(std.testing.allocator);
    const task = &plan.tasks[0];
    var admission = tail.EmptyH1AdmissionV1{
        .local_ordinal = 0,
        .global_ordinal = task.global_ordinal,
        .parent_index = task.parent_index,
        .tail_plan_identity_sha256 = plan.identity_sha256,
        .task_identity_sha256 = task.identity_sha256,
        .empty_source_identity_sha256 = seededSha(31),
        .pair_authority_identity_sha256 = seededSha(32),
        .child_authority_identity_sha256 = .{
            seededSha(33),
            seededSha(34),
        },
        .transcript_authority_identity_sha256 = seededSha(35),
        .parent_statement_sha256 = task.parent_statement_sha256,
        .identity_sha256 = undefined,
    };
    tail.testing.resealEmptyAdmission(&admission);
    try admission.validateAgainst(&plan);
    try std.testing.expect(!admission.production_activation);

    var forged_statement = admission;
    forged_statement.parent_statement_sha256[0] ^= 1;
    tail.testing.resealEmptyAdmission(&forged_statement);
    try std.testing.expectError(
        error.InvalidEmptyH1Admission,
        forged_statement.validateAgainst(&plan),
    );

    var forged_child = admission;
    forged_child.child_authority_identity_sha256[1] = [_]u8{0} ** 32;
    tail.testing.resealEmptyAdmission(&forged_child);
    try std.testing.expectError(
        error.InvalidSecureTreeTailAuthority,
        forged_child.validateAgainst(&plan),
    );
}

fn syntheticPlan(allocator: std.mem.Allocator) !tail.TailPlanV1 {
    const topology_plan = try topology.TopologyPlanV1.init(try job(210));
    var schedule = try topology.BreadthFirstScheduleV1.create(
        allocator,
        topology_plan,
    );
    defer schedule.deinit();
    var result = tail.TailPlanV1{
        .geometry = try tail.auditGeometry(&schedule),
        .topology_plan_identity_sha256 = topology_plan.identity,
        .statement_plan_identity_sha256 = seededSha(1),
        .breadth_schedule_identity_sha256 = schedule.identity,
        .empty_authority_identity_sha256 = seededSha(2),
        .empty_h1_profile_identity_sha256 = seededSha(3),
        .upper_profile_identity_sha256 = undefined,
        .tasks = undefined,
        .identity_sha256 = undefined,
    };
    for (&result.upper_profile_identity_sha256, 0..) |*identity, index|
        identity.* = seededSha(@intCast(index + 4));

    for (&result.tasks, 0..) |*destination, tail_index| {
        const task_class: tail.TaskClassV1 = if (tail_index <
            tail.EMPTY_H1_TASK_COUNT) .empty_h1 else .upper;
        const local = if (task_class == .empty_h1)
            tail_index
        else
            tail_index - tail.EMPTY_H1_TASK_COUNT;
        const global = if (task_class == .empty_h1)
            tail.FIRST_EMPTY_H1_ORDINAL + local
        else
            tail.FIRST_UPPER_ORDINAL + local;
        const scheduled = &schedule.tasks[global];
        const seed: u8 = @truncate(tail_index + 17);
        destination.* = .{
            .task_class = task_class,
            .parent_kind = try topology_plan.nodeKind(
                scheduled.parent_height,
                scheduled.parent_index,
            ),
            .left_kind = scheduled.left_kind,
            .right_kind = scheduled.right_kind,
            .parent_height = scheduled.parent_height,
            .child_height = scheduled.child_height,
            .requires_child_composition_capture = task_class == .upper,
            .local_ordinal = @intCast(local),
            .global_ordinal = @intCast(global),
            .parent_index = @intCast(scheduled.parent_index),
            .left_index = @intCast(scheduled.parent_index * 2),
            .right_index = @intCast(scheduled.parent_index * 2 + 1),
            .topology_task_identity_sha256 = scheduled.identity,
            .left_record_identity_sha256 = seededSha(seed +% 1),
            .right_record_identity_sha256 = seededSha(seed +% 2),
            .left_statement_sha256 = seededSha(seed +% 3),
            .right_statement_sha256 = seededSha(seed +% 4),
            .parent_record_identity_sha256 = seededSha(seed +% 5),
            .parent_statement_sha256 = seededSha(seed +% 6),
            .profile_identity_sha256 = seededSha(seed +% 7),
            .verification_key_id = digest(seed +% 8),
            .next_parent_vk_id = digest(seed +% 9),
            .identity_sha256 = undefined,
        };
        tail.testing.resealTask(destination);
    }
    tail.testing.resealPlan(&result);
    try result.validateCustody();
    return result;
}

fn job(segment_count: u32) !span.JobContext {
    var initial_registers = [_]u32{0} ** 32;
    var final_registers = [_]u32{0} ** 32;
    initial_registers[1] = 7;
    final_registers[1] = 9;
    const initial = try span.MachineState.init(
        0x1000,
        initial_registers,
        digest(11),
        digest(21),
    );
    const final = try span.MachineState.init(
        0x2000,
        final_registers,
        digest(31),
        digest(41),
    );
    return span.JobContext.init(
        try span.CompleteExecution.init(
            recursion.protocol.PROTOCOL_ID_WORDS,
            digest(51),
            initial,
            final,
            digest(61),
            digest(71),
            segment_count,
        ),
        segment_count,
    );
}

fn digest(seed: u8) channel.Digest {
    var result: channel.Digest = undefined;
    for (&result, 0..) |*word, index|
        word.* = @as(u32, seed) + @as(u32, @intCast(index)) + 1;
    return result;
}

fn seededSha(seed: u8) [32]u8 {
    var result: [32]u8 = undefined;
    for (&result, 0..) |*byte, index|
        byte.* = seed +% @as(u8, @intCast(index + 1));
    return result;
}
