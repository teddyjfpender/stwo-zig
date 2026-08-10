//! Ownership, semantic-attribution, and adversarial reservation tests.

const std = @import("std");
const task_profile = @import("task_profile.zig");

fn summary(event_count: usize) task_profile.RequestSummary {
    return .{ .planned_tasks = @intCast(event_count) };
}

fn reservePhysicalOnly(
    recorder: *task_profile.Recorder,
    event_count: usize,
) !task_profile.PendingGraph {
    return recorder.reserveTaskGraphShape(.{
        .event_count = event_count,
        .contribution_count = 0,
        .component_work_count = 0,
    });
}

fn completedEvent(range: task_profile.ContributionRange) task_profile.TaskEvent {
    return .{
        .contribution_range = range,
        .submitted = true,
        .started = true,
        .finished = true,
        .terminal_status = .completed,
        .cleanup_complete = true,
    };
}

test "task profile: reservation publishes by move and snapshot owns strings" {
    const allocator = std.testing.allocator;
    var runtime = [_]u8{ 'z', 'i', 'g' };
    var example = [_]u8{ 'r', 'v' };
    var graph_id = [_]u8{ 'f', 'u', 's', 'e', 'd' };
    var stage_id = [_]u8{ 'c', 'o', 'm', 'p' };
    var physical_kind = [_]u8{ 'l', 'a', 'n', 'e' };
    var semantic_kind = [_]u8{ 'o', 'p', 'c', 'o', 'd', 'e' };
    var lookup_kind = [_]u8{ 't', 'a', 'b', 'l', 'e' };
    var error_name = [_]u8{ 'f', 'a', 'i', 'l' };

    var recorder = task_profile.Recorder.init(allocator, &runtime, &example);
    defer recorder.deinit();
    var pending = try recorder.reserveTaskGraphShape(.{
        .event_count = 2,
        .contribution_count = 3,
        .component_work_count = 2,
    });
    defer pending.deinit();

    pending.events[0] = completedEvent(.{ .start = 0, .len = 2 });
    pending.events[0].stage_id = &stage_id;
    pending.events[0].component_kind = &physical_kind;
    pending.events[1] = .{
        .contribution_range = .{ .start = 2, .len = 1 },
        .stage_id = &stage_id,
        .component_kind = &physical_kind,
        .submitted = true,
        .started = true,
        .finished = true,
        .terminal_status = .failed,
        .error_name = &error_name,
        .cleanup_complete = true,
    };
    pending.contributions[0] = .{
        .component_registry_index = 7,
        .component_kind = &semantic_kind,
        .role = .semantic_constraints,
        .work_estimate = 10,
        .planned_rows = 8,
        .planned_tiles = 1,
        .completed_rows = 8,
        .completed_tiles = 1,
    };
    pending.contributions[1] = .{
        .component_registry_index = 9,
        .component_kind = &lookup_kind,
        .role = .lookup_constraints,
        .work_estimate = 6,
        .planned_rows = 4,
        .planned_tiles = 2,
        .completed_rows = 4,
        .completed_tiles = 2,
    };
    pending.contributions[2] = .{
        .component_registry_index = 7,
        .component_kind = &semantic_kind,
        .role = .semantic_constraints,
        .work_estimate = 5,
        .planned_rows = 4,
        .planned_tiles = 1,
        .completed_rows = null,
        .completed_tiles = null,
    };

    const event_address = @intFromPtr(pending.events.ptr);
    const contribution_address = @intFromPtr(pending.contributions.ptr);
    try recorder.publishTaskGraphAfterJoin(
        &pending,
        .{ .graph_id = &graph_id },
        summary(2),
    );
    try std.testing.expectEqual(@as(u64, 0), pending.generation);
    try std.testing.expectEqual(
        event_address,
        @intFromPtr(recorder.graphs.items[0].events.ptr),
    );
    try std.testing.expectEqual(
        contribution_address,
        @intFromPtr(recorder.graphs.items[0].contributions.ptr),
    );

    var profile = try recorder.snapshot(allocator);
    defer profile.deinit(allocator);
    try std.testing.expectEqual(@as(u32, 2), profile.schema_version);
    try std.testing.expect(!@hasField(task_profile.ComponentWork, "run_ns"));
    try std.testing.expectEqual(@as(usize, 2), profile.graphs[0].events.len);
    try std.testing.expectEqual(@as(usize, 3), profile.graphs[0].contributions.len);
    try std.testing.expect(event_address != @intFromPtr(profile.graphs[0].events.ptr));
    try std.testing.expect(
        contribution_address != @intFromPtr(profile.graphs[0].contributions.ptr),
    );
    try std.testing.expectEqual(@as(u64, 2), profile.graphs[0].component_work[0].task_count);
    try std.testing.expectEqual(@as(u64, 15), profile.graphs[0].component_work[0].work_estimate);
    try std.testing.expectEqual(@as(u64, 12), profile.graphs[0].component_work[0].planned_rows);
    try std.testing.expect(profile.graphs[0].component_work[0].completed_rows == null);
    try std.testing.expectEqual(
        task_profile.ContributionRole.lookup_constraints,
        profile.graphs[0].component_work[1].role,
    );
    try std.testing.expectEqual(@as(?u64, 4), profile.graphs[0].component_work[1].completed_rows);

    runtime[0] = 'X';
    example[0] = 'X';
    graph_id[0] = 'X';
    stage_id[0] = 'X';
    physical_kind[0] = 'X';
    semantic_kind[0] = 'X';
    lookup_kind[0] = 'X';
    error_name[0] = 'X';
    try std.testing.expectEqualStrings("zig", profile.runtime);
    try std.testing.expectEqualStrings("rv", profile.example);
    try std.testing.expectEqualStrings("fused", profile.graphs[0].graph_id);
    try std.testing.expectEqualStrings("comp", profile.graphs[0].events[0].stage_id);
    try std.testing.expectEqualStrings("lane", profile.graphs[0].events[0].component_kind);
    try std.testing.expectEqualStrings("fail", profile.graphs[0].events[1].error_name.?);
    try std.testing.expectEqualStrings(
        "opcode",
        profile.graphs[0].contributions[0].component_kind,
    );
    try std.testing.expectEqualStrings(
        "table",
        profile.graphs[0].component_work[1].component_kind,
    );
}

test "task profile: compatibility reservation synthesizes exact exclusive work" {
    const allocator = std.testing.allocator;
    var recorder = task_profile.Recorder.init(allocator, "zig", "legacy");
    defer recorder.deinit();

    var pending = try recorder.reserveTaskGraph(3, 1);
    defer pending.deinit();
    pending.events[0] = completedEvent(.{ .start = 99, .len = 0 });
    pending.events[0].key.component_registry_index = 5;
    pending.events[0].component_kind = "opcode";
    pending.events[0].work_estimate = 8;
    pending.events[0].planned_rows = 8;
    pending.events[0].completed_rows = 8;
    pending.events[1] = .{
        .key = .{ .component_registry_index = 5 },
        .component_kind = "opcode",
        .started = true,
        .finished = true,
        .terminal_status = .failed,
        .work_estimate = 4,
        .planned_rows = 4,
        .completed_rows = 3,
    };
    pending.events[2] = .{
        .key = .{ .component_registry_index = 5 },
        .component_kind = "opcode",
        .work_estimate = 2,
        .planned_rows = 2,
        .completed_rows = 2,
    };
    pending.contributions[0].component_registry_index = 999;
    pending.component_work[0].work_estimate = 999;

    try recorder.publishTaskGraphAfterJoin(
        &pending,
        .{ .graph_id = "legacy" },
        summary(3),
    );
    var profile = try recorder.snapshot(allocator);
    defer profile.deinit(allocator);
    const graph = profile.graphs[0];
    try std.testing.expectEqual(@as(u32, 0), graph.events[0].contribution_range.start);
    try std.testing.expectEqual(@as(u32, 1), graph.events[1].contribution_range.start);
    try std.testing.expectEqual(@as(u32, 2), graph.events[2].contribution_range.start);
    try std.testing.expectEqual(@as(usize, 3), graph.contributions.len);
    try std.testing.expectEqual(task_profile.ContributionRole.exclusive, graph.contributions[0].role);
    try std.testing.expectEqual(@as(?u64, 8), graph.contributions[0].completed_rows);
    try std.testing.expect(graph.contributions[1].completed_rows == null);
    try std.testing.expectEqual(@as(?u64, 0), graph.contributions[2].completed_rows);
    try std.testing.expectEqual(@as(u64, 3), graph.component_work[0].task_count);
    try std.testing.expectEqual(@as(u64, 14), graph.component_work[0].work_estimate);
    try std.testing.expect(graph.component_work[0].completed_rows == null);
}

test "task profile: abort releases exact reservation" {
    const allocator = std.testing.allocator;
    var recorder = task_profile.Recorder.init(allocator, "zig", "riscv");
    defer recorder.deinit();

    var pending = try recorder.reserveTaskGraphShape(.{
        .event_count = 2,
        .contribution_count = 3,
        .component_work_count = 2,
    });
    try pending.abort();
    try std.testing.expect(recorder.active_reservation == null);

    var replacement = try recorder.reserveTaskGraphShape(.{
        .event_count = 0,
        .contribution_count = 0,
        .component_work_count = 0,
    });
    defer replacement.deinit();
}

test "task profile reservation: stale published copy cannot affect next generation" {
    const allocator = std.testing.allocator;
    var recorder = task_profile.Recorder.init(allocator, "zig", "riscv");
    defer recorder.deinit();

    var first = try reservePhysicalOnly(&recorder, 1);
    var stale = first;
    defer stale.deinit();
    try recorder.publishTaskGraphAfterJoin(&first, .{ .graph_id = "first" }, summary(1));
    try std.testing.expectError(error.TaskGraphReservationStale, stale.abort());

    var second = try reservePhysicalOnly(&recorder, 2);
    defer second.deinit();
    try std.testing.expectError(
        error.TaskGraphReservationStale,
        recorder.publishTaskGraphAfterJoin(&stale, .{ .graph_id = "stale" }, summary(1)),
    );
    try std.testing.expectError(error.TaskGraphReservationStale, stale.abort());
    try recorder.publishTaskGraphAfterJoin(&second, .{ .graph_id = "second" }, summary(2));

    var snapshot = try recorder.snapshot(allocator);
    defer snapshot.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), snapshot.graphs.len);
    try std.testing.expectEqualStrings("first", snapshot.graphs[0].graph_id);
    try std.testing.expectEqualStrings("second", snapshot.graphs[1].graph_id);
}

test "task profile reservation: stale aborted copy cannot free replacement" {
    const allocator = std.testing.allocator;
    var recorder = task_profile.Recorder.init(allocator, "zig", "riscv");
    defer recorder.deinit();

    var first = try reservePhysicalOnly(&recorder, 1);
    var stale = first;
    try first.abort();

    var replacement = try reservePhysicalOnly(&recorder, 3);
    defer replacement.deinit();
    try std.testing.expectError(error.TaskGraphReservationStale, stale.abort());
    stale.deinit();
    try recorder.publishTaskGraphAfterJoin(
        &replacement,
        .{ .graph_id = "replacement" },
        summary(3),
    );

    var snapshot = try recorder.snapshot(allocator);
    defer snapshot.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 3), snapshot.graphs[0].events.len);
}

test "task profile reservation: wrong recorder publication is rejected" {
    const allocator = std.testing.allocator;
    var owner = task_profile.Recorder.init(allocator, "zig", "owner");
    defer owner.deinit();
    var other = task_profile.Recorder.init(allocator, "zig", "other");
    defer other.deinit();

    var pending = try reservePhysicalOnly(&owner, 1);
    defer pending.deinit();
    try std.testing.expectError(
        error.TaskGraphReservationWrongRecorder,
        other.publishTaskGraphAfterJoin(&pending, .{ .graph_id = "wrong" }, summary(1)),
    );
    try owner.publishTaskGraphAfterJoin(&pending, .{ .graph_id = "owner" }, summary(1));
}

test "task profile reservation: malformed publication preserves capability" {
    const allocator = std.testing.allocator;
    var recorder = task_profile.Recorder.init(allocator, "zig", "riscv");
    defer recorder.deinit();

    var pending = try reservePhysicalOnly(&recorder, 1);
    defer pending.deinit();
    try std.testing.expectError(
        error.TaskProfilePlannedTaskCountMismatch,
        recorder.publishTaskGraphAfterJoin(&pending, .{ .graph_id = "wrong" }, summary(0)),
    );
    var bad_scheduler = summary(1);
    bad_scheduler.steal_count = 1;
    try std.testing.expectError(
        error.TaskProfileUnexpectedStealCount,
        recorder.publishTaskGraphAfterJoin(&pending, .{ .graph_id = "steal" }, bad_scheduler),
    );
    try recorder.publishTaskGraphAfterJoin(&pending, .{ .graph_id = "valid" }, summary(1));
}

test "task profile reservation: mutated authority or storage is rejected" {
    const allocator = std.testing.allocator;
    var recorder = task_profile.Recorder.init(allocator, "zig", "riscv");
    defer recorder.deinit();

    var pending = try recorder.reserveTaskGraphShape(.{
        .event_count = 1,
        .contribution_count = 1,
        .component_work_count = 1,
    });
    defer pending.deinit();
    pending.events[0].contribution_range.len = 1;

    var wrong_identity = pending;
    wrong_identity.recorder_identity +%= 1;
    try std.testing.expectError(
        error.TaskGraphReservationStale,
        recorder.publishTaskGraphAfterJoin(&wrong_identity, .{ .graph_id = "id" }, summary(1)),
    );
    var mutated = pending;
    mutated.contributions = mutated.contributions[0..0];
    try std.testing.expectError(
        error.TaskGraphReservationStorageMismatch,
        recorder.publishTaskGraphAfterJoin(&mutated, .{ .graph_id = "storage" }, summary(1)),
    );
    var wrong_mode = pending;
    wrong_mode.compatibility_one_contribution_per_event = true;
    try std.testing.expectError(
        error.TaskGraphReservationStorageMismatch,
        recorder.publishTaskGraphAfterJoin(&wrong_mode, .{ .graph_id = "mode" }, summary(1)),
    );
    try std.testing.expectError(error.TaskGraphReservationActive, recorder.snapshot(allocator));
    try pending.abort();
}

test "task profile reservation: exact ranges are validated before move" {
    const allocator = std.testing.allocator;
    var recorder = task_profile.Recorder.init(allocator, "zig", "ranges");
    defer recorder.deinit();
    var pending = try recorder.reserveTaskGraphShape(.{
        .event_count = 1,
        .contribution_count = 1,
        .component_work_count = 1,
    });
    defer pending.deinit();

    pending.events[0].contribution_range = .{ .start = 1, .len = 0 };
    try std.testing.expectError(
        error.TaskProfileContributionRangeNotContiguous,
        recorder.publishTaskGraphAfterJoin(&pending, .{ .graph_id = "range" }, summary(1)),
    );
    pending.events[0].contribution_range = .{ .start = 0, .len = 2 };
    try std.testing.expectError(
        error.TaskProfileContributionRangeOutOfBounds,
        recorder.publishTaskGraphAfterJoin(&pending, .{ .graph_id = "range" }, summary(1)),
    );
    pending.events[0].contribution_range.len = 0;
    try std.testing.expectError(
        error.TaskProfileContributionRangeCoverageMismatch,
        recorder.publishTaskGraphAfterJoin(&pending, .{ .graph_id = "range" }, summary(1)),
    );
    pending.events[0].contribution_range.len = 1;
    try recorder.publishTaskGraphAfterJoin(&pending, .{ .graph_id = "range" }, summary(1));
}

test "task profile reservation: component identity drift and duplicates fail closed" {
    const allocator = std.testing.allocator;
    var recorder = task_profile.Recorder.init(allocator, "zig", "identity");
    defer recorder.deinit();
    var pending = try recorder.reserveTaskGraphShape(.{
        .event_count = 2,
        .contribution_count = 2,
        .component_work_count = 1,
    });
    defer pending.deinit();
    pending.events[0].contribution_range = .{ .start = 0, .len = 1 };
    pending.events[1].contribution_range = .{ .start = 1, .len = 1 };
    pending.contributions[0] = .{
        .component_registry_index = 4,
        .component_kind = "opcode",
        .role = .semantic_constraints,
    };
    pending.contributions[1] = .{
        .component_registry_index = 4,
        .component_kind = "table",
        .role = .semantic_constraints,
    };
    try std.testing.expectError(
        error.TaskProfileComponentKindDrift,
        recorder.publishTaskGraphAfterJoin(&pending, .{ .graph_id = "kind" }, summary(2)),
    );
    pending.contributions[1].component_kind = "opcode";
    pending.contributions[1].role = .lookup_constraints;
    try std.testing.expectError(
        error.TaskProfileContributionRoleDrift,
        recorder.publishTaskGraphAfterJoin(&pending, .{ .graph_id = "role" }, summary(2)),
    );
    pending.contributions[1].role = .semantic_constraints;
    try recorder.publishTaskGraphAfterJoin(&pending, .{ .graph_id = "valid" }, summary(2));

    var duplicate = try recorder.reserveTaskGraphShape(.{
        .event_count = 1,
        .contribution_count = 2,
        .component_work_count = 2,
    });
    defer duplicate.deinit();
    duplicate.events[0].contribution_range.len = 2;
    duplicate.contributions[0].component_registry_index = 1;
    duplicate.contributions[1].component_registry_index = 1;
    try std.testing.expectError(
        error.TaskProfileExclusiveContributionNotExclusive,
        recorder.publishTaskGraphAfterJoin(&duplicate, .{ .graph_id = "exclusive" }, summary(1)),
    );
    duplicate.contributions[0].role = .semantic_constraints;
    duplicate.contributions[1].role = .semantic_constraints;
    try std.testing.expectError(
        error.TaskProfileDuplicateComponentContribution,
        recorder.publishTaskGraphAfterJoin(&duplicate, .{ .graph_id = "duplicate" }, summary(1)),
    );
    duplicate.contributions[1].component_registry_index = 2;
    try recorder.publishTaskGraphAfterJoin(&duplicate, .{ .graph_id = "distinct" }, summary(1));
}

test "task profile reservation: completion state and aggregate overflow fail closed" {
    const allocator = std.testing.allocator;
    var recorder = task_profile.Recorder.init(allocator, "zig", "completion");
    defer recorder.deinit();
    var pending = try recorder.reserveTaskGraphShape(.{
        .event_count = 2,
        .contribution_count = 2,
        .component_work_count = 1,
    });
    defer pending.deinit();
    pending.events[0] = completedEvent(.{ .start = 0, .len = 1 });
    pending.events[1] = completedEvent(.{ .start = 1, .len = 1 });
    pending.contributions[0] = .{
        .component_registry_index = 1,
        .work_estimate = std.math.maxInt(u64),
    };
    pending.contributions[1] = .{
        .component_registry_index = 1,
        .work_estimate = 1,
    };
    try std.testing.expectError(
        error.TaskProfileComponentWorkOverflow,
        recorder.publishTaskGraphAfterJoin(&pending, .{ .graph_id = "overflow" }, summary(2)),
    );
    pending.contributions[0].work_estimate = 0;
    pending.contributions[0].completed_rows = null;
    try std.testing.expectError(
        error.TaskProfileContributionCompletionStateMismatch,
        recorder.publishTaskGraphAfterJoin(&pending, .{ .graph_id = "unknown" }, summary(2)),
    );
    pending.contributions[0].completed_rows = 1;
    try std.testing.expectError(
        error.TaskProfileContributionCompletionExceedsPlan,
        recorder.publishTaskGraphAfterJoin(&pending, .{ .graph_id = "excess" }, summary(2)),
    );
    pending.contributions[0].planned_rows = 1;
    try recorder.publishTaskGraphAfterJoin(&pending, .{ .graph_id = "valid" }, summary(2));
}

test "task profile reservation: impossible and overflowing shapes allocate nothing" {
    const allocator = std.testing.allocator;
    var recorder = task_profile.Recorder.init(allocator, "zig", "shape");
    defer recorder.deinit();

    try std.testing.expectError(
        error.TaskProfileComponentWorkCountImpossible,
        recorder.reserveTaskGraphShape(.{
            .event_count = 0,
            .contribution_count = 0,
            .component_work_count = 1,
        }),
    );
    const oversized = std.math.cast(
        usize,
        @as(u64, std.math.maxInt(u32)) + 1,
    ) orelse return error.SkipZigTest;
    try std.testing.expectError(
        error.TaskProfileContributionCountOverflow,
        recorder.reserveTaskGraphShape(.{
            .event_count = 0,
            .contribution_count = oversized,
            .component_work_count = 0,
        }),
    );
    try std.testing.expect(recorder.active_reservation == null);
    try std.testing.expectEqual(@as(u64, 0), recorder.next_generation);
}

test "task profile reservation: generation exhaustion fails before allocation" {
    const allocator = std.testing.allocator;
    var recorder = task_profile.Recorder.init(allocator, "zig", "riscv");
    defer recorder.deinit();
    recorder.next_generation = std.math.maxInt(u64);

    try std.testing.expectError(
        error.TaskGraphReservationGenerationExhausted,
        recorder.reserveTaskGraphShape(.{
            .event_count = 1,
            .contribution_count = 1,
            .component_work_count = 1,
        }),
    );
    try std.testing.expect(recorder.active_reservation == null);
}

test "task profile: reservation and snapshot clean up every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        exerciseAllocationFailureCleanup,
        .{},
    );
}

fn exerciseAllocationFailureCleanup(allocator: std.mem.Allocator) !void {
    var recorder = task_profile.Recorder.init(allocator, "zig", "riscv");
    defer recorder.deinit();
    var pending = try recorder.reserveTaskGraphShape(.{
        .event_count = 2,
        .contribution_count = 3,
        .component_work_count = 2,
    });
    defer pending.deinit();

    pending.events[0] = completedEvent(.{ .start = 0, .len = 2 });
    pending.events[0].stage_id = "composition";
    pending.events[0].component_kind = "fused";
    pending.events[1] = .{
        .contribution_range = .{ .start = 2, .len = 1 },
        .stage_id = "composition",
        .component_kind = "retry",
        .started = true,
        .terminal_status = .failed,
        .error_name = "injected",
    };
    pending.contributions[0] = .{
        .component_registry_index = 1,
        .component_kind = "opcode",
        .role = .semantic_constraints,
    };
    pending.contributions[1] = .{
        .component_registry_index = 2,
        .component_kind = "table",
        .role = .lookup_constraints,
    };
    pending.contributions[2] = .{
        .component_registry_index = 1,
        .component_kind = "opcode",
        .role = .semantic_constraints,
        .completed_rows = null,
        .completed_tiles = null,
    };
    try recorder.publishTaskGraphAfterJoin(
        &pending,
        .{ .graph_id = "composition" },
        summary(2),
    );

    var snapshot = try recorder.snapshot(allocator);
    defer snapshot.deinit(allocator);
}
