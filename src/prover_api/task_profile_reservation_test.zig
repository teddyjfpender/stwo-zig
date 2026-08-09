//! Adversarial capability tests for exact task-profile reservations.

const std = @import("std");
const task_profile = @import("task_profile.zig");

fn summary(event_count: usize) task_profile.RequestSummary {
    return .{ .planned_tasks = @intCast(event_count) };
}

test "task profile reservation: stale published copy cannot affect next generation" {
    const allocator = std.testing.allocator;
    var recorder = task_profile.Recorder.init(allocator, "zig", "riscv");
    defer recorder.deinit();

    var first = try recorder.reserveTaskGraph(1, 0);
    var stale = first;
    defer stale.deinit();
    try recorder.publishTaskGraphAfterJoin(
        &first,
        .{ .graph_id = "first" },
        summary(1),
    );
    try std.testing.expectError(
        error.TaskGraphReservationStale,
        stale.abort(),
    );

    var second = try recorder.reserveTaskGraph(2, 0);
    defer second.deinit();
    try std.testing.expectError(
        error.TaskGraphReservationStale,
        recorder.publishTaskGraphAfterJoin(
            &stale,
            .{ .graph_id = "stale" },
            summary(1),
        ),
    );
    try std.testing.expectError(
        error.TaskGraphReservationStale,
        stale.abort(),
    );
    try recorder.publishTaskGraphAfterJoin(
        &second,
        .{ .graph_id = "second" },
        summary(2),
    );

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

    var first = try recorder.reserveTaskGraph(1, 0);
    var stale = first;
    try first.abort();

    var replacement = try recorder.reserveTaskGraph(3, 0);
    defer replacement.deinit();
    try std.testing.expectError(
        error.TaskGraphReservationStale,
        stale.abort(),
    );
    // `deinit` is cleanup-friendly, but performs the same checked abort. It
    // invalidates only this stale value and leaves the replacement untouched.
    stale.deinit();
    try recorder.publishTaskGraphAfterJoin(
        &replacement,
        .{ .graph_id = "replacement" },
        summary(3),
    );

    var snapshot = try recorder.snapshot(allocator);
    defer snapshot.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), snapshot.graphs.len);
    try std.testing.expectEqual(@as(usize, 3), snapshot.graphs[0].events.len);
}

test "task profile reservation: wrong recorder publication is rejected" {
    const allocator = std.testing.allocator;
    var owner = task_profile.Recorder.init(allocator, "zig", "owner");
    defer owner.deinit();
    var other = task_profile.Recorder.init(allocator, "zig", "other");
    defer other.deinit();

    var pending = try owner.reserveTaskGraph(1, 0);
    defer pending.deinit();
    try std.testing.expectError(
        error.TaskGraphReservationWrongRecorder,
        other.publishTaskGraphAfterJoin(
            &pending,
            .{ .graph_id = "wrong" },
            summary(1),
        ),
    );
    try owner.publishTaskGraphAfterJoin(
        &pending,
        .{ .graph_id = "owner" },
        summary(1),
    );
}

test "task profile reservation: malformed publication preserves capability" {
    const allocator = std.testing.allocator;
    var recorder = task_profile.Recorder.init(allocator, "zig", "riscv");
    defer recorder.deinit();

    var pending = try recorder.reserveTaskGraph(1, 0);
    defer pending.deinit();
    try std.testing.expectError(
        error.TaskProfilePlannedTaskCountMismatch,
        recorder.publishTaskGraphAfterJoin(
            &pending,
            .{ .graph_id = "wrong-count" },
            summary(0),
        ),
    );
    var bad_scheduler = summary(1);
    bad_scheduler.steal_count = 1;
    try std.testing.expectError(
        error.TaskProfileUnexpectedStealCount,
        recorder.publishTaskGraphAfterJoin(
            &pending,
            .{ .graph_id = "unexpected-steal" },
            bad_scheduler,
        ),
    );
    try recorder.publishTaskGraphAfterJoin(
        &pending,
        .{ .graph_id = "valid" },
        summary(1),
    );
}

test "task profile reservation: mutated identity or storage is rejected" {
    const allocator = std.testing.allocator;
    var recorder = task_profile.Recorder.init(allocator, "zig", "riscv");
    defer recorder.deinit();

    var pending = try recorder.reserveTaskGraph(1, 0);
    defer pending.deinit();

    var wrong_identity = pending;
    wrong_identity.recorder_identity +%= 1;
    try std.testing.expectError(
        error.TaskGraphReservationStale,
        recorder.publishTaskGraphAfterJoin(
            &wrong_identity,
            .{ .graph_id = "wrong-identity" },
            summary(1),
        ),
    );

    var mutated = pending;
    mutated.events = mutated.events[0..0];
    try std.testing.expectError(
        error.TaskGraphReservationStorageMismatch,
        recorder.publishTaskGraphAfterJoin(
            &mutated,
            .{ .graph_id = "mutated" },
            summary(0),
        ),
    );

    try std.testing.expectError(
        error.TaskGraphReservationActive,
        recorder.snapshot(allocator),
    );
    try pending.abort();
}

test "task profile reservation: generation exhaustion fails before allocation" {
    const allocator = std.testing.allocator;
    var recorder = task_profile.Recorder.init(allocator, "zig", "riscv");
    defer recorder.deinit();
    recorder.next_generation = std.math.maxInt(u64);

    try std.testing.expectError(
        error.TaskGraphReservationGenerationExhausted,
        recorder.reserveTaskGraph(1, 1),
    );
    try std.testing.expect(recorder.active_reservation == null);
}
