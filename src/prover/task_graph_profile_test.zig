//! Capture, admission, and resource tests for flat task profiles.

const std = @import("std");
const prover_api = @import("stwo_prover_api");
const task_graph = @import("task_graph.zig");
const task_graph_profile = @import("task_graph_profile.zig");
const work_pool = @import("work_pool.zig");

const TEST_STACK_SIZE: usize = 1024 * 1024;

const AtomicClock = struct {
    next_ns: std.atomic.Value(u64) = .init(0),

    fn now(raw: *anyopaque) anyerror!u64 {
        const self: *AtomicClock = @ptrCast(@alignCast(raw));
        return self.next_ns.fetchAdd(1, .monotonic);
    }

    fn source(self: *AtomicClock) task_graph_profile.ClockSource {
        return .{ .context = self, .now_fn = now };
    }
};

const Noop = struct {
    fn run(_: *task_graph.TaskContext) !void {}
};

fn key(component_registry_index: u32) task_graph.TaskKey {
    return .{
        .epoch = 0,
        .stage_rank = 1,
        .component_registry_index = component_registry_index,
        .shard_or_chunk_index = 0,
    };
}

test "task graph profile serial diamond has canonical events and exact critical path" {
    const allocator = std.testing.allocator;
    var ignored: u8 = 0;
    var graph = try task_graph.ComponentTaskGraph.init(allocator, 4);
    defer graph.deinit();

    const root = try graph.addTask(.{
        .key = key(30),
        .name = "root",
        .stage_id = "composition_domain",
        .component_kind = "diamond",
        .func = Noop.run,
        .context = &ignored,
        .work_unit = .rows,
        .planned_work_units = 1,
    });
    const left = try graph.addTask(.{
        .key = key(20),
        .name = "left",
        .stage_id = "composition_domain",
        .component_kind = "diamond",
        .func = Noop.run,
        .context = &ignored,
        .deps = &.{root},
        .work_unit = .rows,
        .planned_work_units = 1,
    });
    const right = try graph.addTask(.{
        .key = key(10),
        .name = "right",
        .stage_id = "composition_domain",
        .component_kind = "diamond",
        .func = Noop.run,
        .context = &ignored,
        .deps = &.{root},
        .work_unit = .rows,
        .planned_work_units = 1,
    });
    _ = try graph.addTask(.{
        .key = key(0),
        .name = "join",
        .stage_id = "composition_domain",
        .component_kind = "diamond",
        .func = Noop.run,
        .context = &ignored,
        .deps = &.{ left, right },
        .work_unit = .rows,
        .planned_work_units = 1,
    });

    var recorder = prover_api.stage_profile.Recorder.init(allocator, "Debug", "diamond");
    defer recorder.deinit();
    var clock = AtomicClock{};
    _ = try graph.execute(.{
        .task_profile_recorder = &recorder,
        .task_profile_graph_id = "diamond",
        .task_profile_clock = clock.source(),
    });

    var profile = try recorder.taskSnapshot(allocator);
    defer profile.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), profile.graphs.len);
    const recorded = profile.graphs[0];
    try std.testing.expectEqualStrings("diamond", recorded.graph_id);
    try std.testing.expectEqual(@as(usize, 4), recorded.events.len);
    for (recorded.events, [_]u32{ 0, 10, 20, 30 }) |event, expected| {
        try std.testing.expectEqual(expected, event.key.component_registry_index);
        try std.testing.expect(event.terminal_status == .completed);
        try std.testing.expectEqual(@as(u64, 1), event.run_ns);
        try std.testing.expectEqual(@as(u64, 1), event.completed_rows);
    }
    try std.testing.expectEqual(@as(u8, 2), recorded.events[0].dependency_count);
    try std.testing.expectEqual(@as(u64, 3), recorded.summary.critical_path_ns.?);
    try std.testing.expectEqual(@as(u64, 4), recorded.summary.task_run_ns);
    try std.testing.expectEqual(@as(u64, 4), recorded.summary.worker_busy_ns.?);
    try std.testing.expectEqual(@as(u64, 4), recorded.summary.completed_rows);
    try std.testing.expectEqual(@as(u32, 1), recorded.summary.peak_active_tasks);
    try std.testing.expectEqual(@as(u32, 1), recorded.summary.peak_active_workers.?);
    try std.testing.expectEqual(@as(u64, 21), recorded.summary.graph_elapsed_ns);
}

test "task graph profile disabled path never samples the supplied clock" {
    var ignored: u8 = 0;
    var graph = try task_graph.ComponentTaskGraph.init(std.testing.allocator, 1);
    defer graph.deinit();
    _ = try graph.addTask(.{
        .key = key(0),
        .name = "unprofiled",
        .func = Noop.run,
        .context = &ignored,
    });
    var clock = AtomicClock{};
    _ = try graph.execute(.{ .task_profile_clock = clock.source() });
    try std.testing.expectEqual(@as(u64, 0), clock.next_ns.load(.acquire));
}

test "task graph profile disabled path performs no capture allocation" {
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 1 },
    );
    var runs: usize = 0;
    const Counted = struct {
        fn run(context: *task_graph.TaskContext) !void {
            const count: *usize = @ptrCast(@alignCast(context.user_context));
            count.* += 1;
        }
    };
    var graph = try task_graph.ComponentTaskGraph.init(failing.allocator(), 1);
    defer graph.deinit();
    _ = try graph.addTask(.{
        .key = key(0),
        .name = "allocation-free-disabled-path",
        .func = Counted.run,
        .context = &runs,
    });
    _ = try graph.execute(.{});
    try std.testing.expectEqual(@as(usize, 1), runs);
}

test "task graph profile sidecar allocation rolls back recorder reservation" {
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 1 },
    );
    var runs: usize = 0;
    const Counted = struct {
        fn run(context: *task_graph.TaskContext) !void {
            const count: *usize = @ptrCast(@alignCast(context.user_context));
            count.* += 1;
        }
    };
    var graph = try task_graph.ComponentTaskGraph.init(failing.allocator(), 1);
    defer graph.deinit();
    _ = try graph.addTask(.{
        .key = key(0),
        .name = "sidecar-allocation-failure",
        .func = Counted.run,
        .context = &runs,
    });
    var recorder = prover_api.stage_profile.Recorder.init(
        std.testing.allocator,
        "Debug",
        "sidecar",
    );
    defer recorder.deinit();
    try std.testing.expectError(error.OutOfMemory, graph.execute(.{
        .task_profile_recorder = &recorder,
    }));
    try std.testing.expectEqual(@as(usize, 0), runs);

    // A leaked reservation would make this independent reservation fail.
    var replacement = try recorder.reserveTaskGraph(0, 0);
    replacement.deinit();
}

test "task graph profile records scratch backpressure separately from queue wait" {
    const allocator = std.testing.allocator;
    var pool: work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{
        .worker_count = 2,
        .stack_size = TEST_STACK_SIZE,
    });
    defer pool.deinit();
    const budget = try work_pool.WorkerBudget.init(2);
    const baseline_bytes = try pool.helperReservationBytes(budget);

    var ignored: u8 = 0;
    var graph = try task_graph.ComponentTaskGraph.init(allocator, 2);
    defer graph.deinit();
    for (0..2) |index| _ = try graph.addTask(.{
        .key = key(@intCast(index)),
        .name = "scratch",
        .func = Noop.run,
        .context = &ignored,
        .resources = .{ .exclusive_scratch_bytes = 8 },
    });

    var recorder = prover_api.stage_profile.Recorder.init(allocator, "Debug", "scratch");
    defer recorder.deinit();
    var clock = AtomicClock{};
    _ = try graph.execute(.{
        .worker_budget = budget,
        .pool = &pool,
        .byte_budget = baseline_bytes + 8,
        .task_profile_recorder = &recorder,
        .task_profile_clock = clock.source(),
    });

    var profile = try recorder.taskSnapshot(allocator);
    defer profile.deinit(allocator);
    const recorded = profile.graphs[0];
    try std.testing.expectEqual(@as(u64, 0), recorded.events[0].resource_wait_ns);
    try std.testing.expect(recorded.events[1].resource_wait_ns > 0);
    try std.testing.expect(recorded.events[1].admission_wait_ns >
        recorded.events[0].admission_wait_ns);
    try std.testing.expect(recorded.summary.resource_wait_ns > 0);
    try std.testing.expectEqual(@as(u32, 1), recorded.summary.peak_active_tasks);
}

test "task graph profile leaves nested physical worker activity unknown" {
    const allocator = std.testing.allocator;
    var pool: work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{
        .worker_count = 2,
        .stack_size = TEST_STACK_SIZE,
    });
    defer pool.deinit();

    var ignored: u8 = 0;
    var graph = try task_graph.ComponentTaskGraph.init(allocator, 1);
    defer graph.deinit();
    _ = try graph.addTask(.{
        .key = key(0),
        .name = "exclusive",
        .func = Noop.run,
        .context = &ignored,
        .class = .pool_exclusive,
    });
    var recorder = prover_api.stage_profile.Recorder.init(allocator, "Debug", "exclusive");
    defer recorder.deinit();
    var clock = AtomicClock{};
    _ = try graph.execute(.{
        .worker_budget = try work_pool.WorkerBudget.init(2),
        .pool = &pool,
        .task_profile_recorder = &recorder,
        .task_profile_clock = clock.source(),
    });

    var profile = try recorder.taskSnapshot(allocator);
    defer profile.deinit(allocator);
    const summary = profile.graphs[0].summary;
    try std.testing.expectEqual(@as(u32, 1), summary.peak_active_tasks);
    try std.testing.expect(summary.peak_active_workers == null);
    try std.testing.expect(summary.task_run_ns > 0);
    try std.testing.expect(summary.worker_busy_ns == null);
}
