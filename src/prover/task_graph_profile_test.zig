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

test "task graph profile preserves canonical fused semantic contributions" {
    const allocator = std.testing.allocator;
    var ignored: u8 = 0;
    var graph = try task_graph.ComponentTaskGraph.init(allocator, 2);
    defer graph.deinit();

    const later = [_]task_graph.TaskContributionPlan{
        .{
            .component_registry_index = 3,
            .component_kind = "opcode",
            .role = .semantic_constraints,
            .work_estimate = 10,
            .planned_rows = 5,
        },
        .{
            .component_registry_index = 4,
            .component_kind = "lookup",
            .role = .lookup_constraints,
            .work_estimate = 15,
            .planned_rows = 5,
        },
    };
    const earlier = [_]task_graph.TaskContributionPlan{
        .{
            .component_registry_index = 3,
            .component_kind = "opcode",
            .role = .semantic_constraints,
            .work_estimate = 14,
            .planned_rows = 7,
        },
        .{
            .component_registry_index = 4,
            .component_kind = "lookup",
            .role = .lookup_constraints,
            .work_estimate = 21,
            .planned_rows = 7,
        },
    };
    _ = try graph.addTask(.{
        .key = key(20),
        .name = "later-key",
        .component_kind = "fused_lane",
        .func = Noop.run,
        .context = &ignored,
        .contributions = &later,
    });
    _ = try graph.addTask(.{
        .key = key(10),
        .name = "earlier-key",
        .component_kind = "fused_lane",
        .func = Noop.run,
        .context = &ignored,
        .contributions = &earlier,
    });

    var recorder = prover_api.stage_profile.Recorder.init(allocator, "Debug", "semantic");
    defer recorder.deinit();
    var clock = AtomicClock{};
    _ = try graph.execute(.{
        .task_profile_recorder = &recorder,
        .task_profile_graph_id = "semantic",
        .task_profile_clock = clock.source(),
    });

    var profile = try recorder.taskSnapshot(allocator);
    defer profile.deinit(allocator);
    const recorded = profile.graphs[0];
    try std.testing.expectEqual(@as(usize, 2), recorded.events.len);
    try std.testing.expectEqual(@as(usize, 4), recorded.contributions.len);
    try std.testing.expectEqual(@as(usize, 2), recorded.component_work.len);
    try std.testing.expectEqual(@as(u32, 10), recorded.events[0].key.component_registry_index);
    try std.testing.expectEqual(@as(u32, 0), recorded.events[0].contribution_range.start);
    try std.testing.expectEqual(@as(u32, 2), recorded.events[0].contribution_range.len);
    try std.testing.expectEqual(@as(u64, 7), recorded.contributions[0].planned_rows);
    try std.testing.expectEqual(@as(?u64, 7), recorded.contributions[0].completed_rows);
    try std.testing.expectEqual(@as(u64, 5), recorded.contributions[2].planned_rows);

    const semantic = recorded.component_work[0];
    try std.testing.expectEqual(@as(u32, 3), semantic.component_registry_index);
    try std.testing.expectEqual(task_graph.ContributionRole.semantic_constraints, semantic.role);
    try std.testing.expectEqual(@as(u64, 2), semantic.task_count);
    try std.testing.expectEqual(@as(u64, 24), semantic.work_estimate);
    try std.testing.expectEqual(@as(u64, 12), semantic.planned_rows);
    try std.testing.expectEqual(@as(?u64, 12), semantic.completed_rows);
    const lookup = recorded.component_work[1];
    try std.testing.expectEqual(task_graph.ContributionRole.lookup_constraints, lookup.role);
    try std.testing.expectEqual(@as(u64, 36), lookup.work_estimate);
}

test "task graph profile rejects mixed attribution before launch" {
    const Counter = struct {
        value: usize = 0,

        fn run(context: *task_graph.TaskContext) !void {
            const self: *@This() = @ptrCast(@alignCast(context.user_context));
            self.value += 1;
        }
    };
    var counter = Counter{};
    var graph = try task_graph.ComponentTaskGraph.init(std.testing.allocator, 2);
    defer graph.deinit();
    const contribution = [_]task_graph.TaskContributionPlan{.{
        .component_registry_index = 0,
        .component_kind = "explicit",
        .role = .exclusive,
    }};
    _ = try graph.addTask(.{
        .key = key(0),
        .name = "explicit",
        .func = Counter.run,
        .context = &counter,
        .contributions = &contribution,
    });
    _ = try graph.addTask(.{
        .key = key(1),
        .name = "compatibility",
        .func = Counter.run,
        .context = &counter,
    });
    var recorder = prover_api.stage_profile.Recorder.init(
        std.testing.allocator,
        "Debug",
        "mixed",
    );
    defer recorder.deinit();
    try std.testing.expectError(
        error.TaskProfileMixedAttributionModes,
        graph.execute(.{ .task_profile_recorder = &recorder }),
    );
    try std.testing.expectEqual(@as(usize, 0), counter.value);
}

test "task graph profile rejects invalid attribution before launch" {
    const Counter = struct {
        value: usize = 0,

        fn run(context: *task_graph.TaskContext) !void {
            const self: *@This() = @ptrCast(@alignCast(context.user_context));
            self.value += 1;
        }
    };
    const allocator = std.testing.allocator;
    var counter = Counter{};
    var recorder = prover_api.stage_profile.Recorder.init(
        allocator,
        "Debug",
        "invalid-attribution",
    );
    defer recorder.deinit();

    var exclusive_graph = try task_graph.ComponentTaskGraph.init(allocator, 1);
    defer exclusive_graph.deinit();
    const invalid_exclusive = [_]task_graph.TaskContributionPlan{
        .{
            .component_registry_index = 0,
            .component_kind = "exclusive",
            .role = .exclusive,
        },
        .{
            .component_registry_index = 1,
            .component_kind = "semantic",
            .role = .semantic_constraints,
        },
    };
    _ = try exclusive_graph.addTask(.{
        .key = key(0),
        .name = "invalid-exclusive",
        .func = Counter.run,
        .context = &counter,
        .contributions = &invalid_exclusive,
    });
    try std.testing.expectError(
        error.TaskProfileExclusiveContributionNotExclusive,
        exclusive_graph.execute(.{ .task_profile_recorder = &recorder }),
    );

    var overflow_graph = try task_graph.ComponentTaskGraph.init(allocator, 2);
    defer overflow_graph.deinit();
    const overflow_first = [_]task_graph.TaskContributionPlan{.{
        .component_registry_index = 0,
        .component_kind = "semantic",
        .role = .semantic_constraints,
        .work_estimate = std.math.maxInt(u64),
    }};
    const overflow_second = [_]task_graph.TaskContributionPlan{.{
        .component_registry_index = 0,
        .component_kind = "semantic",
        .role = .semantic_constraints,
        .work_estimate = 1,
    }};
    _ = try overflow_graph.addTask(.{
        .key = key(0),
        .name = "overflow-first",
        .func = Counter.run,
        .context = &counter,
        .contributions = &overflow_first,
    });
    var second_key = key(0);
    second_key.shard_or_chunk_index = 1;
    _ = try overflow_graph.addTask(.{
        .key = second_key,
        .name = "overflow-second",
        .func = Counter.run,
        .context = &counter,
        .contributions = &overflow_second,
    });
    try std.testing.expectError(
        error.TaskProfileComponentWorkOverflow,
        overflow_graph.execute(.{ .task_profile_recorder = &recorder }),
    );

    var compatibility_graph = try task_graph.ComponentTaskGraph.init(allocator, 2);
    defer compatibility_graph.deinit();
    _ = try compatibility_graph.addTask(.{
        .key = key(0),
        .name = "compatibility-first",
        .component_kind = "first-kind",
        .func = Counter.run,
        .context = &counter,
    });
    _ = try compatibility_graph.addTask(.{
        .key = second_key,
        .name = "compatibility-second",
        .component_kind = "second-kind",
        .func = Counter.run,
        .context = &counter,
    });
    try std.testing.expectError(
        error.TaskProfileComponentKindDrift,
        compatibility_graph.execute(.{ .task_profile_recorder = &recorder }),
    );
    try std.testing.expectEqual(@as(usize, 0), counter.value);
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

test "task graph profile measures pool-exclusive outer worker activity" {
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
    try std.testing.expectEqual(@as(u32, 1), summary.peak_active_workers.?);
    try std.testing.expect(summary.task_run_ns > 0);
    try std.testing.expectEqual(summary.task_run_ns, summary.worker_busy_ns.?);
}

test "task graph profile measures nested physical worker busy time" {
    const ChildState = struct {
        ran: std.atomic.Value(bool) = .init(false),

        fn child(self: *@This()) void {
            self.ran.store(true, .release);
        }

        fn parent(context: *task_graph.TaskContext) !void {
            const self: *@This() = @ptrCast(@alignCast(context.user_context));
            try context.spawnChild(child, .{self});
            try context.waitForChildren();
        }
    };

    const allocator = std.testing.allocator;
    var pool: work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{
        .worker_count = 2,
        .stack_size = TEST_STACK_SIZE,
    });
    defer pool.deinit();

    var state = ChildState{};
    var graph = try task_graph.ComponentTaskGraph.init(allocator, 1);
    defer graph.deinit();
    _ = try graph.addTask(.{
        .key = key(0),
        .name = "exclusive-with-child",
        .func = ChildState.parent,
        .context = &state,
        .class = .pool_exclusive,
    });
    var recorder = prover_api.stage_profile.Recorder.init(allocator, "Debug", "exclusive-child");
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
    try std.testing.expect(state.ran.load(.acquire));
    try std.testing.expectEqual(@as(u32, 1), summary.peak_active_tasks);
    try std.testing.expectEqual(@as(u32, 2), summary.peak_active_workers.?);
    try std.testing.expect(summary.worker_busy_ns.? > summary.task_run_ns);
    try std.testing.expect(summary.worker_busy_ns.? <= summary.worker_capacity_ns);
}

test "task graph profile closes nested worker accounting on parent failure" {
    const FailureState = struct {
        cancellation: ?*const task_graph.CancellationToken = null,
        child_finished: std.atomic.Value(bool) = .init(false),

        fn child(self: *@This()) void {
            while (!self.cancellation.?.isCancelled()) {
                std.atomic.spinLoopHint();
            }
            self.child_finished.store(true, .release);
        }

        fn parent(context: *task_graph.TaskContext) !void {
            const self: *@This() = @ptrCast(@alignCast(context.user_context));
            self.cancellation = context.cancellation;
            try context.spawnChild(child, .{self});
            return error.ProfiledExclusiveParentFailure;
        }
    };

    const allocator = std.testing.allocator;
    var pool: work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{
        .worker_count = 2,
        .stack_size = TEST_STACK_SIZE,
    });
    defer pool.deinit();

    var state = FailureState{};
    var graph = try task_graph.ComponentTaskGraph.init(allocator, 1);
    defer graph.deinit();
    _ = try graph.addTask(.{
        .key = key(0),
        .name = "failing-exclusive-with-child",
        .func = FailureState.parent,
        .context = &state,
        .class = .pool_exclusive,
    });
    var recorder = prover_api.stage_profile.Recorder.init(
        allocator,
        "Debug",
        "exclusive-child-failure",
    );
    defer recorder.deinit();
    var clock = AtomicClock{};
    try std.testing.expectError(
        error.ProfiledExclusiveParentFailure,
        graph.execute(.{
            .worker_budget = try work_pool.WorkerBudget.init(2),
            .pool = &pool,
            .task_profile_recorder = &recorder,
            .task_profile_clock = clock.source(),
        }),
    );

    var profile = try recorder.taskSnapshot(allocator);
    defer profile.deinit(allocator);
    const recorded = profile.graphs[0];
    try std.testing.expect(state.child_finished.load(.acquire));
    try std.testing.expectEqual(@as(u64, 1), recorded.summary.failed_tasks);
    try std.testing.expectEqual(@as(u64, 1), recorded.summary.submitted_tasks);
    try std.testing.expectEqual(@as(u64, 1), recorded.summary.finished_tasks);
    try std.testing.expect(recorded.summary.critical_path_ns == null);
    try std.testing.expectEqual(@as(u32, 2), recorded.summary.peak_active_workers.?);
    try std.testing.expect(recorded.summary.worker_busy_ns.? > recorded.summary.task_run_ns);
    try std.testing.expect(recorded.events[0].cleanup_complete);
    try std.testing.expectEqualStrings(
        "ProfiledExclusiveParentFailure",
        recorded.events[0].error_name.?,
    );
}
