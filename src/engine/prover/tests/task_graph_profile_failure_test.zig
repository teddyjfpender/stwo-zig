//! Failure, cancellation, and clock adversaries for flat task profiles.

const std = @import("std");
const prover_api = @import("stwo_prover_api");
const task_graph = @import("../task_graph.zig");
const task_graph_profile = @import("../task_graph_profile.zig");
const work_pool = @import("../work_pool.zig");

const TEST_STACK_SIZE: usize = 1024 * 1024;

const CausalClockRole = enum(u8) {
    none,
    failure,
    sibling,
};

threadlocal var causal_clock_role: CausalClockRole = .none;

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

const RegressingClock = struct {
    calls: std.atomic.Value(u64) = .init(0),

    fn now(raw: *anyopaque) anyerror!u64 {
        const self: *RegressingClock = @ptrCast(@alignCast(raw));
        const call = self.calls.fetchAdd(1, .monotonic);
        return if (call == 0) 10 else 9;
    }

    fn source(self: *RegressingClock) task_graph_profile.ClockSource {
        return .{ .context = self, .now_fn = now };
    }
};

const UnavailableClock = struct {
    calls: std.atomic.Value(u64) = .init(0),

    fn now(raw: *anyopaque) anyerror!u64 {
        const self: *UnavailableClock = @ptrCast(@alignCast(raw));
        const call = self.calls.fetchAdd(1, .monotonic);
        if (call != 0) return error.InjectedClockUnavailable;
        return 0;
    }

    fn source(self: *UnavailableClock) task_graph_profile.ClockSource {
        return .{ .context = self, .now_fn = now };
    }
};

const OrderedFailureClock = struct {
    regression_first: bool,
    calls: std.atomic.Value(u64) = .init(0),

    fn now(raw: *anyopaque) anyerror!u64 {
        const self: *OrderedFailureClock = @ptrCast(@alignCast(raw));
        const call = self.calls.fetchAdd(1, .monotonic);
        if (call == 0) return 10;
        const regression_call: u64 = if (self.regression_first) 1 else 2;
        if (call == regression_call) return 9;
        return error.InjectedClockUnavailable;
    }

    fn source(self: *OrderedFailureClock) task_graph_profile.ClockSource {
        return .{ .context = self, .now_fn = now };
    }
};

/// Delays a post-publication failure-thread clock sample until a sibling has
/// observed cancellation. The sibling clock records whether its finish sample
/// escaped before that request timestamp was ready.
const CancellationCausalityClock = struct {
    cancellation: *const task_graph.CancellationToken,
    next_ns: std.atomic.Value(u64) = .init(0),
    sibling_observed_cancellation: std.atomic.Value(bool) = .init(false),
    cancellation_timestamp_sampled: std.atomic.Value(bool) = .init(false),
    early_sibling_finish_sample: std.atomic.Value(bool) = .init(false),

    fn now(raw: *anyopaque) anyerror!u64 {
        const self: *CancellationCausalityClock = @ptrCast(@alignCast(raw));
        if (causal_clock_role == .failure and self.cancellation.isCancelled()) {
            while (!self.sibling_observed_cancellation.load(.acquire)) {
                std.atomic.spinLoopHint();
            }
            // Give an unguarded sibling finish boundary ample opportunity to
            // expose itself. The correct executor blocks it on timestamp-ready.
            for (0..100_000) |_| std.atomic.spinLoopHint();
            self.cancellation_timestamp_sampled.store(true, .release);
        }
        const timestamp = self.next_ns.fetchAdd(1, .monotonic);
        if (causal_clock_role == .sibling and
            self.cancellation.isCancelled() and
            !self.cancellation_timestamp_sampled.load(.acquire))
        {
            self.early_sibling_finish_sample.store(true, .release);
        }
        return timestamp;
    }

    fn source(self: *CancellationCausalityClock) task_graph_profile.ClockSource {
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

test "task graph profile rejects duplicate coarse completion reports" {
    const Duplicate = struct {
        fn run(context: *task_graph.TaskContext) !void {
            try context.setCompletedWork(1);
            try context.setCompletedWork(1);
        }
    };
    const allocator = std.testing.allocator;
    var ignored: u8 = 0;
    var graph = try task_graph.ComponentTaskGraph.init(allocator, 1);
    defer graph.deinit();
    _ = try graph.addTask(.{
        .key = key(0),
        .name = "duplicate-progress",
        .func = Duplicate.run,
        .context = &ignored,
        .work_unit = .rows,
        .planned_work_units = 2,
    });
    var recorder = prover_api.stage_profile.Recorder.init(allocator, "Debug", "duplicate");
    defer recorder.deinit();
    var clock = AtomicClock{};
    try std.testing.expectError(error.DuplicateCompletedTaskWork, graph.execute(.{
        .task_profile_recorder = &recorder,
        .task_profile_clock = clock.source(),
    }));

    var profile = try recorder.taskSnapshot(allocator);
    defer profile.deinit(allocator);
    const recorded = profile.graphs[0];
    try std.testing.expect(recorded.summary.critical_path_ns == null);
    try std.testing.expectEqual(@as(u64, 1), recorded.summary.failed_tasks);
    try std.testing.expectEqual(@as(u64, 1), recorded.summary.completed_rows);
    try std.testing.expectEqualStrings(
        "DuplicateCompletedTaskWork",
        recorded.events[0].error_name.?,
    );
}

test "task graph profile keeps lowest task failure ahead of completion order" {
    const Barrier = struct {
        started: std.atomic.Value(usize) = .init(0),
    };
    const Failure = struct {
        barrier: *Barrier,
        failure: anyerror,

        fn run(context: *task_graph.TaskContext) !void {
            const self: *@This() = @ptrCast(@alignCast(context.user_context));
            _ = self.barrier.started.fetchAdd(1, .acq_rel);
            while (self.barrier.started.load(.acquire) != 2) std.atomic.spinLoopHint();
            return self.failure;
        }
    };

    const allocator = std.testing.allocator;
    var pool: work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{
        .worker_count = 2,
        .stack_size = TEST_STACK_SIZE,
    });
    defer pool.deinit();
    var barrier = Barrier{};
    var failures = [_]Failure{
        .{ .barrier = &barrier, .failure = error.HigherKeyFailure },
        .{ .barrier = &barrier, .failure = error.LowerKeyFailure },
    };
    var graph = try task_graph.ComponentTaskGraph.init(allocator, 2);
    defer graph.deinit();
    _ = try graph.addTask(.{
        .key = key(9),
        .name = "higher",
        .func = Failure.run,
        .context = &failures[0],
    });
    _ = try graph.addTask(.{
        .key = key(1),
        .name = "lower",
        .func = Failure.run,
        .context = &failures[1],
    });
    var recorder = prover_api.stage_profile.Recorder.init(allocator, "Debug", "failures");
    defer recorder.deinit();
    var clock = AtomicClock{};
    try std.testing.expectError(error.LowerKeyFailure, graph.execute(.{
        .worker_budget = try work_pool.WorkerBudget.init(2),
        .pool = &pool,
        .task_profile_recorder = &recorder,
        .task_profile_clock = clock.source(),
    }));

    var profile = try recorder.taskSnapshot(allocator);
    defer profile.deinit(allocator);
    const recorded = profile.graphs[0];
    try std.testing.expectEqual(@as(u32, 1), recorded.events[0].key.component_registry_index);
    try std.testing.expectEqualStrings("LowerKeyFailure", recorded.events[0].error_name.?);
    try std.testing.expectEqual(@as(u32, 9), recorded.events[1].key.component_registry_index);
    try std.testing.expectEqualStrings("HigherKeyFailure", recorded.events[1].error_name.?);
    try std.testing.expectEqual(@as(u64, 2), recorded.summary.failed_tasks);
    try std.testing.expect(recorded.summary.critical_path_ns == null);
}

test "task graph profile accounts for deterministic unsubmitted cancellation" {
    const Failing = struct {
        fn run(_: *task_graph.TaskContext) !void {
            return error.InjectedRootFailure;
        }
    };
    const allocator = std.testing.allocator;
    var ignored: u8 = 0;
    var graph = try task_graph.ComponentTaskGraph.init(allocator, 3);
    defer graph.deinit();
    const root = try graph.addTask(.{
        .key = key(0),
        .name = "failing-root",
        .func = Failing.run,
        .context = &ignored,
    });
    _ = try graph.addTask(.{
        .key = key(1),
        .name = "dependent",
        .func = Noop.run,
        .context = &ignored,
        .deps = &.{root},
    });
    _ = try graph.addTask(.{
        .key = key(2),
        .name = "queued-sibling",
        .func = Noop.run,
        .context = &ignored,
    });

    var recorder = prover_api.stage_profile.Recorder.init(allocator, "Debug", "cancelled");
    defer recorder.deinit();
    var clock = AtomicClock{};
    try std.testing.expectError(error.InjectedRootFailure, graph.execute(.{
        .task_profile_recorder = &recorder,
        .task_profile_clock = clock.source(),
    }));

    var profile = try recorder.taskSnapshot(allocator);
    defer profile.deinit(allocator);
    const recorded = profile.graphs[0];
    try std.testing.expectEqual(@as(u64, 3), recorded.summary.planned_tasks);
    try std.testing.expectEqual(@as(u64, 1), recorded.summary.submitted_tasks);
    try std.testing.expectEqual(@as(u64, 1), recorded.summary.failed_tasks);
    try std.testing.expectEqual(@as(u64, 0), recorded.summary.cancelled_tasks);
    try std.testing.expectEqual(
        @as(u64, 2),
        recorded.summary.unsubmitted_cancelled_tasks,
    );
    try std.testing.expectEqual(@as(u64, 1), recorded.summary.started_tasks);
    try std.testing.expectEqual(@as(u64, 1), recorded.summary.finished_tasks);
    try std.testing.expect(recorded.summary.cancellation_latency_ns != null);
    try std.testing.expect(recorded.summary.critical_path_ns == null);
    try std.testing.expect(recorded.events[0].terminal_status == .failed);
    for (recorded.events[1..]) |event| {
        try std.testing.expect(!event.submitted and !event.started and event.finished);
        try std.testing.expect(event.terminal_status == .cancelled);
        try std.testing.expect(event.cancellation_reason == .sibling_failure);
        try std.testing.expect(event.finish_ns != null);
    }
}

test "task graph profile linearizes cancellation timestamp before publication" {
    const Barrier = struct {
        started: std.atomic.Value(usize) = .init(0),
    };
    const Failing = struct {
        barrier: *Barrier,

        fn run(context: *task_graph.TaskContext) !void {
            const self: *@This() = @ptrCast(@alignCast(context.user_context));
            causal_clock_role = .failure;
            _ = self.barrier.started.fetchAdd(1, .acq_rel);
            while (self.barrier.started.load(.acquire) != 2) {
                std.atomic.spinLoopHint();
            }
            return error.CausalFailure;
        }
    };
    const Sibling = struct {
        barrier: *Barrier,
        clock: *CancellationCausalityClock,

        fn run(context: *task_graph.TaskContext) !void {
            const self: *@This() = @ptrCast(@alignCast(context.user_context));
            causal_clock_role = .sibling;
            _ = self.barrier.started.fetchAdd(1, .acq_rel);
            while (!context.isCancelled()) std.atomic.spinLoopHint();
            self.clock.sibling_observed_cancellation.store(true, .release);
        }
    };

    const allocator = std.testing.allocator;
    var pool: work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{
        .worker_count = 2,
        .stack_size = TEST_STACK_SIZE,
    });
    defer pool.deinit();
    var barrier = Barrier{};
    var failing = Failing{ .barrier = &barrier };
    var graph = try task_graph.ComponentTaskGraph.init(allocator, 2);
    defer graph.deinit();
    var clock = CancellationCausalityClock{ .cancellation = &graph.cancellation };
    var sibling = Sibling{ .barrier = &barrier, .clock = &clock };
    const failing_contribution = [_]task_graph.TaskContributionPlan{.{
        .component_registry_index = 0,
        .component_kind = "failing-semantic",
        .role = .semantic_constraints,
        .planned_rows = 8,
    }};
    const sibling_contribution = [_]task_graph.TaskContributionPlan{.{
        .component_registry_index = 1,
        .component_kind = "cancelled-semantic",
        .role = .semantic_constraints,
        .planned_rows = 8,
    }};
    _ = try graph.addTask(.{
        .key = key(0),
        .name = "causal-failure",
        .func = Failing.run,
        .context = &failing,
        .contributions = &failing_contribution,
    });
    _ = try graph.addTask(.{
        .key = key(1),
        .name = "cancellation-observer",
        .func = Sibling.run,
        .context = &sibling,
        .contributions = &sibling_contribution,
    });
    var recorder = prover_api.stage_profile.Recorder.init(allocator, "Debug", "causality");
    defer recorder.deinit();
    try std.testing.expectError(error.CausalFailure, graph.execute(.{
        .worker_budget = try work_pool.WorkerBudget.init(2),
        .pool = &pool,
        .task_profile_recorder = &recorder,
        .task_profile_clock = clock.source(),
    }));

    var profile = try recorder.taskSnapshot(allocator);
    defer profile.deinit(allocator);
    const events = profile.graphs[0].events;
    const requested_ns = events[0].cancellation_requested_ns.?;
    try std.testing.expect(events[0].start_ns.? <= requested_ns);
    try std.testing.expect(events[1].start_ns.? <= requested_ns);
    try std.testing.expect(events[1].finish_ns.? >= requested_ns);
    try std.testing.expect(events[0].finish_ns.? >= requested_ns);
    try std.testing.expect(!clock.early_sibling_finish_sample.load(.acquire));
    try std.testing.expectEqual(
        prover_api.task_profile.TerminalStatus.failed,
        events[0].terminal_status,
    );
    try std.testing.expectEqual(
        prover_api.task_profile.TerminalStatus.cancelled,
        events[1].terminal_status,
    );
    const recorded = profile.graphs[0];
    try std.testing.expectEqual(@as(u64, 0), recorded.summary.completed_tasks);
    try std.testing.expectEqual(@as(u64, 1), recorded.summary.failed_tasks);
    try std.testing.expectEqual(@as(u64, 1), recorded.summary.cancelled_tasks);
    for (recorded.contributions) |contribution| {
        try std.testing.expect(contribution.completed_rows == null);
        try std.testing.expect(contribution.completed_tiles == null);
    }
    for (recorded.component_work) |work| {
        try std.testing.expect(work.completed_rows == null);
        try std.testing.expect(work.completed_tiles == null);
    }
}

test "task graph profile publishes an exact empty graph" {
    const allocator = std.testing.allocator;
    var graph = try task_graph.ComponentTaskGraph.init(allocator, 0);
    defer graph.deinit();
    var recorder = prover_api.stage_profile.Recorder.init(allocator, "Debug", "empty");
    defer recorder.deinit();
    var clock = AtomicClock{};
    const report = try graph.execute(.{
        .task_profile_recorder = &recorder,
        .task_profile_graph_id = "empty",
        .task_profile_clock = clock.source(),
    });
    try std.testing.expectEqual(@as(usize, 0), report.submitted_tasks);

    var profile = try recorder.taskSnapshot(allocator);
    defer profile.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), profile.graphs.len);
    const recorded = profile.graphs[0];
    try std.testing.expectEqualStrings("empty", recorded.graph_id);
    try std.testing.expectEqual(@as(usize, 0), recorded.events.len);
    try std.testing.expectEqual(@as(usize, 0), recorded.component_work.len);
    try std.testing.expectEqual(@as(u64, 0), recorded.summary.planned_tasks);
    try std.testing.expectEqual(@as(u64, 0), recorded.summary.critical_path_ns.?);
}

test "task graph profile labels a pre-cancelled request without inventing a timestamp" {
    const allocator = std.testing.allocator;
    var ignored: u8 = 0;
    var graph = try task_graph.ComponentTaskGraph.init(allocator, 1);
    defer graph.deinit();
    _ = try graph.addTask(.{
        .key = key(0),
        .name = "pre-cancelled",
        .func = Noop.run,
        .context = &ignored,
    });
    try std.testing.expect(graph.cancellation.request());
    var recorder = prover_api.stage_profile.Recorder.init(allocator, "Debug", "pre-cancelled");
    defer recorder.deinit();
    var clock = AtomicClock{};
    _ = try graph.execute(.{
        .task_profile_recorder = &recorder,
        .task_profile_clock = clock.source(),
    });

    var profile = try recorder.taskSnapshot(allocator);
    defer profile.deinit(allocator);
    const event = profile.graphs[0].events[0];
    try std.testing.expect(event.terminal_status == .cancelled);
    try std.testing.expect(event.cancellation_reason == .request_cancelled);
    try std.testing.expect(event.cancellation_winner == null);
    try std.testing.expect(event.cancellation_requested_ns == null);
    try std.testing.expect(profile.graphs[0].summary.cancellation_latency_ns == null);
}

test "task graph profile rejects impossible worker metadata before launch" {
    const Counted = struct {
        fn run(context: *task_graph.TaskContext) !void {
            const runs: *usize = @ptrCast(@alignCast(context.user_context));
            runs.* += 1;
        }
    };
    const allocator = std.testing.allocator;
    var pool: work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{
        .worker_count = 2,
        .stack_size = TEST_STACK_SIZE,
    });
    defer pool.deinit();
    var runs: usize = 0;
    var graph = try task_graph.ComponentTaskGraph.init(allocator, 1);
    defer graph.deinit();
    _ = try graph.addTask(.{
        .key = key(0),
        .name = "metadata-preflight",
        .func = Counted.run,
        .context = &runs,
    });
    var recorder = prover_api.stage_profile.Recorder.init(allocator, "Debug", "metadata");
    defer recorder.deinit();
    try std.testing.expectError(error.InvalidTaskProfileAccounting, graph.execute(.{
        .worker_budget = try work_pool.WorkerBudget.init(2),
        .pool = &pool,
        .task_profile_recorder = &recorder,
        .requested_worker_count = 1,
        .pool_capacity = 2,
    }));
    try std.testing.expectEqual(@as(usize, 0), runs);

    _ = try graph.execute(.{
        .worker_budget = try work_pool.WorkerBudget.init(2),
        .pool = &pool,
        .task_profile_recorder = &recorder,
        .requested_worker_count = 2,
        .pool_capacity = 2,
    });
    try std.testing.expectEqual(@as(usize, 1), runs);
}

test "task graph profile error never masks the canonical task failure" {
    const FailingTask = struct {
        runs: *usize,

        fn run(context: *task_graph.TaskContext) !void {
            const self: *@This() = @ptrCast(@alignCast(context.user_context));
            self.runs.* += 1;
            return error.CanonicalTaskFailure;
        }
    };
    const allocator = std.testing.allocator;
    var runs: usize = 0;
    var task = FailingTask{ .runs = &runs };
    var graph = try task_graph.ComponentTaskGraph.init(allocator, 1);
    defer graph.deinit();
    _ = try graph.addTask(.{
        .key = key(0),
        .name = "canonical-failure",
        .func = FailingTask.run,
        .context = &task,
    });
    var recorder = prover_api.stage_profile.Recorder.init(allocator, "Debug", "clock-failure");
    defer recorder.deinit();
    var clock = RegressingClock{};
    try std.testing.expectError(error.CanonicalTaskFailure, graph.execute(.{
        .task_profile_recorder = &recorder,
        .task_profile_clock = clock.source(),
    }));
    try std.testing.expectEqual(@as(usize, 1), runs);
    var profile = try recorder.taskSnapshot(allocator);
    defer profile.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 0), profile.graphs.len);
}

test "task graph profile allocation failure occurs before task launch" {
    const Counted = struct {
        fn run(context: *task_graph.TaskContext) !void {
            const runs: *usize = @ptrCast(@alignCast(context.user_context));
            runs.* += 1;
        }
    };
    const allocator = std.testing.allocator;
    var runs: usize = 0;
    var graph = try task_graph.ComponentTaskGraph.init(allocator, 1);
    defer graph.deinit();
    _ = try graph.addTask(.{
        .key = key(0),
        .name = "never-launched",
        .func = Counted.run,
        .context = &runs,
    });
    var failing = std.testing.FailingAllocator.init(allocator, .{ .fail_index = 0 });
    var recorder = prover_api.stage_profile.Recorder.init(
        failing.allocator(),
        "Debug",
        "allocation-failure",
    );
    defer recorder.deinit();
    try std.testing.expectError(error.OutOfMemory, graph.execute(.{
        .task_profile_recorder = &recorder,
    }));
    try std.testing.expectEqual(@as(usize, 0), runs);
}

test "task profile clock failures have deterministic precedence" {
    var clock_source = UnavailableClock{};
    const clock = try task_graph_profile.Clock.start(clock_source.source());
    var failure = std.atomic.Value(u8).init(@intFromEnum(
        task_graph_profile.ClockFailure.none,
    ));
    try std.testing.expect(clock.sample(&failure) == null);
    task_graph_profile.recordCounterOverflow(&failure);
    try std.testing.expect(
        task_graph_profile.clockError(&failure).? ==
            error.TaskProfileCounterOverflow,
    );

    var second_source = UnavailableClock{};
    const second_clock = try task_graph_profile.Clock.start(second_source.source());
    var reverse = std.atomic.Value(u8).init(@intFromEnum(
        task_graph_profile.ClockFailure.none,
    ));
    task_graph_profile.recordCounterOverflow(&reverse);
    try std.testing.expect(second_clock.sample(&reverse) == null);
    try std.testing.expect(
        task_graph_profile.clockError(&reverse).? ==
            error.TaskProfileCounterOverflow,
    );

    for ([_]bool{ false, true }) |regression_first| {
        var ordered_source = OrderedFailureClock{
            .regression_first = regression_first,
        };
        const ordered_clock = try task_graph_profile.Clock.start(
            ordered_source.source(),
        );
        var ordered_failure = std.atomic.Value(u8).init(@intFromEnum(
            task_graph_profile.ClockFailure.none,
        ));
        try std.testing.expect(ordered_clock.sample(&ordered_failure) == null);
        try std.testing.expect(ordered_clock.sample(&ordered_failure) == null);
        try std.testing.expect(
            task_graph_profile.clockError(&ordered_failure).? ==
                error.TaskProfileClockRegression,
        );
        task_graph_profile.recordCounterOverflow(&ordered_failure);
        try std.testing.expect(
            task_graph_profile.clockError(&ordered_failure).? ==
                error.TaskProfileCounterOverflow,
        );
    }
}

test "task lifecycle diagnostic executes actual capture ownership success abort and foreign clock refusal" {
    const a = std.testing.allocator;
    var graph = try task_graph.ComponentTaskGraph.init(a, 0);
    defer graph.deinit();
    var recorder = prover_api.stage_profile.Recorder.init(a, "Debug", "typed-capture");
    defer recorder.deinit();
    var failure: ?@import("stwo_core").error_codes.Entry = null;
    var occupied = try recorder.reserveTaskGraph(0, 0);
    try std.testing.expectError(error.TaskGraphReservationActive, task_graph_profile.Capture.initDiagnosed(a, &recorder, &graph, null, &failure));
    try std.testing.expectEqual(@as(u16, 0x3102), failure.?.code);
    try occupied.abortDiagnosed(&failure);
    try std.testing.expect(failure == null);
    var capture = try task_graph_profile.Capture.initDiagnosed(a, &recorder, &graph, null, &failure);
    defer capture.deinit();
    try std.testing.expect(failure == null);
    try std.testing.expectError(error.TaskProfilePlannedTaskCountMismatch, capture.publish("bad", .{ .planned_tasks = 1 }));
    try std.testing.expectEqual(@as(u16, 0x3109), failure.?.code);
    try capture.publish("good", .{});
    try std.testing.expect(failure == null);
    var snapshot = try recorder.taskSnapshotDiagnosed(a, &failure);
    defer snapshot.deinit(a);
    try std.testing.expectEqual(@as(usize, 1), snapshot.graphs.len);
    const Foreign = struct {
        fn now(_: *anyopaque) anyerror!u64 {
            return error.TaskGraphReservationActive;
        }
    };
    failure = prover_api.error_codes.fromTaskProfile(error.TaskGraphReservationActive);
    var context: u8 = 0;
    try std.testing.expectError(error.TaskProfileClockUnavailable, task_graph_profile.Capture.initDiagnosed(a, &recorder, &graph, .{ .context = &context, .now_fn = Foreign.now }, &failure));
    try std.testing.expect(failure == null);
    // The failing clock ran after reservation. Capture's error cleanup returned
    // the owned storage, so another actual capture remains admissible.
    var next = try task_graph_profile.Capture.initDiagnosed(a, &recorder, &graph, null, &failure);
    defer next.deinit();
    try next.pending.abortDiagnosed(&failure);
    try std.testing.expect(failure == null);
}

test "task lifecycle diagnostic retains pending identity and every capture allocation cleanup" {
    const a = std.testing.allocator;
    var recorder = prover_api.stage_profile.Recorder.init(a, "Debug", "pending");
    defer recorder.deinit();
    var other = prover_api.stage_profile.Recorder.init(a, "Debug", "other");
    defer other.deinit();
    var failure: ?@import("stwo_core").error_codes.Entry = null;
    var pending = try recorder.reserveTaskGraphShapeDiagnosed(.{ .event_count = 0, .contribution_count = 0, .component_work_count = 0 }, &failure);
    defer pending.deinit();
    try std.testing.expectError(error.TaskGraphReservationWrongRecorder, other.publishTaskGraphAfterJoinDiagnosed(&pending, .{ .graph_id = "foreign" }, .{}, &failure));
    try std.testing.expectEqual(@as(u16, 0x3106), failure.?.code);
    var stale = pending;
    try pending.abortDiagnosed(&failure);
    try std.testing.expectError(error.TaskGraphReservationStale, stale.abortDiagnosed(&failure));
    try std.testing.expectEqual(@as(u16, 0x3104), failure.?.code);
    const Runner = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var graph = try task_graph.ComponentTaskGraph.init(allocator, 0);
            defer graph.deinit();
            var owner = prover_api.stage_profile.Recorder.init(allocator, "Debug", "oom");
            defer owner.deinit();
            var detail: ?@import("stwo_core").error_codes.Entry = null;
            var captured = task_graph_profile.Capture.initDiagnosed(allocator, &owner, &graph, null, &detail) catch |err| {
                if (detail) |entry| try std.testing.expectEqual(@as(u16, 0x3118), entry.code);
                return err;
            };
            defer captured.deinit();
            try captured.publish("joined", .{});
            var snapshot = try owner.taskSnapshotDiagnosed(allocator, &detail);
            defer snapshot.deinit(allocator);
            try std.testing.expect(detail == null);
        }
    };
    try std.testing.checkAllAllocationFailures(a, Runner.run, .{});
}

test "task lifecycle diagnostic executes all contribution validation origins" {
    const wire = prover_api.task_profile;
    const a = std.testing.allocator;
    var owner = prover_api.stage_profile.Recorder.init(a, "Debug", "contributions");
    defer owner.deinit();
    const errors = [_]wire.PublicationError{ error.TaskProfileComponentKindDrift, error.TaskProfileComponentWorkCountMismatch, error.TaskProfileComponentWorkOverflow, error.TaskProfileContributionCompletionExceedsPlan, error.TaskProfileContributionCompletionStateMismatch, error.TaskProfileContributionRangeCoverageMismatch, error.TaskProfileContributionRangeNotContiguous, error.TaskProfileContributionRangeOutOfBounds, error.TaskProfileContributionRoleDrift, error.TaskProfileDuplicateComponentContribution, error.TaskProfileExclusiveContributionNotExclusive };
    for (errors) |expected| {
        var failure: ?@import("stwo_core").error_codes.Entry = null;
        var pending = try owner.reserveTaskGraphShapeDiagnosed(.{ .event_count = 2, .contribution_count = 2, .component_work_count = if (expected == error.TaskProfileComponentWorkCountMismatch) 2 else 1 }, &failure);
        defer pending.deinit();
        pending.events[0].contribution_range = .{ .start = 0, .len = 1 };
        pending.events[1].contribution_range = .{ .start = 1, .len = 1 };
        @memset(pending.contributions, .{ .component_registry_index = 4, .component_kind = "opcode", .role = .semantic_constraints });
        switch (expected) {
            error.TaskProfileComponentKindDrift => pending.contributions[1].component_kind = "foreign",
            error.TaskProfileComponentWorkCountMismatch => {},
            error.TaskProfileComponentWorkOverflow => {
                pending.contributions[0].work_estimate = std.math.maxInt(u64);
                pending.contributions[1].work_estimate = 1;
            },
            error.TaskProfileContributionCompletionExceedsPlan => {
                pending.events[1].started = true;
                pending.events[1].terminal_status = .completed;
                pending.contributions[1].completed_rows = 1;
            },
            error.TaskProfileContributionCompletionStateMismatch => pending.contributions[1].completed_rows = null,
            error.TaskProfileContributionRangeCoverageMismatch => pending.events[1].contribution_range.len = 0,
            error.TaskProfileContributionRangeNotContiguous => pending.events[0].contribution_range.start = 1,
            error.TaskProfileContributionRangeOutOfBounds => pending.events[0].contribution_range.len = 3,
            error.TaskProfileContributionRoleDrift => pending.contributions[1].role = .lookup_constraints,
            error.TaskProfileDuplicateComponentContribution, error.TaskProfileExclusiveContributionNotExclusive => {
                pending.events[0].contribution_range.len = 2;
                pending.events[1].contribution_range = .{ .start = 2, .len = 0 };
                if (expected == error.TaskProfileExclusiveContributionNotExclusive) pending.contributions[0].role = .exclusive;
            },
            else => unreachable,
        }
        try std.testing.expectError(expected, owner.publishTaskGraphAfterJoinDiagnosed(&pending, .{ .graph_id = "bad" }, .{ .planned_tasks = 2 }, &failure));
        try std.testing.expectEqual(prover_api.error_codes.fromTaskProfile(expected).code, failure.?.code);
        try pending.abortDiagnosed(&failure);
        try std.testing.expect(failure == null);
    }
}

test "task lifecycle diagnostic records resource storage and joined summary refusal without stale state" {
    const a = std.testing.allocator;
    var owner = prover_api.stage_profile.Recorder.init(a, "Debug", "resources");
    defer owner.deinit();
    var failure: ?@import("stwo_core").error_codes.Entry = null;
    try std.testing.expectError(error.TaskProfileContributionCountOverflow, owner.reserveTaskGraphShapeDiagnosed(.{ .event_count = 0, .contribution_count = @as(usize, std.math.maxInt(u32)) + 1, .component_work_count = 0 }, &failure));
    try std.testing.expectEqual(@as(u16, 0x3108), failure.?.code);
    try std.testing.expectError(error.TaskProfileComponentWorkCountImpossible, owner.reserveTaskGraphShapeDiagnosed(.{ .event_count = 0, .contribution_count = 0, .component_work_count = 1 }, &failure));
    try std.testing.expectEqual(@as(u16, 0x3107), failure.?.code);
    owner.task_recorder.next_generation = std.math.maxInt(u64);
    try std.testing.expectError(error.TaskGraphReservationGenerationExhausted, owner.reserveTaskGraphShapeDiagnosed(.{ .event_count = 0, .contribution_count = 0, .component_work_count = 0 }, &failure));
    try std.testing.expectEqual(@as(u16, 0x3103), failure.?.code);
    owner.task_recorder.next_generation = 0;
    var pending = try owner.reserveTaskGraph(0, 0);
    defer pending.deinit();
    var mutated = pending;
    mutated.compatibility_one_contribution_per_event = !pending.compatibility_one_contribution_per_event;
    try std.testing.expectError(error.TaskGraphReservationStorageMismatch, owner.publishTaskGraphAfterJoinDiagnosed(&mutated, .{ .graph_id = "bad-storage" }, .{}, &failure));
    try std.testing.expectEqual(@as(u16, 0x3105), failure.?.code);
    try std.testing.expectError(error.TaskGraphReservationActive, owner.taskSnapshotDiagnosed(a, &failure));
    try std.testing.expectEqual(@as(u16, 0x3102), failure.?.code);
    try std.testing.expectError(error.TaskProfileUnexpectedStealCount, owner.publishTaskGraphAfterJoinDiagnosed(&pending, .{ .graph_id = "stolen" }, .{ .steal_count = 1 }, &failure));
    try std.testing.expectEqual(@as(u16, 0x310b), failure.?.code);
    try pending.abortDiagnosed(&failure);
    try std.testing.expect(failure == null);
}

test "work accounting diagnostics retain actual stage state and all four owned failures" {
    const work = prover_api.work_profile;
    const codes = prover_api.error_codes;
    var stage = prover_api.stage_profile.Recorder.initWithOptions(std.testing.allocator, "Debug", "work-diagnostic", .{ .capture_work = true });
    defer stage.deinit();
    const active = stage.workCaptureRecorder().?;
    const good = work.Delta{ .producer = .column_preparation_fft, .source_mask = work.SourceMask.one(.fft_butterflies), .counters = .{ .fft_butterflies = std.math.maxInt(u64) } };
    var failure: ?@import("stwo_core").error_codes.Entry = codes.fromWorkProfile(error.InvalidWorkProfile);
    try active.recordDiagnosed(good, &failure);
    try std.testing.expect(failure == null);
    const before = try stage.workSnapshot();
    try std.testing.expectEqualDeep(before, try stage.workSnapshotDiagnosed(&failure));
    var next = good;
    next.counters.fft_butterflies = 1;
    try std.testing.expectError(error.CounterOverflow, active.recordDiagnosed(next, &failure));
    try std.testing.expectEqual(@as(u16, 0x3201), failure.?.code);
    try std.testing.expectEqualDeep(before, try stage.workSnapshot());
    next.source_mask = work.SourceMask.one(.fri_folds);
    try std.testing.expectError(error.InvalidCounterGroup, active.recordDiagnosed(next, &failure));
    try std.testing.expectEqual(@as(u16, 0x3202), failure.?.code);
    next = good;
    next.site = .main_witness_field;
    try std.testing.expectError(error.InvalidProducerCoverage, active.recordDiagnosed(next, &failure));
    try std.testing.expectEqual(@as(u16, 0x3203), failure.?.code);
    try std.testing.expectEqualDeep(before, try stage.workSnapshot());
    active.record_count += 1;
    try std.testing.expectError(error.InvalidWorkProfile, stage.workSnapshotDiagnosed(&failure));
    try std.testing.expectEqual(@as(u16, 0x3204), failure.?.code);
    active.record_count -= 1;
    try std.testing.expectEqualDeep(before, try stage.workSnapshotDiagnosed(&failure));
    try std.testing.expect(failure == null);
    var disabled: work.Recorder(false) = .{};
    try std.testing.expectEqual(@as(usize, 0), @sizeOf(@TypeOf(disabled)));
    failure = codes.fromWorkProfile(error.CounterOverflow);
    try disabled.recordDiagnosed(next, &failure);
    try std.testing.expect(failure == null);
    try std.testing.expectEqualDeep(work.Profile.unavailable(), try disabled.snapshotDiagnosed(&failure));
    stage.capture_work = false;
    failure = codes.fromWorkProfile(error.InvalidWorkProfile);
    try std.testing.expectEqualDeep(work.Profile.unavailable(), try stage.workSnapshotDiagnosed(&failure));
    try std.testing.expect(failure == null);
}
