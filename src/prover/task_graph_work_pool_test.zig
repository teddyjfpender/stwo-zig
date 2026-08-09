const std = @import("std");
const task_graph = @import("task_graph.zig");
const work_pool = @import("work_pool.zig");

const AtomicUsize = std.atomic.Value(usize);
const TEST_STACK_SIZE: usize = 1024 * 1024;

fn key(index: u32) task_graph.TaskKey {
    return .{
        .epoch = 0,
        .stage_rank = 0,
        .component_registry_index = index,
        .shard_or_chunk_index = 0,
    };
}

fn initPool(pool: *work_pool.WorkPool, workers: usize) !void {
    try pool.initInPlaceWithOptions(.{
        .worker_count = workers,
        .stack_size = TEST_STACK_SIZE,
    });
}

const Noop = struct {
    fn run(_: *task_graph.TaskContext) !void {}
};

test "task graph compatibility: serial dependency order is unchanged" {
    const Context = struct {
        id: u8,
        order: *[3]u8,
        cursor: *usize,

        fn run(raw: *anyopaque) !void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.order[self.cursor.*] = self.id;
            self.cursor.* += 1;
        }
    };

    var order: [3]u8 = undefined;
    var cursor: usize = 0;
    var contexts = [_]Context{
        .{ .id = 0, .order = &order, .cursor = &cursor },
        .{ .id = 1, .order = &order, .cursor = &cursor },
        .{ .id = 2, .order = &order, .cursor = &cursor },
    };
    var graph = task_graph.TaskGraph.init(std.testing.allocator);
    _ = graph.addTask("first", Context.run, &contexts[0]);
    const second = graph.addTask(
        "second",
        Context.run,
        &contexts[1],
    );
    _ = graph.addTaskWithDeps(
        "third",
        Context.run,
        &contexts[2],
        &.{second},
    );

    try graph.execute();
    try std.testing.expectEqualSlices(u8, &.{ 0, 1, 2 }, &order);
    try std.testing.expectEqual(
        [_]task_graph.TaskStatus{ .done, .done, .done },
        graph.status[0..3].*,
    );
}

test "task graph compatibility: callback errors remain TaskFailed" {
    const Failure = struct {
        fn run(_: *anyopaque) !void {
            return error.SpecificLegacyFailure;
        }
    };
    var ignored: u8 = 0;
    var graph = task_graph.TaskGraph.init(std.testing.allocator);
    _ = graph.addTask("failure", Failure.run, &ignored);
    try std.testing.expectError(error.TaskFailed, graph.execute());
    try std.testing.expectEqual(task_graph.TaskStatus.failed, graph.status[0]);
}

test "component task graph rejects malformed or incomplete plans" {
    var incomplete = try task_graph.ComponentTaskGraph.init(
        std.testing.allocator,
        1,
    );
    defer incomplete.deinit();
    try std.testing.expectError(
        error.TaskCountMismatch,
        incomplete.execute(.{}),
    );

    var invalid_dep = try task_graph.ComponentTaskGraph.init(
        std.testing.allocator,
        1,
    );
    defer invalid_dep.deinit();
    var ignored: u8 = 0;
    try std.testing.expectError(
        error.InvalidDependency,
        invalid_dep.addTask(.{
            .key = key(0),
            .name = "forward",
            .func = Noop.run,
            .context = &ignored,
            .deps = &.{0},
        }),
    );

    var duplicate_key = try task_graph.ComponentTaskGraph.init(
        std.testing.allocator,
        2,
    );
    defer duplicate_key.deinit();
    _ = try duplicate_key.addTask(.{
        .key = key(0),
        .name = "first",
        .func = Noop.run,
        .context = &ignored,
    });
    try std.testing.expectError(
        error.DuplicateTaskKey,
        duplicate_key.addTask(.{
            .key = key(0),
            .name = "duplicate",
            .func = Noop.run,
            .context = &ignored,
        }),
    );
}

test "component task graph N=1 preserves canonical serial identity" {
    const Context = struct {
        id: u8,
        order: *[4]u8,
        cursor: *usize,

        fn run(context: *task_graph.TaskContext) !void {
            const self: *@This() = @ptrCast(@alignCast(context.user_context));
            self.order[self.cursor.*] = self.id;
            self.cursor.* += 1;
        }
    };

    var order: [4]u8 = undefined;
    var cursor: usize = 0;
    var contexts = [_]Context{
        .{ .id = 0, .order = &order, .cursor = &cursor },
        .{ .id = 1, .order = &order, .cursor = &cursor },
        .{ .id = 2, .order = &order, .cursor = &cursor },
        .{ .id = 3, .order = &order, .cursor = &cursor },
    };
    var graph = try task_graph.ComponentTaskGraph.init(
        std.testing.allocator,
        contexts.len,
    );
    defer graph.deinit();
    const first = try graph.addTask(.{
        .key = key(0),
        .name = "first",
        .func = Context.run,
        .context = &contexts[0],
    });
    const second = try graph.addTask(.{
        .key = key(1),
        .name = "second",
        .func = Context.run,
        .context = &contexts[1],
        .deps = &.{first},
    });
    const third = try graph.addTask(.{
        .key = key(2),
        .name = "third",
        .func = Context.run,
        .context = &contexts[2],
    });
    _ = try graph.addTask(.{
        .key = key(3),
        .name = "fourth",
        .func = Context.run,
        .context = &contexts[3],
        .deps = &.{ second, third },
    });

    const report = try graph.execute(.{});
    try std.testing.expectEqualSlices(u8, &.{ 0, 1, 2, 3 }, &order);
    try std.testing.expectEqual(@as(usize, 1), report.configured_workers);
    try std.testing.expectEqual(@as(usize, 4), report.submitted_tasks);
    try std.testing.expectEqual(report.submitted_tasks, report.started_tasks);
    try std.testing.expectEqual(report.started_tasks, report.succeeded_tasks);
    try std.testing.expectEqual(report.started_tasks, report.finished_tasks);
    try std.testing.expectEqual(@as(usize, 1), report.peak_active_tasks);
    try std.testing.expectEqual(@as(usize, 0), report.cancelled_tasks);
}

test "component task graph ranks level then work then TaskKey" {
    const Context = struct {
        id: u8,
        order: *[5]u8,
        cursor: *usize,

        fn run(context: *task_graph.TaskContext) !void {
            const self: *@This() = @ptrCast(@alignCast(context.user_context));
            self.order[self.cursor.*] = self.id;
            self.cursor.* += 1;
        }
    };

    var order: [5]u8 = undefined;
    var cursor: usize = 0;
    var contexts: [5]Context = undefined;
    for (&contexts, 0..) |*context, index| {
        context.* = .{
            .id = @intCast(index),
            .order = &order,
            .cursor = &cursor,
        };
    }
    var graph = try task_graph.ComponentTaskGraph.init(
        std.testing.allocator,
        5,
    );
    defer graph.deinit();
    _ = try graph.addTask(.{
        .key = key(0),
        .name = "wide-independent",
        .func = Context.run,
        .context = &contexts[0],
        .work_estimate = 100,
    });
    const root = try graph.addTask(.{
        .key = key(1),
        .name = "critical-root",
        .func = Context.run,
        .context = &contexts[1],
        .work_estimate = 1,
    });
    const middle = try graph.addTask(.{
        .key = key(2),
        .name = "critical-middle",
        .func = Context.run,
        .context = &contexts[2],
        .deps = &.{root},
        .work_estimate = 1,
    });
    _ = try graph.addTask(.{
        .key = key(3),
        .name = "critical-tail",
        .func = Context.run,
        .context = &contexts[3],
        .deps = &.{middle},
        .work_estimate = 1,
    });
    _ = try graph.addTask(.{
        .key = key(4),
        .name = "wide-key-tie",
        .func = Context.run,
        .context = &contexts[4],
        .work_estimate = 100,
    });

    _ = try graph.execute(.{});
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 0, 4, 3 }, &order);
    try std.testing.expectEqual(@as(u16, 2), graph.remainingLevel(root));
    try std.testing.expectEqual(@as(u16, 1), graph.remainingLevel(middle));
    try std.testing.expectEqual(
        @as(u64, 24),
        try task_graph.checkedWorkEstimate(&.{ 2, 3, 4 }),
    );
    try std.testing.expectError(
        error.WorkEstimateOverflow,
        task_graph.checkedWorkEstimate(&.{ std.math.maxInt(u64), 2 }),
    );
}

test "task contexts expose serial children except pool-exclusive work" {
    const Seen = struct {
        workers: usize = 0,
        has_lease: bool = false,

        fn run(context: *task_graph.TaskContext) !void {
            const self: *@This() = @ptrCast(@alignCast(context.user_context));
            self.workers = context.worker_budget.count;
            self.has_lease = context.exclusive_lease != null;
        }
    };

    var pool: work_pool.WorkPool = undefined;
    try initPool(&pool, 4);
    defer pool.deinit();
    var seen = [_]Seen{ .{}, .{}, .{} };
    var graph = try task_graph.ComponentTaskGraph.init(
        std.testing.allocator,
        seen.len,
    );
    defer graph.deinit();
    _ = try graph.addTask(.{
        .key = key(0),
        .name = "leaf",
        .func = Seen.run,
        .context = &seen[0],
        .class = .leaf,
    });
    _ = try graph.addTask(.{
        .key = key(1),
        .name = "coordinator",
        .func = Seen.run,
        .context = &seen[1],
        .class = .coordinator,
    });
    _ = try graph.addTask(.{
        .key = key(2),
        .name = "exclusive",
        .func = Seen.run,
        .context = &seen[2],
        .class = .pool_exclusive,
    });

    _ = try graph.execute(.{
        .worker_budget = try work_pool.WorkerBudget.init(4),
        .pool = &pool,
    });
    try std.testing.expectEqual(@as(usize, 1), seen[0].workers);
    try std.testing.expectEqual(@as(usize, 1), seen[1].workers);
    try std.testing.expectEqual(@as(usize, 4), seen[2].workers);
    try std.testing.expect(!seen[0].has_lease);
    try std.testing.expect(!seen[1].has_lease);
    try std.testing.expect(seen[2].has_lease);
}

test "work pool leases bound capacity and per-wave submissions" {
    try std.testing.expectError(
        error.InvalidWorkerBudget,
        work_pool.WorkerBudget.init(0),
    );
    var pool: work_pool.WorkPool = undefined;
    try initPool(&pool, 3);
    defer pool.deinit();
    try std.testing.expectEqual(@as(usize, TEST_STACK_SIZE), pool.stackSize());

    var lease = try pool.acquire(try work_pool.WorkerBudget.init(2));
    try std.testing.expectEqual(@as(usize, 1), pool.availableWorkers());
    try std.testing.expectError(
        error.WorkerBudgetUnavailable,
        pool.acquire(try work_pool.WorkerBudget.init(2)),
    );

    const Job = struct {
        fn run(counter: *AtomicUsize) void {
            _ = counter.fetchAdd(1, .monotonic);
        }
    };
    var counter = AtomicUsize.init(0);
    var wait_group = std.Thread.WaitGroup{};
    try lease.spawnWg(&wait_group, Job.run, .{&counter});
    try std.testing.expectError(
        error.SubmissionLimitExceeded,
        lease.spawnWg(&wait_group, Job.run, .{&counter}),
    );
    wait_group.wait();
    lease.completeWave();
    lease.deinit();

    try std.testing.expectEqual(@as(usize, 1), counter.load(.acquire));
    try std.testing.expectEqual(@as(usize, 3), pool.availableWorkers());
}

test "component task graph never exceeds N=2 or N=4 admitted waves" {
    const Barrier = struct {
        arrived: AtomicUsize = AtomicUsize.init(0),
        target: usize,

        fn run(context: *task_graph.TaskContext) !void {
            const self: *@This() = @ptrCast(@alignCast(context.user_context));
            _ = self.arrived.fetchAdd(1, .acq_rel);
            while (self.arrived.load(.acquire) != self.target) {
                std.atomic.spinLoopHint();
            }
        }
    };

    for ([_]usize{ 2, 4 }) |workers| {
        var pool: work_pool.WorkPool = undefined;
        try initPool(&pool, workers);
        defer pool.deinit();
        var barrier = Barrier{ .target = workers };
        var graph = try task_graph.ComponentTaskGraph.init(
            std.testing.allocator,
            workers,
        );
        defer graph.deinit();
        for (0..workers) |index| {
            _ = try graph.addTask(.{
                .key = key(@intCast(index)),
                .name = "parallel",
                .func = Barrier.run,
                .context = &barrier,
            });
        }

        const report = try graph.execute(.{
            .worker_budget = try work_pool.WorkerBudget.init(workers),
            .pool = &pool,
        });
        try std.testing.expectEqual(workers, report.peak_active_tasks);
        try std.testing.expect(report.peak_active_tasks <= report.configured_workers);
        try std.testing.expectEqual(workers, report.succeeded_tasks);
    }
}

test "component task graph byte reservations backpressure ready tasks" {
    var pool: work_pool.WorkPool = undefined;
    try initPool(&pool, 2);
    defer pool.deinit();
    var ignored: u8 = 0;
    var graph = try task_graph.ComponentTaskGraph.init(
        std.testing.allocator,
        2,
    );
    defer graph.deinit();
    for (0..2) |index| {
        _ = try graph.addTask(.{
            .key = key(@intCast(index)),
            .name = "reserved",
            .func = Noop.run,
            .context = &ignored,
            .resources = .{ .exclusive_scratch_bytes = 6 },
        });
    }

    const report = try graph.execute(.{
        .worker_budget = try work_pool.WorkerBudget.init(2),
        .pool = &pool,
        .byte_budget = TEST_STACK_SIZE +
            work_pool.STRUCTURED_JOB_RESERVATION_BYTES + 10,
    });
    try std.testing.expectEqual(
        @as(
            usize,
            TEST_STACK_SIZE + work_pool.STRUCTURED_JOB_RESERVATION_BYTES + 6,
        ),
        report.peak_reserved_bytes,
    );
    try std.testing.expectEqual(
        @as(usize, TEST_STACK_SIZE),
        report.admitted_worker_stack_bytes,
    );
    try std.testing.expectEqual(
        work_pool.STRUCTURED_JOB_RESERVATION_BYTES,
        report.admitted_submission_bytes,
    );
    try std.testing.expectEqual(@as(usize, 1), report.peak_active_tasks);
}

test "component task graph rejects oversized reservation before launch" {
    const Counter = struct {
        value: usize = 0,
        fn run(context: *task_graph.TaskContext) !void {
            const self: *@This() = @ptrCast(@alignCast(context.user_context));
            self.value += 1;
        }
    };
    var counter = Counter{};
    var graph = try task_graph.ComponentTaskGraph.init(
        std.testing.allocator,
        1,
    );
    defer graph.deinit();
    _ = try graph.addTask(.{
        .key = key(0),
        .name = "oversized",
        .func = Counter.run,
        .context = &counter,
        .resources = .{ .exclusive_scratch_bytes = 11 },
    });

    try std.testing.expectError(
        error.TaskMemoryBudgetExceeded,
        graph.execute(.{ .byte_budget = 10 }),
    );
    try std.testing.expectEqual(@as(usize, 0), counter.value);
    try std.testing.expectEqual(@as(usize, 0), graph.report().submitted_tasks);
}

test "component task graph admits all five resource classes with checked stacks" {
    var ignored: u8 = 0;
    var graph = try task_graph.ComponentTaskGraph.init(
        std.testing.allocator,
        1,
    );
    defer graph.deinit();
    _ = try graph.addTask(.{
        .key = key(0),
        .name = "all-resource-classes",
        .func = Noop.run,
        .context = &ignored,
        .resources = .{
            .final_output_bytes = 3,
            .exclusive_scratch_bytes = 11,
            .shared_resident_bytes = 5,
            .device_resident_bytes = 7,
            .worker_stack_bytes = 1024,
        },
    });
    const report = try graph.execute(.{ .byte_budget = 26 });
    try std.testing.expectEqual(@as(usize, 15), report.fixed_resident_bytes);
    try std.testing.expectEqual(@as(usize, 0), report.admitted_worker_stack_bytes);
    try std.testing.expectEqual(@as(usize, 0), report.admitted_submission_bytes);
    try std.testing.expectEqual(@as(usize, 26), report.peak_reserved_bytes);

    var pool: work_pool.WorkPool = undefined;
    try initPool(&pool, 2);
    defer pool.deinit();
    var oversized_stack = try task_graph.ComponentTaskGraph.init(
        std.testing.allocator,
        1,
    );
    defer oversized_stack.deinit();
    _ = try oversized_stack.addTask(.{
        .key = key(0),
        .name = "oversized-stack",
        .func = Noop.run,
        .context = &ignored,
        .resources = .{ .worker_stack_bytes = TEST_STACK_SIZE + 1 },
    });
    try std.testing.expectError(
        error.TaskWorkerStackExceeded,
        oversized_stack.execute(.{
            .worker_budget = try work_pool.WorkerBudget.init(2),
            .pool = &pool,
        }),
    );

    var overflow = try task_graph.ComponentTaskGraph.init(
        std.testing.allocator,
        1,
    );
    defer overflow.deinit();
    _ = try overflow.addTask(.{
        .key = key(0),
        .name = "overflow",
        .func = Noop.run,
        .context = &ignored,
        .resources = .{
            .final_output_bytes = std.math.maxInt(usize),
            .shared_resident_bytes = 1,
        },
    });
    try std.testing.expectError(
        error.ResourceReservationOverflow,
        overflow.execute(.{}),
    );
}

test "component task graph chooses the lowest TaskKey failure after join" {
    const Failures = struct {
        arrived: *AtomicUsize,

        fn rendezvous(self: *@This()) void {
            _ = self.arrived.fetchAdd(1, .acq_rel);
            while (self.arrived.load(.acquire) != 2) {
                std.atomic.spinLoopHint();
            }
        }

        fn lower(context: *task_graph.TaskContext) !void {
            const self: *@This() = @ptrCast(@alignCast(context.user_context));
            self.rendezvous();
            return error.LowerKeyFailure;
        }

        fn upper(context: *task_graph.TaskContext) !void {
            const self: *@This() = @ptrCast(@alignCast(context.user_context));
            self.rendezvous();
            return error.UpperKeyFailure;
        }
    };

    var pool: work_pool.WorkPool = undefined;
    try initPool(&pool, 2);
    defer pool.deinit();
    var arrived = AtomicUsize.init(0);
    var failures = Failures{ .arrived = &arrived };
    var graph = try task_graph.ComponentTaskGraph.init(
        std.testing.allocator,
        2,
    );
    defer graph.deinit();
    const upper = try graph.addTask(.{
        .key = key(1),
        .name = "upper",
        .func = Failures.upper,
        .context = &failures,
    });
    const lower = try graph.addTask(.{
        .key = key(0),
        .name = "lower",
        .func = Failures.lower,
        .context = &failures,
    });

    try std.testing.expectError(
        error.LowerKeyFailure,
        graph.execute(.{
            .worker_budget = try work_pool.WorkerBudget.init(2),
            .pool = &pool,
        }),
    );
    try std.testing.expectEqual(task_graph.TaskStatus.failed, graph.status(lower));
    try std.testing.expectEqual(task_graph.TaskStatus.failed, graph.status(upper));
    const report = graph.report();
    try std.testing.expectEqual(@as(usize, 2), report.started_tasks);
    try std.testing.expectEqual(@as(usize, 2), report.failed_tasks);
    try std.testing.expectEqual(report.started_tasks, report.finished_tasks);
    try std.testing.expectEqual(
        report.submitted_tasks,
        report.succeeded_tasks + report.failed_tasks + report.cancelled_tasks,
    );
    try std.testing.expect(report.cancellation_winner != null);
    try std.testing.expectEqual(@as(usize, 0), report.duplicate_starts);
    try std.testing.expectEqual(@as(usize, 0), report.duplicate_finishes);

    var metadata: [2]task_graph.TaskTerminalMetadata = undefined;
    try graph.writeTerminalMetadata(&metadata);
    try std.testing.expect(metadata[0].key.eql(key(0)));
    try std.testing.expect(metadata[1].key.eql(key(1)));
    try std.testing.expectEqualStrings("LowerKeyFailure", metadata[0].failure_name.?);
    try std.testing.expectEqualStrings("UpperKeyFailure", metadata[1].failure_name.?);
    try std.testing.expect(metadata[0].cleanup_complete);
    try std.testing.expect(metadata[1].cleanup_complete);
    try std.testing.expect(metadata[0].cancellation_winner.?.eql(
        report.cancellation_winner.?,
    ));
    try std.testing.expect(metadata[1].cancellation_winner.?.eql(
        report.cancellation_winner.?,
    ));
}

test "component task graph cancels queued work and joins running siblings" {
    const Shared = struct {
        observer_started: std.atomic.Value(bool) = .init(false),
        observed_cancellation: std.atomic.Value(bool) = .init(false),
        queued_runs: AtomicUsize = AtomicUsize.init(0),

        fn fail(context: *task_graph.TaskContext) !void {
            const self: *@This() = @ptrCast(@alignCast(context.user_context));
            while (!self.observer_started.load(.acquire)) {
                std.atomic.spinLoopHint();
            }
            return error.FatalTaskFailure;
        }

        fn observe(context: *task_graph.TaskContext) !void {
            const self: *@This() = @ptrCast(@alignCast(context.user_context));
            self.observer_started.store(true, .release);
            while (!context.isCancelled()) {
                std.atomic.spinLoopHint();
            }
            self.observed_cancellation.store(true, .release);
        }

        fn queued(context: *task_graph.TaskContext) !void {
            const self: *@This() = @ptrCast(@alignCast(context.user_context));
            _ = self.queued_runs.fetchAdd(1, .monotonic);
        }
    };

    var pool: work_pool.WorkPool = undefined;
    try initPool(&pool, 2);
    defer pool.deinit();
    var shared = Shared{};
    var graph = try task_graph.ComponentTaskGraph.init(
        std.testing.allocator,
        3,
    );
    defer graph.deinit();
    const failed = try graph.addTask(.{
        .key = key(0),
        .name = "fail",
        .func = Shared.fail,
        .context = &shared,
    });
    const observer = try graph.addTask(.{
        .key = key(1),
        .name = "observer",
        .func = Shared.observe,
        .context = &shared,
    });
    const queued = try graph.addTask(.{
        .key = key(2),
        .name = "queued",
        .func = Shared.queued,
        .context = &shared,
    });

    try std.testing.expectError(
        error.FatalTaskFailure,
        graph.execute(.{
            .worker_budget = try work_pool.WorkerBudget.init(2),
            .pool = &pool,
        }),
    );
    try std.testing.expect(shared.observed_cancellation.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), shared.queued_runs.load(.acquire));
    try std.testing.expectEqual(task_graph.TaskStatus.failed, graph.status(failed));
    try std.testing.expectEqual(task_graph.TaskStatus.done, graph.status(observer));
    try std.testing.expectEqual(task_graph.TaskStatus.cancelled, graph.status(queued));
    const report = graph.report();
    try std.testing.expectEqual(@as(usize, 2), report.submitted_tasks);
    try std.testing.expectEqual(report.submitted_tasks, report.finished_tasks);
    try std.testing.expectEqual(@as(usize, 1), report.succeeded_tasks);
    try std.testing.expectEqual(@as(usize, 1), report.failed_tasks);
    try std.testing.expectEqual(@as(usize, 0), report.cancelled_tasks);
    try std.testing.expectEqual(@as(usize, 1), report.unsubmitted_cancelled_tasks);
    try std.testing.expectEqual(
        report.submitted_tasks,
        report.succeeded_tasks + report.failed_tasks + report.cancelled_tasks,
    );
    try std.testing.expect(report.cancellation_winner.?.eql(key(0)));
    var metadata: [3]task_graph.TaskTerminalMetadata = undefined;
    try graph.writeTerminalMetadata(&metadata);
    try std.testing.expect(!metadata[2].submitted);
    try std.testing.expect(!metadata[2].started);
    try std.testing.expect(metadata[2].finished);
    try std.testing.expect(metadata[2].cleanup_complete);
    try std.testing.expectEqual(
        task_graph.TaskStatus.cancelled,
        metadata[2].terminal_status,
    );
}

test "submitted cancellation closes outcome accounting without callback start" {
    const State = struct {
        blocker_started: std.atomic.Value(bool) = .init(false),
        callback_runs: AtomicUsize = AtomicUsize.init(0),

        fn occupy(
            cancellation: *const task_graph.CancellationToken,
            started: *std.atomic.Value(bool),
        ) void {
            started.store(true, .release);
            while (!cancellation.isCancelled()) std.atomic.spinLoopHint();
        }

        fn fail(_: *task_graph.TaskContext) !void {
            return error.AccountedFailure;
        }

        fn shouldNotStart(context: *task_graph.TaskContext) !void {
            const self: *@This() = @ptrCast(@alignCast(context.user_context));
            _ = self.callback_runs.fetchAdd(1, .monotonic);
        }
    };

    var pool: work_pool.WorkPool = undefined;
    try initPool(&pool, 2);
    defer pool.deinit();
    var state = State{};
    var graph = try task_graph.ComponentTaskGraph.init(
        std.testing.allocator,
        2,
    );
    defer graph.deinit();
    _ = try graph.addTask(.{
        .key = key(0),
        .name = "failure",
        .func = State.fail,
        .context = &state,
    });
    const cancelled = try graph.addTask(.{
        .key = key(1),
        .name = "submitted-cancelled",
        .func = State.shouldNotStart,
        .context = &state,
    });

    var blocker = std.Thread.WaitGroup{};
    pool.spawnWg(
        &blocker,
        State.occupy,
        .{ &graph.cancellation, &state.blocker_started },
    );
    while (!state.blocker_started.load(.acquire)) std.atomic.spinLoopHint();
    try std.testing.expectError(
        error.AccountedFailure,
        graph.execute(.{
            .worker_budget = try work_pool.WorkerBudget.init(2),
            .pool = &pool,
        }),
    );
    blocker.wait();

    const report = graph.report();
    try std.testing.expectEqual(@as(usize, 2), report.submitted_tasks);
    try std.testing.expectEqual(@as(usize, 1), report.failed_tasks);
    try std.testing.expectEqual(@as(usize, 1), report.cancelled_tasks);
    try std.testing.expectEqual(@as(usize, 2), report.finished_tasks);
    try std.testing.expectEqual(
        report.submitted_tasks,
        report.succeeded_tasks + report.failed_tasks + report.cancelled_tasks,
    );
    try std.testing.expectEqual(@as(usize, 0), state.callback_runs.load(.acquire));
    try std.testing.expectEqual(task_graph.TaskStatus.cancelled, graph.status(cancelled));
}

test "component task graph rejects nested submission from a leaf" {
    const Nested = struct {
        fn job() void {}

        fn run(context: *task_graph.TaskContext) !void {
            try context.spawnChild(job, .{});
        }
    };

    var ignored: u8 = 0;
    var graph = try task_graph.ComponentTaskGraph.init(
        std.testing.allocator,
        1,
    );
    defer graph.deinit();
    _ = try graph.addTask(.{
        .key = key(0),
        .name = "nested",
        .func = Nested.run,
        .context = &ignored,
    });
    try std.testing.expectError(
        error.NestedSubmissionRejected,
        graph.execute(.{}),
    );
}

test "component task graph allocation failure occurs before task launch" {
    var failing = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        task_graph.ComponentTaskGraph.init(failing.allocator(), 1),
    );
}
