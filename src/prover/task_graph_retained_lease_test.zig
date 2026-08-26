//! Ownership and failure adversaries for retained request leases.

const std = @import("std");
const task_graph = @import("task_graph.zig");
const work_pool = @import("work_pool.zig");

const TEST_STACK_BYTES: usize = 128 * 1024;

fn key(epoch: u16, index: u32) task_graph.TaskKey {
    return .{
        .epoch = epoch,
        .stage_rank = 0,
        .component_registry_index = index,
        .shard_or_chunk_index = 0,
    };
}

const Count = struct {
    value: std.atomic.Value(usize) = .init(0),

    fn run(context: *task_graph.TaskContext) !void {
        const self: *Count = @ptrCast(@alignCast(context.user_context));
        if (context.worker_budget.count != 1) {
            return error.LeafObservedNestedWorkerBudget;
        }
        _ = self.value.fetchAdd(1, .monotonic);
    }
};

fn countedGraph(
    allocator: std.mem.Allocator,
    epoch: u16,
    count: *Count,
    task_count: usize,
) !task_graph.ComponentTaskGraph {
    var graph = try task_graph.ComponentTaskGraph.init(allocator, task_count);
    errdefer graph.deinit();
    for (0..task_count) |index| {
        _ = try graph.addTask(.{
            .key = key(epoch, @intCast(index)),
            .name = "retained-lease-count",
            .func = Count.run,
            .context = count,
            .class = .leaf,
            .resources = .{ .worker_stack_bytes = TEST_STACK_BYTES },
        });
    }
    return graph;
}

test "retained lease: one reservation spans drained graphs without allocation" {
    const allocator = std.testing.allocator;
    var pool: work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{
        .worker_count = 4,
        .stack_size = TEST_STACK_BYTES,
        .backing_allocator = allocator,
    });
    defer pool.deinit();

    const budget = try work_pool.WorkerBudget.init(4);
    var lease = try pool.acquire(budget);
    defer lease.deinit();
    try std.testing.expectEqual(@as(usize, 0), pool.availableWorkers());

    var failing = std.testing.FailingAllocator.init(allocator, .{});
    var count = Count{};
    var first = try countedGraph(failing.allocator(), 1, &count, 7);
    defer first.deinit();
    var second = try countedGraph(failing.allocator(), 2, &count, 5);
    defer second.deinit();
    const allocation_count = failing.alloc_index;
    const resize_count = failing.resize_index;
    failing.fail_index = allocation_count;
    failing.resize_fail_index = resize_count;

    const first_report = try first.execute(.{
        .worker_budget = budget,
        .retained_lease = &lease,
    });
    try std.testing.expectEqual(@as(usize, 0), pool.availableWorkers());
    try lease.validateRetained(budget);
    try std.testing.expectError(
        error.WorkerBudgetUnavailable,
        pool.acquire(work_pool.WorkerBudget.serial()),
    );

    const second_report = try second.execute(.{
        .worker_budget = budget,
        .retained_lease = &lease,
    });
    try lease.validateRetained(budget);
    try std.testing.expectEqual(@as(usize, 12), count.value.load(.acquire));
    try std.testing.expectEqual(@as(usize, 7), first_report.succeeded_tasks);
    try std.testing.expectEqual(@as(usize, 5), second_report.succeeded_tasks);
    try std.testing.expectEqual(
        3 * TEST_STACK_BYTES,
        second_report.admitted_worker_stack_bytes,
    );
    try std.testing.expectEqual(allocation_count, failing.alloc_index);
    try std.testing.expectEqual(resize_count, failing.resize_index);
    try std.testing.expect(!failing.has_induced_failure);
}

test "retained lease: joined failure leaves reservation reusable" {
    const Shared = struct {
        arrivals: std.atomic.Value(usize) = .init(0),

        fn run(context: *task_graph.TaskContext) !void {
            const self: *@This() = @ptrCast(@alignCast(context.user_context));
            const index = context.key.component_registry_index;
            _ = self.arrivals.fetchAdd(1, .acq_rel);
            while (self.arrivals.load(.acquire) < 4) std.atomic.spinLoopHint();
            if (index == 0) return error.RetainedLeaseInjectedFailure;
            while (!context.isCancelled()) std.atomic.spinLoopHint();
        }
    };

    const allocator = std.testing.allocator;
    var pool: work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{
        .worker_count = 4,
        .stack_size = TEST_STACK_BYTES,
        .backing_allocator = allocator,
    });
    defer pool.deinit();
    const budget = try work_pool.WorkerBudget.init(4);
    var lease = try pool.acquire(budget);
    defer lease.deinit();

    var shared = Shared{};
    var failed = try task_graph.ComponentTaskGraph.init(allocator, 4);
    defer failed.deinit();
    for (0..4) |index| {
        _ = try failed.addTask(.{
            .key = key(3, @intCast(index)),
            .name = "retained-lease-failure",
            .func = Shared.run,
            .context = &shared,
            .resources = .{ .worker_stack_bytes = TEST_STACK_BYTES },
        });
    }
    try std.testing.expectError(
        error.RetainedLeaseInjectedFailure,
        failed.execute(.{
            .worker_budget = budget,
            .retained_lease = &lease,
        }),
    );
    const failure_report = failed.report();
    try std.testing.expectEqual(@as(usize, 1), failure_report.failed_tasks);
    try std.testing.expectEqual(@as(usize, 3), failure_report.cancelled_tasks);
    try std.testing.expectEqual(@as(usize, 0), pool.availableWorkers());
    try lease.validateRetained(budget);

    var count = Count{};
    var recovery = try countedGraph(allocator, 4, &count, 4);
    defer recovery.deinit();
    _ = try recovery.execute(.{
        .worker_budget = budget,
        .retained_lease = &lease,
    });
    try std.testing.expectEqual(@as(usize, 4), count.value.load(.acquire));
    try lease.validateRetained(budget);
}

test "retained lease: invalid ownership and width reject before launch" {
    const allocator = std.testing.allocator;
    var pool: work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{
        .worker_count = 2,
        .stack_size = TEST_STACK_BYTES,
        .backing_allocator = allocator,
    });
    defer pool.deinit();
    const dual = try work_pool.WorkerBudget.init(2);
    var lease = try pool.acquire(dual);

    var count = Count{};
    var graph = try countedGraph(allocator, 5, &count, 1);
    defer graph.deinit();
    try std.testing.expectError(
        error.RetainedLeaseBudgetMismatch,
        graph.execute(.{
            .worker_budget = work_pool.WorkerBudget.serial(),
            .retained_lease = &lease,
        }),
    );
    try std.testing.expectError(
        error.AmbiguousWorkLeaseOwnership,
        graph.execute(.{
            .worker_budget = dual,
            .pool = &pool,
            .retained_lease = &lease,
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), count.value.load(.acquire));

    lease.deinit();
    try std.testing.expectError(
        error.RetainedLeaseReleased,
        graph.execute(.{
            .worker_budget = dual,
            .retained_lease = &lease,
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), count.value.load(.acquire));
}

test "retained lease: active child wave rejects graph borrowing" {
    const Blocker = struct {
        started: std.Thread.ResetEvent = .{},
        release: std.Thread.ResetEvent = .{},

        fn run(self: *@This()) void {
            self.started.set();
            self.release.wait();
        }
    };

    const allocator = std.testing.allocator;
    var pool: work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{
        .worker_count = 2,
        .stack_size = TEST_STACK_BYTES,
        .backing_allocator = allocator,
    });
    defer pool.deinit();
    const budget = try work_pool.WorkerBudget.init(2);
    var lease = try pool.acquire(budget);
    defer lease.deinit();

    var blocker = Blocker{};
    var wait_group = std.Thread.WaitGroup{};
    try lease.spawnWg(&wait_group, Blocker.run, .{&blocker});
    blocker.started.wait();

    var count = Count{};
    var graph = try countedGraph(allocator, 6, &count, 1);
    defer graph.deinit();
    try std.testing.expectError(
        error.RetainedLeaseWaveActive,
        graph.execute(.{
            .worker_budget = budget,
            .retained_lease = &lease,
        }),
    );
    try std.testing.expectEqual(@as(usize, 0), count.value.load(.acquire));

    blocker.release.set();
    wait_group.wait();
    lease.completeWave();
    try lease.validateRetained(budget);
}
