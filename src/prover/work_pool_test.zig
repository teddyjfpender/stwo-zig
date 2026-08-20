//! Scoped work-pool lifecycle and allocation tests.

const std = @import("std");
const builtin = @import("builtin");
const work_pool = @import("work_pool.zig");

const MAX_WORKERS = work_pool.MAX_WORKERS;
const STRUCTURED_JOB_RESERVATION_BYTES = work_pool.STRUCTURED_JOB_RESERVATION_BYTES;
const WorkPool = work_pool.WorkPool;
const ScopedPoolBinding = work_pool.ScopedPoolBinding;
const WorkerBudget = work_pool.WorkerBudget;
const getGlobalPool = work_pool.getGlobalPool;

test "work_pool: detection and test-global behavior" {
    const n = work_pool.testing.detectWorkerCount();
    try std.testing.expect(n >= 1);
    try std.testing.expect(n <= MAX_WORKERS);
    try std.testing.expect(getGlobalPool() == null);
}

test "work_pool: scoped binding exposes one pool and suppresses unbound helpers" {
    var pool: WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{
        .worker_count = 2,
        .stack_size = 64 * 1024,
        .backing_allocator = std.testing.allocator,
    });
    defer pool.deinit();

    var binding = try ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    try std.testing.expectEqual(&pool, getGlobalPool().?);
    try std.testing.expectError(
        error.ScopedPoolAlreadyBound,
        ScopedPoolBinding.init(&pool),
    );

    var helper_saw_pool = true;
    const helper = try std.Thread.spawn(.{}, struct {
        fn run(result: *bool) void {
            result.* = getGlobalPool() != null;
        }
    }.run, .{&helper_saw_pool});
    helper.join();
    try std.testing.expect(!helper_saw_pool);
}

test "work_pool: concurrent coordinators resolve only their own scoped pools" {
    var pools: [2]WorkPool = undefined;
    for (&pools) |*pool| {
        try pool.initInPlaceWithOptions(.{
            .worker_count = 1,
            .stack_size = 64 * 1024,
            .backing_allocator = std.testing.allocator,
        });
    }
    defer for (&pools) |*pool| pool.deinit();

    var ready: std.atomic.Value(usize) = .init(0);
    var release: std.atomic.Value(bool) = .init(false);
    var resolved = [_]bool{ false, false };
    const Coordinator = struct {
        fn run(
            pool: *WorkPool,
            ready_count: *std.atomic.Value(usize),
            release_flag: *std.atomic.Value(bool),
            result: *bool,
        ) void {
            var binding = ScopedPoolBinding.init(pool) catch {
                _ = ready_count.fetchAdd(1, .acq_rel);
                return;
            };
            defer binding.deinit();
            result.* = getGlobalPool() == pool;
            _ = ready_count.fetchAdd(1, .acq_rel);
            while (!release_flag.load(.acquire)) std.Thread.yield() catch {};
        }
    };

    var threads: [2]std.Thread = undefined;
    var spawned: usize = 0;
    errdefer {
        release.store(true, .release);
        for (threads[0..spawned]) |*thread| thread.join();
    }
    for (&threads, &pools, &resolved) |*thread, *pool, *result| {
        thread.* = try std.Thread.spawn(
            .{},
            Coordinator.run,
            .{ pool, &ready, &release, result },
        );
        spawned += 1;
    }
    while (ready.load(.acquire) != threads.len) std.Thread.yield() catch {};
    try std.testing.expectEqual(@as(usize, threads.len), work_pool.testing.activeScopedPoolCount());
    release.store(true, .release);
    for (&threads) |*thread| thread.join();

    try std.testing.expectEqual(@as(usize, 0), work_pool.testing.activeScopedPoolCount());
    try std.testing.expect(std.mem.allEqual(bool, &resolved, true));
}

test "work pool records and detects its stable initialized address" {
    var pool: WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{
        .worker_count = 1,
        .stack_size = 64 * 1024,
    });
    defer pool.deinit();

    try std.testing.expect(work_pool.testing.hasStableAddress(&pool));
    const relocated_copy = pool;
    try std.testing.expect(!work_pool.testing.hasStableAddress(&relocated_copy));
}

test "work_pool: structured leases submit without backing allocations" {
    if (comptime builtin.single_threaded) return error.SkipZigTest;

    var failing = std.testing.FailingAllocator.init(std.testing.allocator, .{});
    var pool: WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{
        .worker_count = 3,
        .stack_size = 64 * 1024,
        .backing_allocator = failing.allocator(),
    });
    defer {
        failing.fail_index = std.math.maxInt(usize);
        failing.resize_fail_index = std.math.maxInt(usize);
        pool.deinit();
    }

    const budget = try WorkerBudget.init(3);
    try std.testing.expectEqual(
        2 * (64 * 1024 + STRUCTURED_JOB_RESERVATION_BYTES),
        try pool.helperReservationBytes(budget),
    );
    var lease = try pool.acquire(budget);
    defer lease.deinit();

    const Job = struct {
        fn run(counter: *std.atomic.Value(usize)) void {
            _ = counter.fetchAdd(1, .monotonic);
        }
    };
    var counter = std.atomic.Value(usize).init(0);
    var wait_group = std.Thread.WaitGroup{};
    const allocation_count = failing.alloc_index;
    const resize_count = failing.resize_index;
    failing.fail_index = allocation_count;
    failing.resize_fail_index = resize_count;
    try lease.spawnWg(&wait_group, Job.run, .{&counter});
    try lease.spawnWg(&wait_group, Job.run, .{&counter});
    wait_group.wait();
    lease.completeWave();

    try std.testing.expectEqual(@as(usize, 2), counter.load(.acquire));
    try std.testing.expectEqual(allocation_count, failing.alloc_index);
    try std.testing.expectEqual(resize_count, failing.resize_index);
    try std.testing.expect(!failing.has_induced_failure);
}
