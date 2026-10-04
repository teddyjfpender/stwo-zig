const std = @import("std");
const engine = @import("stwo_prover_engine");
const Queue = @import("../block_v5_cpu_family_queue_v1.zig");

test "v5 family shared pool preserves binding ownership and rejects a different nested pool" {
    var shared: engine.work_pool.WorkPool = undefined;
    try shared.initInPlaceWithOptions(.{ .worker_count = 1, .backing_allocator = std.testing.allocator });
    defer shared.deinit();
    var different: engine.work_pool.WorkPool = undefined;
    try different.initInPlaceWithOptions(.{ .worker_count = 1, .backing_allocator = std.testing.allocator });
    defer different.deinit();
    try std.testing.expectEqual(@as(?*engine.work_pool.WorkPool, null), engine.work_pool.currentScopedPool());
    var owned = (try engine.work_pool.ScopedPoolBinding.initIfNeeded(&shared)).?;
    defer if (owned.active) owned.deinit();
    try std.testing.expectEqual(@as(?engine.work_pool.ScopedPoolBinding, null), try engine.work_pool.ScopedPoolBinding.initIfNeeded(&shared));
    try std.testing.expectError(error.ScopedPoolAlreadyBound, engine.work_pool.ScopedPoolBinding.initIfNeeded(&different));
    try std.testing.expectEqual(@as(?*engine.work_pool.WorkPool, &shared), engine.work_pool.currentScopedPool());
    try std.testing.expectEqual(@as(?*engine.work_pool.WorkPool, &shared), engine.work_pool.getGlobalPool());
    owned.deinit();
    try std.testing.expectEqual(@as(?*engine.work_pool.WorkPool, null), engine.work_pool.currentScopedPool());
}

const Gate = struct {
    pool: *engine.work_pool.WorkPool,
    a: std.mem.Allocator,
    target: usize,
    bytes: usize = 4096,
    fail: bool = false,
    calls: std.atomic.Value(usize) = .init(0),
    ready: std.Thread.ResetEvent = .{},
    release: std.Thread.ResetEvent = .{},
    fn run(raw: *anyopaque) !void {
        const self: *Gate = @ptrCast(@alignCast(raw));
        if (engine.work_pool.getGlobalPool() != self.pool) return error.UnsharedV5FamilyPool;
        const buffer = try self.a.alloc(u8, self.bytes);
        defer self.a.free(buffer);
        @memset(buffer, 0xa5);
        if (self.calls.fetchAdd(1, .acq_rel) + 1 == self.target) self.ready.set();
        self.release.wait();
        if (self.fail) return error.InjectedV5FamilyFailure;
    }
    fn job(self: *Gate, family: Queue.Family, reservation: usize) Queue.Job {
        return .{ .family = family, .context = self, .reservation = reservation, .run = run };
    }
};

test "v5 family queue overlaps real allocations within one aggregate budget and pool" {
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 4 * 1024 * 1024);
    defer budget.destroy();
    const a = budget.allocator();
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 1, .backing_allocator = a });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const queue = try Queue.Queue.start(a, &pool, .{ .coordinators = 2, .capacity = 2, .reservation_limit = 2 * 1024 * 1024, .family_reservation = 1024 * 1024 }, 4 * 1024 * 1024);
    defer queue.deinit();
    var gate = Gate{ .pool = &pool, .a = a, .target = 2, .bytes = 1024 * 1024 };
    defer gate.release.set();
    try queue.submit(gate.job(.memory, 1024 * 1024));
    try queue.submit(gate.job(.caller, 1024 * 1024));
    gate.ready.wait();
    const active = queue.snapshot();
    try std.testing.expectEqual(@as(usize, 2), active.active);
    try std.testing.expectEqual(@as(usize, 2 * 1024 * 1024), active.live_reservation);
    try std.testing.expect(budget.snapshot().live_bytes >= 2 * 1024 * 1024);
    gate.release.set();
    const finished = try queue.finish();
    try std.testing.expectEqual(@as(usize, 2), finished.completed);
    try std.testing.expectEqual(@as(usize, 2), finished.peak_active);
    try std.testing.expectEqual(@as(usize, 0), finished.live_reservation);
    try std.testing.expectError(error.ClosedV5FamilyQueue, queue.submit(gate.job(.program, 1)));
}

test "v5 family queue reservation admission serializes otherwise independent coordinators" {
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 1, .backing_allocator = std.testing.allocator });
    defer pool.deinit();
    const queue = try Queue.Queue.start(std.testing.allocator, &pool, .{ .coordinators = 2, .capacity = 2, .reservation_limit = 1, .family_reservation = 1 }, 2);
    defer queue.deinit();
    var gate = Gate{ .pool = &pool, .a = std.testing.allocator, .target = 1 };
    defer gate.release.set();
    try queue.submit(gate.job(.memory, 1));
    gate.ready.wait();
    try queue.submit(gate.job(.lookup, 1));
    const waiting = queue.snapshot();
    try std.testing.expectEqual(@as(usize, 1), waiting.active);
    try std.testing.expectEqual(@as(usize, 1), waiting.queued);
    try std.testing.expectEqual(@as(usize, 1), gate.calls.load(.acquire));
    gate.release.set();
    const finished = try queue.finish();
    try std.testing.expectEqual(@as(usize, 2), finished.completed);
    try std.testing.expectEqual(@as(usize, 1), finished.peak_active);
    try std.testing.expectEqual(@as(usize, 1), finished.peak_reservation);
}

test "v5 family queue preserves first error and cancels unpublished queued work" {
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 1, .backing_allocator = std.testing.allocator });
    defer pool.deinit();
    const queue = try Queue.Queue.start(std.testing.allocator, &pool, .{ .coordinators = 1, .capacity = 1, .reservation_limit = 1, .family_reservation = 1 }, 2);
    defer queue.deinit();
    var failing = Gate{ .pool = &pool, .a = std.testing.allocator, .target = 1, .fail = true };
    defer failing.release.set();
    var unused = Gate{ .pool = &pool, .a = std.testing.allocator, .target = 1 };
    unused.release.set();
    try queue.submit(failing.job(.memory, 1));
    failing.ready.wait();
    try queue.submit(unused.job(.program, 1));
    failing.release.set();
    try std.testing.expectError(error.InjectedV5FamilyFailure, queue.finish());
    try std.testing.expectEqual(@as(usize, 0), unused.calls.load(.acquire));
    try std.testing.expectEqual(@as(usize, 1), queue.snapshot().cancelled);
    try std.testing.expectEqual(@as(usize, 0), queue.snapshot().active);
    try std.testing.expectError(error.InjectedV5FamilyFailure, queue.requireHealthy());
    const boundary = queue.boundary();
    try std.testing.expectError(error.InjectedV5FamilyFailure, boundary.check(boundary.context));
    try std.testing.expectError(error.InjectedV5FamilyFailure, queue.submit(unused.job(.lookup, 1)));
}

test "v5 family queue foreground abort joins borrowed contexts and cancels queued work" {
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 1, .backing_allocator = std.testing.allocator });
    defer pool.deinit();
    const queue = try Queue.Queue.start(std.testing.allocator, &pool, .{ .coordinators = 1, .capacity = 1, .reservation_limit = 1, .family_reservation = 1 }, 2);
    defer queue.deinit();
    var active = Gate{ .pool = &pool, .a = std.testing.allocator, .target = 1 };
    defer active.release.set();
    var unused = Gate{ .pool = &pool, .a = std.testing.allocator, .target = 1 };
    unused.release.set();
    try queue.submit(active.job(.memory, 1));
    active.ready.wait();
    try queue.submit(unused.job(.program, 1));
    const Abort = struct {
        fn run(q: *Queue.Queue) void {
            q.abort();
        }
    };
    const aborter = try std.Thread.spawn(.{}, Abort.run, .{queue});
    // The active job pins queue/context lifetime until release. Observe the
    // abort state before releasing it, then join before inspecting counters.
    while (true) {
        queue.requireHealthy() catch |err| {
            try std.testing.expectEqual(error.AbortedV5FamilyQueue, err);
            break;
        };
        std.Thread.yield() catch {};
    }
    active.release.set();
    aborter.join();
    try std.testing.expectEqual(@as(usize, 0), unused.calls.load(.acquire));
    try std.testing.expectEqual(@as(usize, 1), queue.snapshot().cancelled);
    try std.testing.expectEqual(@as(usize, 0), queue.snapshot().active);
    try std.testing.expectError(error.AbortedV5FamilyQueue, queue.finish());
}

test "v5 family queue rejects invalid admission and enforces actual parent allocation limit" {
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 1024 * 1024);
    defer budget.destroy();
    const a = budget.allocator();
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 1, .backing_allocator = a });
    defer pool.deinit();
    try std.testing.expectError(error.InvalidV5FamilyQueueOptions, Queue.Queue.start(a, &pool, .{ .reservation_limit = 1024 * 1024, .family_reservation = 1 }, 1024 * 1024));
    const queue = try Queue.Queue.start(a, &pool, .{ .coordinators = 1, .capacity = 1, .reservation_limit = 1, .family_reservation = 1 }, 1024 * 1024);
    defer queue.deinit();
    var gate = Gate{ .pool = &pool, .a = a, .target = 1, .bytes = 2 * 1024 * 1024 };
    gate.release.set();
    try std.testing.expectError(error.InvalidV5FamilyReservation, queue.submit(gate.job(.memory, 0)));
    try std.testing.expectError(error.InvalidV5FamilyReservation, queue.submit(gate.job(.memory, 2)));
    try queue.submit(gate.job(.memory, 1));
    try std.testing.expectError(error.OutOfMemory, queue.finish());
    try std.testing.expect(budget.snapshot().peak_live_bytes <= 1024 * 1024);
}
