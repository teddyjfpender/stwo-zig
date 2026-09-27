//! Owned callback scheduling fixtures only. No native/recursive proof is run.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Owned = @import("block_v5_owned_ordered_queue_v1.zig");
const Payload = struct { byte: *u8 };
const Queue = Owned.ForPayload(Payload);
const Harness = struct {
    a: std.mem.Allocator,
    queue: ?*Queue = null,
    entered: std.Thread.ResetEvent = .{},
    release: std.Thread.ResetEvent = .{},
    fail: bool = false,
    destroyed: std.atomic.Value(usize) = .init(0),
    published: [4]u32 = undefined,
    count: usize = 0,
    fn make(self: *Harness, value: u8) !Payload {
        const byte = try self.a.create(u8);
        byte.* = value;
        return .{ .byte = byte };
    }
    fn callbacks(self: *Harness) Queue.Callbacks {
        return .{ .context = self, .run = run, .destroy = destroy };
    }
    fn run(raw: *anyopaque, index: u32, payload: *Payload) !void {
        const self: *Harness = @ptrCast(@alignCast(raw));
        if (index == 0) {
            self.entered.set();
            self.release.wait();
        }
        if (self.fail) return error.InjectedCapacityLeafFailure;
        try self.queue.?.requireHealthy();
        if (payload.byte.* != index) return error.InvalidFixturePayload;
        self.published[self.count] = index;
        self.count += 1;
    }
    fn destroy(raw: *anyopaque, payload: *Payload) void {
        const self: *Harness = @ptrCast(@alignCast(raw));
        self.a.destroy(payload.byte);
        payload.* = undefined;
        _ = self.destroyed.fetchAdd(1, .acq_rel);
    }
};
fn initPool(pool: *engine.work_pool.WorkPool) !void {
    try pool.initInPlaceWithOptions(.{ .worker_count = 1, .backing_allocator = std.testing.allocator });
}

test "block-v5 capacity leaf queue owns captures orders publication and applies backpressure" {
    const a = std.testing.allocator;
    var pool: engine.work_pool.WorkPool = undefined;
    try initPool(&pool);
    defer pool.deinit();
    var h = Harness{ .a = a };
    const queue = try Queue.start(a, &pool, 3, h.callbacks(), .{ .capacity = 1 }, null);
    defer queue.deinit();
    defer h.release.set();
    h.queue = queue;
    var first = try h.make(0);
    try queue.submit(0, &first);
    h.entered.wait();
    var second = try h.make(1);
    try queue.submit(1, &second);
    const saturated = queue.snapshot();
    try std.testing.expectEqual(@as(usize, 1), saturated.active);
    try std.testing.expectEqual(@as(usize, 1), saturated.queued);
    const Producer = struct {
        queue: *Queue,
        h: *Harness,
        entered: std.Thread.ResetEvent = .{},
        done: std.atomic.Value(bool) = .init(false),
        failure: ?anyerror = null,
        fn run(self: *@This()) void {
            self.entered.set();
            self.queue.waitForSlot(2) catch |err| {
                self.failure = err;
                return;
            };
            var payload = self.h.make(2) catch |err| {
                self.failure = err;
                return;
            };
            self.queue.submit(2, &payload) catch |err| {
                Harness.destroy(self.h, &payload);
                self.failure = err;
                return;
            };
            self.done.store(true, .release);
        }
    };
    var producer = Producer{ .queue = queue, .h = &h };
    const thread = try std.Thread.spawn(.{}, Producer.run, .{&producer});
    var joined = false;
    defer if (!joined) {
        h.release.set();
        thread.join();
    };
    producer.entered.wait();
    try std.testing.expect(!producer.done.load(.acquire));
    h.release.set();
    thread.join();
    joined = true;
    if (producer.failure) |err| return err;
    const stats = try queue.finish();
    try std.testing.expectEqualSlices(u32, &.{ 0, 1, 2 }, h.published[0..h.count]);
    try std.testing.expectEqual(@as(usize, 3), h.destroyed.load(.acquire));
    try std.testing.expectEqual(@as(usize, 3), stats.completed);
    try std.testing.expectEqual(@as(usize, 1), stats.peak_pending);
    try std.testing.expectEqual(@as(usize, 2), stats.peak_owned);
}

test "block-v5 capacity leaf queue error retains rejected owner and destroys queued captures" {
    const a = std.testing.allocator;
    var pool: engine.work_pool.WorkPool = undefined;
    try initPool(&pool);
    defer pool.deinit();
    var h = Harness{ .a = a, .fail = true };
    const queue = try Queue.start(a, &pool, 2, h.callbacks(), .{}, null);
    defer queue.deinit();
    defer h.release.set();
    h.queue = queue;
    var invalid = try h.make(1);
    try std.testing.expectError(error.InvalidV5OwnedQueueOrder, queue.submit(1, &invalid));
    try std.testing.expectEqual(@as(u8, 1), invalid.byte.*);
    Harness.destroy(&h, &invalid);
    var first = try h.make(0);
    try queue.submit(0, &first);
    h.entered.wait();
    var second = try h.make(1);
    try queue.submit(1, &second);
    h.release.set();
    try std.testing.expectError(error.InjectedCapacityLeafFailure, queue.finish());
    try std.testing.expectEqual(@as(usize, 3), h.destroyed.load(.acquire));
    try std.testing.expectEqual(@as(usize, 1), queue.snapshot().cancelled);
    const boundary = queue.boundary();
    try std.testing.expectError(error.InjectedCapacityLeafFailure, boundary.check(boundary.context));
}

test "block-v5 capacity leaf queue abort joins inflight owner before borrowed context teardown" {
    const a = std.testing.allocator;
    var pool: engine.work_pool.WorkPool = undefined;
    try initPool(&pool);
    defer pool.deinit();
    var h = Harness{ .a = a };
    const queue = try Queue.start(a, &pool, 2, h.callbacks(), .{}, null);
    defer queue.deinit();
    defer h.release.set();
    h.queue = queue;
    var first = try h.make(0);
    try queue.submit(0, &first);
    h.entered.wait();
    var second = try h.make(1);
    try queue.submit(1, &second);
    const Abort = struct {
        fn run(q: *Queue) void {
            q.abort();
        }
    };
    const thread = try std.Thread.spawn(.{}, Abort.run, .{queue});
    var joined = false;
    defer if (!joined) {
        h.release.set();
        thread.join();
    };
    while (true) {
        queue.requireHealthy() catch |err| {
            try std.testing.expectEqual(error.AbortedV5OwnedQueue, err);
            break;
        };
        std.Thread.yield() catch {};
    }
    h.release.set();
    thread.join();
    joined = true;
    try std.testing.expectEqual(@as(usize, 2), h.destroyed.load(.acquire));
    try std.testing.expectEqual(@as(usize, 0), h.count);
    try std.testing.expectEqual(@as(usize, 0), queue.snapshot().active);
    try std.testing.expectError(error.AbortedV5OwnedQueue, queue.finish());
}

test "block-v5 capacity leaf queue rejects invalid bounds and incomplete publication" {
    const a = std.testing.allocator;
    var pool: engine.work_pool.WorkPool = undefined;
    try initPool(&pool);
    defer pool.deinit();
    var h = Harness{ .a = a };
    try std.testing.expectError(error.InvalidV5OwnedQueueOptions, Queue.start(a, &pool, 1, h.callbacks(), .{ .capacity = 0 }, null));
    try std.testing.expectError(error.InvalidV5OwnedQueueOptions, Queue.start(a, &pool, 1, h.callbacks(), .{ .capacity = 65 }, null));
    const queue = try Queue.start(a, &pool, 1, h.callbacks(), .{}, null);
    defer queue.deinit();
    try std.testing.expectError(error.IncompleteV5OwnedQueue, queue.finish());
    const empty = try Queue.start(a, &pool, 0, h.callbacks(), .{}, null);
    defer empty.deinit();
    _ = try empty.finish();
}

test "block-v5 capacity leaf queue retains genuine capture publication and queue codegen bodies only" {
    const Stage = @import("block_v5_native_capacity_recursive_stage_v1.zig").ForBackend(Cpu);
    const Async = @import("block_v5_native_capacity_leaf_queue_v1.zig").ForBackend(Cpu);
    // Function addresses force actual bodies without invoking any proof path.
    const retained = [_]usize{
        @intFromPtr(&Stage.captureNative), @intFromPtr(&Stage.publishFromVerifiedCapture),
        @intFromPtr(&Stage.publish),       @intFromPtr(&Async.start),
        @intFromPtr(&Async.enqueueProof),  @intFromPtr(&Async.finish),
        @intFromPtr(&Async.abort),         @intFromPtr(&Async.deinit),
    };
    for (retained) |address| try std.testing.expect(address != 0);
}

fn allocationQueue(a: std.mem.Allocator, pool: *engine.work_pool.WorkPool, h: *Harness) !void {
    const queue = try Queue.start(a, pool, 0, h.callbacks(), .{}, null);
    defer queue.deinit();
    _ = try queue.finish();
}
test "block-v5 capacity leaf queue allocation failures and external cancellation preserve owners" {
    const a = std.testing.allocator;
    var pool: engine.work_pool.WorkPool = undefined;
    try initPool(&pool);
    defer pool.deinit();
    var h = Harness{ .a = a };
    try std.testing.checkAllAllocationFailures(a, allocationQueue, .{ &pool, &h });
    const External = struct {
        fn check(_: *anyopaque) !void {
            return error.InjectedFamilyBoundaryFailure;
        }
    };
    const queue = try Queue.start(a, &pool, 1, h.callbacks(), .{}, .{ .context = &h, .check = External.check });
    defer queue.deinit();
    var payload = try h.make(0);
    defer Harness.destroy(&h, &payload);
    try std.testing.expectError(error.InjectedFamilyBoundaryFailure, queue.submit(0, &payload));
    try std.testing.expectEqual(@as(u8, 0), payload.byte.*);
    try std.testing.expectEqual(@as(usize, 0), queue.snapshot().submitted);
}
