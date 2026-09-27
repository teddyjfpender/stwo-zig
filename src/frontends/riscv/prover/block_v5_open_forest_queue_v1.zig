//! Bounded ready queue for the exact mixed-radix parent DAG. Publication is
//! canonical by task index, even when independent proofs finish out of order.
const std = @import("std");
const dag_mod = @import("block_v5_open_exact_forest_plan_v1.zig");

pub const Queue = struct {
    a: std.mem.Allocator,
    dag: *const dag_mod.Plan,
    remaining: []u8,
    consumer: []?u32,
    claimed: []bool,
    completed: []bool,
    leaf_ready: []bool,
    leaf_consumer: []?u32,
    leaves_closed: bool,
    submitted: usize = 0,
    max_active: usize,
    active: usize = 0,
    finished: usize = 0,
    failure: ?anyerror = null,
    mutex: std.Thread.Mutex = .{},
    changed: std.Thread.Condition = .{},

    pub fn init(a: std.mem.Allocator, dag: *const dag_mod.Plan, max_active: usize) !Queue {
        var initialized = try initStreaming(a, dag, leafCount(dag), max_active);
        errdefer initialized.deinit();
        for (0..initialized.leaf_ready.len) |i| try initialized.publishLeaf(@intCast(i));
        try initialized.closeLeaves();
        return initialized;
    }

    /// The DAG is known from the sealed exact count, but leaf files may arrive
    /// later. A leaf publication releases only its unique canonical consumer.
    pub fn initStreaming(a: std.mem.Allocator, dag: *const dag_mod.Plan, leaf_count: u32, max_active: usize) !Queue {
        if (max_active == 0 or max_active > 64) return error.InvalidMixedForestConcurrency;
        if (leaf_count == 0 or leaf_count != leafCount(dag)) return error.InvalidMixedForestDependency;
        const n = dag.tasks.len;
        const remaining = try a.alloc(u8, n);
        errdefer a.free(remaining);
        const consumer = try a.alloc(?u32, n);
        errdefer a.free(consumer);
        const claimed = try a.alloc(bool, n);
        errdefer a.free(claimed);
        const completed = try a.alloc(bool, n);
        errdefer a.free(completed);
        const leaf_ready = try a.alloc(bool, leaf_count);
        errdefer a.free(leaf_ready);
        const leaf_consumer = try a.alloc(?u32, leaf_count);
        errdefer a.free(leaf_consumer);
        @memset(remaining, 0);
        @memset(consumer, null);
        @memset(claimed, false);
        @memset(completed, false);
        @memset(leaf_ready, false);
        @memset(leaf_consumer, null);
        for (dag.tasks, 0..) |task, index| {
            if (task.index != index) return error.InvalidMixedForestTaskIndex;
            for (task.children[0..task.childCount()]) |child| switch (child.node) {
                .leaf => |leaf| {
                    if (leaf >= leaf_count or leaf_consumer[leaf] != null) return error.InvalidMixedForestDependency;
                    leaf_consumer[leaf] = @intCast(index);
                    remaining[index] += 1;
                },
                .parent => |prior| {
                    if (prior >= index or consumer[prior] != null)
                        return error.InvalidMixedForestDependency;
                    consumer[prior] = @intCast(index);
                    remaining[index] += 1;
                },
            };
        }
        for (dag.roots) |root| switch (root.node) {
            .leaf => |leaf| if (leaf >= leaf_count or leaf_consumer[leaf] != null) return error.InvalidMixedForestDependency,
            .parent => |prior| if (prior >= n or consumer[prior] != null) return error.InvalidMixedForestDependency,
        };
        return .{ .a = a, .dag = dag, .remaining = remaining, .consumer = consumer, .claimed = claimed, .completed = completed, .leaf_ready = leaf_ready, .leaf_consumer = leaf_consumer, .leaves_closed = false, .max_active = max_active };
    }

    fn leafCount(dag: *const dag_mod.Plan) u32 {
        var count: u32 = 0;
        for (dag.roots) |root| count = @max(count, @as(u32, @intCast(root.slots.endExclusive())));
        return count;
    }

    /// Caller writes immutable file/policy metadata before this release barrier.
    pub fn publishLeaf(self: *Queue, index: u32) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.failure) |err| return err;
        if (self.leaves_closed or index >= self.leaf_ready.len or self.leaf_ready[index]) return error.InvalidMixedForestLeafPublication;
        self.leaf_ready[index] = true;
        self.submitted += 1;
        if (self.leaf_consumer[index]) |next| {
            std.debug.assert(self.remaining[next] != 0);
            self.remaining[next] -= 1;
        }
        self.changed.broadcast();
    }

    pub fn closeLeaves(self: *Queue) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.leaves_closed = true;
        if (self.submitted != self.leaf_ready.len and self.failure == null) self.failure = error.IncompleteMixedForestLeaves;
        self.changed.broadcast();
        if (self.failure) |err| return err;
    }

    pub const Progress = struct { submitted: usize, completed: usize, active: usize, failure: ?anyerror };
    pub fn progress(self: *Queue) Progress {
        self.mutex.lock();
        defer self.mutex.unlock();
        return .{ .submitted = self.submitted, .completed = self.finished, .active = self.active, .failure = self.failure };
    }

    /// Waits only for already-released work. A coordinator must not wait for a
    /// fold whose leaf dependencies it has not yet published.
    pub fn waitForCompleted(self: *Queue, count: usize) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (count > self.dag.tasks.len) return error.InvalidMixedForestCompletion;
        while (self.finished < count and self.failure == null) self.changed.wait(&self.mutex);
        if (self.failure) |err| return err;
    }

    pub fn deinit(self: *Queue) void {
        std.debug.assert(self.active == 0);
        self.a.free(self.remaining);
        self.a.free(self.consumer);
        self.a.free(self.claimed);
        self.a.free(self.completed);
        self.a.free(self.leaf_ready);
        self.a.free(self.leaf_consumer);
        self.* = undefined;
    }

    pub fn take(self: *Queue) ?u32 {
        self.mutex.lock();
        defer self.mutex.unlock();
        while (true) {
            if (self.failure != null or self.finished == self.dag.tasks.len) return null;
            if (self.active < self.max_active) {
                if (self.takeReadyLocked()) |index| return index;
                if (self.active == 0 and self.leaves_closed) {
                    self.failure = error.StalledMixedForest;
                    self.changed.broadcast();
                    return null;
                }
            }
            self.changed.wait(&self.mutex);
        }
    }

    /// Non-blocking coordinator/diagnostic access; the same ownership protocol
    /// as take applies. Missing leaf dependencies are not a stalled DAG.
    pub fn tryTake(self: *Queue) ?u32 {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.takeReadyLocked();
    }
    fn takeReadyLocked(self: *Queue) ?u32 {
        if (self.failure != null or self.active >= self.max_active) return null;
        for (self.remaining, 0..) |count, index| {
            if (count == 0 and !self.claimed[index]) {
                self.claimed[index] = true;
                self.active += 1;
                return @intCast(index);
            }
        }
        return null;
    }

    /// Call only after the proof file is durable and its pin published at the
    /// task's canonical index. The mutex is the publication barrier.
    pub fn complete(self: *Queue, index: u32) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (index >= self.dag.tasks.len or !self.claimed[index] or self.completed[index])
            return error.InvalidMixedForestCompletion;
        self.completed[index] = true;
        self.finished += 1;
        self.active -= 1;
        if (self.consumer[index]) |next| {
            if (self.remaining[next] == 0) return error.InvalidMixedForestDependency;
            self.remaining[next] -= 1;
        }
        self.changed.broadcast();
    }

    pub fn cancel(self: *Queue, index: u32, err: anyerror) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        std.debug.assert(index < self.dag.tasks.len and self.claimed[index] and !self.completed[index]);
        self.active -= 1;
        if (self.failure == null) self.failure = err;
        self.changed.broadcast();
    }

    pub fn stop(self: *Queue, err: anyerror) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.failure == null) self.failure = err;
        self.changed.broadcast();
    }

    pub fn result(self: *Queue) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.failure) |err| return err;
        if (!self.leaves_closed or self.submitted != self.leaf_ready.len or self.finished != self.dag.tasks.len or self.active != 0)
            return error.IncompleteMixedForest;
    }
};

test "218-leaf open-v3 queue publishes exactly 73 dependency-ordered parents" {
    const a = std.testing.allocator;
    var dag = try dag_mod.plan(a, 218, 218);
    defer dag.deinit();
    var queue = try Queue.init(a, &dag, 4);
    defer queue.deinit();
    const Worker = struct {
        fn run(q: *Queue) void {
            while (q.take()) |index| {
                if ((index & 3) == 0) std.Thread.yield() catch {};
                q.complete(index) catch unreachable;
            }
        }
    };
    var threads: [4]std.Thread = undefined;
    for (&threads) |*thread| thread.* = try std.Thread.spawn(.{}, Worker.run, .{&queue});
    for (threads) |thread| thread.join();
    try queue.result();
    try std.testing.expectEqual(@as(usize, 73), queue.finished);
}

test "open-v3 queue stops new work after a failed proof" {
    const a = std.testing.allocator;
    var dag = try dag_mod.plan(a, 8, 8);
    defer dag.deinit();
    var queue = try Queue.init(a, &dag, 2);
    defer queue.deinit();
    const first = queue.take().?;
    const second = queue.take().?;
    queue.cancel(first, error.ProvingFailed);
    try std.testing.expectEqual(@as(?u32, null), queue.take());
    try queue.complete(second);
    try std.testing.expectError(error.ProvingFailed, queue.result());
}

test "open-v3 incremental queue folds an exact quartet before odd tail arrives" {
    const a = std.testing.allocator;
    var dag = try dag_mod.plan(a, 5, 5);
    defer dag.deinit();
    var queue = try Queue.initStreaming(a, &dag, 5, 2);
    defer queue.deinit();
    try std.testing.expectEqual(@as(?u32, null), queue.tryTake());
    for (0..3) |i| try queue.publishLeaf(@intCast(i));
    try std.testing.expectEqual(@as(?u32, null), queue.tryTake());
    try queue.publishLeaf(3);
    const quartet = queue.tryTake().?;
    try std.testing.expectEqual(@as(u32, 0), quartet);
    try queue.complete(quartet);
    try std.testing.expectEqual(@as(usize, 4), queue.progress().submitted);
    try std.testing.expectEqual(@as(usize, 1), queue.progress().completed);
    try std.testing.expectError(error.InvalidMixedForestLeafPublication, queue.publishLeaf(3));
    try queue.publishLeaf(4);
    try queue.closeLeaves();
    try queue.result();
    try std.testing.expectEqual(@as(usize, 2), dag.roots.len);
    try std.testing.expectEqual(@as(u64, 4), dag.roots[1].slots.first);
}

test "open-v3 incremental queue releases nested parents only after both completions" {
    const a = std.testing.allocator;
    var dag = try dag_mod.plan(a, 8, 8);
    defer dag.deinit();
    var queue = try Queue.initStreaming(a, &dag, 8, 2);
    defer queue.deinit();
    // Noncanonical arrival order is accepted; proof publication order stays
    // canonical, and exact sibling dependencies select every ready task.
    for ([_]u32{ 7, 2, 0, 6, 1, 3 }) |i| try queue.publishLeaf(i);
    const first = queue.tryTake().?;
    try std.testing.expectEqual(@as(u32, 0), first);
    try std.testing.expectEqual(@as(?u32, null), queue.tryTake());
    try queue.complete(first);
    try queue.publishLeaf(5);
    try queue.publishLeaf(4);
    const second = queue.tryTake().?;
    try std.testing.expectEqual(@as(u32, 1), second);
    try std.testing.expectEqual(@as(?u32, null), queue.tryTake());
    try queue.complete(second);
    const nested = queue.tryTake().?;
    try std.testing.expectEqual(@as(u32, 2), nested);
    try queue.complete(nested);
    try queue.closeLeaves();
    try queue.result();
}

test "open-v3 incremental queue rejects missing leaves and wakes waiting lanes" {
    const a = std.testing.allocator;
    var dag = try dag_mod.plan(a, 5, 5);
    defer dag.deinit();
    var queue = try Queue.initStreaming(a, &dag, 5, 1);
    defer queue.deinit();
    const Worker = struct {
        fn run(q: *Queue) void { std.debug.assert(q.take() == null); }
    };
    const thread = try std.Thread.spawn(.{}, Worker.run, .{&queue});
    try std.testing.expectError(error.IncompleteMixedForestLeaves, queue.closeLeaves());
    thread.join();
    try std.testing.expectError(error.IncompleteMixedForestLeaves, queue.result());
    try std.testing.expectEqual(@as(usize, 0), queue.progress().active);
}
