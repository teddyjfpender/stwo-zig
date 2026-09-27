//! Bounded ready queue for the exact mixed-radix parent DAG. Publication is
//! canonical by task index, even when independent proofs finish out of order.
const std = @import("std");
const dag_mod = @import("block_v4_cpu_mixed_forest_plan.zig");

pub const Queue = struct {
    a: std.mem.Allocator,
    dag: *const dag_mod.Plan,
    remaining: []u8,
    consumer: []?u32,
    claimed: []bool,
    completed: []bool,
    max_active: usize,
    active: usize = 0,
    finished: usize = 0,
    failure: ?anyerror = null,
    mutex: std.Thread.Mutex = .{},
    changed: std.Thread.Condition = .{},

    pub fn init(a: std.mem.Allocator, dag: *const dag_mod.Plan, max_active: usize) !Queue {
        if (max_active == 0 or max_active > 64) return error.InvalidMixedForestConcurrency;
        const n = dag.tasks.len;
        const remaining = try a.alloc(u8, n);
        errdefer a.free(remaining);
        const consumer = try a.alloc(?u32, n);
        errdefer a.free(consumer);
        const claimed = try a.alloc(bool, n);
        errdefer a.free(claimed);
        const completed = try a.alloc(bool, n);
        errdefer a.free(completed);
        @memset(remaining, 0);
        @memset(consumer, null);
        @memset(claimed, false);
        @memset(completed, false);
        for (dag.tasks, 0..) |task, index| {
            if (task.index != index) return error.InvalidMixedForestTaskIndex;
            for (task.children[0..task.childCount()]) |child| switch (child.node) {
                .leaf => {},
                .parent => |prior| {
                    if (prior >= index or consumer[prior] != null)
                        return error.InvalidMixedForestDependency;
                    consumer[prior] = @intCast(index);
                    remaining[index] += 1;
                },
            };
        }
        return .{ .a = a, .dag = dag, .remaining = remaining, .consumer = consumer, .claimed = claimed, .completed = completed, .max_active = max_active };
    }

    pub fn deinit(self: *Queue) void {
        std.debug.assert(self.active == 0);
        self.a.free(self.remaining);
        self.a.free(self.consumer);
        self.a.free(self.claimed);
        self.a.free(self.completed);
        self.* = undefined;
    }

    pub fn take(self: *Queue) ?u32 {
        self.mutex.lock();
        defer self.mutex.unlock();
        while (true) {
            if (self.failure != null or self.finished == self.dag.tasks.len) return null;
            if (self.active < self.max_active) {
                for (self.remaining, 0..) |count, index| {
                    if (count == 0 and !self.claimed[index]) {
                        self.claimed[index] = true;
                        self.active += 1;
                        return @intCast(index);
                    }
                }
                if (self.active == 0) {
                    self.failure = error.StalledMixedForest;
                    self.changed.broadcast();
                    return null;
                }
            }
            self.changed.wait(&self.mutex);
        }
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
        if (self.finished != self.dag.tasks.len or self.active != 0)
            return error.IncompleteMixedForest;
    }
};

test "218-leaf mixed queue publishes exactly 73 dependency-ordered parents" {
    const a = std.testing.allocator;
    var dag = try dag_mod.plan(a, 218);
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

test "mixed queue stops new work after a failed proof" {
    const a = std.testing.allocator;
    var dag = try dag_mod.plan(a, 8);
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
