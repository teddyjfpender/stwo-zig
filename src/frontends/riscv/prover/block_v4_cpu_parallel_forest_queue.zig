//! Bounded ready queue for the exact-count parent DAG. The queue schedules
//! work only; staged proofs and independently pinned keys remain authoritative.
const std = @import("std");
const dag_mod = @import("block_v4_cpu_parallel_forest_plan.zig");

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
        if (max_active == 0 or max_active > 64) return error.InvalidParallelForestConcurrency;
        const len = dag.tasks.len;
        const remaining = try a.alloc(u8, len);
        errdefer a.free(remaining);
        const consumer = try a.alloc(?u32, len);
        errdefer a.free(consumer);
        const claimed = try a.alloc(bool, len);
        errdefer a.free(claimed);
        const completed = try a.alloc(bool, len);
        errdefer a.free(completed);
        @memset(remaining, 0);
        @memset(consumer, null);
        @memset(claimed, false);
        @memset(completed, false);
        for (dag.tasks, 0..) |task, index| {
            if (task.index != index) return error.InvalidParallelForestTaskIndex;
            for ([_]dag_mod.Ref{ task.left, task.right }) |child| switch (child) {
                .leaf => {},
                .parent => |parent_index| {
                    if (parent_index >= index or consumer[parent_index] != null)
                        return error.InvalidParallelForestDependency;
                    consumer[parent_index] = @intCast(index);
                    remaining[index] += 1;
                },
            };
        }
        return .{
            .a = a,
            .dag = dag,
            .remaining = remaining,
            .consumer = consumer,
            .claimed = claimed,
            .completed = completed,
            .max_active = max_active,
        };
    }

    pub fn deinit(self: *Queue) void {
        std.debug.assert(self.active == 0);
        self.a.free(self.remaining);
        self.a.free(self.consumer);
        self.a.free(self.claimed);
        self.a.free(self.completed);
        self.* = undefined;
    }

    /// Claims the lowest-index ready parent. Returns null after all parents
    /// finish or any lane cancels. A waiting lane wakes on child completion.
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
                    self.failure = error.StalledParallelForest;
                    self.changed.broadcast();
                    return null;
                }
            }
            self.changed.wait(&self.mutex);
        }
    }

    /// Publish only after the parent proof file is durable and its pin is
    /// written at the canonical task index. A parent has at most one consumer.
    pub fn complete(self: *Queue, index: u32) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (index >= self.dag.tasks.len or !self.claimed[index] or self.completed[index])
            return error.InvalidParallelForestCompletion;
        self.completed[index] = true;
        self.finished += 1;
        self.active -= 1;
        if (self.consumer[index]) |next| {
            if (self.remaining[next] == 0) return error.InvalidParallelForestDependency;
            self.remaining[next] -= 1;
        }
        self.changed.broadcast();
    }

    /// A failed lane still releases its claim. All lanes then stop claiming;
    /// the orchestrator joins them before destroying this queue or files.
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
            return error.IncompleteParallelForest;
    }
};

test "218-parent queue releases only ready tasks with bounded active work" {
    const a = std.testing.allocator;
    var dag = try dag_mod.plan(a, 218);
    defer dag.deinit();
    var queue = try Queue.init(a, &dag, 2);
    defer queue.deinit();
    var staged = try a.alloc(bool, dag.tasks.len);
    defer a.free(staged);
    @memset(staged, false);
    while (queue.finished < dag.tasks.len) {
        const index = queue.take().?;
        const task = dag.tasks[index];
        for ([_]dag_mod.Ref{ task.left, task.right }) |child| switch (child) {
            .leaf => {},
            .parent => |dependency| try std.testing.expect(staged[dependency]),
        };
        staged[index] = true;
        try queue.complete(index);
    }
    try queue.result();
    try std.testing.expectEqual(@as(?u32, null), queue.take());
    try std.testing.expectEqual(@as(usize, 213), queue.finished);
}

test "ready queue bounds claims and preserves canonical slots after reversed completion" {
    const a = std.testing.allocator;
    var dag = try dag_mod.plan(a, 6);
    defer dag.deinit();
    var queue = try Queue.init(a, &dag, 2);
    defer queue.deinit();
    const first = queue.take().?;
    const second = queue.take().?;
    try std.testing.expectEqual(@as(u32, 0), first);
    try std.testing.expectEqual(@as(u32, 1), second);
    try std.testing.expectEqual(@as(usize, 2), queue.active);
    try queue.complete(second);
    try std.testing.expectEqual(@as(u32, 3), queue.take().?);
    try queue.complete(first);
    try std.testing.expectEqual(@as(u32, 2), queue.take().?);
    try queue.complete(3);
    try queue.complete(2);
    try queue.result();
    try std.testing.expectEqual(@as(?u32, null), queue.take());
}

test "four lanes complete the 218-parent DAG without a padded task" {
    const a = std.testing.allocator;
    var dag = try dag_mod.plan(a, 218);
    defer dag.deinit();
    var queue = try Queue.init(a, &dag, 4);
    defer queue.deinit();
    const Worker = struct {
        fn run(q: *Queue) void {
            while (q.take()) |index| {
                // Reverse small task batches to exercise out-of-order release.
                if ((index & 3) == 0) std.Thread.yield() catch {};
                q.complete(index) catch unreachable;
            }
        }
    };
    var threads: [4]std.Thread = undefined;
    for (&threads) |*thread| thread.* = try std.Thread.spawn(.{}, Worker.run, .{&queue});
    for (threads) |thread| thread.join();
    try queue.result();
    try std.testing.expectEqual(@as(usize, 213), queue.finished);
}

test "lane failure cancels new claims and drains active work" {
    const a = std.testing.allocator;
    var dag = try dag_mod.plan(a, 6);
    defer dag.deinit();
    var queue = try Queue.init(a, &dag, 2);
    defer queue.deinit();
    const first = queue.take().?;
    const second = queue.take().?;
    queue.cancel(first, error.ProvingFailed);
    try std.testing.expectEqual(@as(?u32, null), queue.take());
    try queue.complete(second);
    try std.testing.expectError(error.ProvingFailed, queue.result());
    try std.testing.expectEqual(@as(usize, 0), queue.active);
}
