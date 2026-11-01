//! Cooperative composition work queue.
//!
//! One queue is driven by every thread of a composition wave. It owns two
//! kinds of work:
//!
//! * top-level items supplied by a `TopLevel` source (whole AIR components,
//!   admitted under the source's own memory bound), and
//! * split batches: disjoint index ranges (row chunks, column chunks)
//!   published by a top-level item while it runs.
//!
//! Split work always takes priority over admitting a new top-level item, so
//! the number of simultaneously expanded components stays bounded by both the
//! source's byte budget and the work actually available. A thread that
//! publishes a batch claims its own indices first, then helps other batches,
//! and sleeps only when every remaining index of its batch is already running
//! elsewhere. Batch tasks are leaves: they never publish further batches, so
//! helping cannot nest more than one level and cannot deadlock.
//!
//! Scheduling never changes values: every batch index writes a disjoint
//! output range that the publishing component would otherwise write
//! serially.

const std = @import("std");

/// One published split. Lives on the publisher's stack until `split` returns.
pub const Batch = struct {
    context: *anyopaque,
    run: *const fn (context: *anyopaque, index: usize) void,
    count: usize,
    claimed: usize = 0,
    completed: usize = 0,
    /// Admission sequence of the publishing item; lower runs first.
    priority: u64 = std.math.maxInt(u64),
    next: ?*Batch = null,
};

/// Source of top-level work. Every callback except `run` executes with the
/// queue mutex held, so implementations need no further synchronisation for
/// state they only touch from these callbacks.
pub const TopLevel = struct {
    context: *anyopaque,
    /// Returns an admissible item, or null when none can start now.
    take: *const fn (context: *anyopaque) ?usize,
    /// Executes an item without the queue mutex.
    run: *const fn (context: *anyopaque, item: usize) void,
    /// Releases an item's admission after `run` returned.
    finish: *const fn (context: *anyopaque, item: usize) void,
    /// True once no item will ever be admitted again and none is running.
    exhausted: *const fn (context: *anyopaque) bool,
};

threadlocal var current_queue: ?*Queue = null;
/// Admission sequence of the item the calling thread is executing.
threadlocal var current_priority: u64 = std.math.maxInt(u64);

/// The queue driven by the calling thread, if any. Shared row/column
/// providers consult this when they are not handed an explicit pool.
pub fn current() ?*Queue {
    return current_queue;
}

pub const Queue = struct {
    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    head: ?*Batch = null,
    /// Number of threads driving this queue; used only to size splits.
    threads: usize,
    /// Telemetry (monotonic, read after the wave joins).
    batches_published: usize = 0,
    batch_tasks_run: usize = 0,
    helped_tasks: usize = 0,
    items_admitted: u64 = 0,
    /// When set, time spent blocked on the condition is summed into
    /// `idle_ns` (under the mutex), so utilisation is
    /// `1 - idle_ns / (threads * wave wall time)`.
    measure: bool = false,
    idle_ns: u64 = 0,

    pub fn init(threads: usize) Queue {
        return .{ .threads = @max(threads, 1) };
    }

    /// Preferred number of chunks for a split over `available` independent
    /// units: enough to balance over every driving thread without making
    /// chunks tiny.
    pub fn preferredChunks(self: *const Queue, available: usize) usize {
        return @max(1, @min(available, 4 * self.threads));
    }

    /// Runs every index of `batch` on this queue and returns once all of
    /// them have completed. Must be called by a thread that drives this
    /// queue (`current() == self`).
    pub fn split(self: *Queue, batch: *Batch) void {
        if (batch.count == 0) return;
        if (batch.count == 1) {
            batch.run(batch.context, 0);
            return;
        }
        self.mutex.lock();
        defer self.mutex.unlock();
        batch.claimed = 0;
        batch.completed = 0;
        batch.priority = current_priority;
        batch.next = self.head;
        self.head = batch;
        self.batches_published += 1;
        self.cond.broadcast();
        while (true) {
            if (batch.claimed < batch.count) {
                const index = batch.claimed;
                batch.claimed += 1;
                if (batch.claimed == batch.count) self.unlink(batch);
                self.runClaimed(batch, index);
                continue;
            }
            if (batch.completed == batch.count) return;
            // Help only equally or more urgent work, so the publisher is
            // never held up by a less urgent item's chunk.
            if (self.claimAny(batch.priority)) |claim| {
                self.helped_tasks += 1;
                self.runClaimed(claim.batch, claim.index);
                continue;
            }
            self.wait();
        }
    }

    /// Worker loop: drains batches first, then admits top-level items, and
    /// returns once the source is exhausted and no batch remains.
    pub fn drive(self: *Queue, top: TopLevel) void {
        const previous = current_queue;
        current_queue = self;
        defer current_queue = previous;
        self.mutex.lock();
        defer self.mutex.unlock();
        while (true) {
            if (self.claimAny(std.math.maxInt(u64))) |claim| {
                self.runClaimed(claim.batch, claim.index);
                continue;
            }
            if (top.take(top.context)) |item| {
                const sequence = self.items_admitted;
                self.items_admitted += 1;
                self.mutex.unlock();
                const previous_priority = current_priority;
                current_priority = sequence;
                top.run(top.context, item);
                current_priority = previous_priority;
                self.mutex.lock();
                top.finish(top.context, item);
                self.cond.broadcast();
                continue;
            }
            if (self.head == null and top.exhausted(top.context)) {
                self.cond.broadcast();
                return;
            }
            self.wait();
        }
    }

    fn now(self: *const Queue) ?std.time.Instant {
        if (!self.measure) return null;
        return std.time.Instant.now() catch null;
    }

    /// Blocks on the condition; called with the mutex held.
    fn wait(self: *Queue) void {
        const started = self.now();
        self.cond.wait(&self.mutex);
        const begin = started orelse return;
        const end = std.time.Instant.now() catch return;
        self.idle_ns += end.since(begin);
    }

    const Claim = struct { batch: *Batch, index: usize };

    /// Claims the next index of the most urgent batch whose priority is at
    /// most `limit`. Earlier-admitted (larger, critical-path) items win.
    fn claimAny(self: *Queue, limit: u64) ?Claim {
        var best: ?*Batch = null;
        var node = self.head;
        while (node) |candidate| : (node = candidate.next) {
            if (candidate.priority > limit) continue;
            if (best == null or candidate.priority < best.?.priority) best = candidate;
        }
        const batch = best orelse return null;
        const index = batch.claimed;
        batch.claimed += 1;
        if (batch.claimed == batch.count) self.unlink(batch);
        return .{ .batch = batch, .index = index };
    }

    fn unlink(self: *Queue, batch: *Batch) void {
        var link = &self.head;
        while (link.*) |node| : (link = &node.next) {
            if (node == batch) {
                link.* = node.next;
                node.next = null;
                return;
            }
        }
    }

    /// Called and returns with the mutex held.
    fn runClaimed(self: *Queue, batch: *Batch, index: usize) void {
        self.mutex.unlock();
        batch.run(batch.context, index);
        self.mutex.lock();
        self.batch_tasks_run += 1;
        batch.completed += 1;
        if (batch.completed == batch.count) self.cond.broadcast();
    }
};

const testing = std.testing;

test "cooperative queue: split runs every index once on one thread" {
    var queue = Queue.init(1);
    const Ctx = struct {
        hits: [37]u32 = @splat(0),
        fn run(context: *anyopaque, index: usize) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            self.hits[index] += 1;
        }
    };
    var ctx = Ctx{};
    const Top = struct {
        queue: *Queue,
        ctx: *Ctx,
        taken: bool = false,
        done: bool = false,
        fn take(c: *anyopaque) ?usize {
            const self: *@This() = @ptrCast(@alignCast(c));
            if (self.taken) return null;
            self.taken = true;
            return 0;
        }
        fn run(c: *anyopaque, _: usize) void {
            const self: *@This() = @ptrCast(@alignCast(c));
            var batch = Batch{ .context = self.ctx, .run = Ctx.run, .count = self.ctx.hits.len };
            current().?.split(&batch);
        }
        fn finish(c: *anyopaque, _: usize) void {
            const self: *@This() = @ptrCast(@alignCast(c));
            self.done = true;
        }
        fn exhausted(c: *anyopaque) bool {
            const self: *@This() = @ptrCast(@alignCast(c));
            return self.done;
        }
    };
    var top = Top{ .queue = &queue, .ctx = &ctx };
    queue.drive(.{ .context = &top, .take = Top.take, .run = Top.run, .finish = Top.finish, .exhausted = Top.exhausted });
    for (ctx.hits) |hit| try testing.expectEqual(@as(u32, 1), hit);
    try testing.expect(current() == null);
}

test "cooperative queue: many threads drain nested splits from many items" {
    const items = 24;
    const per_item = 53;
    const Ctx = struct {
        hits: [items][per_item]std.atomic.Value(u32) = undefined,
        fn run(context: *anyopaque, index: usize) void {
            const row: *[per_item]std.atomic.Value(u32) = @ptrCast(@alignCast(context));
            _ = row[index].fetchAdd(1, .monotonic);
        }
    };
    var ctx = Ctx{};
    for (&ctx.hits) |*row| for (row) |*hit| {
        hit.* = .init(0);
    };
    const Top = struct {
        ctx: *Ctx,
        next: usize = 0,
        active: usize = 0,
        fn take(c: *anyopaque) ?usize {
            const self: *@This() = @ptrCast(@alignCast(c));
            // At most two items admitted at once.
            if (self.next >= items or self.active >= 2) return null;
            self.active += 1;
            self.next += 1;
            return self.next - 1;
        }
        fn run(c: *anyopaque, item: usize) void {
            const self: *@This() = @ptrCast(@alignCast(c));
            var batch = Batch{ .context = &self.ctx.hits[item], .run = Ctx.run, .count = per_item };
            current().?.split(&batch);
        }
        fn finish(c: *anyopaque, _: usize) void {
            const self: *@This() = @ptrCast(@alignCast(c));
            self.active -= 1;
        }
        fn exhausted(c: *anyopaque) bool {
            const self: *@This() = @ptrCast(@alignCast(c));
            return self.next >= items and self.active == 0;
        }
    };
    var top = Top{ .ctx = &ctx };
    var queue = Queue.init(4);
    const source = TopLevel{ .context = &top, .take = Top.take, .run = Top.run, .finish = Top.finish, .exhausted = Top.exhausted };
    var threads: [3]std.Thread = undefined;
    for (&threads) |*thread| thread.* = try std.Thread.spawn(.{}, Queue.drive, .{ &queue, source });
    queue.drive(source);
    for (threads) |thread| thread.join();
    for (ctx.hits) |row| for (row) |hit| try testing.expectEqual(@as(u32, 1), hit.load(.monotonic));
    try testing.expectEqual(@as(usize, items * per_item), queue.batch_tasks_run);
}
