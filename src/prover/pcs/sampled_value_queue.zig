//! Bounded sampled-coefficient wave over the proof's existing scoped pool.
//! One tree owns planning/basis scratch at a time. Its disjoint native-width
//! column batches are helped by all admitted threads through the existing
//! cooperative queue; no tree worker waits for another pool acquisition.
const std = @import("std");
const pools = @import("../work_pool.zig");
pub fn run(pool: *pools.WorkPool, count: usize, first: usize, context: *anyopaque, execute: *const fn (*anyopaque, usize) void) void {
    std.debug.assert(count != 0 and first < count);
    const Source = struct {
        count: usize,
        first: usize,
        next: usize = 0,
        completed: usize = 0,
        active: bool = false,
        context: *anyopaque,
        execute: *const fn (*anyopaque, usize) void,
        fn take(raw: *anyopaque) ?usize {
            const self: *@This() = @ptrCast(@alignCast(raw));
            if (self.active or self.next == self.count) return null;
            const ordinal = self.next;
            self.next += 1;
            self.active = true;
            if (ordinal == 0) return self.first;
            const index = ordinal - 1;
            return index + @intFromBool(index >= self.first);
        }
        fn runItem(raw: *anyopaque, index: usize) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.execute(self.context, index);
        }
        fn finish(raw: *anyopaque, _: usize) void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.active = false;
            self.completed += 1;
        }
        fn exhausted(raw: *anyopaque) bool {
            const self: *@This() = @ptrCast(@alignCast(raw));
            return self.completed == self.count;
        }
    };
    var lease: ?pools.WorkLease = null;
    defer if (lease) |*held| held.deinit();
    var threads: usize = 1;
    // Existing callers may already own the pool. A bounded one-thread wave
    // remains live without creating a global pool or awaiting a nested lease.
    const available = pool.availableWorkers();
    if (available > 1 and pools.cooperative.current() == null) {
        const budget = pools.WorkerBudget.init(available) catch unreachable;
        if (pool.acquire(budget)) |held| {
            lease = held;
            threads = available;
        } else |_| {}
    }
    var queue = pools.cooperative.Queue.init(threads);
    var source = Source{ .count = count, .first = first, .context = context, .execute = execute };
    const top = pools.cooperative.TopLevel{ .context = &source, .take = Source.take, .run = Source.runItem, .finish = Source.finish, .exhausted = Source.exhausted };
    const Drive = struct {
        queue: *pools.cooperative.Queue,
        top: pools.cooperative.TopLevel,
        fn run(self: *@This()) void {
            self.queue.drive(self.top);
        }
    };
    var drive = Drive{ .queue = &queue, .top = top };
    var group: std.Thread.WaitGroup = .{};
    if (lease) |*held| for (1..threads) |_| held.spawnWg(&group, Drive.run, .{&drive}) catch break;
    drive.run();
    group.wait();
    if (lease) |*held| held.completeWave();
    if (std.process.hasEnvVarConstant("STWO_ZIG_PROFILE_SAMPLED_QUEUE")) std.debug.print("SAMPLED_QUEUE threads={d} trees={d} batches={d} tasks={d}\n", .{ threads, count, queue.batches_published, queue.batch_tasks_run });
}
