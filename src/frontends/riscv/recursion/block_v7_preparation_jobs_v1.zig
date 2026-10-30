//! Bounded independent preparation jobs. Results are written into caller-owned
//! ordinal slots; namespace allocation and final joining never run in workers.
const std = @import("std");
const Pool = @import("stwo_prover_engine").work_pool;
pub fn run(a: std.mem.Allocator, count: usize, parallelism: usize, context: anytype, comptime prepare: fn (@TypeOf(context), usize) anyerror!void) !void {
    if (parallelism == 0 or parallelism > Pool.MAX_WORKERS) return error.InvalidParallelPreparation;
    if (count == 0) return;
    var lease: ?Pool.WorkLease = null;
    if (parallelism > 1 and count > 1) if (Pool.currentScopedPool()) |pool| {
        const workers = @min(@min(parallelism, count), pool.workerCount());
        if (workers > 1) lease = pool.acquire(try Pool.WorkerBudget.init(workers)) catch |err| switch (err) {
            error.WorkerBudgetUnavailable => null,
            else => return err,
        };
    };
    defer if (lease) |*held| held.deinit();
    const width = if (lease) |*held| held.workerCount() else 1;
    const Job = struct {
        context: @TypeOf(context),
        ordinal: usize,
        failure: ?anyerror = null,
        fn execute(self: *@This()) void {
            prepare(self.context, self.ordinal) catch |err| {
                self.failure = err;
            };
        }
    };
    const jobs = try a.alloc(Job, width);
    defer a.free(jobs);
    var first: usize = 0;
    while (first < count) {
        const current = jobs[0..@min(width, count - first)];
        var wait = std.Thread.WaitGroup{};
        {
            // Includes partial submission failure: no borrowed context can
            // escape while any submitted worker still executes.
            defer {
                wait.wait();
                if (lease) |*held| held.completeWave();
            }
            for (current, 0..) |*job, i| {
                job.* = .{ .context = context, .ordinal = first + i };
                if (i + 1 < current.len) try lease.?.spawnWg(&wait, Job.execute, .{job}) else job.execute();
            }
        }
        for (current) |job| if (job.failure) |failure| return failure;
        first += current.len;
    }
}
