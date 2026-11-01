//! Bounded allocation-free row work on an existing proof pool. No global pool,
//! no nested queue acquisition and no transcript access from helper callbacks.
const std = @import("std");
const pools = @import("../work_pool.zig");
pub const MAX_SHARDS = 16;
pub const MIN_ROWS_PER_SHARD = 4096;
fn run(count: usize, context: anytype) usize {
    const Context = @TypeOf(context.*);
    const Job = struct {
        context: *Context,
        index: usize,
        start: usize,
        end: usize,
        fn execute(self: *@This()) void {
            self.context.runRange(self.index, self.start, self.end);
        }
    };
    const pool = pools.currentScopedPool() orelse {
        context.runRange(0, 0, count);
        return 1;
    };
    if (pools.cooperative.current() != null) {
        context.runRange(0, 0, count);
        return 1;
    }
    const shards: usize = @min(MAX_SHARDS, @min(pool.availableWorkers(), count / MIN_ROWS_PER_SHARD));
    if (shards < 2) {
        context.runRange(0, 0, count);
        return 1;
    }
    const budget = pools.WorkerBudget.init(shards) catch unreachable;
    var lease = pool.acquire(budget) catch {
        context.runRange(0, 0, count);
        return 1;
    };
    defer lease.deinit();
    var jobs: [MAX_SHARDS]Job = undefined;
    const width = count / shards;
    const extra = count % shards;
    var begin: usize = 0;
    for (jobs[0..shards], 0..) |*job, index| {
        const end = begin + width + @intFromBool(index < extra);
        job.* = .{ .context = context, .index = index, .start = begin, .end = end };
        begin = end;
    }
    var group: std.Thread.WaitGroup = .{};
    for (jobs[1..shards]) |*job| lease.spawnWg(&group, Job.execute, .{job}) catch job.execute();
    jobs[0].execute();
    group.wait();
    lease.completeWave();
    return shards;
}
pub fn reduce(comptime S: type, count: usize, algorithm: anytype) [2]S {
    const Context = struct {
        algorithm: @TypeOf(algorithm),
        partial: [MAX_SHARDS][2]S = undefined,
        fn runRange(self: *@This(), index: usize, start: usize, end: usize) void {
            self.partial[index] = self.algorithm.sumRange(start, end);
        }
    };
    var context = Context{ .algorithm = algorithm };
    const shards = run(count, &context);
    var sum = [2]S{ S.zero(), S.zero() };
    for (context.partial[0..shards]) |part| {
        sum[0] = sum[0].add(part[0]);
        sum[1] = sum[1].add(part[1]);
    }
    return sum;
}
pub fn fill(count: usize, algorithm: anytype) void {
    const Context = struct {
        algorithm: @TypeOf(algorithm),
        fn runRange(self: *@This(), _: usize, start: usize, end: usize) void {
            self.algorithm.fillRange(start, end);
        }
    };
    var context = Context{ .algorithm = algorithm };
    _ = run(count, &context);
}
/// Maximum stack payload of the scheduler records and partial reductions.
/// Pool-owned helper stacks/submission slots already exist and are leased.
pub fn scratchBytes(comptime S: type) usize {
    return MAX_SHARDS * (4 * @sizeOf(usize) + 2 * @sizeOf(S)) + @sizeOf(pools.WorkLease) + @sizeOf(std.Thread.WaitGroup) + 512;
}
