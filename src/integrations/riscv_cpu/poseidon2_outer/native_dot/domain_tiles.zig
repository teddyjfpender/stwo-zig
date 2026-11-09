//! Bounded disjoint ranges on the caller's existing proof pool. Row kernels
//! use packed alignment; independent column jobs use unit alignment. Helpers
//! never discover a second pool or recursively wait for a saturated lease.
const std = @import("std");
const E = @import("stwo_prover_engine");
pub fn run(comptime Kernel: type, kernel: *const Kernel, count: usize, width: usize) !void {
    if (width == 0 or count % width != 0) return error.NativeDotPackedRange;
    if (count == 0) return;
    const pool = E.work_pool.getGlobalPool() orelse return kernel.runRange(0, count);
    const workers = @min(pool.availableWorkers(), count / width);
    if (workers < 2) return kernel.runRange(0, count);
    var lease = pool.acquire(try E.work_pool.WorkerBudget.init(workers)) catch |err| switch (err) {
        error.WorkerBudgetUnavailable => return kernel.runRange(0, count),
        else => return err,
    };
    defer lease.deinit();
    const Job = struct {
        context: *const Kernel,
        first: usize,
        end: usize,
        failure: ?anyerror = null,
        fn execute(self: *@This()) void {
            self.context.runRange(self.first, self.end) catch |err| {
                self.failure = err;
            };
        }
    };
    var jobs: [E.work_pool.MAX_WORKERS]Job = undefined;
    const packs = count / width;
    for (jobs[0..workers], 0..) |*job, i| job.* = .{ .context = kernel, .first = packs * i / workers * width, .end = packs * (i + 1) / workers * width };
    var group = std.Thread.WaitGroup{};
    var joined = false;
    defer {
        if (!joined) group.wait();
        lease.completeWave();
    }
    for (jobs[1..workers]) |*job| try lease.spawnWg(&group, Job.execute, .{job});
    jobs[0].execute();
    group.wait();
    joined = true;
    for (jobs[0..workers]) |job| if (job.failure) |err| return err;
}
