//! Joined, disjoint output ranges on the prover's existing bounded pool.
//! This schedules a kernel; it defines no machine, constraint or transcript.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const work = engine.work_pool;
const Column = engine.air.accumulation.ColumnAccumulator;
pub const Kernel = struct {
    context: *const anyopaque,
    run: *const fn (*const anyopaque, usize, usize, *Column) anyerror!void,
};
pub const MIN_STACK = if (@import("builtin").mode == .Debug) 1024 * 1024 else 256 * 1024;
pub fn evaluate(kernel: Kernel, size: usize, output: *Column, pool: ?*work.WorkPool) !void {
    var timing = @import("domain_timing.zig").Span.begin(.rows, size, output.random_coeff_powers.len, if (pool != null) "leased" else if (work.cooperative.current() != null) "queue" else "serial");
    defer timing.end();
    return evaluateImpl(kernel, size, output, pool, null);
}
fn evaluateImpl(kernel: Kernel, size: usize, output: *Column, pool: ?*work.WorkPool, fail_after_helpers: ?usize) !void {
    if (size == 0 or size % 16 != 0) return error.InvalidPackedRowExtent;
    if (pool == null) if (work.cooperative.current()) |queue| return evaluateCooperative(kernel, size, output, queue);
    if (pool) |active| if (active.stackSize() < MIN_STACK) return error.InvalidPackedRowWorkerStack;
    const workers = if (pool) |active| @min(active.workerCount(), @max(1, size / 4096)) else 1;
    if (workers == 1) return kernel.run(kernel.context, 0, size, output);
    const active = pool.?;
    var lease = try active.acquire(try work.WorkerBudget.init(workers));
    defer lease.deinit();
    var group = std.Thread.WaitGroup{};
    var joined = false;
    defer {
        if (!joined) group.wait();
        lease.completeWave();
    }
    // columns() supplies zeroed buckets. Existing contributions remain intact;
    // only private copies of the sequential fresh cursor are changed by jobs.
    output.next_fresh_index = null;
    var jobs: [work.MAX_WORKERS]Job = undefined;
    const blocks = size / 16;
    for (jobs[0..workers], 0..) |*job, i| job.* = .{
        .kernel = kernel,
        .start = 16 * (blocks * i / workers),
        .end = 16 * (blocks * (i + 1) / workers),
        .output = output.*,
    };
    for (jobs[1..workers], 0..) |*job, submitted| {
        if (fail_after_helpers == submitted) return error.InjectedPackedRowSubmissionFailure;
        try lease.spawnWg(&group, Job.run, .{job});
    }
    jobs[0].run();
    group.wait();
    joined = true;
    for (jobs[0..workers]) |job| if (job.failure) |err| return err;
}
/// Upper bound on cooperative row chunks; chunks stay >= 4096 rows.
pub const MAX_COOPERATIVE_CHUNKS = 128;
/// Same disjoint 16-row-aligned ranges as the leased path, published on the
/// composition queue driven by the calling thread. Chunks are finer than one
/// per worker so concurrently running components balance across threads.
fn evaluateCooperative(kernel: Kernel, size: usize, output: *Column, queue: *work.cooperative.Queue) !void {
    const chunks = @min(MAX_COOPERATIVE_CHUNKS, queue.preferredChunks(@max(1, size / 4096)));
    if (chunks == 1) return kernel.run(kernel.context, 0, size, output);
    output.next_fresh_index = null;
    const Split = struct {
        kernel: Kernel,
        blocks: usize,
        chunks: usize,
        output: *Column,
        failures: [MAX_COOPERATIVE_CHUNKS]?anyerror = @splat(null),
        fn run(context: *anyopaque, index: usize) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            var local = self.output.*;
            const start = 16 * (self.blocks * index / self.chunks);
            const end = 16 * (self.blocks * (index + 1) / self.chunks);
            self.kernel.run(self.kernel.context, start, end, &local) catch |err| {
                self.failures[index] = err;
            };
        }
    };
    var split = Split{ .kernel = kernel, .blocks = size / 16, .chunks = chunks, .output = output };
    var batch = work.cooperative.Batch{ .context = &split, .run = Split.run, .count = chunks };
    queue.split(&batch);
    for (split.failures[0..chunks]) |failure| if (failure) |err| return err;
}
const Job = struct {
    kernel: Kernel,
    start: usize,
    end: usize,
    output: Column,
    failure: ?anyerror = null,
    fn run(self: *Job) void {
        self.kernel.run(self.kernel.context, self.start, self.end, &self.output) catch |err| {
            self.failure = err;
        };
    }
};
pub const testing = if (@import("builtin").is_test) struct {
    pub fn failAfter(kernel: Kernel, size: usize, output: *Column, pool: *work.WorkPool, count: usize) !void {
        return evaluateImpl(kernel, size, output, pool, count);
    }
} else struct {};
