//! Shared column-parallel coset transform, moved from the full CPU evaluator.
//! One bounded joined wave; each worker owns complete, disjoint column buffers.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const work = engine.work_pool;
const M = core.fields.m31.M31;
const Domain = core.poly.circle.domain.CircleDomain;
const Twiddles = engine.poly.twiddles.TwiddleTree([]const M);
pub fn evaluate(buffers: [][]M, domain: Domain, tree: Twiddles, pool: ?*work.WorkPool) !void {
    var timing = @import("domain_timing.zig").Span.begin(.fft, domain.size(), buffers.len, if (pool != null) "leased" else if (work.cooperative.current() != null) "queue" else "serial");
    defer timing.end();
    return evaluateImpl(buffers, domain, tree, pool);
}
fn evaluateImpl(buffers: [][]M, domain: Domain, tree: Twiddles, pool: ?*work.WorkPool) !void {
    if (buffers.len == 0) return;
    const size = domain.size();
    for (buffers) |buffer| if (buffer.len != size) return error.InvalidDomainTransformShape;
    const cells = std.math.mul(usize, buffers.len, size) catch return error.InvalidDomainTransformShape;
    if (pool == null) if (work.cooperative.current()) |queue| return evaluateCooperative(buffers, domain, tree, queue);
    const workers = if (pool) |active| @min(active.workerCount(), @min(buffers.len, @max(1, cells / 8192))) else 1;
    if (workers <= 1) return engine.poly.circle.poly.evaluateBuffersWithTwiddles(buffers, domain, tree);
    var lease = try pool.?.acquire(try work.WorkerBudget.init(workers));
    defer lease.deinit();
    var jobs: [work.MAX_WORKERS]Job = undefined;
    for (jobs[0..workers], 0..) |*job, i| job.* = .{ .buffers = buffers[buffers.len * i / workers .. buffers.len * (i + 1) / workers], .target = domain, .twiddles = tree };
    {
        var group = std.Thread.WaitGroup{};
        defer {
            group.wait();
            lease.completeWave();
        }
        for (jobs[1..workers]) |*job| try lease.spawnWg(&group, Job.run, .{job});
        jobs[0].run();
    }
    for (jobs[0..workers]) |job| if (job.failure) |failure| return failure;
}
/// Column chunks published on the composition queue driven by the caller.
/// Every column is transformed by exactly the serial routine.
fn evaluateCooperative(buffers: [][]M, domain: Domain, tree: Twiddles, queue: *work.cooperative.Queue) !void {
    const chunks = @min(MAX_COOPERATIVE_CHUNKS, queue.preferredChunks(buffers.len));
    if (chunks <= 1) return engine.poly.circle.poly.evaluateBuffersWithTwiddles(buffers, domain, tree);
    const Split = struct {
        buffers: [][]M,
        chunks: usize,
        domain: Domain,
        tree: Twiddles,
        failures: [MAX_COOPERATIVE_CHUNKS]?anyerror = @splat(null),
        fn run(context: *anyopaque, index: usize) void {
            const self: *@This() = @ptrCast(@alignCast(context));
            const slice = self.buffers[self.buffers.len * index / self.chunks .. self.buffers.len * (index + 1) / self.chunks];
            engine.poly.circle.poly.evaluateBuffersWithTwiddles(slice, self.domain, self.tree) catch |err| {
                self.failures[index] = err;
            };
        }
    };
    var split = Split{ .buffers = buffers, .chunks = chunks, .domain = domain, .tree = tree };
    var batch = work.cooperative.Batch{ .context = &split, .run = Split.run, .count = chunks };
    queue.split(&batch);
    for (split.failures[0..chunks]) |failure| if (failure) |err| return err;
}
pub const MAX_COOPERATIVE_CHUNKS = 128;
const Job = struct {
    buffers: [][]M,
    target: Domain,
    twiddles: Twiddles,
    failure: ?anyerror = null,
    fn run(self: *Job) void {
        engine.poly.circle.poly.evaluateBuffersWithTwiddles(self.buffers, self.target, self.twiddles) catch |err| {
            self.failure = err;
        };
    }
};
