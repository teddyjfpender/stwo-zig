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
    if (buffers.len == 0) return;
    const size = domain.size();
    for (buffers) |buffer| if (buffer.len != size) return error.InvalidDomainTransformShape;
    const cells = std.math.mul(usize, buffers.len, size) catch return error.InvalidDomainTransformShape;
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
