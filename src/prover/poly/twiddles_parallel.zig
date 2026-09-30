//! Exact bounded host preparation of the circle twiddle tower.
const std = @import("std");
const core = @import("stwo_core");
const pool_mod = @import("../work_pool.zig");
const serial = @import("twiddles.zig");
const M31 = core.fields.m31.M31;
const Coset = core.circle.Coset;

pub fn precompute(allocator: std.mem.Allocator, root: Coset) !serial.TwiddleTree([]M31) {
    if (root.size() < 1 << 17) return serial.precomputeM31(allocator, root);
    const pool = pool_mod.getGlobalPool() orelse return serial.precomputeM31(allocator, root);
    if (pool.workerCount() < 2) return serial.precomputeM31(allocator, root);
    var lease = pool.acquire(try pool_mod.WorkerBudget.init(pool.workerCount())) catch |err| switch (err) {
        error.WorkerBudgetUnavailable => return serial.precomputeM31(allocator, root),
        else => return err,
    };
    defer lease.deinit();
    const forward = try allocator.alloc(M31, root.size());
    errdefer allocator.free(forward);
    const inverse = try allocator.alloc(M31, root.size());
    errdefer allocator.free(inverse);
    var coset = root;
    var offset: usize = 0;
    for (0..root.logSize()) |_| {
        const len = coset.size() / 2;
        const values = forward[offset..][0..len];
        try wave(&lease, .generate, coset, values, &.{});
        try wave(&lease, .reverse, coset, values, &.{});
        offset += len;
        coset = coset.double();
    }
    std.debug.assert(offset + 1 == forward.len);
    forward[offset] = M31.one();
    try wave(&lease, .inverse, root, forward, inverse);
    return serial.TwiddleTree([]M31).init(root, forward, inverse);
}

const Mode = enum { generate, reverse, inverse };
const Job = struct {
    mode: Mode,
    coset: Coset,
    values: []M31,
    inverse: []M31,
    begin: usize,
    end: usize,
    failure: ?serial.TwiddleError = null,

    fn run(self: *Job) void {
        switch (self.mode) {
            .generate => {
                var point = self.coset.at(self.begin);
                for (self.values[self.begin..self.end]) |*value| {
                    value.* = point.x;
                    point = point.add(self.coset.step);
                }
            },
            .reverse => {
                const log: u32 = std.math.log2_int(usize, self.values.len);
                for (self.begin..self.end) |i| {
                    const j = core.utils.bitReverseIndex(i, log);
                    // Each unordered pair has a single owner, even across
                    // job boundaries; no two jobs access the same pair.
                    if (i < j) std.mem.swap(M31, &self.values[i], &self.values[j]);
                }
            },
            .inverse => core.fields.batchInverseChunked(M31, self.values[self.begin..self.end], self.inverse[self.begin..self.end], 4096) catch {
                self.failure = error.SingularTwiddle;
            },
        }
    }
};

fn wave(lease: *pool_mod.WorkLease, mode: Mode, coset: Coset, values: []M31, inverse: []M31) !void {
    var jobs: [pool_mod.MAX_WORKERS]Job = undefined;
    const count = if (values.len < 1 << 16) 1 else lease.workerCount();
    var wait = std.Thread.WaitGroup{};
    {
        defer {
            wait.wait();
            lease.completeWave();
        }
        for (jobs[0..count], 0..) |*job, i| {
            job.* = .{
                .mode = mode,
                .coset = coset,
                .values = values,
                .inverse = inverse,
                .begin = values.len * i / count,
                .end = values.len * (i + 1) / count,
            };
            if (i + 1 < count) try lease.spawnWg(&wait, Job.run, .{job}) else job.run();
        }
    }
    for (jobs[0..count]) |job| if (job.failure) |err| return err;
}
