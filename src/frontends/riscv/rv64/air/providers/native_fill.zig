//! One joined physical-row scheduler with private histograms. Adapter owns row
//! arithmetic and immutable inputs; no machine, AIR or transcript is defined.
const std = @import("std");
const core = @import("stwo_core");
const work = @import("stwo_prover_engine").work_pool;
pub const MIN_STACK_BYTES = if (@import("builtin").mode == .Debug) 1024 * 1024 else 256 * 1024;

/// Adapter: Context, BINS:[K]usize, rows(Context,start,end,[]u64) void, and
/// prepare(Context) void. Histograms are flattened in BINS order. Every write
/// starts only after all allocations and submissions succeed. Provisional row
/// output may be discarded on a post-join mass error; histograms publish last.
pub fn fill(comptime Adapter: type, a: std.mem.Allocator, context: Adapter.Context, n: usize, counts: [Adapter.BINS.len][]u64, masses: [Adapter.BINS.len]u64, pool: ?*work.WorkPool) !void {
    return fillImpl(Adapter, a, context, n, counts, masses, pool, null);
}
fn fillImpl(comptime Adapter: type, a: std.mem.Allocator, context: Adapter.Context, n: usize, counts: [Adapter.BINS.len][]u64, masses: [Adapter.BINS.len]u64, pool: ?*work.WorkPool, fail_after: ?usize) !void {
    if (n == 0 or n > std.math.maxInt(usize) / work.MAX_WORKERS) return error.InvalidNativeFillShape;
    comptime var histogram_size: usize = 0;
    inline for (Adapter.BINS) |bins| histogram_size += bins;
    inline for (Adapter.BINS, 0..) |bins, k| {
        if (counts[k].len != bins) return error.InvalidNativeFillShape;
        for (counts[k]) |value| if (value != 0) return error.InvalidNativeFillPhase;
        const first = @intFromPtr(counts[k].ptr);
        const last = std.math.add(usize, first, std.math.mul(usize, bins, @sizeOf(u64)) catch return error.InvalidNativeFillShape) catch return error.InvalidNativeFillShape;
        for (counts[0..k]) |prior| {
            const prior_first = @intFromPtr(prior.ptr);
            const prior_last = std.math.add(usize, prior_first, std.math.mul(usize, prior.len, @sizeOf(u64)) catch return error.InvalidNativeFillShape) catch return error.InvalidNativeFillShape;
            if (first < prior_last and prior_first < last) return error.InvalidNativeFillShape;
        }
    }
    if (pool) |p| if (p.stackSize() < MIN_STACK_BYTES) return error.InvalidNativeFillStack;
    const workers = if (pool) |p| @min(p.workerCount(), @max(1, n / 4096)) else 1;
    const length = std.math.mul(usize, workers, histogram_size) catch return error.InvalidNativeFillShape;
    const histograms = try a.alloc(u64, length);
    defer a.free(histograms);
    @memset(histograms, 0);
    const Job = struct {
        context: Adapter.Context,
        start: usize,
        end: usize,
        counts: []u64,
        gate: *std.Thread.ResetEvent,
        cancelled: *std.atomic.Value(bool),
        fn run(self: *@This()) void {
            self.gate.wait();
            if (!self.cancelled.load(.acquire)) Adapter.rows(self.context, self.start, self.end, self.counts);
        }
    };
    var gate: std.Thread.ResetEvent = .{};
    var cancelled: std.atomic.Value(bool) = .init(false);
    var jobs: [work.MAX_WORKERS]Job = undefined;
    const blocks = std.math.divCeil(usize, n, 16) catch return error.InvalidNativeFillShape;
    for (jobs[0..workers], 0..) |*job, i| job.* = .{
        .context = context,
        .start = @min(n, 16 * (blocks * i / workers)),
        .end = @min(n, 16 * (blocks * (i + 1) / workers)),
        .counts = histograms[i * histogram_size ..][0..histogram_size],
        .gate = &gate,
        .cancelled = &cancelled,
    };
    if (workers == 1) {
        Adapter.prepare(context);
        gate.set();
        jobs[0].run();
    } else {
        var lease = try pool.?.acquire(try work.WorkerBudget.init(workers));
        defer lease.deinit();
        var group = std.Thread.WaitGroup{};
        var released = false;
        defer {
            if (!released) {
                cancelled.store(true, .release);
                gate.set();
            }
            group.wait();
            lease.completeWave();
        }
        for (jobs[1..workers], 0..) |*job, submitted| {
            if (fail_after == submitted) return error.InjectedNativeFillSubmissionFailure;
            try lease.spawnWg(&group, Job.run, .{job});
        }
        Adapter.prepare(context);
        released = true;
        gate.set();
        jobs[0].run();
    }
    const merged = histograms[0..histogram_size];
    for (1..workers) |worker| for (merged, histograms[worker * histogram_size ..][0..histogram_size]) |*total, value| {
        total.* = std.math.add(u64, total.*, value) catch return error.InvalidNativeFillMass;
    };
    var begin: usize = 0;
    inline for (Adapter.BINS, 0..) |bins, k| {
        var mass: u64 = 0;
        for (merged[begin..][0..bins]) |value| {
            if (value >= core.fields.m31.Modulus) return error.InvalidNativeFillMass;
            mass = std.math.add(u64, mass, value) catch return error.InvalidNativeFillMass;
        }
        if (mass != masses[k]) return error.InvalidNativeFillMass;
        begin += bins;
    }
    begin = 0;
    inline for (Adapter.BINS, 0..) |bins, k| {
        @memcpy(counts[k], merged[begin..][0..bins]);
        begin += bins;
    }
}
pub const testing = if (@import("builtin").is_test) struct {
    pub fn failSubmission(comptime Adapter: type, a: std.mem.Allocator, context: Adapter.Context, n: usize, counts: [Adapter.BINS.len][]u64, masses: [Adapter.BINS.len]u64, pool: *work.WorkPool, after: usize) !void {
        return fillImpl(Adapter, a, context, n, counts, masses, pool, after);
    }
} else struct {};
