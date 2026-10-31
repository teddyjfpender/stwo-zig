//! Joined physical CPU projection with private U16/U8 histograms.
//! This schedules total, prevalidated row formatters, not an instruction machine.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const work = engine.work_pool;
pub const MIN_STACK_BYTES = if (@import("builtin").mode == .Debug) 1024 * 1024 else 256 * 1024;
const U16 = 65536;
const U8 = 256;
pub const HISTOGRAM_BYTES_PER_WORKER = (U16 + U8) * @sizeOf(u64);
pub const Kernel = struct {
    context: *const anyopaque,
    rows: *const fn (*const anyopaque, usize, usize, []u64, []u64) void,
};
pub fn fill(a: std.mem.Allocator, log: u32, kernel: Kernel, counts16: []u64, counts8: []u64, pool: ?*work.WorkPool) !void {
    return fillImpl(a, log, kernel, counts16, counts8, pool, null);
}
fn fillImpl(a: std.mem.Allocator, log: u32, kernel: Kernel, counts16: []u64, counts8: []u64, pool: ?*work.WorkPool, fail_after: ?usize) !void {
    if (log < 5 or log > 22 or counts16.len != U16 or counts8.len != U8) return error.InvalidNativeProjectionShape;
    for (counts16) |count| if (count != 0) return error.InvalidNativeProjectionPhase;
    for (counts8) |count| if (count != 0) return error.InvalidNativeProjectionPhase;
    if (pool) |active| if (active.stackSize() < MIN_STACK_BYTES) return error.InvalidNativeProjectionStack;
    const n: usize = @as(usize, 1) << @intCast(log);
    const workers = if (pool) |active| @min(active.workerCount(), @max(1, n / 4096)) else 1;
    const histograms = try a.alloc(u64, workers * (U16 + U8));
    defer a.free(histograms);
    @memset(histograms, 0);
    var gate: std.Thread.ResetEvent = .{};
    var cancelled: std.atomic.Value(bool) = .init(false);
    var jobs: [work.MAX_WORKERS]Job = undefined;
    const blocks = n / 16;
    for (jobs[0..workers], 0..) |*job, i| job.* = .{
        .kernel = kernel,
        .start = 16 * (blocks * i / workers),
        .end = 16 * (blocks * (i + 1) / workers),
        .counts16 = histograms[i * (U16 + U8) ..][0..U16],
        .counts8 = histograms[i * (U16 + U8) + U16 ..][0..U8],
        .gate = &gate,
        .cancelled = &cancelled,
    };
    if (workers == 1) {
        gate.set();
        jobs[0].run();
    } else {
        var lease = try pool.?.acquire(try work.WorkerBudget.init(workers));
        defer lease.deinit();
        var released = false;
        {
            var group = std.Thread.WaitGroup{};
            defer {
                if (!released) {
                    cancelled.store(true, .release);
                    gate.set();
                }
                group.wait();
                lease.completeWave();
            }
            for (jobs[1..workers], 0..) |*job, submitted| {
                if (fail_after == submitted) return error.InjectedNativeProjectionSubmissionFailure;
                try lease.spawnWg(&group, Job.run, .{job});
            }
            released = true;
            gate.set();
            jobs[0].run();
        }
    }
    // The caller's histograms remain unchanged until every range is joined and
    // checked. Its provisional wide owner may be discarded on any error.
    const merged = histograms[0 .. U16 + U8];
    for (1..workers) |worker| for (merged, histograms[worker * (U16 + U8) ..][0 .. U16 + U8]) |*total, count| {
        total.* = std.math.add(u64, total.*, count) catch return error.InvalidNativeProjectionMass;
    };
    var totals: [2]u64 = @splat(0);
    for (merged, 0..) |count, i| {
        if (count >= core.fields.m31.Modulus) return error.InvalidNativeProjectionMass;
        const kind: usize = @intFromBool(i >= U16);
        totals[kind] = std.math.add(u64, totals[kind], count) catch return error.InvalidNativeProjectionMass;
    }
    if (totals[0] != 3 * n or totals[1] != 3 * n) return error.InvalidNativeProjectionMass;
    @memcpy(counts16, merged[0..U16]);
    @memcpy(counts8, merged[U16..]);
}
const Job = struct {
    kernel: Kernel,
    start: usize,
    end: usize,
    counts16: []u64,
    counts8: []u64,
    gate: *std.Thread.ResetEvent,
    cancelled: *std.atomic.Value(bool),
    fn run(self: *Job) void {
        self.gate.wait();
        if (self.cancelled.load(.acquire)) return;
        self.kernel.rows(self.kernel.context, self.start, self.end, self.counts16, self.counts8);
    }
};
pub const testing = if (@import("builtin").is_test) struct {
    pub fn failSubmission(a: std.mem.Allocator, log: u32, kernel: Kernel, counts16: []u64, counts8: []u64, pool: *work.WorkPool, after: usize) !void {
        return fillImpl(a, log, kernel, counts16, counts8, pool, after);
    }
} else struct {};
