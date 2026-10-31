//! Concrete joined native BINARY projection. Facts and weights are prevalidated;
//! the same row authority formats scalar and parallel ranges. No worker owns
//! caller buffers or recorder state. All failures before the start gate leave
//! borrowed MAIN untouched; every submitted helper drains before returning.
const std = @import("std");
const builtin = @import("builtin");
const core = @import("stwo_core");
const work = @import("stwo_prover_engine").work_pool;
const S = @import("binary_source.zig");
const M = core.fields.m31.M31;
const HISTOGRAM = 65536;
pub const HISTOGRAM_BYTES_PER_WORKER = HISTOGRAM * @sizeOf(u64);
pub const MIN_STACK_BYTES = if (builtin.mode == .Debug) 1024 * 1024 else 256 * 1024;

pub const Fill = struct {
    facts: []const S.Fact,
    weights: ?[]const u32,
    log: u32,
    main: []M,
    metadata: []S.Metadata,
    pub fn run(self: Fill, a: std.mem.Allocator, counts: []u64, pool: ?*work.WorkPool) !void {
        return self.runInternal(a, counts, pool, null);
    }
    fn runInternal(self: Fill, a: std.mem.Allocator, counts: []u64, pool: ?*work.WorkPool, fail_after: ?usize) !void {
        const n: usize = @intCast((try S.massForLog(self.log)).fact_capacity);
        if (self.main.len != S.MAIN * n or self.metadata.len != n or counts.len != HISTOGRAM) return error.InvalidBinaryNativeFillShape;
        for (counts) |c| if (c != 0) return error.InvalidBinaryNativeFillPhase;
        if (pool) |p| if (p.stackSize() < MIN_STACK_BYTES) return error.InvalidBinaryNativeFillStack;
        const workers = if (pool) |p| @min(p.workerCount(), @max(1, n / 4096)) else 1;
        if (workers == 1) {
            self.rows(0, n, counts);
            return;
        }
        const histograms = try a.alloc(u64, workers * HISTOGRAM);
        defer a.free(histograms);
        @memset(histograms, 0);
        var gate: std.Thread.ResetEvent = .{};
        var cancelled: std.atomic.Value(bool) = .init(false);
        var jobs: [work.MAX_WORKERS]Job = undefined;
        const blocks = n / 16;
        for (jobs[0..workers], 0..) |*job, i| job.* = .{
            .fill = self,
            .start = 16 * (blocks * i / workers),
            .end = 16 * (blocks * (i + 1) / workers),
            .counts = histograms[i * HISTOGRAM ..][0..HISTOGRAM],
            .gate = &gate,
            .cancelled = &cancelled,
        };
        var lease = try pool.?.acquire(try work.WorkerBudget.init(workers));
        defer lease.deinit();
        {
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
                if (fail_after == submitted) return error.InjectedBinaryNativeFillSubmissionFailure;
                try lease.spawnWg(&group, Job.run, .{job});
            }
            // Logical metadata writes are bit-reversed across workers. Establish
            // its private pages once before scatter. MAIN ranges are contiguous
            // physical partitions and do not need a whole-domain prefill.
            prepareMetadataPages(std.mem.sliceAsBytes(self.metadata));
            released = true;
            gate.set();
            jobs[0].run();
        }
        const merged = histograms[0..HISTOGRAM];
        for (1..workers) |worker| for (merged, histograms[worker * HISTOGRAM ..][0..HISTOGRAM]) |*total, c| {
            total.* = std.math.add(u64, total.*, c) catch return error.InvalidBinaryNativeFillMass;
        };
        var total: u64 = 0;
        for (merged) |c| {
            if (c >= core.fields.m31.Modulus) return error.InvalidBinaryNativeFillMass;
            total = std.math.add(u64, total, c) catch return error.InvalidBinaryNativeFillMass;
        }
        if (total != 8 * n) return error.InvalidBinaryNativeFillMass;
        @memcpy(counts, merged);
    }
    fn rows(self: Fill, start: usize, end: usize, counts: []u64) void {
        const n = @as(usize, 1) << @intCast(self.log);
        for (start..end) |position| {
            const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(position, self.log), self.log);
            S.NativeSupport.write(self.facts, self.weights, self.main, self.metadata, counts, n, logical, position);
        }
    }
};
const Job = struct {
    fill: Fill,
    start: usize,
    end: usize,
    counts: []u64,
    gate: *std.Thread.ResetEvent,
    cancelled: *std.atomic.Value(bool),
    fn run(self: *Job) void {
        self.gate.wait();
        if (self.cancelled.load(.acquire)) return;
        self.fill.rows(self.start, self.end, self.counts);
    }
};
fn prepareMetadataPages(bytes: []u8) void {
    // This is page establishment, NOT byte/field initialization. Every used
    // metadata field is subsequently assigned by rows; padding is never read.
    const page = std.heap.pageSize();
    if (bytes.len < page) return;
    const first: *volatile u8 = &bytes[0];
    first.* = 0;
    var at = page - @intFromPtr(bytes.ptr) % page;
    while (at < bytes.len) : (at += page) {
        const p: *volatile u8 = &bytes[at];
        p.* = 0;
    }
}
pub const testing = if (builtin.is_test) struct {
    pub fn failSubmission(fill: Fill, a: std.mem.Allocator, counts: []u64, pool: *work.WorkPool, after: usize) !void {
        return fill.runInternal(a, counts, pool, after);
    }
} else struct {};
