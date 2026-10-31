//! Concrete joined native LS projection. Inputs have passed Native.validate;
//! the same row authority formats scalar and parallel ranges. No worker owns
//! caller buffers or recorder state. All failures before the start gate leave
//! borrowed MAIN untouched; every submitted helper drains before returning.
const std = @import("std");
const builtin = @import("builtin");
const core = @import("stwo_core");
const work = @import("stwo_prover_engine").work_pool;
const Native = @import("native.zig");
const S = @import("source.zig");
const L = @import("layout.zig");
const V = @import("../load_store_v1/mod.zig").layout;
const M = core.fields.m31.M31;
const U16 = 65536;
const U8 = 256;
const SELECTION = 131072;
const HISTOGRAM = U16 + U8 + SELECTION;
pub const HISTOGRAM_BYTES_PER_WORKER = HISTOGRAM * @sizeOf(u64);
pub const MIN_STACK_BYTES = if (builtin.mode == .Debug) 1024 * 1024 else 256 * 1024;

pub const Fill = struct {
    events: []const Native.Event,
    log: u32,
    main: []M,
    metadata: []S.Metadata,
    pub fn run(self: Fill, a: std.mem.Allocator, c16: []u64, c8: []u64, selection: []u64, pool: ?*work.WorkPool) !void {
        return self.runInternal(a, c16, c8, selection, pool, null);
    }
    fn runInternal(self: Fill, a: std.mem.Allocator, c16: []u64, c8: []u64, selection: []u64, pool: ?*work.WorkPool, fail_after: ?usize) !void {
        const n = try S.sizeForLog(self.log);
        if (self.main.len != L.MAIN * n or self.metadata.len != n or c16.len != U16 or c8.len != U8 or selection.len != SELECTION) return error.InvalidLsNativeFillShape;
        for (c16) |c| if (c != 0) return error.InvalidLsNativeFillPhase;
        for (c8) |c| if (c != 0) return error.InvalidLsNativeFillPhase;
        for (selection) |c| if (c != 0) return error.InvalidLsNativeFillPhase;
        if (pool) |p| if (p.stackSize() < MIN_STACK_BYTES) return error.InvalidLsNativeFillStack;
        const workers = if (pool) |p| @min(p.workerCount(), @max(1, n / 4096)) else 1;
        if (workers == 1) {
            self.rows(0, n, c16, c8, selection);
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
                if (fail_after == submitted) return error.InjectedLsNativeFillSubmissionFailure;
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
            total.* = std.math.add(u64, total.*, c) catch return error.InvalidLsNativeFillMass;
        };
        var totals: [3]u64 = @splat(0);
        for (merged, 0..) |c, i| {
            if (c >= core.fields.m31.Modulus) return error.InvalidLsNativeFillMass;
            const family: usize = if (i < U16) 0 else if (i < U16 + U8) 1 else 2;
            totals[family] = std.math.add(u64, totals[family], c) catch return error.InvalidLsNativeFillMass;
        }
        if (totals[0] != L.U16.len * n or totals[1] != L.U8.len * n or totals[2] != n) return error.InvalidLsNativeFillMass;
        @memcpy(c16, merged[0..U16]);
        @memcpy(c8, merged[U16..][0..U8]);
        @memcpy(selection, merged[U16 + U8 ..]);
    }
    fn rows(self: Fill, start: usize, end: usize, c16: []u64, c8: []u64, selection: []u64) void {
        const n = @as(usize, 1) << @intCast(self.log);
        for (start..end) |position| {
            const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(position, self.log), self.log);
            const values = Native.row(if (logical < self.events.len) self.events[logical] else null);
            for (values, 0..) |v, c| self.main[c * n + position] = v;
            const meta = &self.metadata[logical];
            for (L.U16, 0..) |c, i| {
                meta.range16[i] = @intCast(values[c].v);
                c16[values[c].v] += 1;
            }
            for (L.U8, 0..) |c, i| {
                meta.range8[i] = @intCast(values[c].v);
                c8[values[c].v] += 1;
            }
            var parity: u32 = 0;
            for ([_]usize{ 1, 3, 5, 7 }) |i| parity += values[V.offsets + i].v;
            const index = 2 * values[V.selected_limb].v + parity;
            meta.selection_words = .{ @truncate(index), @truncate(index >> 16) };
            selection[index] += 1;
            meta.opcode = @intCast(values[V.opcode].v);
            meta.flags = @intCast(values[0].v | (values[22].v << 1) | (values[23].v << 2));
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
        self.fill.rows(self.start, self.end, self.counts[0..U16], self.counts[U16..][0..U8], self.counts[U16 + U8 ..]);
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
    pub fn failSubmission(fill: Fill, a: std.mem.Allocator, c16: []u64, c8: []u64, selection: []u64, pool: *work.WorkPool, after: usize) !void {
        return fill.runInternal(a, c16, c8, selection, pool, after);
    }
} else struct {};
