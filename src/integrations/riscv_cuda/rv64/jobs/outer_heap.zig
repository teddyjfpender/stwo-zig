//! Work heap of one OuterNodeJob enqueue: a first-fit, address-ordered,
//! coalescing free list over ONE region taken from the worker's work window
//! (api.Enqueue.alloc). The worker's window is a stream-ordered bump
//! allocator that reclaims only LIFO frees; the node body (TC, RC, PCS)
//! frees out of order, so on real nodes most frees were never reclaimed and
//! the arena peak was the sum of all allocations. Every consumer of this
//! heap enqueues on the job's single exec stream, so a freed range may be
//! reused by the next allocation immediately (same ordering argument as the
//! worker's own LIFO reuse). Pure host bookkeeping: no CUDA calls.
//!
//! Deterministic: the same allocation/free sequence from the same base
//! yields the same addresses (graph re-record / direct re-run safe).
const std = @import("std");
const api = @import("api.zig");
const Plan = @import("outer_plan.zig");
const K = @import("outer_kernels.zig");

pub const granule: usize = 64;

pub const Heap = struct {
    const Span = struct { at: usize, words: usize };
    base: usize = 0,
    words: usize = 0,
    /// Free spans, sorted by address, never adjacent (coalesced).
    free_spans: [max_spans]Span = undefined,
    n_free: usize = 0,
    live: usize = 0,
    peak: usize = 0,
    /// Highest end offset ever allocated: the region size this schedule
    /// actually needs (>= peak; the difference is fragmentation).
    high: usize = 0,
    allocations: u64 = 0,
    /// Largest single request (words) in the guarded phases (the margin to
    /// Plan.max_indexable_words) and in the unguarded ones (see `guarded`).
    max_alloc: usize = 0,
    max_unguarded_alloc: usize = 0,
    /// Per-phase live peak and high-water (see `Phase`), for measurement.
    phase: Phase = .held,
    phase_peak: [n_phases]usize = @splat(0),
    phase_high: [n_phases]usize = @splat(0),
    const max_spans = 512;

    pub const Phase = @import("outer_kernels.zig").Phase;
    pub const n_phases = @typeInfo(Phase).@"enum".fields.len;
    pub fn enter(self: *Heap, phase: Phase) void {
        self.phase = phase;
        const i = @intFromEnum(phase);
        self.phase_peak[i] = @max(self.phase_peak[i], self.live);
    }

    pub fn init(region: api.DeviceBuffer) Heap {
        var h = Heap{ .base = @intFromPtr(region.ptr), .words = std.mem.alignBackward(usize, region.words, granule) };
        h.free_spans[0] = .{ .at = 0, .words = h.words };
        h.n_free = 1;
        return h;
    }

    pub fn alloc(self: *Heap, requested: usize) !api.DeviceBuffer {
        if (guarded(self.phase)) {
            try Plan.requireIndexable(&.{requested});
            self.max_alloc = @max(self.max_alloc, requested);
        } else self.max_unguarded_alloc = @max(self.max_unguarded_alloc, requested);
        return self.place(requested);
    }

    /// Phases whose transients feed the trace-commit kernels (B2N,
    /// stwo_lde_n2b_columns_on, the tree kernel) the int32 guard exists for:
    /// held buffers, FIXED, MAIN, INTER, incl. the full-LDE scratch. Not
    /// guarded: composition (RC role arenas/buckets/accumulator) and the
    /// native PCS, both legacy deployed code that allocates single buffers
    /// of 2^31 words or more on folds [M outer-fold-review rg1: a
    /// guard-everything build refused 26235156 folds 4 and 9 in the
    /// composition phase; the same allocations were byte-identical to the D2
    /// golden on every earlier gate]. The composition commit's chunk/banks
    /// are checked up front (outer_job.zig holdBuffers).
    pub fn guarded(phase: Phase) bool {
        return switch (phase) {
            .held, .fixed, .main, .inter => true,
            .composition, .pcs => false,
        };
    }

    fn place(self: *Heap, requested: usize) !api.DeviceBuffer {
        if (requested == 0) return error.InvalidAllocation;
        const words = std.mem.alignForward(usize, requested, granule);
        for (self.free_spans[0..self.n_free], 0..) |*s, i| {
            if (s.words < words) continue;
            const at = s.at;
            s.at += words;
            s.words -= words;
            if (s.words == 0) self.remove(i);
            self.live += words;
            self.peak = @max(self.peak, self.live);
            self.high = @max(self.high, at + words);
            const ph = @intFromEnum(self.phase);
            self.phase_peak[ph] = @max(self.phase_peak[ph], self.live);
            self.phase_high[ph] = @max(self.phase_high[ph], at + words);
            self.allocations += 1;
            return .{ .ptr = @ptrFromInt(self.base + 4 * at), .words = requested };
        }
        return error.JobWorkExceedsArena;
    }

    /// Ignores buffers outside the heap (e.g. worker-owned slab fields).
    pub fn free(self: *Heap, b: api.DeviceBuffer) void {
        const address = @intFromPtr(b.ptr);
        if (address < self.base or (address - self.base) % 4 != 0) return;
        const at = (address - self.base) / 4;
        const words = std.mem.alignForward(usize, b.words, granule);
        if (at + words > self.words) return;
        var i: usize = 0;
        while (i < self.n_free and self.free_spans[i].at < at) i += 1;
        // Double free / overlap: refuse silently rather than corrupt the list.
        if (i > 0 and self.free_spans[i - 1].at + self.free_spans[i - 1].words > at) return;
        if (i < self.n_free and at + words > self.free_spans[i].at) return;
        const merge_prev = i > 0 and self.free_spans[i - 1].at + self.free_spans[i - 1].words == at;
        const merge_next = i < self.n_free and at + words == self.free_spans[i].at;
        if (merge_prev and merge_next) {
            self.free_spans[i - 1].words += words + self.free_spans[i].words;
            self.remove(i);
        } else if (merge_prev) {
            self.free_spans[i - 1].words += words;
        } else if (merge_next) {
            self.free_spans[i].at = at;
            self.free_spans[i].words += words;
        } else {
            if (self.n_free == max_spans) return; // leak the span; never corrupt
            std.mem.copyBackwards(Span, self.free_spans[i + 1 .. self.n_free + 1], self.free_spans[i..self.n_free]);
            self.free_spans[i] = .{ .at = at, .words = words };
            self.n_free += 1;
        }
        self.live -|= words;
    }

    fn remove(self: *Heap, i: usize) void {
        std.mem.copyForwards(Span, self.free_spans[i .. self.n_free - 1], self.free_spans[i + 1 .. self.n_free]);
        self.n_free -= 1;
    }
};

/// What native_pcs.PcsJob.enqueueOpening needs from an enqueue (`anytype`):
/// alloc/free through the heap, the job's channel and exec context.
pub const PcsEnqueue = struct {
    e: *api.Enqueue,
    heap: *Heap,
    channel: *api.DeviceChannel,
    pub fn init(e: *api.Enqueue, heap: *Heap) PcsEnqueue {
        return .{ .e = e, .heap = heap, .channel = e.channel };
    }
    pub fn alloc(self: *PcsEnqueue, words: usize) !api.DeviceBuffer {
        return self.heap.alloc(words);
    }
    pub fn free(self: *PcsEnqueue, b: api.DeviceBuffer) void {
        self.heap.free(b);
    }
    pub fn ctx(self: *PcsEnqueue) *anyopaque {
        return self.e.ctx();
    }
    pub fn stream(self: *PcsEnqueue) *anyopaque {
        return self.e.stream();
    }
};

/// Execution adapters share the same heap and transcript owner.
pub const DeviceEnqueue = struct {
    e: *api.Enqueue,
    heap: *Heap,
    pub const vtable = K.Device.VTable{ .alloc = alloc, .free = free, .mix = mix, .draw = draw };
    fn of(raw: *anyopaque) *DeviceEnqueue {
        return @ptrCast(@alignCast(raw));
    }
    pub fn phase(raw: *anyopaque, which: K.Phase) void {
        of(raw).heap.enter(which);
    }
    fn alloc(raw: *anyopaque, words: usize) anyerror!K.Buffer {
        const b = try of(raw).heap.alloc(words);
        return .{ .ptr = b.ptr, .words = b.words };
    }
    fn free(raw: *anyopaque, b: K.Buffer) void {
        of(raw).heap.free(.{ .ptr = b.ptr, .words = b.words });
    }
    fn mix(raw: *anyopaque, words: [*]const u32, count: u32, field: bool) anyerror!void {
        const b = api.DeviceBuffer{ .ptr = @constCast(words), .words = count };
        const ch = of(raw).e.channel;
        return if (field) ch.mixFelts(b) else ch.mixWords(b);
    }
    fn draw(raw: *anyopaque, felts: u32, out: [*]u32) anyerror!void {
        return of(raw).e.channel.drawSecureFelts(felts, .{ .ptr = out, .words = @as(usize, felts) * 8 });
    }
};

test "heap reuses out-of-order frees and coalesces" {
    var backing: [64 * 16]u32 align(256) = undefined;
    var h = Heap.init(.{ .ptr = &backing, .words = backing.len });
    const a = try h.alloc(64);
    const b = try h.alloc(128);
    const c = try h.alloc(64);
    h.free(a);
    h.free(c);
    try std.testing.expectEqual(@as(usize, 128), h.live);
    const d = try h.alloc(64);
    try std.testing.expectEqual(@intFromPtr(a.ptr), @intFromPtr(d.ptr));
    h.free(b);
    h.free(d);
    try std.testing.expectEqual(@as(usize, 0), h.live);
    try std.testing.expectEqual(@as(usize, 1), h.n_free);
    const all = try h.alloc(64 * 16);
    try std.testing.expectEqual(@intFromPtr(&backing), @intFromPtr(all.ptr));
    try std.testing.expectError(error.JobWorkExceedsArena, h.alloc(1));
    try std.testing.expectEqual(@as(usize, 64 * 16), h.peak);
    try std.testing.expectEqual(@as(usize, 64 * 16), h.high);
}

test "heap attributes peaks to phases" {
    var backing: [64 * 16]u32 align(256) = undefined;
    var h = Heap.init(.{ .ptr = &backing, .words = backing.len });
    const held = try h.alloc(64);
    h.enter(.main);
    const t = try h.alloc(64 * 4);
    h.free(t);
    h.enter(.pcs);
    const u = try h.alloc(64 * 2);
    h.free(u);
    h.free(held);
    try std.testing.expectEqual(@as(usize, 64), h.phase_peak[@intFromEnum(Heap.Phase.held)]);
    try std.testing.expectEqual(@as(usize, 64 * 5), h.phase_peak[@intFromEnum(Heap.Phase.main)]);
    try std.testing.expectEqual(@as(usize, 64 * 3), h.phase_peak[@intFromEnum(Heap.Phase.pcs)]);
    try std.testing.expectEqual(@as(usize, 64 * 3), h.phase_high[@intFromEnum(Heap.Phase.pcs)]);
}

test "heap is deterministic and ignores foreign frees" {
    var backing: [64 * 8]u32 align(256) = undefined;
    var other: [64]u32 align(256) = undefined;
    var x = Heap.init(.{ .ptr = &backing, .words = backing.len });
    var y = Heap.init(.{ .ptr = &backing, .words = backing.len });
    for ([_]*Heap{ &x, &y }) |h| {
        const p = try h.alloc(100);
        _ = try h.alloc(10);
        h.free(p);
        h.free(.{ .ptr = &other, .words = 64 });
        h.free(p); // double free ignored
    }
    try std.testing.expectEqual(x.n_free, y.n_free);
    try std.testing.expectEqual((try x.alloc(64)).ptr, (try y.alloc(64)).ptr);
}

test "heap refuses any single allocation of 2^31 words or more (int32 index guard) and records the largest" {
    // Host bookkeeping only: the region is never dereferenced.
    var h = Heap.init(.{ .ptr = @ptrFromInt(1 << 20), .words = 1 << 34 });
    const limit: usize = @intCast(Plan.max_indexable_words);
    try std.testing.expectError(error.OuterBufferExceedsInt32Index, h.alloc(limit));
    try std.testing.expectError(error.OuterBufferExceedsInt32Index, h.alloc(limit + 4096));
    try std.testing.expectEqual(@as(usize, 0), h.live);
    _ = try h.alloc(limit - 1);
    _ = try h.alloc(1000);
    try std.testing.expectEqual(limit - 1, h.max_alloc);
    // Composition / PCS phases are recorded, not refused.
    h.enter(.composition);
    _ = try h.alloc(limit + 64);
    h.enter(.pcs);
    _ = try h.alloc(limit);
    try std.testing.expectEqual(limit + 64, h.max_unguarded_alloc);
    try std.testing.expectEqual(limit - 1, h.max_alloc);
    h.enter(.inter);
    try std.testing.expectError(error.OuterBufferExceedsInt32Index, h.alloc(limit));
}
