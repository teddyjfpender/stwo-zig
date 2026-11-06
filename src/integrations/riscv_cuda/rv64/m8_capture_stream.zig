//! M8 GPU-native capture hand-off (rv64-m8-gpu-native.md §1, §2 H1; driver).
//!
//! Capture/emulation is the only CPU compute allowed on the request path and
//! it must overlap proving. This is the bridge from the capture thread to the
//! device:
//!
//!   capture thread                     driver / GPUs
//!   ring.acquire(seg) -> fill pinned   (backpressure only: the ring is full)
//!   sink.chunk(TraceChunk)  --------->  native.chunk(ctx, chunk, device(seg))
//!                                       (native enqueues the h2d + witness)
//!   sink.sealed_segment(seg, rows) -->  releases Stage1(seg)'s host gate: the
//!                                       GPU's batch enqueues it now, while
//!                                       capture continues with seg+1
//!   sink.done(n)                       n must equal the planned segments,
//!                                       else every unreleased gate fails
//!   ...                                 exec stream, after Stage1(seg):
//!                                       host fn ring.releaseSegment(seg)
//!
//! The capture thread never waits on the GPU; Stage1 never waits on the
//! whole block. Ring slots return through a host function enqueued after the
//! segment's Stage1 (pure host bookkeeping, no CUDA call).
const std = @import("std");
const G = @import("jobs/gpu_native.zig");
const W = @import("jobs/worker.zig");
const O = @import("jobs/ops.zig");
const api = @import("jobs/api.zig");

/// Pinned chunk buffers shared by capture and the device uploads.
pub const Ring = struct {
    a: std.mem.Allocator,
    wait: *const O.Wait,
    buffers: [][]u32,
    owner: []u32,
    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    free_count: usize,
    closed: bool = false,
    acquires: u64 = 0,
    blocked_ns: u64 = 0,

    const free_owner = std.math.maxInt(u32);

    /// Install time: `count` pinned buffers of `words` each.
    pub fn init(a: std.mem.Allocator, wait: *const O.Wait, count: usize, words: usize) !*Ring {
        const self = try a.create(Ring);
        errdefer a.destroy(self);
        const buffers = try a.alloc([]u32, count);
        errdefer a.free(buffers);
        const owner = try a.alloc(u32, count);
        errdefer a.free(owner);
        var made: usize = 0;
        errdefer for (buffers[0..made]) |b| {
            _ = wait.host_free(b.ptr);
        };
        // lint:install-begin — the ring is pinned once per service.
        for (buffers) |*b| {
            var host: ?*anyopaque = null;
            try O.check(wait.host_alloc(words * 4, &host));
            b.* = @as([*]u32, @ptrCast(@alignCast(host orelse return error.PinnedAllocationFailed)))[0..words];
            made += 1;
        }
        // lint:install-end
        @memset(owner, free_owner);
        self.* = .{ .a = a, .wait = wait, .buffers = buffers, .owner = owner, .free_count = count };
        return self;
    }
    pub fn deinit(self: *Ring) void {
        for (self.buffers) |b| _ = self.wait.host_free(b.ptr);
        self.a.free(self.buffers);
        self.a.free(self.owner);
        self.a.destroy(self);
    }
    /// Capture thread: a free pinned buffer for `segment` (blocks only while
    /// every buffer belongs to a segment whose Stage1 has not run yet).
    pub fn acquire(self: *Ring, segment: u32) ![]u32 {
        if (segment == free_owner) return error.InvalidCaptureSegment;
        self.mutex.lock();
        defer self.mutex.unlock();
        var timer = std.time.Timer.start() catch unreachable;
        while (self.free_count == 0 and !self.closed) self.cond.wait(&self.mutex);
        self.blocked_ns += timer.read();
        if (self.closed) return error.CaptureRingClosed;
        for (self.owner, 0..) |*o, i| if (o.* == free_owner) {
            o.* = segment;
            self.free_count -= 1;
            self.acquires += 1;
            return self.buffers[i];
        };
        unreachable;
    }
    /// Host-fn safe (no CUDA): every buffer of `segment` returns to the ring.
    pub fn releaseSegment(self: *Ring, segment: u32) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.owner) |*o| if (o.* == segment) {
            o.* = free_owner;
            self.free_count += 1;
        };
        self.cond.broadcast();
    }
    /// Release everything (request end or abort) and wake a blocked capture.
    pub fn reset(self: *Ring) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        @memset(self.owner, free_owner);
        self.free_count = self.owner.len;
        self.cond.broadcast();
    }
    pub fn close(self: *Ring) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.closed = true;
        self.cond.broadcast();
    }
};

pub const Stream = struct {
    a: std.mem.Allocator,
    native: G.NativeFactory,
    ring: ?*Ring,
    /// Per segment (capacity fixed at install).
    gates: []W.BatchDep,
    releases: []Release,
    sealed_rows: []u64,
    expected: u32 = 0,
    ctx: ?*const G.RequestContext = null,
    attached: std.Thread.ResetEvent = .{},
    failure: std.atomic.Value(bool) = .init(false),
    chunks: std.atomic.Value(u64) = .init(0),
    chunk_words: std.atomic.Value(u64) = .init(0),
    attach_wait_ns: u64 = 0,

    pub const Release = struct { stream: *Stream, segment: u32 };

    pub fn create(a: std.mem.Allocator, native: G.NativeFactory, ring: ?*Ring, capacity: u32) !*Stream {
        const self = try a.create(Stream);
        errdefer a.destroy(self);
        const gates = try a.alloc(W.BatchDep, capacity);
        errdefer a.free(gates);
        const releases = try a.alloc(Release, capacity);
        errdefer a.free(releases);
        const rows = try a.alloc(u64, capacity);
        self.* = .{ .a = a, .native = native, .ring = ring, .gates = gates, .releases = releases, .sealed_rows = rows };
        for (releases, 0..) |*r, i| r.* = .{ .stream = self, .segment = @intCast(i) };
        return self;
    }
    pub fn destroy(self: *Stream) void {
        self.a.free(self.gates);
        self.a.free(self.releases);
        self.a.free(self.sealed_rows);
        self.a.destroy(self);
    }

    /// Request start (driver thread, before the batches run).
    pub fn begin(self: *Stream, segments: u32) !void {
        if (segments > self.gates.len) return error.GpuNativeCaptureCapacity;
        self.expected = segments;
        for (self.gates[0..segments]) |*g| g.* = .{};
        @memset(self.sealed_rows, 0);
        // `attached` is NOT reset here: a capture thread may already wait on
        // it (ResetEvent.reset with a waiter loses the wakeup). `detach` at
        // the previous request's end reset it while nobody could wait.
        self.failure.store(false, .release);
        self.chunks.store(0, .monotonic);
        self.chunk_words.store(0, .monotonic);
        self.attach_wait_ns = 0;
        if (self.ring) |r| r.reset();
    }
    /// The request context exists: chunks may flow to the native factory.
    pub fn attach(self: *Stream, ctx: *const G.RequestContext) void {
        self.ctx = ctx;
        self.attached.set();
    }
    /// Request end (driver): a capture for the NEXT request blocks until
    /// that request attaches, so it never touches this request's gates.
    pub fn detach(self: *Stream) void {
        self.attached.reset();
        self.ctx = null;
    }
    fn awaitAttach(self: *Stream) void {
        if (self.attached.isSet()) return;
        var t = std.time.Timer.start() catch unreachable;
        self.attached.wait();
        self.attach_wait_ns += t.read();
    }
    pub fn gate(self: *Stream, segment: u32) *W.BatchDep {
        return &self.gates[segment];
    }
    /// Host step after Stage1(segment): return its ring buffers.
    pub fn releaseFn(self: *Stream, segment: u32) ?api.HostFn {
        if (self.ring == null) return null;
        return .{ .call = releaseCall, .user = &self.releases[segment] };
    }
    fn releaseCall(user: ?*anyopaque) callconv(.c) void {
        const r: *Release = @ptrCast(@alignCast(user.?));
        if (r.stream.ring) |ring| ring.releaseSegment(r.segment);
    }
    /// Capture failed: every unreleased Stage1 fails (its batch skips the body).
    pub fn fail(self: *Stream) void {
        self.failure.store(true, .release);
        for (self.gates[0..self.expected]) |*g| if (!g.recorded.isSet()) g.signal(null, true);
        self.attached.set();
        if (self.ring) |r| r.close();
    }

    pub fn sink(self: *Stream) G.CaptureSink {
        return .{ .ctx = self, .chunk = chunk, .sealed_segment = sealed, .done = done };
    }
    fn of(raw: *anyopaque) *Stream {
        return @ptrCast(@alignCast(raw));
    }
    fn chunk(raw: *anyopaque, c: G.TraceChunk) anyerror!void {
        const self = of(raw);
        self.awaitAttach();
        if (c.segment >= self.expected) return error.GpuNativeCaptureSegmentOutOfRange;
        if (self.failure.load(.acquire)) return error.GpuNativeCaptureFailed;
        const ctx = self.ctx.?;
        const device = if (ctx.segment_device.len > c.segment) ctx.segment_device[c.segment] else 0;
        _ = self.chunks.fetchAdd(1, .monotonic);
        _ = self.chunk_words.fetchAdd(c.words.len, .monotonic);
        return self.native.vtable.chunk(self.native.ctx, ctx, c, device);
    }
    fn sealed(raw: *anyopaque, segment: u32, rows: u64) anyerror!void {
        const self = of(raw);
        self.awaitAttach();
        if (segment >= self.expected) return error.GpuNativeCaptureSegmentOutOfRange;
        if (self.gates[segment].recorded.isSet()) return error.GpuNativeCaptureSegmentSealedTwice;
        self.sealed_rows[segment] = rows;
        self.gates[segment].signal(null, false);
    }
    fn done(raw: *anyopaque, segments: u32) anyerror!void {
        const self = of(raw);
        self.awaitAttach();
        if (segments != self.expected) {
            self.fail();
            return error.GpuNativeCaptureSegmentCountChanged;
        }
        for (self.gates[0..segments]) |*g| if (!g.recorded.isSet()) {
            self.fail();
            return error.GpuNativeCaptureSegmentNotSealed;
        };
    }
};

const testing = std.testing;
const F = @import("jobs/fake.zig");

test "capture stream: sealed segments release Stage1 gates; a short capture fails the rest" {
    const Native = struct {
        seen: u32 = 0,
        fn chunkFn(raw: *anyopaque, _: *const G.RequestContext, c: G.TraceChunk, _: u32) anyerror!void {
            const self: *@This() = @ptrCast(@alignCast(raw));
            self.seen += c.rows;
        }
    };
    var n = Native{};
    const vt = G.NativeFactory.VTable{ .warm = undefined, .class_of = undefined, .stage1 = undefined, .stage2 = undefined, .seal = undefined, .chunk = Native.chunkFn };
    const ring = try Ring.init(testing.allocator, &F.ops.wait, 2, 16);
    defer ring.deinit();
    const s = try Stream.create(testing.allocator, .{ .ctx = &n, .vtable = &vt }, ring, 4);
    defer s.destroy();
    try s.begin(3);
    var layout: G.RequestLayout = undefined;
    const ctx = G.RequestContext{ .request = 1, .layout = &layout, .exchange = .{ .segments = 3, .claims_per_segment = 1, .devices = 1 }, .peer = undefined, .classes = undefined, .segments = &.{}, .segment_device = &.{ 0, 0, 0 } };
    s.attach(&ctx);
    const sink = s.sink();
    const buf = try ring.acquire(0);
    try sink.chunk(sink.ctx, .{ .segment = 0, .sequence = 0, .first_row = 0, .rows = 7, .last = true, .words = buf[0..4] });
    try sink.sealed_segment(sink.ctx, 0, 7);
    try testing.expect(s.gate(0).recorded.isSet() and !s.gate(0).failed.load(.acquire));
    try testing.expectEqual(@as(u32, 7), n.seen);
    // Stage1(0) ran: its host fn returns the buffer.
    _ = try ring.acquire(1);
    try testing.expectEqual(@as(usize, 0), ring.free_count);
    const f = s.releaseFn(0).?;
    f.call(f.user);
    try testing.expectEqual(@as(usize, 1), ring.free_count);
    try sink.sealed_segment(sink.ctx, 1, 9);
    try testing.expectError(error.GpuNativeCaptureSegmentCountChanged, sink.done(sink.ctx, 2));
    try testing.expect(s.gate(2).recorded.isSet() and s.gate(2).failed.load(.acquire));
    try testing.expect(!s.gate(1).failed.load(.acquire));
    try testing.expectError(error.CaptureRingClosed, ring.acquire(2));
}
