//! M8 GPU-native capture hand-off (rv64-m8-gpu-native.md §1, §2 H1; driver).
//!
//! Capture/emulation is the only CPU compute allowed on the request path and
//! it must overlap proving. This is the bridge from the capture thread to the
//! device:
//!
//!   service: stream.prepare(segment_rows)   BEFORE the capture thread starts
//!   capture thread                     driver / GPUs
//!   stream.acquire(seg) -> fill pinned (backpressure only: the ring is full)
//!   sink.chunk(TraceChunk)  --------->  native.chunk(ctx, chunk, device(seg))
//!                                       (native enqueues the h2d + witness)
//!   sink.sealed_segment(seg, rows) -->  releases Stage1(seg)'s host gate: the
//!                                       GPU's batch stages + enqueues it now,
//!                                       while capture continues with seg+1
//!   sink.done(n)                        EXACTLY once, on every exit path of
//!                                       the capture thread (also after an
//!                                       error): the capture no longer touches
//!                                       any ring buffer. n must equal the
//!                                       planned segments, else every
//!                                       unreleased gate fails
//!   ...                                 exec stream, after Stage1(seg):
//!                                       host fn ring.releaseSegment(seg)
//!   driver: stream.detach()             request end: waits for `done`, then
//!                                       returns whatever this request still
//!                                       holds in the ring
//!
//! One epoch per request: `prepare` opens it (the previous request detached,
//! so no capture thread of it is alive), `detach` closes it. Nothing resets
//! per-request state while a capture thread of that request can run, so a
//! failure the capture signalled early is never wiped and no buffer it still
//! fills is handed to someone else.
//!
//! Geometry is checked, not trusted: `sealed(seg, rows)` must match the rows
//! the request was planned from (the class key, MAIN view, slab capacity
//! and exchange shape were sized from them) and the chunks' row total; a
//! chunk must start at the segment's running row cursor and never follow its
//! seal. Any mismatch fails the stream (every unreleased Stage1 fails closed).
//!
//! The capture thread never waits on the GPU; Stage1 never waits on the
//! whole block. Ring slots return through a host function enqueued after the
//! segment's Stage1 (pure host bookkeeping, no CUDA call).
//!
//! Pipelining (two requests in flight): one Stream per in-flight request (the
//! driver refuses a stream that the other in-flight request holds); streams
//! may share one Ring. Ring buffers are owned by (stream token, segment), so
//! a request's Stage1 release never frees the other request's buffers, and a
//! failed capture cancels only its own stream's acquires (the ring stays open
//! for the next request).
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
    owner: []Owner,
    mutex: std.Thread.Mutex = .{},
    cond: std.Thread.Condition = .{},
    free_count: usize,
    closed: bool = false,
    acquires: u64 = 0,
    blocked_ns: u64 = 0,

    /// Token 0 = free (Stream tokens start at 1).
    pub const Owner = struct { token: u32 = 0, segment: u32 = 0 };

    /// Install time: `count` pinned buffers of `words` each.
    pub fn init(a: std.mem.Allocator, wait: *const O.Wait, count: usize, words: usize) !*Ring {
        const self = try a.create(Ring);
        errdefer a.destroy(self);
        const buffers = try a.alloc([]u32, count);
        errdefer a.free(buffers);
        const owner = try a.alloc(Owner, count);
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
        @memset(owner, .{});
        self.* = .{ .a = a, .wait = wait, .buffers = buffers, .owner = owner, .free_count = count };
        return self;
    }
    pub fn deinit(self: *Ring) void {
        for (self.buffers) |b| _ = self.wait.host_free(b.ptr);
        self.a.free(self.buffers);
        self.a.free(self.owner);
        self.a.destroy(self);
    }
    /// Pinned words the whole ring holds (one segment's capture must fit).
    pub fn capacityWords(self: *const Ring) u64 {
        var n: u64 = 0;
        for (self.buffers) |b| n += b.len;
        return n;
    }
    /// Capture thread: a free pinned buffer for (`token`, `segment`) (blocks
    /// only while every buffer belongs to a segment whose Stage1 has not run
    /// yet). `cancel` (the owner's failure flag) aborts the wait. `sealed`
    /// (the owner's Stage1 gates): when every buffer belongs to this owner and
    /// none of their segments is sealed, nothing can ever free one (only the
    /// blocked capture could seal them), so the wait fails instead of hanging.
    pub fn acquire(self: *Ring, token: u32, segment: u32, cancel: ?*const std.atomic.Value(bool), sealed: ?[]const W.BatchDep) ![]u32 {
        if (token == 0) return error.InvalidCaptureOwner;
        self.mutex.lock();
        defer self.mutex.unlock();
        var timer = std.time.Timer.start() catch unreachable;
        const cancelled = struct {
            fn f(c: ?*const std.atomic.Value(bool)) bool {
                return if (c) |x| x.load(.acquire) else false;
            }
        }.f;
        while (self.free_count == 0 and !self.closed and !cancelled(cancel)) {
            if (sealed) |gates| if (self.selfDeadlocked(token, gates)) {
                self.blocked_ns += timer.read();
                return error.GpuNativeCaptureRingExhausted;
            };
            self.cond.wait(&self.mutex);
        }
        self.blocked_ns += timer.read();
        if (self.closed) return error.CaptureRingClosed;
        if (cancelled(cancel)) return error.GpuNativeCaptureFailed;
        for (self.owner, 0..) |*o, i| if (o.token == 0) {
            o.* = .{ .token = token, .segment = segment };
            self.free_count -= 1;
            self.acquires += 1;
            return self.buffers[i];
        };
        unreachable;
    }
    /// Must hold `mutex`.
    fn selfDeadlocked(self: *const Ring, token: u32, gates: []const W.BatchDep) bool {
        for (self.owner) |o| {
            if (o.token != token) return false; // another stream's Stage1 frees it
            if (o.segment >= gates.len or gates[o.segment].recorded.isSet()) return false; // its Stage1 frees it
        }
        return true;
    }
    /// Host-fn safe (no CUDA): every buffer of (`token`, `segment`) returns.
    pub fn releaseSegment(self: *Ring, token: u32, segment: u32) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.owner) |*o| if (o.token == token and o.segment == segment) {
            o.* = .{};
            self.free_count += 1;
        };
        self.cond.broadcast();
    }
    /// Every buffer `token` still holds returns (its request ended: no
    /// capture writes and no upload reads them any more).
    pub fn releaseOwner(self: *Ring, token: u32) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        for (self.owner) |*o| if (o.token == token) {
            o.* = .{};
            self.free_count += 1;
        };
        self.cond.broadcast();
    }
    /// Wake blocked acquirers (they re-check their cancel flag).
    pub fn wake(self: *Ring) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.cond.broadcast();
    }
    /// Service shutdown only: every acquire fails from now on.
    pub fn close(self: *Ring) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.closed = true;
        self.cond.broadcast();
    }
};

var next_token: std.atomic.Value(u32) = .init(1);

/// How long `detach` waits for the capture thread's `done` after the request
/// ended (a capture that never reports done is a service bug: the stream is
/// poisoned and its buffers are never handed out again). Safety bound, not a
/// tuning constant: no proving work waits on it.
pub const detach_timeout_ns: u64 = 60 * std.time.ns_per_s;

pub const Stream = struct {
    a: std.mem.Allocator,
    native: G.NativeFactory,
    ring: ?*Ring,
    /// Ring ownership identity (unique per process, never 0).
    token: u32 = 0,
    /// Per segment (capacity fixed at install).
    gates: []W.BatchDep,
    releases: []Release,
    sealed_rows: []u64,
    planned_rows: []u64,
    /// Rows received in chunks per segment (the next chunk's first_row).
    cursor: []u64,
    expected: u32 = 0,
    ctx: ?*const G.RequestContext = null,
    /// Request epoch, under `mutex`.
    mutex: std.Thread.Mutex = .{},
    state: State = .idle,
    poisoned: bool = false,
    attached: std.Thread.ResetEvent = .{},
    /// The capture thread reported `done` (it touches no buffer any more).
    ended: std.Thread.ResetEvent = .{},
    failure: std.atomic.Value(bool) = .init(false),
    chunks: std.atomic.Value(u64) = .init(0),
    chunk_words: std.atomic.Value(u64) = .init(0),
    attach_wait_ns: u64 = 0,
    /// A capture-ring buffer may not be handed to another stream.
    fail_hook: Fail = undefined,

    pub const State = enum { idle, prepared, attached };
    pub const Release = struct { stream: *Stream, segment: u32 };
    const Fail = struct { stream: *Stream };

    pub fn create(a: std.mem.Allocator, native: G.NativeFactory, ring: ?*Ring, capacity: u32) !*Stream {
        const self = try a.create(Stream);
        errdefer a.destroy(self);
        const gates = try a.alloc(W.BatchDep, capacity);
        errdefer a.free(gates);
        const releases = try a.alloc(Release, capacity);
        errdefer a.free(releases);
        const rows = try a.alloc(u64, capacity);
        errdefer a.free(rows);
        const planned = try a.alloc(u64, capacity);
        errdefer a.free(planned);
        const cursor = try a.alloc(u64, capacity);
        self.* = .{ .a = a, .native = native, .ring = ring, .token = next_token.fetchAdd(1, .monotonic), .gates = gates, .releases = releases, .sealed_rows = rows, .planned_rows = planned, .cursor = cursor };
        self.fail_hook = .{ .stream = self };
        for (gates) |*g| g.* = .{};
        for (releases, 0..) |*r, i| r.* = .{ .stream = self, .segment = @intCast(i) };
        return self;
    }
    pub fn destroy(self: *Stream) void {
        self.a.free(self.gates);
        self.a.free(self.releases);
        self.a.free(self.sealed_rows);
        self.a.free(self.planned_rows);
        self.a.free(self.cursor);
        self.a.destroy(self);
    }

    /// Service, BEFORE starting the request's capture thread: open the
    /// request epoch with the geometry the request is planned from. Refused
    /// while the previous request has not detached.
    pub fn prepare(self: *Stream, segment_rows: []const u64) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.poisoned) return error.GpuNativeCaptureStreamPoisoned;
        if (self.state != .idle) return error.GpuNativeCaptureStreamBusy;
        if (segment_rows.len == 0 or segment_rows.len > self.gates.len) return error.GpuNativeCaptureCapacity;
        self.expected = @intCast(segment_rows.len);
        for (self.gates[0..segment_rows.len]) |*g| g.* = .{};
        @memset(self.sealed_rows, 0);
        @memset(self.cursor, 0);
        @memcpy(self.planned_rows[0..segment_rows.len], segment_rows);
        self.chunks.store(0, .monotonic);
        self.chunk_words.store(0, .monotonic);
        self.attach_wait_ns = 0;
        self.failure.store(false, .release);
        self.ended.reset();
        self.attached.reset();
        self.state = .prepared;
    }
    /// Driver (make): bind the prepared epoch to the request context. The
    /// geometry must be the one the stream was prepared with.
    pub fn bind(self: *Stream, segment_rows: []const u64, ctx: *const G.RequestContext) !void {
        self.mutex.lock();
        defer self.mutex.unlock();
        if (self.state != .prepared) return error.GpuNativeCaptureNotPrepared;
        if (segment_rows.len != self.expected or !std.mem.eql(u64, segment_rows, self.planned_rows[0..self.expected])) return error.GpuNativeCaptureGeometryMismatch;
        self.ctx = ctx;
        self.state = .attached;
        self.attached.set();
    }
    /// Driver, request end (success or failure; after every GPU's work that
    /// could read this request's buffers completed): wait for the capture's
    /// `done`, return this request's leftover ring buffers, close the epoch.
    /// A capture that never reports `done` poisons the stream (its buffers
    /// are never handed out again) instead of risking two writers.
    pub fn detach(self: *Stream) void {
        {
            self.mutex.lock();
            defer self.mutex.unlock();
            if (self.state == .idle) return;
        }
        // A request that ends before its capture sealed everything (driver
        // failure path): cancel the capture first, so its blocked calls
        // return. A fully sealed capture is only waited for (its `done`).
        if (!self.ended.isSet() and !self.allSealed()) self.fail();
        const ended = if (self.ended.timedWait(detach_timeout_ns)) |_| true else |_| false;
        self.mutex.lock();
        defer self.mutex.unlock();
        if (!ended) {
            std.log.err("M8 capture stream token {d}: capture never reported done; stream poisoned", .{self.token});
            self.poisoned = true;
        } else if (self.ring) |r| r.releaseOwner(self.token);
        self.ctx = null;
        self.state = .idle;
    }
    /// Capture thread: a pinned ring buffer for `segment` of this request.
    pub fn acquire(self: *Stream, segment: u32) ![]u32 {
        const r = self.ring orelse return error.GpuNativeCaptureNoRing;
        if (!self.isOpen()) return error.GpuNativeCaptureNotPrepared;
        if (segment >= self.expected) return error.GpuNativeCaptureSegmentOutOfRange;
        return r.acquire(self.token, segment, &self.failure, self.gates[0..self.expected]) catch |err| {
            if (err == error.GpuNativeCaptureRingExhausted) self.fail();
            return err;
        };
    }
    fn allSealed(self: *Stream) bool {
        for (self.gates[0..self.expected]) |*g| if (!g.recorded.isSet() or g.failed.load(.acquire)) return false;
        return true;
    }
    fn isOpen(self: *Stream) bool {
        self.mutex.lock();
        defer self.mutex.unlock();
        return self.state != .idle;
    }
    fn awaitAttach(self: *Stream) !void {
        if (!self.isOpen()) return error.GpuNativeCaptureNotPrepared;
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
        if (r.stream.ring) |ring| ring.releaseSegment(r.stream.token, r.segment);
    }
    /// Host call for the driver's batch `on_fail` (a Stage1 failed): cancel
    /// the capture so blocked acquires and unreleased gates fail closed.
    pub fn failFn(self: *Stream) api.HostFn {
        return .{ .call = failCall, .user = &self.fail_hook };
    }
    fn failCall(user: ?*anyopaque) callconv(.c) void {
        const f: *Fail = @ptrCast(@alignCast(user.?));
        f.stream.fail();
    }
    /// Capture or the request failed: every unreleased Stage1 fails (its
    /// batch skips the body). Idempotent; never resets anything.
    pub fn fail(self: *Stream) void {
        self.mutex.lock();
        defer self.mutex.unlock();
        self.failure.store(true, .release);
        if (self.state != .idle) for (self.gates[0..self.expected]) |*g| if (!g.recorded.isSet()) g.signal(null, true);
        self.attached.set();
        // Cancel this stream's blocked acquire only; the ring stays open for
        // the next request (closing it here failed every later capture).
        if (self.ring) |r| r.wake();
    }

    pub fn sink(self: *Stream) G.CaptureSink {
        return .{ .ctx = self, .chunk = chunk, .sealed_segment = sealed, .done = done };
    }
    fn of(raw: *anyopaque) *Stream {
        return @ptrCast(@alignCast(raw));
    }
    fn chunk(raw: *anyopaque, c: G.TraceChunk) anyerror!void {
        const self = of(raw);
        try self.awaitAttach();
        if (c.segment >= self.expected) return error.GpuNativeCaptureSegmentOutOfRange;
        if (self.failure.load(.acquire)) return error.GpuNativeCaptureFailed;
        // A chunk after the seal would change a witness Stage1 already staged.
        if (self.gates[c.segment].recorded.isSet()) {
            self.fail();
            return error.GpuNativeCaptureChunkAfterSeal;
        }
        if (c.first_row != self.cursor[c.segment] or self.cursor[c.segment] + c.rows > self.planned_rows[c.segment]) {
            self.fail();
            return error.GpuNativeCaptureGeometryMismatch;
        }
        self.cursor[c.segment] += c.rows;
        const ctx = self.ctx.?;
        const device = if (ctx.segment_device.len > c.segment) ctx.segment_device[c.segment] else 0;
        _ = self.chunks.fetchAdd(1, .monotonic);
        _ = self.chunk_words.fetchAdd(c.words.len, .monotonic);
        return self.native.vtable.chunk(self.native.ctx, ctx, c, device);
    }
    fn sealed(raw: *anyopaque, segment: u32, rows: u64) anyerror!void {
        const self = of(raw);
        try self.awaitAttach();
        if (segment >= self.expected) return error.GpuNativeCaptureSegmentOutOfRange;
        if (self.failure.load(.acquire)) return error.GpuNativeCaptureFailed;
        if (self.gates[segment].recorded.isSet()) return error.GpuNativeCaptureSegmentSealedTwice;
        // The plan (class key, MAIN view, slab, exchange) was sized from the
        // planned rows: a different capture geometry never reaches Stage1.
        if (rows != self.planned_rows[segment] or self.cursor[segment] != rows) {
            self.fail();
            return error.GpuNativeCaptureGeometryMismatch;
        }
        self.sealed_rows[segment] = rows;
        self.gates[segment].signal(null, false);
    }
    fn done(raw: *anyopaque, segments: u32) anyerror!void {
        const self = of(raw);
        // Whatever happens below, the capture thread is finished with every
        // buffer once it called done.
        defer self.ended.set();
        if (!self.isOpen()) return error.GpuNativeCaptureNotPrepared;
        if (segments != self.expected) {
            self.fail();
            return error.GpuNativeCaptureSegmentCountChanged;
        }
        if (self.failure.load(.acquire)) return error.GpuNativeCaptureFailed;
        for (self.gates[0..segments]) |*g| if (!g.recorded.isSet()) {
            self.fail();
            return error.GpuNativeCaptureSegmentNotSealed;
        };
    }
};

const testing = std.testing;
const F = @import("jobs/fake.zig");

const NativeCount = struct {
    seen: u32 = 0,
    fn chunkFn(raw: *anyopaque, _: *const G.RequestContext, c: G.TraceChunk, _: u32) anyerror!void {
        const self: *@This() = @ptrCast(@alignCast(raw));
        self.seen += c.rows;
    }
    const vt = G.NativeFactory.VTable{ .warm = undefined, .class_of = undefined, .stage1 = undefined, .stage2 = undefined, .seal = undefined, .chunk = chunkFn };
};

fn testCtx(layout: *G.RequestLayout) G.RequestContext {
    return .{ .request = 1, .layout = layout, .exchange = .{ .segments = 3, .claims_per_segment = 1, .devices = 1 }, .peer = undefined, .classes = undefined, .segments = &.{}, .segment_device = &.{ 0, 0, 0 } };
}

test "capture stream: sealed segments release Stage1 gates; a short capture fails the rest" {
    var n = NativeCount{};
    const ring = try Ring.init(testing.allocator, &F.ops.wait, 2, 16);
    defer ring.deinit();
    const s = try Stream.create(testing.allocator, .{ .ctx = &n, .vtable = &NativeCount.vt }, ring, 4);
    defer s.destroy();
    const rows = [_]u64{ 7, 9, 5 };
    try s.prepare(&rows);
    var layout: G.RequestLayout = undefined;
    const ctx = testCtx(&layout);
    try s.bind(&rows, &ctx);
    const sink = s.sink();
    const buf = try s.acquire(0);
    try sink.chunk(sink.ctx, .{ .segment = 0, .sequence = 0, .first_row = 0, .rows = 7, .last = true, .words = buf[0..4] });
    try sink.sealed_segment(sink.ctx, 0, 7);
    try testing.expect(s.gate(0).recorded.isSet() and !s.gate(0).failed.load(.acquire));
    try testing.expectEqual(@as(u32, 7), n.seen);
    // Stage1(0) ran: its host fn returns the buffer.
    _ = try s.acquire(1);
    try testing.expectEqual(@as(usize, 0), ring.free_count);
    const f = s.releaseFn(0).?;
    f.call(f.user);
    try testing.expectEqual(@as(usize, 1), ring.free_count);
    try sink.chunk(sink.ctx, .{ .segment = 1, .sequence = 0, .first_row = 0, .rows = 9, .last = true, .words = &.{} });
    try sink.sealed_segment(sink.ctx, 1, 9);
    try testing.expectError(error.GpuNativeCaptureSegmentCountChanged, sink.done(sink.ctx, 2));
    try testing.expect(s.gate(2).recorded.isSet() and s.gate(2).failed.load(.acquire));
    try testing.expect(!s.gate(1).failed.load(.acquire));
    try testing.expectError(error.GpuNativeCaptureFailed, s.acquire(2));
    // A new epoch only after the request detached; detach returns leftovers.
    try testing.expectError(error.GpuNativeCaptureStreamBusy, s.prepare(&rows));
    s.detach();
    try testing.expectEqual(@as(usize, 2), ring.free_count);
    // The failure was this request's only: the next request captures again.
    try s.prepare(rows[0..2]);
    try s.bind(rows[0..2], &ctx);
    _ = try s.acquire(0);
}

test "capture stream: geometry is checked against the plan (rows, contiguity, late chunks)" {
    var n = NativeCount{};
    const s = try Stream.create(testing.allocator, .{ .ctx = &n, .vtable = &NativeCount.vt }, null, 4);
    defer s.destroy();
    var layout: G.RequestLayout = undefined;
    const ctx = testCtx(&layout);
    const rows = [_]u64{ 8, 8 };
    // The driver binds only the geometry the stream was prepared with.
    try testing.expectError(error.GpuNativeCaptureNotPrepared, s.bind(&rows, &ctx));
    try s.prepare(&rows);
    try testing.expectError(error.GpuNativeCaptureGeometryMismatch, s.bind(&.{ 8, 9 }, &ctx));
    try s.bind(&rows, &ctx);
    const sink = s.sink();
    // (a) a sealed row count that differs from the planned one fails closed
    try sink.chunk(sink.ctx, .{ .segment = 0, .sequence = 0, .first_row = 0, .rows = 6, .last = false, .words = &.{} });
    try testing.expectError(error.GpuNativeCaptureGeometryMismatch, sink.sealed_segment(sink.ctx, 0, 6));
    try testing.expect(s.gate(0).failed.load(.acquire) and s.gate(1).failed.load(.acquire));
    try testing.expectError(error.GpuNativeCaptureFailed, sink.done(sink.ctx, 2));
    s.detach();
    // (b) a non-contiguous chunk fails closed
    try s.prepare(&rows);
    try s.bind(&rows, &ctx);
    try sink.chunk(sink.ctx, .{ .segment = 0, .sequence = 0, .first_row = 0, .rows = 4, .last = false, .words = &.{} });
    try testing.expectError(error.GpuNativeCaptureGeometryMismatch, sink.chunk(sink.ctx, .{ .segment = 0, .sequence = 1, .first_row = 5, .rows = 3, .last = true, .words = &.{} }));
    try testing.expect(s.gate(0).failed.load(.acquire));
    sink.done(sink.ctx, 2) catch {};
    s.detach();
    // (c) a chunk after its segment's seal fails closed
    try s.prepare(&rows);
    try s.bind(&rows, &ctx);
    try sink.chunk(sink.ctx, .{ .segment = 0, .sequence = 0, .first_row = 0, .rows = 8, .last = true, .words = &.{} });
    try sink.sealed_segment(sink.ctx, 0, 8);
    try testing.expectError(error.GpuNativeCaptureChunkAfterSeal, sink.chunk(sink.ctx, .{ .segment = 0, .sequence = 1, .first_row = 8, .rows = 1, .last = true, .words = &.{} }));
    try testing.expect(s.gate(1).failed.load(.acquire));
    sink.done(sink.ctx, 2) catch {};
    s.detach();
    // A clean capture of the planned geometry passes.
    try s.prepare(&rows);
    try s.bind(&rows, &ctx);
    for (0..2) |seg| {
        try sink.chunk(sink.ctx, .{ .segment = @intCast(seg), .sequence = 0, .first_row = 0, .rows = 3, .last = false, .words = &.{} });
        try sink.chunk(sink.ctx, .{ .segment = @intCast(seg), .sequence = 1, .first_row = 3, .rows = 5, .last = true, .words = &.{} });
        try sink.sealed_segment(sink.ctx, @intCast(seg), 8);
    }
    try sink.done(sink.ctx, 2);
    s.detach();
}

test "capture stream: a segment larger than the ring fails instead of deadlocking" {
    var n = NativeCount{};
    const ring = try Ring.init(testing.allocator, &F.ops.wait, 2, 16);
    defer ring.deinit();
    const s = try Stream.create(testing.allocator, .{ .ctx = &n, .vtable = &NativeCount.vt }, ring, 4);
    defer s.destroy();
    try s.prepare(&.{ 100, 100 });
    _ = try s.acquire(0);
    _ = try s.acquire(0);
    // Every buffer belongs to unsealed segment 0: only this capture could
    // seal it, and it is the one waiting.
    try testing.expectError(error.GpuNativeCaptureRingExhausted, s.acquire(0));
    try testing.expect(s.gate(1).failed.load(.acquire));
    s.sink().done(s, 2) catch {};
    s.detach();
    try testing.expectEqual(@as(usize, 2), ring.free_count);
}

test "capture stream: a capture started before the driver binds keeps its early failure" {
    var n = NativeCount{};
    const ring = try Ring.init(testing.allocator, &F.ops.wait, 2, 16);
    defer ring.deinit();
    const s = try Stream.create(testing.allocator, .{ .ctx = &n, .vtable = &NativeCount.vt }, ring, 4);
    defer s.destroy();
    const rows = [_]u64{ 4, 4 };
    try s.prepare(&rows);
    // The capture thread already holds a buffer and failed before bind.
    const held = try s.acquire(0);
    s.fail();
    var layout: G.RequestLayout = undefined;
    const ctx = testCtx(&layout);
    try s.bind(&rows, &ctx); // binding never wipes the failure or the buffer
    try testing.expect(s.gate(0).failed.load(.acquire) and s.gate(1).failed.load(.acquire));
    try testing.expectEqual(@as(usize, 1), ring.free_count);
    try testing.expectEqual(s.token, ring.owner[0].token);
    _ = held;
    s.sink().done(s, 2) catch {};
    s.detach();
    try testing.expectEqual(@as(usize, 2), ring.free_count);
}

test "capture stream: two in-flight streams on one ring never free each other's buffers" {
    var n = NativeCount{};
    const ring = try Ring.init(testing.allocator, &F.ops.wait, 3, 16);
    defer ring.deinit();
    const a = try Stream.create(testing.allocator, .{ .ctx = &n, .vtable = &NativeCount.vt }, ring, 4);
    defer a.destroy();
    const b = try Stream.create(testing.allocator, .{ .ctx = &n, .vtable = &NativeCount.vt }, ring, 4);
    defer b.destroy();
    try a.prepare(&.{ 4, 4 });
    _ = try a.acquire(0); // request N, segment 0: its Stage1 upload is still queued
    try b.prepare(&.{ 4, 4 }); // request N+1 starts: must not reclaim N's buffer
    try testing.expectEqual(@as(usize, 2), ring.free_count);
    _ = try b.acquire(0);
    // N's Stage1(0) release returns N's buffer only.
    const f = a.releaseFn(0).?;
    f.call(f.user);
    try testing.expectEqual(@as(usize, 2), ring.free_count);
    try testing.expectEqual(b.token, ring.owner[1].token);
    // A failed capture on b cancels b, not a.
    b.fail();
    try testing.expectError(error.GpuNativeCaptureFailed, b.acquire(1));
    _ = try a.acquire(1);
}
