//! Capture-stream/feed lifecycle tests: shared-ring custody, ordering and terminal failure.
const Owner = @import("m8_capture_stream.zig");
const std = @import("std");
const G = @import("jobs/gpu_native.zig");
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
    const ring = try Owner.Ring.init(testing.allocator, &F.ops.wait, 2, 16);
    defer ring.deinit();
    const s = try Owner.Stream.create(testing.allocator, .{ .ctx = &n, .vtable = &NativeCount.vt }, ring, 4);
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
    const s = try Owner.Stream.create(testing.allocator, .{ .ctx = &n, .vtable = &NativeCount.vt }, null, 4);
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
    const ring = try Owner.Ring.init(testing.allocator, &F.ops.wait, 2, 16);
    defer ring.deinit();
    const s = try Owner.Stream.create(testing.allocator, .{ .ctx = &n, .vtable = &NativeCount.vt }, ring, 4);
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
    const ring = try Owner.Ring.init(testing.allocator, &F.ops.wait, 2, 16);
    defer ring.deinit();
    const s = try Owner.Stream.create(testing.allocator, .{ .ctx = &n, .vtable = &NativeCount.vt }, ring, 4);
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
    const ring = try Owner.Ring.init(testing.allocator, &F.ops.wait, 3, 16);
    defer ring.deinit();
    const a = try Owner.Stream.create(testing.allocator, .{ .ctx = &n, .vtable = &NativeCount.vt }, ring, 4);
    defer a.destroy();
    const b = try Owner.Stream.create(testing.allocator, .{ .ctx = &n, .vtable = &NativeCount.vt }, ring, 4);
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

/// A packer that splits each segment into two chunks of `rows/2` rows whose
/// words carry (segment, chunk) tags; records what the captured hooks saw.
const Packer = struct {
    rows: u64 = 8,
    leave_outstanding: bool = false,
    chunks: u32 = 0,
    words: std.ArrayListUnmanaged(u32) = .empty,
    ends: u32 = 0,
    rec_ends: u32 = 0,
    fn packFn(raw: *anyopaque, _: *const G.RequestContext, cs: G.CapturedSegment, w: G.ChunkWriter) anyerror!u64 {
        const self: *@This() = @ptrCast(@alignCast(raw));
        const tag: *const u32 = @ptrCast(@alignCast(cs.native));
        const half: u32 = @intCast(self.rows / 2);
        for (0..2) |k| {
            const b = try w.next();
            b[0] = tag.* * 16 + @as(u32, @intCast(k));
            try w.put(1, half, k == 1);
        }
        if (self.leave_outstanding) _ = try w.next();
        return self.rows;
    }
    fn chunkFn(raw: *anyopaque, _: *const G.RequestContext, c: G.TraceChunk, _: u32) anyerror!void {
        const self: *@This() = @ptrCast(@alignCast(raw));
        self.chunks += 1;
        try self.words.append(testing.allocator, c.words[0]);
    }
    fn capturedFn(raw: *anyopaque, _: *const G.RequestContext, ce: G.CaptureEnd) anyerror!void {
        const self: *@This() = @ptrCast(@alignCast(raw));
        self.ends += ce.segments;
    }
    fn recCapturedFn(raw: *anyopaque, _: *const G.RequestContext, _: G.CaptureEnd) anyerror!void {
        const self: *@This() = @ptrCast(@alignCast(raw));
        self.rec_ends += 1;
    }
    const nvt = G.NativeFactory.VTable{ .warm = undefined, .class_of = undefined, .stage1 = undefined, .stage2 = undefined, .seal = undefined, .chunk = chunkFn, .pack = packFn, .captured = capturedFn };
    const rvt = G.RecursionFactory.VTable{ .warm = undefined, .class_of = undefined, .truth = undefined, .node = undefined, .captured = recCapturedFn };
};

fn captureEnd(segments: u32) G.CaptureEnd {
    const dummy = struct {
        var x: u8 = 0;
    };
    return .{ .segments = segments, .owner = &dummy.x, .image = &dummy.x, .program = &dummy.x, .config = &dummy.x };
}

test "capture feed: packed segments stream as chunks, seal in order, end hooks run, end gate opens" {
    var p = Packer{};
    defer p.words.deinit(testing.allocator);
    const ring = try Owner.Ring.init(testing.allocator, &F.ops.wait, 4, 16);
    defer ring.deinit();
    const s = try Owner.Stream.create(testing.allocator, .{ .ctx = &p, .vtable = &Packer.nvt }, ring, 4);
    defer s.destroy();
    s.recursion = .{ .ctx = &p, .vtable = &Packer.rvt };
    const rows = [_]u64{ 8, 8, 8 };
    try s.prepare(&rows);
    var layout: G.RequestLayout = undefined;
    const ctx = testCtx(&layout);
    try s.bind(&rows, &ctx);
    var f = s.feed();
    const tags = [_]u32{ 1, 2, 3 };
    for (0..3) |i| {
        try f.segment(.{ .segment = @intCast(i), .native = &tags[i], .events = &tags[i] });
        try testing.expect(s.gate(@intCast(i)).recorded.isSet() and !s.gate(@intCast(i)).failed.load(.acquire));
        // Stage1(i) ran: its buffers return (else the ring of 4 runs dry).
        const r = s.releaseFn(@intCast(i)).?;
        r.call(r.user);
    }
    try testing.expect(!s.endGate().recorded.isSet());
    try f.end(captureEnd(3));
    f.finish(null);
    f.finish(null); // idempotent
    try testing.expect(f.failure == null);
    try testing.expect(s.endGate().recorded.isSet() and !s.endGate().failed.load(.acquire));
    try testing.expectEqual(@as(u32, 6), p.chunks);
    try testing.expectEqualSlices(u32, &.{ 16, 17, 32, 33, 48, 49 }, p.words.items);
    try testing.expectEqual(@as(u32, 3), p.ends);
    try testing.expectEqual(@as(u32, 1), p.rec_ends);
    s.detach();
    try testing.expectEqual(@as(usize, 4), ring.free_count);
}

test "capture feed: out-of-order, wrong rows, an unemitted buffer and a capture error fail closed" {
    var p = Packer{};
    defer p.words.deinit(testing.allocator);
    const ring = try Owner.Ring.init(testing.allocator, &F.ops.wait, 8, 16);
    defer ring.deinit();
    const s = try Owner.Stream.create(testing.allocator, .{ .ctx = &p, .vtable = &Packer.nvt }, ring, 4);
    defer s.destroy();
    var layout: G.RequestLayout = undefined;
    const ctx = testCtx(&layout);
    const rows = [_]u64{ 8, 8 };
    const tag: u32 = 7;
    // (a) segment 1 before segment 0
    try s.prepare(&rows);
    try s.bind(&rows, &ctx);
    var f = s.feed();
    try testing.expectError(error.GpuNativeCaptureOutOfOrder, f.segment(.{ .segment = 1, .native = &tag, .events = &tag }));
    try testing.expect(s.gate(0).failed.load(.acquire) and s.endGate().failed.load(.acquire));
    f.finish(null);
    s.detach();
    // (b) the packer reports rows that differ from the plan
    p.rows = 6;
    try s.prepare(&rows);
    try s.bind(&rows, &ctx);
    f = s.feed();
    try testing.expectError(error.GpuNativeCaptureGeometryMismatch, f.segment(.{ .segment = 0, .native = &tag, .events = &tag }));
    f.finish(null);
    s.detach();
    // (c) a buffer handed out and never emitted
    p.rows = 8;
    p.leave_outstanding = true;
    try s.prepare(&rows);
    try s.bind(&rows, &ctx);
    f = s.feed();
    try testing.expectError(error.GpuNativeCaptureChunkNotEmitted, f.segment(.{ .segment = 0, .native = &tag, .events = &tag }));
    try testing.expect(s.gate(0).failed.load(.acquire));
    f.finish(null);
    s.detach();
    // (d) the capture itself failed after one sealed segment
    p.leave_outstanding = false;
    try s.prepare(&rows);
    try s.bind(&rows, &ctx);
    f = s.feed();
    try f.segment(.{ .segment = 0, .native = &tag, .events = &tag });
    f.finish(error.EthereumStepBudgetExceeded);
    try testing.expectEqual(error.EthereumStepBudgetExceeded, f.failure.?);
    try testing.expect(!s.gate(0).failed.load(.acquire) and s.gate(1).failed.load(.acquire) and s.endGate().failed.load(.acquire));
    s.detach();
    try testing.expectEqual(@as(usize, 8), ring.free_count);
    // (e) a factory without a packer cannot stream
    var n = NativeCount{};
    const bare = try Owner.Stream.create(testing.allocator, .{ .ctx = &n, .vtable = &NativeCount.vt }, ring, 4);
    defer bare.destroy();
    try bare.prepare(&rows);
    try bare.bind(&rows, &ctx);
    var g = bare.feed();
    try testing.expectError(error.GpuNativeCaptureNoPacker, g.segment(.{ .segment = 0, .native = &tag, .events = &tag }));
    g.finish(null);
    bare.detach();
}

test "capture feed: a clean finish without end, or a capture error after the last seal, fails awaitCaptured" {
    var p = Packer{};
    defer p.words.deinit(testing.allocator);
    const ring = try Owner.Ring.init(testing.allocator, &F.ops.wait, 8, 16);
    defer ring.deinit();
    const s = try Owner.Stream.create(testing.allocator, .{ .ctx = &p, .vtable = &Packer.nvt }, ring, 4);
    defer s.destroy();
    var layout: G.RequestLayout = undefined;
    const ctx = testCtx(&layout);
    const rows = [_]u64{ 8, 8 };
    const tag: u32 = 7;
    // (a) every segment sealed, `end` never ran: the end gate fails closed.
    try s.prepare(&rows);
    try s.bind(&rows, &ctx);
    var f = s.feed();
    for (0..2) |i| try f.segment(.{ .segment = @intCast(i), .native = &tag, .events = &tag });
    f.finish(null);
    try testing.expectEqual(error.GpuNativeCaptureEndMissing, f.failure.?);
    try testing.expect(s.endGate().failed.load(.acquire));
    try testing.expectError(error.GpuNativeCaptureFailed, s.awaitCaptured());
    s.detach();
    // (b) every segment sealed and ended, then the capture's final checks
    // failed: no Stage1 gate fails, but publication must not happen.
    try s.prepare(&rows);
    try s.bind(&rows, &ctx);
    f = s.feed();
    for (0..2) |i| try f.segment(.{ .segment = @intCast(i), .native = &tag, .events = &tag });
    try f.end(captureEnd(2));
    f.finish(error.EthereumTerminalMismatch);
    try testing.expect(!s.gate(0).failed.load(.acquire) and !s.gate(1).failed.load(.acquire));
    try testing.expectError(error.GpuNativeCaptureFailed, s.awaitCaptured());
    s.detach();
    // (c) the clean path passes.
    try s.prepare(&rows);
    try s.bind(&rows, &ctx);
    f = s.feed();
    for (0..2) |i| try f.segment(.{ .segment = @intCast(i), .native = &tag, .events = &tag });
    try f.end(captureEnd(2));
    f.finish(null);
    try s.awaitCaptured();
    s.detach();
    try testing.expectEqual(@as(usize, 8), ring.free_count);
}
