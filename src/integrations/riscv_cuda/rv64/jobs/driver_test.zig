//! Request execution, capture, concurrency and publication on the fake device.
const std = @import("std");
const G = @import("gpu_native.zig");
const W = @import("worker.zig");
const F = @import("fake.zig");
const R = @import("driver_request.zig");
const D = @import("driver_dag.zig");
const C = @import("../m8_capture_stream.zig");
const T = @import("driver_fixture_test.zig");
const testing = std.testing;

test "D1: flat manifest needs no partials and still refuses an unset proof check" {
    var world = T.World{ .a = testing.allocator };
    var rig = try T.Rig.initWithPartials(&world, false);
    defer rig.deinit();
    var out = try rig.driver.serve(&T.request(801));
    // Seal + root/claims per segment; no unproduced partial flags.
    try testing.expectEqual(@as(u64, 7), out.receipt.peer_publishes);
    out.deinit();
    world.reset();
    world.skip_check = .public_claims;
    try testing.expectError(error.GpuNativeProofRejected, rig.driver.serve(&T.request(802)));
}

test "D1: one host wait and one slab D2H per GPU, no request-path allocation, byte-exact publication" {
    var world = T.World{ .a = testing.allocator };
    var rig = try T.Rig.init(&world);
    defer rig.deinit();
    const before = F.counters;
    var out = try rig.driver.serve(&T.request(41));
    defer out.deinit();
    const after = F.counters;
    try testing.expectEqual(@as(usize, 1), after.host_waits - before.host_waits);
    try testing.expectEqual(@as(usize, 2), after.d2h - before.d2h);
    try testing.expectEqual(@as(usize, 4), after.h2d - before.h2d); // header + directory per GPU
    try testing.expectEqual(@as(usize, 0), after.allocations - before.allocations);
    try testing.expectEqual(@as(u32, 1), out.receipt.host_waits);
    try testing.expectEqual(@as(u32, 2), out.receipt.d2h);
    try testing.expect(world.seal_ran);
    // 3 natives + 1 truth + 5 nodes; every job finished (no aborts).
    try testing.expectEqual(@as(usize, 9), out.proofs.len);
    try testing.expectEqual(@as(usize, 3 + 1 + 3 + 1 + 5), world.finished);
    try testing.expectEqual(@as(usize, 0), world.aborted);
    for (out.proofs) |p| {
        if (p.id.kind == .native_segment or p.id.kind == .truth) {
            try testing.expectEqual(@as(usize, T.encoded_bytes), p.bytes.len);
            for (p.bytes, 0..) |b, i| try testing.expectEqual(@as(u8, @truncate(i + p.id.ordinal * 7 + @intFromEnum(p.id.kind) * 31 + 41)), b);
        } else try testing.expectEqual(@as(usize, 32), p.bytes.len);
    }
    // Peer protocol: 2 slots per segment + 2 partials + the seal, each
    // copied (data + flag) to the other GPU.
    try testing.expectEqual(@as(u64, 3 * 2 + 2 + 1), out.receipt.peer_publishes);
    try testing.expectEqual(@as(u64, 2 * (3 * 2 + 2 + 1)), out.receipt.peer_copies);
}

test "D1: publish refuses an unset word, a reject code, an encoder overrun and a stale header" {
    var world = T.World{ .a = testing.allocator };
    var rig = try T.Rig.init(&world);
    defer rig.deinit();
    world.skip_check = .pcs_status;
    try testing.expectError(error.GpuNativeProofRejected, rig.driver.serve(&T.request(1)));
    world.reset();
    world.skip_check = null;
    world.reject_check = .composition_accept;
    try testing.expectError(error.GpuNativeProofRejected, rig.driver.serve(&T.request(2)));
    world.reset();
    world.reject_check = null;
    world.overrun = true;
    try testing.expectError(error.GpuNativeEncodedOverrun, rig.driver.serve(&T.request(3)));
    world.reset();
    world.overrun = false;
    world.stale_header = true;
    try testing.expectError(error.GpuNativeSlabHeaderMismatch, rig.driver.serve(&T.request(4)));
    world.reset();
    world.stale_header = false;
    var ok = try rig.driver.serve(&T.request(5));
    ok.deinit();
}

test "D1: two pipelined requests do not cross slabs" {
    var world = T.World{ .a = testing.allocator };
    var rig = try T.Rig.init(&world);
    defer rig.deinit();
    const r1 = T.request(10);
    const r2 = T.request(20);
    const f1 = try rig.driver.begin(&r1);
    world.reset();
    const f2 = try rig.driver.begin(&r2);
    try testing.expectError(error.GpuNativePipelineFull, rig.driver.begin(&T.request(30)));
    var o1 = try rig.driver.finish(f1);
    defer o1.deinit();
    var o2 = try rig.driver.finish(f2);
    defer o2.deinit();
    for (o1.proofs, o2.proofs) |p, q| if (p.id.kind == .native_segment) {
        try testing.expectEqual(@as(u8, @truncate(p.id.ordinal * 7 + 31 + 10)), p.bytes[0]);
        try testing.expectEqual(@as(u8, @truncate(q.id.ordinal * 7 + 31 + 20)), q.bytes[0]);
    };
}

test "D1: a class never warmed fails closed before any device work" {
    var world = T.World{ .a = testing.allocator };
    var rig = try T.Rig.init(&world);
    defer rig.deinit();
    const before = F.counters;
    var r = T.request(7);
    r.segment_rows = &.{ 1 << 10, 999, 1 << 9 };
    try testing.expectError(error.GpuNativeClassNotWarmed, rig.driver.serve(&r));
    try testing.expectEqual(before.host_waits, F.counters.host_waits);
    try testing.expectEqual(before.d2h, F.counters.d2h);
}

test "D1: capture releases Stage1 per sealed segment while capture continues" {
    var world = T.World{ .a = testing.allocator };
    var rig = try T.Rig.init(&world);
    defer rig.deinit();
    const cap = try C.Stream.create(testing.allocator, world.nativeFactory(), null, 8);
    defer cap.destroy();
    world.capture = cap;
    var r = T.request(9);
    r.capture = cap;
    // Capture starts before the request is planned (the service prepares the
    // stream first; chunks wait for the driver's bind).
    try cap.prepare(r.segment_rows);
    const t = try std.Thread.spawn(.{}, T.Capture.full, .{ cap, r.segment_rows });
    var out = try rig.driver.serve(&r);
    t.join();
    defer out.deinit();
    try testing.expectEqual(@as(usize, 3), world.chunks);
    try testing.expectEqual(@as(usize, 9), out.proofs.len);
    // A short capture poisons the unsealed Stage1s: the request fails closed.
    world.reset();
    const Short = struct {
        fn run(s: *C.Stream, rows: []const u64) void {
            const sink = s.sink();
            defer sink.done(sink.ctx, 1) catch {};
            sink.chunk(sink.ctx, .{ .segment = 0, .sequence = 0, .first_row = 0, .rows = @intCast(rows[0]), .last = true, .words = &.{} }) catch return;
            sink.sealed_segment(sink.ctx, 0, rows[0]) catch return;
        }
    };
    try cap.prepare(r.segment_rows);
    const t2 = try std.Thread.spawn(.{}, Short.run, .{ cap, r.segment_rows });
    try testing.expectError(error.BatchDependencyFailed, rig.driver.serve(&r));
    t2.join();
    // A capture whose geometry differs from the plan never reaches Stage1.
    world.reset();
    const Wrong = struct {
        fn run(s: *C.Stream) void {
            const sink = s.sink();
            defer sink.done(sink.ctx, 3) catch {};
            sink.chunk(sink.ctx, .{ .segment = 0, .sequence = 0, .first_row = 0, .rows = 4, .last = true, .words = &.{} }) catch return;
            sink.sealed_segment(sink.ctx, 0, 4) catch return;
        }
    };
    try cap.prepare(r.segment_rows);
    const t3 = try std.Thread.spawn(.{}, Wrong.run, .{cap});
    try testing.expectError(error.BatchDependencyFailed, rig.driver.serve(&r));
    t3.join();
    try testing.expect(cap.gate(0).failed.load(.acquire));
}

test "D1: a failed Stage1 with a ring smaller than the segment count fails closed instead of hanging" {
    var world = T.World{ .a = testing.allocator };
    var rig = try T.Rig.init(&world);
    defer rig.deinit();
    const ring = try C.Ring.init(testing.allocator, &F.ops.wait, 2, 16);
    defer ring.deinit();
    const cap = try C.Stream.create(testing.allocator, world.nativeFactory(), ring, 8);
    defer cap.destroy();
    world.capture = cap;
    var r = T.request(201);
    r.capture = cap;
    world.refuse_stage1 = 0;
    try cap.prepare(r.segment_rows);
    const t = try std.Thread.spawn(.{}, T.Capture.ringed, .{ cap, r.segment_rows });
    if (rig.driver.serve(&r)) |o| {
        var out = o;
        out.deinit();
        return error.TestExpectedRefusal;
    } else |err| try testing.expect(err == error.JobFootprintExceedsArena or err == error.BatchDependencyFailed);
    t.join();
    // Every ring buffer came back (no capture wedged, nothing leaked).
    try testing.expectEqual(@as(usize, 2), ring.free_count);
    // The next request through the same stream and ring proves.
    world.refuse_stage1 = null;
    world.reset();
    try cap.prepare(r.segment_rows);
    const t2 = try std.Thread.spawn(.{}, T.Capture.ringed, .{ cap, r.segment_rows });
    var ok = try rig.driver.serve(&r);
    t2.join();
    ok.deinit();
    try testing.expectEqual(@as(usize, 2), ring.free_count);
}

test "D1: a request whose segments all sit on one GPU proves (the idle GPU owns no partial)" {
    var world = T.World{ .a = testing.allocator };
    var rig = try T.Rig.init(&world);
    defer rig.deinit();
    const one = [_]D.RecursionNode{.{ .segments = &.{0} }};
    const r = R.Request{ .id = 301, .segment_rows = &.{1 << 10}, .recursion = &one, .root = 0 };
    var out = try rig.driver.serve(&r);
    defer out.deinit();
    try testing.expectEqual(@as(usize, 2), out.proofs.len);
    // seal + 1 partial + root + claims
    try testing.expectEqual(@as(u64, 4), out.receipt.peer_publishes);
}

test "D1: a failed begin never costs the pipeline a parity" {
    var world = T.World{ .a = testing.allocator };
    var rig = try T.Rig.init(&world);
    defer rig.deinit();
    const r1 = T.request(401);
    const f1 = try rig.driver.begin(&r1);
    var bad = T.request(402);
    bad.segment_rows = &.{ 1 << 10, 999, 1 << 9 };
    try testing.expectError(error.GpuNativeClassNotWarmed, rig.driver.begin(&bad));
    world.reset();
    const r3 = T.request(403);
    const f3 = try rig.driver.begin(&r3);
    var o1 = try rig.driver.finish(f1);
    o1.deinit();
    var o3 = try rig.driver.finish(f3);
    o3.deinit();
}

test "D1: teardown with a request in flight quiesces and aborts it" {
    var world = T.World{ .a = testing.allocator };
    var rig = try T.Rig.init(&world);
    _ = try rig.driver.begin(&T.request(501));
    rig.deinit();
    try testing.expectEqual(@as(usize, 3 + 1 + 3 + 1 + 5), world.aborted);
}

test "D1: install sizes main_resident per GPU from placement, and plans against measured memory" {
    var world = T.World{ .a = testing.allocator };
    var rig = try T.Rig.init(&world);
    // max_segments 8 on 2 GPUs: at most 4 segments' MAIN per GPU.
    for (rig.driver.resources.lanes) |l| try testing.expectEqual(@as(usize, 4 * T.main_words), l.main.words);
    rig.deinit();
    // A GPU another tenant holds: the plan refuses at install with the numbers.
    const saved = F.memory_free_bytes;
    defer F.memory_free_bytes = saved;
    F.memory_free_bytes = 4 << 10;
    const a = testing.allocator;
    var ws: [2]*W.Worker = undefined;
    ws[0] = try W.Worker.create(a, &F.ops, .{ .plan_from_env = false, .device = 0, .arena_words = 1 << 10, .pinned_slot_words = 1 << 10 });
    defer ws[0].destroy();
    ws[1] = try W.Worker.create(a, &F.ops, .{ .plan_from_env = false, .device = 1, .arena_words = 1 << 10, .pinned_slot_words = 1 << 10 });
    defer ws[1].destroy();
    try testing.expectError(error.GpuNativeMemoryPlanExceedsDevice, R.Driver.install(a, &F.ops, &F.peer, &ws, world.nativeFactory(), world.recursionFactory(), .{ .capacity_words = &.{ 1 << 20, 1 << 20 }, .max_segments = 8, .max_jobs_per_device = 32, .slab_words = 1 << 13, .reserve_words = 1 << 10, .graph_exec_words = 1 << 10, .arena_cap_words = 1 << 15 }));
}

test "worker: concurrent calls each get their own completion" {
    const a = testing.allocator;
    const w = try W.Worker.create(a, &F.ops, .{ .plan_from_env = false, .device = 0, .arena_words = 1 << 10, .pinned_slot_words = 1 << 10 });
    defer w.destroy();
    const Ctx = struct {
        value: u32,
        seen: u32 = 0,
        fn run(raw: *anyopaque, _: *W.Worker) anyerror!void {
            const c: *@This() = @ptrCast(@alignCast(raw));
            std.Thread.sleep(std.time.ns_per_ms);
            c.seen = c.value;
            if (c.value % 2 == 1) return error.OddCall;
        }
        fn caller(wk: *W.Worker, c: *@This(), out: *anyerror!void) void {
            out.* = wk.call(.{ .ctx = c, .run = run });
        }
    };
    var ctxs: [8]Ctx = undefined;
    var results: [8]anyerror!void = undefined;
    var threads: [8]std.Thread = undefined;
    for (&ctxs, 0..) |*c, i| c.* = .{ .value = @intCast(i + 1) };
    for (&threads, 0..) |*t, i| t.* = try std.Thread.spawn(.{}, Ctx.caller, .{ w, &ctxs[i], &results[i] });
    for (threads) |t| t.join();
    for (ctxs, results) |c, r| {
        try testing.expectEqual(c.value, c.seen);
        if (c.value % 2 == 1) try testing.expectError(error.OddCall, r) else try r;
    }
}

test "D1: a stale flag of the previous same-parity request never satisfies exchange_complete" {
    var world = T.World{ .a = testing.allocator };
    var rig = try T.Rig.init(&world);
    defer rig.deinit();
    // Generations 1 (parity 0) and 2 (parity 1) publish every flag.
    for ([_]u64{ 61, 62 }) |id| {
        world.reset();
        var o = try rig.driver.serve(&T.request(id));
        o.deinit();
    }
    // Generation 3 reuses parity 0, whose replica still holds generation 1's
    // flags (replicas are never zeroed per request). Device 1's partial is
    // withheld: only the tag tells the stale flag from a landed one.
    world.reset();
    world.withhold_partial = 1;
    try testing.expectError(error.GpuNativeProofRejected, rig.driver.serve(&T.request(63)));
    world.withhold_partial = null;
    world.reset();
    var ok = try rig.driver.serve(&T.request(64));
    ok.deinit();
}

test "D1: a Stage1 refused at stage poisons its dependents (the seal never enqueues)" {
    var world = T.World{ .a = testing.allocator };
    var rig = try T.Rig.init(&world);
    defer rig.deinit();
    world.refuse_stage1 = 1;
    // The first failed job in batch order names the request's error: the
    // refused Stage1 or a dependent poisoned by it (never a seal that ran).
    if (rig.driver.serve(&T.request(71))) |o| {
        var out = o;
        out.deinit();
        return error.TestExpectedRefusal;
    } else |err| try testing.expect(err == error.JobFootprintExceedsArena or err == error.BatchDependencyFailed);
    try testing.expect(!world.seal_enqueued);
    try testing.expect(!world.seal_ran);
    world.refuse_stage1 = null;
    world.reset();
    var ok = try rig.driver.serve(&T.request(72));
    ok.deinit();
    try testing.expect(world.seal_ran);
}

test "D1: plan phases keep stable arena epochs across requests; a plan worker never parks" {
    var world = T.World{ .a = testing.allocator };
    var rig = try T.Rig.init(&world);
    defer rig.deinit();
    var seen: [2]u64 = undefined;
    for (0..2) |i| {
        world.reset();
        var o = try rig.driver.serve(&T.request(80 + i));
        o.deinit();
        for (rig.workers, 0..) |w, d| {
            const e = w.planPhaseEpochs();
            try testing.expect(e[0] != 0 and e[1] != e[0]);
            const now = w.arenaEpoch();
            try testing.expect(now == e[0] or now == e[1]);
            if (i == 0) seen[d] = now else try testing.expectEqual(seen[d], now);
        }
    }
    try testing.expectError(error.WorkerPlanArenaInstalled, rig.workers[0].park(.{}));
}

test "D1: the installed hook sees the plan (main_resident, phase epochs) before the class cache seals" {
    var world = T.World{ .a = testing.allocator };
    const Hook = struct {
        fn installed(raw: *anyopaque, cache: *G.ClassCache, info: *const G.Installed) anyerror!void {
            const w: *T.World = @ptrCast(@alignCast(raw));
            w.installed_info = info.*;
            w.installed_sealed = cache.phase == .request;
            w.installed_cache = cache;
        }
    };
    var vt = T.World.native_vt;
    vt.installed = Hook.installed;
    const a = testing.allocator;
    var ws: [2]*W.Worker = undefined;
    ws[0] = try W.Worker.create(a, &F.ops, .{ .plan_from_env = false, .device = 0, .arena_words = 1 << 10, .pinned_slot_words = 1 << 10 });
    defer ws[0].destroy();
    ws[1] = try W.Worker.create(a, &F.ops, .{ .plan_from_env = false, .device = 1, .arena_words = 1 << 10, .pinned_slot_words = 1 << 10 });
    defer ws[1].destroy();
    const drv = try R.Driver.install(a, &F.ops, &F.peer, &ws, .{ .ctx = &world, .vtable = &vt }, world.recursionFactory(), .{ .capacity_words = &.{ 1 << 20, 1 << 20 }, .max_segments = 8, .max_jobs_per_device = 32, .slab_words = 1 << 13, .reserve_words = 1 << 10, .graph_exec_words = 1 << 10, .arena_cap_words = 1 << 15 });
    defer drv.deinit();
    const info = world.installed_info.?;
    try testing.expectEqual(@as(u32, 2), info.devices);
    try testing.expectEqual(false, world.installed_sealed.?);
    try testing.expectEqual(&drv.resources.classes, world.installed_cache.?);
    try testing.expect(drv.resources.classes.phase == .request);
    for (drv.resources.lanes, 0..) |l, d| {
        try testing.expectEqual(l.main.ptr, info.main_resident[d].ptr);
        try testing.expectEqual(ws[d].planPhaseEpochs(), info.arena_epochs[d]);
    }
}

test "D1: a capture stream is refused while the other in-flight request holds it; receipts are per request" {
    var world = T.World{ .a = testing.allocator };
    var rig = try T.Rig.init(&world);
    defer rig.deinit();
    const cap = try C.Stream.create(testing.allocator, world.nativeFactory(), null, 8);
    defer cap.destroy();
    var r1 = T.request(91);
    r1.capture = cap;
    try cap.prepare(r1.segment_rows);
    const t = try std.Thread.spawn(.{}, T.Capture.full, .{ cap, r1.segment_rows });
    const f1 = try rig.driver.begin(&r1);
    t.join();
    var r2 = T.request(92);
    r2.capture = cap;
    try testing.expectError(error.GpuNativeCaptureStreamInFlight, rig.driver.begin(&r2));
    world.reset();
    const f2 = try rig.driver.begin(&T.request(93));
    var o1 = try rig.driver.finish(f1);
    defer o1.deinit();
    var o2 = try rig.driver.finish(f2);
    defer o2.deinit();
    // Each receipt counts its own request's peer traffic (9 slots each),
    // although request 93 began before request 91 finished.
    try testing.expectEqual(@as(u64, 9), o1.receipt.peer_publishes);
    try testing.expectEqual(@as(u64, 9), o2.receipt.peer_publishes);
}

test "D1: streamed capture (Feed) + end-gated truth + stage-one region + publish hooks write the artifacts" {
    var world = T.World{ .a = testing.allocator, .stage_one = true, .truth_end = true };
    var rig = try T.Rig.init(&world);
    defer rig.deinit();
    const ring = try C.Ring.init(testing.allocator, &F.ops.wait, 4, 16);
    defer ring.deinit();
    const cap = try C.Stream.create(testing.allocator, world.nativeFactory(), ring, 8);
    defer cap.destroy();
    cap.recursion = world.recursionFactory();
    world.capture = cap;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var r = T.request(601);
    r.capture = cap;
    r.out = tmp.dir;
    r.block = 26235156;
    const before = F.counters;
    try cap.prepare(r.segment_rows);
    var out = blk: {
        const t = try std.Thread.spawn(.{}, T.feedCapture, .{ cap, r.segment_rows });
        defer t.join();
        break :blk try rig.driver.serve(&r);
    };
    defer out.deinit();
    try testing.expectEqual(@as(usize, 1), F.counters.host_waits - before.host_waits);
    try testing.expectEqual(@as(usize, 2), F.counters.d2h - before.d2h);
    try testing.expectEqual(@as(usize, 3), world.packs);
    try testing.expectEqual(@as(usize, 3), world.chunks);
    try testing.expectEqual(@as(usize, 1), world.captured_native);
    try testing.expectEqual(@as(usize, 1), world.captured_recursion);
    try testing.expectEqual(@as(u32, 1), out.receipt.capture_end_gated);
    try testing.expectEqual(@as(u64, T.stage_one_written), out.receipt.stage_one_bytes);
    // Native publishes before recursion; each exactly once.
    try testing.expectEqual([2]usize{ 1, 1 }, world.published);
    try testing.expect(world.publish_order[0] < world.publish_order[1]);
    const stage = try tmp.dir.readFileAlloc(testing.allocator, "stage-one.bin", 1 << 16);
    defer testing.allocator.free(stage);
    try testing.expectEqual(@as(usize, T.stage_one_written), stage.len);
    for (stage, 0..) |b, i| try testing.expectEqual(@as(u8, @truncate(i ^ 0x5a)), b);
    for (out.proofs) |p| if (p.id.kind == .native_segment) {
        var buf: [32]u8 = undefined;
        const bytes = try tmp.dir.readFileAlloc(testing.allocator, try std.fmt.bufPrint(&buf, "cpu-{d}.bin", .{p.id.ordinal}), 1 << 16);
        defer testing.allocator.free(bytes);
        try testing.expectEqualSlices(u8, p.bytes, bytes);
    };
    const root = try tmp.dir.readFileAlloc(testing.allocator, "recursion-om31/root.proof", 1 << 16);
    defer testing.allocator.free(root);
    try testing.expectEqual(@as(usize, 32), root.len);
    try testing.expectEqual(@as(usize, 4), ring.free_count);
}

test "D1: a stage-one region the seal never filled refuses publication; a failed capture fails the gated truth" {
    var world = T.World{ .a = testing.allocator, .stage_one = true, .truth_end = true, .stage_one_empty = true };
    var rig = try T.Rig.init(&world);
    defer rig.deinit();
    try testing.expectError(error.GpuNativeEncodedEmpty, rig.driver.serve(&T.request(611)));
    try testing.expectEqual([2]usize{ 0, 0 }, world.published);
    // The capture dies after segment 0: Stage1(1..2) and the truth fail closed.
    world.reset();
    world.stage_one_empty = false;
    const cap = try C.Stream.create(testing.allocator, world.nativeFactory(), null, 8);
    defer cap.destroy();
    world.capture = cap;
    var r = T.request(612);
    r.capture = cap;
    const Dies = struct {
        fn run(s: *C.Stream, rows: []const u64) void {
            var f = s.feed();
            f.segment(.{ .segment = 0, .native = &rows[0], .events = &rows[0] }) catch {};
            f.finish(error.CaptureCrashed);
        }
    };
    // The no-ring stream cannot hand out buffers: give the packer one.
    const ring = try C.Ring.init(testing.allocator, &F.ops.wait, 2, 16);
    defer ring.deinit();
    cap.ring = ring;
    try cap.prepare(r.segment_rows);
    const t = try std.Thread.spawn(.{}, Dies.run, .{ cap, r.segment_rows });
    try testing.expectError(error.BatchDependencyFailed, rig.driver.serve(&r));
    t.join();
    try testing.expect(cap.endGate().failed.load(.acquire));
    try testing.expectEqual([2]usize{ 0, 0 }, world.published);
    // The next request through the same stream proves.
    world.reset();
    try cap.prepare(r.segment_rows);
    const t2 = try std.Thread.spawn(.{}, T.feedCapture, .{ cap, r.segment_rows });
    var ok = try rig.driver.serve(&r);
    t2.join();
    ok.deinit();
}

test "D1: a capture that fails after its last seal (no end-gated job) refuses publication" {
    var world = T.World{ .a = testing.allocator, .stage_one = true };
    var rig = try T.Rig.init(&world);
    defer rig.deinit();
    const ring = try C.Ring.init(testing.allocator, &F.ops.wait, 4, 16);
    defer ring.deinit();
    const cap = try C.Stream.create(testing.allocator, world.nativeFactory(), ring, 8);
    defer cap.destroy();
    cap.recursion = world.recursionFactory();
    world.capture = cap;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var r = T.request(621);
    r.capture = cap;
    r.out = tmp.dir;
    const Late = struct {
        /// Every segment sealed and the end handed over; then GE's final
        /// checks fail (terminal state / collector equivalence).
        fn run(s: *C.Stream, rows: []const u64, skip_end: bool) void {
            var f = s.feed();
            for (rows, 0..) |*n, seg| f.segment(.{ .segment = @intCast(seg), .native = n, .events = n }) catch return f.finish(null);
            if (!skip_end) f.end(T.captureEnd(@intCast(rows.len))) catch {};
            f.finish(if (skip_end) null else error.EthereumTerminalMismatch);
        }
    };
    for ([_]bool{ false, true }) |skip_end| {
        world.reset();
        try cap.prepare(r.segment_rows);
        const t = try std.Thread.spawn(.{}, Late.run, .{ cap, r.segment_rows, skip_end });
        try testing.expectError(error.GpuNativeCaptureFailed, rig.driver.serve(&r));
        t.join();
        try testing.expectEqual([2]usize{ 0, 0 }, world.published);
        try testing.expectEqual(@as(usize, 4), ring.free_count);
    }
    // The next request through the same stream proves.
    world.reset();
    try cap.prepare(r.segment_rows);
    const t2 = try std.Thread.spawn(.{}, T.feedCapture, .{ cap, r.segment_rows });
    var ok = try rig.driver.serve(&r);
    t2.join();
    ok.deinit();
}

test "DAG: two-stage truths frame the seal (stage 1 before, stage 2 after, same GPU); leaves read stage 2" {
    const segs = [_]D.Segment{ .{}, .{} };
    const rec = [_]D.RecursionNode{ .{ .segments = &.{0} }, .{ .segments = &.{1}, .truths = &.{ 0, 1 } }, .{ .children = &.{ 0, 1 } } };
    var dag = try D.build(testing.allocator, .{ .devices = 2, .segments = &segs, .truths = &.{ .{}, .{} }, .truth_two_stage = true, .recursion = &rec, .root = 2 });
    defer dag.deinit();
    const seal = dag.nodes[dag.seal];
    try testing.expectEqual(@as(usize, 4), seal.deps.len);
    for (dag.truth, dag.truth2) |t1, t2| {
        try testing.expect(std.mem.indexOfScalar(u32, seal.deps, t1) != null);
        try testing.expect(dag.nodes[t1].proof == null);
        try testing.expectEqual(G.ProofKind.truth, dag.nodes[t2].proof.?.kind);
        try testing.expectEqual(dag.nodes[t1].device, dag.nodes[t2].device);
        try testing.expect(std.mem.indexOfScalar(u32, dag.nodes[t2].deps, dag.seal) != null);
        try testing.expect(std.mem.indexOfScalar(u32, dag.nodes[t2].deps, t1) != null);
    }
    const leaf = dag.nodes[dag.recursion[1]];
    for (dag.truth2) |t2| try testing.expect(std.mem.indexOfScalar(u32, leaf.deps, t2) != null);
    // Global order: both truth stage 1s before the seal, stage 2s after.
    const pos = struct {
        fn of(order: []const u32, n: u32) usize {
            return std.mem.indexOfScalar(u32, order, n).?;
        }
    };
    for (dag.truth, dag.truth2) |t1, t2| {
        try testing.expect(pos.of(dag.order, t1) < pos.of(dag.order, dag.seal));
        try testing.expect(pos.of(dag.order, t2) > pos.of(dag.order, dag.seal));
    }
    try testing.expectError(error.GpuNativeTruthStagesConflict, D.build(testing.allocator, .{ .devices = 2, .segments = &segs, .truths = &.{.{}}, .truth_two_stage = true, .truth_after_seal = true }));
}

test "D1: two-stage truths: roots exchanged before the seal, proofs after it, one host wait" {
    var world = T.World{ .a = testing.allocator, .two_stage = true };
    const a = testing.allocator;
    var ws: [2]*W.Worker = undefined;
    ws[0] = try W.Worker.create(a, &F.ops, .{ .plan_from_env = false, .device = 0, .arena_words = 1 << 10, .pinned_slot_words = 1 << 10 });
    defer ws[0].destroy();
    ws[1] = try W.Worker.create(a, &F.ops, .{ .plan_from_env = false, .device = 1, .arena_words = 1 << 10, .pinned_slot_words = 1 << 10 });
    defer ws[1].destroy();
    const drv = try R.Driver.install(a, &F.ops, &F.peer, &ws, world.nativeFactory(), .{ .ctx = &world, .vtable = &T.World.rec_vt2 }, .{ .capacity_words = &.{ 1 << 20, 1 << 20 }, .max_segments = 8, .max_truths = 4, .max_jobs_per_device = 32, .slab_words = 1 << 13, .reserve_words = 1 << 10, .graph_exec_words = 1 << 10, .arena_cap_words = 1 << 15 });
    defer drv.deinit();
    const before = F.counters;
    const rec = [_]D.RecursionNode{ .{ .segments = &.{0} }, .{ .segments = &.{1}, .truths = &.{ 0, 1 } }, .{ .children = &.{ 0, 1 } } };
    const r = R.Request{ .id = 701, .segment_rows = &.{ 1 << 10, 1 << 9 }, .truths = 2, .recursion = &rec, .root = 2 };
    var out = try drv.serve(&r);
    defer out.deinit();
    try testing.expectEqual(@as(usize, 1), F.counters.host_waits - before.host_waits);
    try testing.expectEqual(@as(usize, 2), F.counters.d2h - before.d2h);
    try testing.expect(world.seal_ran);
    var truths: usize = 0;
    for (out.proofs) |p| if (p.id.kind == .truth) {
        truths += 1;
        try testing.expectEqual(@as(usize, T.encoded_bytes), p.bytes.len);
    };
    try testing.expectEqual(@as(usize, 2), truths);
    // 2 segments x 2 slots + 2 partials + 2 truth roots + seal.
    try testing.expectEqual(@as(u64, 2 * 2 + 2 + 2 + 1), out.receipt.peer_publishes);
    // Too many truths for the install capacity fails before device work.
    const r5 = R.Request{ .id = 702, .segment_rows = &.{ 1 << 10, 1 << 9 }, .truths = 5, .recursion = &.{.{ .segments = &.{0} }}, .root = 0 };
    try testing.expectError(error.GpuNativeTruthsExceedPlan, drv.serve(&r5));
}

test {
    _ = @import("driver_service_test.zig");
}
