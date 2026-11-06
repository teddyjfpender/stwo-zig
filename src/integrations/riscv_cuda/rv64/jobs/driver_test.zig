//! D1 (rv64-m8-gpu-native.md §6.3): the GPU-native request driver on two fake
//! GPUs (fake.zig host device model) with fake native and recursion
//! factories that behave like device jobs: they write exchange slots, status
//! words and encoded proofs only through device views, publish/await peer
//! slots, and keep MAIN in the plan's main_resident region.
//!
//! Asserts: exactly ONE host wait and ONE slab D2H per GPU per request; zero
//! device allocations after install; the seal runs only after every root and
//! claims slot was awaited; publish refuses an unset word, a reject code, an
//! encoder overrun and a stale header; two pipelined requests do not cross
//! slabs; a class never warmed fails closed; capture gates release Stage1.
const std = @import("std");
const api = @import("api.zig");
const G = @import("gpu_native.zig");
const W = @import("worker.zig");
const F = @import("fake.zig");
const R = @import("driver_request.zig");
const D = @import("driver_dag.zig");
const C = @import("../m8_capture_stream.zig");

const testing = std.testing;

fn key(tag: u8) G.ClassKey {
    var k: G.ClassKey = @splat(0);
    k[0] = tag;
    return k;
}
const k_native = key(1);
const k_truth = key(2);
const k_leaf = key(3);
const k_fold = key(4);
const k_root = key(5);
const encoded_bytes = 96;
const main_words = 256;

fn noopDestroy(_: *anyopaque) void {}

/// A device job built from closures over host-model device memory.
const FakeJob = struct {
    a: std.mem.Allocator,
    kind: enum { stage1, seal, stage2, truth, node },
    ctx: *const G.RequestContext,
    world: *World,
    ordinal: u32,
    device: u32,
    id: ?G.ProofId = null,
    children: []const G.ProofId = &.{},
    aborted: bool = false,

    pub fn classKey(self: *FakeJob) [32]u8 {
        return switch (self.kind) {
            .stage1, .seal, .stage2 => k_native,
            .truth => k_truth,
            .node => if (self.id.?.kind == .leaf) k_leaf else if (self.id.?.kind == .fold) k_fold else k_root,
        };
    }
    pub fn footprint(_: *FakeJob) api.Footprint {
        return .{ .device_words = 256 };
    }
    pub fn stage(_: *FakeJob, _: *api.Stager) !void {}
    pub fn enqueue(self: *FakeJob, e: *api.Enqueue) !void {
        const w = self.world;
        const seg = self.ctx.segments[self.device];
        const layout = &self.ctx.layout.segments[self.device];
        const ex = self.ctx.exchange;
        const replica = seg.ptr + layout.exchange_offset;
        // Any arena use proves the job runs inside the plan arena.
        const scratch = try e.alloc(64);
        @memset(scratch.ptr[0..64], self.ordinal);
        switch (self.kind) {
            .stage1 => {
                if (w.capture) |cap| if (cap.sealed_rows[self.ordinal] == 0) return error.Stage1BeforeSeal;
                // MAIN stays resident in the plan region until Stage2.
                @memset(self.ctx.main_resident[self.ordinal].ptr[0..main_words], 0x4d00 + self.ordinal);
                const root = try ex.root(self.ordinal);
                for (replica[root.offset..][0..8], 0..) |*x, i| x.* = @intCast(self.ordinal * 100 + i);
                try self.ctx.peer.publish(self.device, root);
                const claims = try ex.claims(self.ordinal);
                for (replica[claims.offset..][0..claims.words], 0..) |*x, i| x.* = @intCast(self.ordinal * 1000 + i);
                try self.ctx.peer.publish(self.device, claims);
                // The device's chi/LogUp partial, once per GPU per request.
                if (!w.partial_done[self.device].swap(true, .acq_rel)) {
                    const part = try ex.partial(self.device);
                    @memset(replica[part.offset..][0..8], 0x9a + self.device);
                    try self.ctx.peer.publish(self.device, part);
                }
                const id = G.ProofId{ .kind = .native_segment, .ordinal = self.ordinal };
                for ([_]G.Check{ .witness_status, .binding_authority, .root_match }) |c| try self.verdict(id, c, G.Verdict.accepted);
                _ = w.stage1_done.fetchAdd(1, .acq_rel);
            },
            .seal => {
                // Every root/claims slot must have landed (await is the device wait).
                var acc: [8]u32 = @splat(0);
                for (0..ex.segments) |s| {
                    const src = self.ctx.segment_device[s];
                    try self.ctx.peer.awaitSlot(self.device, src, try ex.root(@intCast(s)));
                    try self.ctx.peer.awaitSlot(self.device, src, try ex.claims(@intCast(s)));
                    const root = try ex.root(@intCast(s));
                    for (&acc, replica[root.offset..][0..8]) |*x, y| x.* ^= y;
                }
                if (w.stage1_done.load(.acquire) != ex.segments) return error.SealBeforeStage1;
                const slot = ex.seal();
                @memcpy(replica[slot.offset..][0..8], &acc);
                try self.ctx.peer.publish(self.device, slot);
                try self.verdict(.{ .kind = .request, .ordinal = 0 }, .global_seal, G.Verdict.accepted);
                w.seal_ran = true;
            },
            .stage2 => {
                // The seal GPU is the driver's default seal device (0).
                try self.ctx.peer.awaitSlot(self.device, 0, ex.seal());
                const main = self.ctx.main_resident[self.ordinal].ptr[0..main_words];
                const intact = for (main) |x| {
                    if (x != 0x4d00 + self.ordinal) break false;
                } else true;
                const id = G.ProofId{ .kind = .native_segment, .ordinal = self.ordinal };
                const skip = w.skip_check;
                for ([_]G.Check{ .channel_order, .global_status, .composition_accept, .public_claims, .pcs_status }) |c| {
                    if (skip != null and skip.? == c and self.ordinal == 0) continue;
                    try self.verdict(id, c, if (w.reject_check != null and w.reject_check.? == c and self.ordinal == 0) G.Verdict.reject(c, 7) else G.Verdict.accepted);
                }
                try self.verdict(id, .oods_constraint, if (intact) G.Verdict.accepted else G.Verdict.reject(.oods_constraint, 2));
                try self.encode(id);
            },
            .truth => {
                const id = G.ProofId{ .kind = .truth, .ordinal = self.ordinal };
                for ([_]G.Check{ .channel_order, .truth_status, .pcs_status }) |c| try self.verdict(id, c, G.Verdict.accepted);
                try self.encode(id);
            },
            .node => {
                const id = self.id.?;
                // Children's encoded regions: own segment or the peer's (device order is the DAG's).
                var h = std.crypto.hash.blake2.Blake2s256.init(.{});
                for (self.children) |c| {
                    const at = findProof(self.ctx, c) orelse return error.ChildNotInLayout;
                    const region = try self.ctx.layout.segments[at].encodedBuffer(self.ctx.segments[at], c);
                    const len = region.ptr[0];
                    if (len == 0) return error.ChildNotEncoded;
                    if (len > (region.words - 1) * 4) return error.ChildOverrun;
                    h.update(std.mem.sliceAsBytes(region.ptr[1..region.words])[0..len]);
                }
                var digest: [32]u8 = undefined;
                h.final(&digest);
                for ([_]G.Check{ .channel_order, .seed_tape, .child_binding, .lookup_sum, .node_oods_constraint, .node_pcs_status }) |c| try self.verdict(id, c, G.Verdict.accepted);
                try self.encodeBytes(id, &digest);
            },
        }
        if (w.stale_header and self.kind == .seal) seg.ptr[2] ^= 1;
    }
    fn verdict(self: *FakeJob, id: G.ProofId, c: G.Check, v: u32) !void {
        const at = findProof(self.ctx, id) orelse return error.ProofNotInLayout;
        const word = try self.ctx.layout.segments[at].statusBuffer(self.ctx.segments[at], id, c);
        word.ptr[0] = v;
    }
    fn encode(self: *FakeJob, id: G.ProofId) !void {
        var bytes: [encoded_bytes]u8 = undefined;
        for (&bytes, 0..) |*b, i| b.* = @truncate(i + id.ordinal * 7 + @intFromEnum(id.kind) * 31 + self.ctx.request);
        try self.encodeBytes(id, &bytes);
    }
    fn encodeBytes(self: *FakeJob, id: G.ProofId, bytes: []const u8) !void {
        const region = try self.ctx.layout.segments[self.device].encodedBuffer(self.ctx.segments[self.device], id);
        const cap = (region.words - 1) * 4;
        const n: u32 = if (self.world.overrun and id.kind == .root) @intCast(cap + 4) else @intCast(bytes.len);
        @memcpy(std.mem.sliceAsBytes(region.ptr[1..region.words])[0..bytes.len], bytes);
        region.ptr[0] = n;
        // A lying encoder (overrun with an accepted bounds word): publish's own
        // length check must still refuse.
        try self.verdict(id, .encode_bounds, G.Verdict.accepted);
    }
    pub fn finish(self: *FakeJob, v: api.SlabView) !void {
        if (v.receipt.host_waits != 0) return error.PerJobHostWait;
        self.world.finished += 1;
        self.a.destroy(self);
    }
    pub fn abort(self: *FakeJob) void {
        self.world.aborted += 1;
        self.a.destroy(self);
    }
};

fn findProof(ctx: *const G.RequestContext, id: G.ProofId) ?usize {
    for (ctx.layout.segments, 0..) |s, d| if (s.find(id) != null) return d;
    return null;
}

const World = struct {
    a: std.mem.Allocator,
    stage1_done: std.atomic.Value(u32) = .init(0),
    partial_done: [2]std.atomic.Value(bool) = .{ .init(false), .init(false) },
    seal_ran: bool = false,
    finished: usize = 0,
    aborted: usize = 0,
    chunks: usize = 0,
    skip_check: ?G.Check = null,
    reject_check: ?G.Check = null,
    overrun: bool = false,
    stale_header: bool = false,
    capture: ?*C.Stream = null,

    fn reset(self: *World) void {
        self.stage1_done.store(0, .release);
        for (&self.partial_done) |*p| p.store(false, .release);
        self.seal_ran = false;
    }
    fn make(self: *World, kind: @FieldType(FakeJob, "kind"), ctx: *const G.RequestContext, ordinal: u32, device: u32, id: ?G.ProofId, children: []const G.ProofId) !api.Job {
        const j = try self.a.create(FakeJob);
        j.* = .{ .a = self.a, .kind = kind, .ctx = ctx, .world = self, .ordinal = ordinal, .device = device, .id = id, .children = children };
        return api.Job.from(FakeJob, j);
    }

    // native factory
    fn nativeFactory(self: *World) G.NativeFactory {
        return .{ .ctx = self, .vtable = &native_vt };
    }
    const native_vt = G.NativeFactory.VTable{ .warm = nWarm, .class_of = nClass, .stage1 = nStage1, .stage2 = nStage2, .seal = nSeal, .chunk = nChunk };
    fn of(raw: *anyopaque) *World {
        return @ptrCast(@alignCast(raw));
    }
    fn build(_: *anyopaque, _: std.mem.Allocator, k: G.ClassKey) anyerror!G.ClassEntry {
        return .{ .key = k, .plan = @ptrFromInt(8), .destroy = noopDestroy, .max_encoded_bytes = encoded_bytes, .main_resident_words = if (k[0] == 1) main_words else 0, .claims_per_segment = if (k[0] == 1) 2 else 0, .cost_us = if (k[0] == 1) 10 else 3 };
    }
    fn nWarm(raw: *anyopaque, cache: *G.ClassCache) anyerror!void {
        _ = try cache.warm(k_native, .{ .ctx = raw, .build = build });
    }
    fn nClass(_: *anyopaque, _: u32, rows: u64) anyerror!G.ClassKey {
        return if (rows == 999) key(99) else k_native;
    }
    fn nStage1(raw: *anyopaque, ctx: *const G.RequestContext, s: u32, d: u32) anyerror!api.Job {
        return of(raw).make(.stage1, ctx, s, d, null, &.{});
    }
    fn nStage2(raw: *anyopaque, ctx: *const G.RequestContext, s: u32, d: u32) anyerror!api.Job {
        return of(raw).make(.stage2, ctx, s, d, .{ .kind = .native_segment, .ordinal = s }, &.{});
    }
    fn nSeal(raw: *anyopaque, ctx: *const G.RequestContext, d: u32) anyerror!api.Job {
        return of(raw).make(.seal, ctx, 0, d, null, &.{});
    }
    fn nChunk(raw: *anyopaque, _: *const G.RequestContext, _: G.TraceChunk, _: u32) anyerror!void {
        of(raw).chunks += 1;
    }

    // recursion factory
    fn recursionFactory(self: *World) G.RecursionFactory {
        return .{ .ctx = self, .vtable = &rec_vt };
    }
    const rec_vt = G.RecursionFactory.VTable{ .warm = rWarm, .class_of = rClass, .truth = rTruth, .node = rNode };
    fn rWarm(raw: *anyopaque, cache: *G.ClassCache) anyerror!void {
        for ([_]G.ClassKey{ k_truth, k_leaf, k_fold, k_root }) |k| _ = try cache.warm(k, .{ .ctx = raw, .build = build });
    }
    fn rClass(_: *anyopaque, id: G.ProofId) anyerror!G.ClassKey {
        return switch (id.kind) {
            .truth => k_truth,
            .leaf => k_leaf,
            .fold => k_fold,
            .root => k_root,
            else => error.NotARecursionProof,
        };
    }
    fn rTruth(raw: *anyopaque, ctx: *const G.RequestContext, t: u32, d: u32) anyerror!api.Job {
        return of(raw).make(.truth, ctx, t, d, .{ .kind = .truth, .ordinal = t }, &.{});
    }
    fn rNode(raw: *anyopaque, ctx: *const G.RequestContext, id: G.ProofId, children: []const G.ProofId, d: u32) anyerror!api.Job {
        return of(raw).make(.node, ctx, id.ordinal, d, id, children);
    }
};

const Rig = struct {
    workers: [2]*W.Worker,
    world: *World,
    driver: *R.Driver,
    fn init(world: *World) !Rig {
        const a = testing.allocator;
        var ws: [2]*W.Worker = undefined;
        ws[0] = try W.Worker.create(a, &F.ops, .{ .plan_from_env = false, .device = 0, .arena_words = 1 << 10, .pinned_slot_words = 1 << 10 });
        errdefer ws[0].destroy();
        ws[1] = try W.Worker.create(a, &F.ops, .{ .plan_from_env = false, .device = 1, .arena_words = 1 << 10, .pinned_slot_words = 1 << 10 });
        errdefer ws[1].destroy();
        const drv = try R.Driver.install(a, &F.ops, &F.peer, &ws, world.nativeFactory(), world.recursionFactory(), .{ .capacity_words = &.{ 1 << 20, 1 << 20 }, .max_segments = 8, .max_jobs_per_device = 32, .slab_words = 1 << 13, .reserve_words = 1 << 10, .graph_exec_words = 1 << 10, .arena_cap_words = 1 << 15 });
        return .{ .workers = ws, .world = world, .driver = drv };
    }
    fn deinit(self: *Rig) void {
        self.driver.deinit();
        for (self.workers) |w| w.destroy();
    }
};

// 3 segments, 1 truth; leaves: {s0}, {s1}, {s2, t0}; folds (0,1) -> 3; root (3,2) -> 4.
const topology = [_]D.RecursionNode{ .{ .segments = &.{0} }, .{ .segments = &.{1} }, .{ .segments = &.{2}, .truths = &.{0} }, .{ .children = &.{ 0, 1 } }, .{ .children = &.{ 3, 2 } } };

fn request(id: u64) R.Request {
    return .{ .id = id, .segment_rows = &.{ 1 << 10, 1 << 10, 1 << 9 }, .truths = 1, .recursion = &topology, .root = 4 };
}

test "D1: one host wait and one slab D2H per GPU, no request-path allocation, byte-exact publication" {
    var world = World{ .a = testing.allocator };
    var rig = try Rig.init(&world);
    defer rig.deinit();
    const before = F.counters;
    var out = try rig.driver.serve(&request(41));
    defer out.deinit();
    const after = F.counters;
    try testing.expectEqual(@as(usize, 1), after.host_waits - before.host_waits);
    try testing.expectEqual(@as(usize, 2), after.d2h - before.d2h);
    try testing.expectEqual(@as(usize, 2), after.h2d - before.h2d); // the two prefix uploads
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
            try testing.expectEqual(@as(usize, encoded_bytes), p.bytes.len);
            for (p.bytes, 0..) |b, i| try testing.expectEqual(@as(u8, @truncate(i + p.id.ordinal * 7 + @intFromEnum(p.id.kind) * 31 + 41)), b);
        } else try testing.expectEqual(@as(usize, 32), p.bytes.len);
    }
    // Peer protocol: 2 slots per segment + 2 partials + the seal, each
    // copied (data + flag) to the other GPU.
    try testing.expectEqual(@as(u64, 3 * 2 + 2 + 1), out.receipt.peer_publishes);
    try testing.expectEqual(@as(u64, 2 * (3 * 2 + 2 + 1)), out.receipt.peer_copies);
}

test "D1: publish refuses an unset word, a reject code, an encoder overrun and a stale header" {
    var world = World{ .a = testing.allocator };
    var rig = try Rig.init(&world);
    defer rig.deinit();
    world.skip_check = .pcs_status;
    try testing.expectError(error.GpuNativeProofRejected, rig.driver.serve(&request(1)));
    world.reset();
    world.skip_check = null;
    world.reject_check = .composition_accept;
    try testing.expectError(error.GpuNativeProofRejected, rig.driver.serve(&request(2)));
    world.reset();
    world.reject_check = null;
    world.overrun = true;
    try testing.expectError(error.GpuNativeEncodedOverrun, rig.driver.serve(&request(3)));
    world.reset();
    world.overrun = false;
    world.stale_header = true;
    try testing.expectError(error.GpuNativeSlabHeaderMismatch, rig.driver.serve(&request(4)));
    world.reset();
    world.stale_header = false;
    var ok = try rig.driver.serve(&request(5));
    ok.deinit();
}

test "D1: two pipelined requests do not cross slabs" {
    var world = World{ .a = testing.allocator };
    var rig = try Rig.init(&world);
    defer rig.deinit();
    const r1 = request(10);
    const r2 = request(20);
    const f1 = try rig.driver.begin(&r1);
    world.reset();
    const f2 = try rig.driver.begin(&r2);
    try testing.expectError(error.GpuNativePipelineFull, rig.driver.begin(&request(30)));
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
    var world = World{ .a = testing.allocator };
    var rig = try Rig.init(&world);
    defer rig.deinit();
    const before = F.counters;
    var r = request(7);
    r.segment_rows = &.{ 1 << 10, 999, 1 << 9 };
    try testing.expectError(error.GpuNativeClassNotWarmed, rig.driver.serve(&r));
    try testing.expectEqual(before.host_waits, F.counters.host_waits);
    try testing.expectEqual(before.d2h, F.counters.d2h);
}

test "D1: capture releases Stage1 per sealed segment while capture continues" {
    var world = World{ .a = testing.allocator };
    var rig = try Rig.init(&world);
    defer rig.deinit();
    const cap = try C.Stream.create(testing.allocator, world.nativeFactory(), null, 8);
    defer cap.destroy();
    world.capture = cap;
    var r = request(9);
    r.capture = cap;
    const Capture = struct {
        fn run(s: *C.Stream) void {
            const sink = s.sink();
            for (0..3) |seg| {
                std.Thread.sleep(2 * std.time.ns_per_ms);
                const words = [_]u32{ 1, 2, 3, 4 };
                sink.chunk(sink.ctx, .{ .segment = @intCast(seg), .sequence = 0, .first_row = 0, .rows = 4, .last = true, .words = &words }) catch return;
                sink.sealed_segment(sink.ctx, @intCast(seg), 4) catch return;
            }
            sink.done(sink.ctx, 3) catch {};
        }
    };
    // Capture starts before the request is planned (its chunks wait for attach).
    const t = try std.Thread.spawn(.{}, Capture.run, .{cap});
    var out = try rig.driver.serve(&r);
    t.join();
    defer out.deinit();
    try testing.expectEqual(@as(usize, 3), world.chunks);
    try testing.expectEqual(@as(usize, 9), out.proofs.len);
    // A short capture poisons the unsealed Stage1s: the request fails closed.
    world.reset();
    const Short = struct {
        fn run(s: *C.Stream) void {
            const sink = s.sink();
            sink.sealed_segment(sink.ctx, 0, 4) catch return;
            sink.done(sink.ctx, 1) catch {};
        }
    };
    const t2 = try std.Thread.spawn(.{}, Short.run, .{cap});
    try testing.expectError(error.BatchDependencyFailed, rig.driver.serve(&r));
    t2.join();
}
