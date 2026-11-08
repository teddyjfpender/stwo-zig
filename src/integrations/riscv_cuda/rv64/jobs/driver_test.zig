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
const S = @import("driver_serve.zig");

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
const stage_one_written = 300;
/// Generations a test runs at most (fake per-request state slots).
const gens = 64;
const main_words = 256;

fn noopDestroy(_: *anyopaque) void {}

/// A device job built from closures over host-model device memory.
const FakeJob = struct {
    a: std.mem.Allocator,
    kind: enum { stage1, seal, stage2, truth, node, truth2 },
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
            .truth, .truth2 => k_truth,
            .node => if (self.id.?.kind == .leaf) k_leaf else if (self.id.?.kind == .fold) k_fold else k_root,
        };
    }
    pub fn footprint(self: *FakeJob) api.Footprint {
        // A footprint the arena can never hold: the worker refuses at stage.
        if (self.kind == .stage1 and self.world.refuse_stage1 != null and self.world.refuse_stage1.? == self.ordinal) return .{ .device_words = 1 << 30 };
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
                if (ex.hasPartial(self.device) and !w.partial_done[self.ctx.generation % gens][self.device].swap(true, .acq_rel) and !(w.withhold_partial != null and w.withhold_partial.? == self.device)) {
                    const part = try ex.partial(self.device);
                    @memset(replica[part.offset..][0..8], 0x9a + self.device);
                    try self.ctx.peer.publish(self.device, part);
                }
                const id = G.ProofId{ .kind = .native_segment, .ordinal = self.ordinal };
                for ([_]G.Check{ .witness_status, .binding_authority, .root_match }) |c| try self.verdict(id, c, G.Verdict.accepted);
                _ = w.stage1_done[self.ctx.generation % gens].fetchAdd(1, .acq_rel);
            },
            .seal => {
                w.seal_enqueued = true;
                // Every root/claims slot must have landed (await is the device wait).
                var acc: [8]u32 = @splat(0);
                for (0..ex.segments) |s| {
                    const src = self.ctx.segment_device[s];
                    try self.ctx.peer.awaitSlot(self.device, src, try ex.root(@intCast(s)));
                    try self.ctx.peer.awaitSlot(self.device, src, try ex.claims(@intCast(s)));
                    const root = try ex.root(@intCast(s));
                    for (&acc, replica[root.offset..][0..8]) |*x, y| x.* ^= y;
                }
                if (w.stage1_done[self.ctx.generation % gens].load(.acquire) != ex.segments) return error.SealBeforeStage1;
                // Two-stage truths: the seal frames every truth's MAIN root.
                for (0..ex.truths) |t| {
                    const tr = try ex.truthRoot(@intCast(t));
                    try self.ctx.peer.awaitSlot(self.device, w.truth_device[t], tr);
                    if (replica[tr.offset] != 0x7700 + t) return error.SealWithoutTruthRoot;
                    for (&acc, replica[tr.offset..][0..8]) |*x, y| x.* ^= y;
                }
                const slot = ex.seal();
                @memcpy(replica[slot.offset..][0..8], &acc);
                try self.ctx.peer.publish(self.device, slot);
                try self.verdict(.{ .kind = .request, .ordinal = 0 }, .global_seal, G.Verdict.accepted);
                // Stage-one bytes into the request pseudo-proof's region.
                if (w.stage_one) {
                    const rid = G.ProofId{ .kind = .request, .ordinal = 0 };
                    const region = try layout.encodedBuffer(seg, rid);
                    const bytes = std.mem.sliceAsBytes(region.ptr[1..region.words]);
                    for (bytes[0..stage_one_written], 0..) |*b, i| b.* = @truncate(i ^ 0x5a);
                    if (!w.stage_one_empty) region.ptr[0] = stage_one_written;
                }
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
            .truth2 => {
                try self.ctx.peer.awaitSlot(self.device, 0, ex.seal());
                if (w.truth1_done.load(.acquire) & (@as(u32, 1) << @intCast(self.ordinal)) == 0) return error.TruthStage2BeforeStage1;
                const id = G.ProofId{ .kind = .truth, .ordinal = self.ordinal };
                for ([_]G.Check{ .channel_order, .truth_status, .pcs_status }) |c| try self.verdict(id, c, G.Verdict.accepted);
                try self.encode(id);
            },
            .truth => if (w.two_stage) {
                if (w.seal_ran) return error.TruthStage1AfterSeal;
                const tr = try ex.truthRoot(self.ordinal);
                for (replica[tr.offset..][0..8], 0..) |*x, i| x.* = @intCast(0x7700 + self.ordinal + i * 0x10000);
                w.truth_device[self.ordinal] = self.device;
                try self.ctx.peer.publish(self.device, tr);
                _ = w.truth1_done.fetchOr(@as(u32, 1) << @intCast(self.ordinal), .acq_rel);
            } else {
                if (w.truth_end) if (w.capture) |cap| if (!cap.endGate().recorded.isSet()) return error.TruthBeforeCaptureEnd;
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
        self.poisonAndFree();
    }
    pub fn abort(self: *FakeJob) void {
        self.world.aborted += 1;
        self.poisonAndFree();
    }
    /// A job may free itself in finish/abort: poison first so any later touch
    /// by the worker (e.g. classKey) panics on an invalid enum in Debug.
    fn poisonAndFree(self: *FakeJob) void {
        const a = self.a;
        @memset(std.mem.asBytes(self), 0xaa);
        a.destroy(self);
    }
};

fn findProof(ctx: *const G.RequestContext, id: G.ProofId) ?usize {
    for (ctx.layout.segments, 0..) |s, d| if (s.find(id) != null) return d;
    return null;
}

const World = struct {
    a: std.mem.Allocator,
    /// Per request generation (two requests may be in flight).
    stage1_done: [gens]std.atomic.Value(u32) = @splat(.init(0)),
    partial_done: [gens][2]std.atomic.Value(bool) = @splat(.{ .init(false), .init(false) }),
    seal_ran: bool = false,
    finished: usize = 0,
    aborted: usize = 0,
    chunks: usize = 0,
    skip_check: ?G.Check = null,
    reject_check: ?G.Check = null,
    overrun: bool = false,
    stale_header: bool = false,
    /// Device whose chi partial is never published (nobody awaits partials:
    /// only Check.exchange_complete can notice).
    withhold_partial: ?u32 = null,
    /// Segment whose Stage1 the worker refuses at stage (footprint > arena).
    refuse_stage1: ?u32 = null,
    seal_enqueued: bool = false,
    installed_info: ?G.Installed = null,
    installed_sealed: ?bool = null,
    capture: ?*C.Stream = null,
    /// Native classes declare a stage-one share; the seal encodes it.
    stage_one: bool = false,
    stage_one_empty: bool = false,
    /// Truth classes need the capture's end (gated on Stream.endGate).
    truth_end: bool = false,
    packs: usize = 0,
    captured_native: usize = 0,
    captured_recursion: usize = 0,
    published: [2]usize = .{ 0, 0 },
    publish_order: [2]u8 = .{ 0, 0 },
    publish_at: u8 = 0,
    /// Two-stage truths (RecursionFactory.truth_stage2 bound).
    two_stage: bool = false,
    truth_device: [8]u32 = @splat(0),
    truth1_done: std.atomic.Value(u32) = .init(0),

    fn reset(self: *World) void {
        for (&self.stage1_done) |*x| x.store(0, .release);
        for (&self.partial_done) |*g| for (g) |*p| p.store(false, .release);
        self.seal_ran = false;
        self.seal_enqueued = false;
        self.truth1_done.store(0, .release);
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
    const native_vt = G.NativeFactory.VTable{ .warm = nWarm, .class_of = nClass, .stage1 = nStage1, .stage2 = nStage2, .seal = nSeal, .chunk = nChunk, .pack = nPack, .captured = nCaptured, .publish = nPublish, .shape = nShape };
    fn nShape(_: *anyopaque, a: std.mem.Allocator, wb: G.WarmBlock) anyerror![]u64 {
        // The warm capture's segment count; the block number picks the rows.
        const rows = try a.alloc(u64, wb.capture.segments);
        for (rows, 0..) |*r, i| r.* = if (i + 1 == rows.len) 1 << 9 else 1 << 10;
        return rows;
    }
    fn of(raw: *anyopaque) *World {
        return @ptrCast(@alignCast(raw));
    }
    fn build(raw: *anyopaque, _: std.mem.Allocator, k: G.ClassKey) anyerror!G.ClassEntry {
        const w = of(raw);
        return .{ .key = k, .plan = @ptrFromInt(8), .destroy = noopDestroy, .max_encoded_bytes = encoded_bytes, .main_resident_words = if (k[0] == 1) main_words else 0, .claims_per_segment = if (k[0] == 1) 2 else 0, .cost_us = if (k[0] == 1) 10 else 3, .stage_one_bytes = if (k[0] == 1 and w.stage_one) 100 else 0, .needs_capture_end = k[0] == 2 and w.truth_end };
    }
    /// One chunk per segment through the ring writer; the native tag is the rows.
    fn nPack(raw: *anyopaque, _: *const G.RequestContext, cs: G.CapturedSegment, wr: G.ChunkWriter) anyerror!u64 {
        const rows: *const u64 = @ptrCast(@alignCast(cs.native));
        const b = try wr.next();
        b[0] = cs.segment;
        try wr.put(1, @intCast(rows.*), true);
        of(raw).packs += 1;
        return rows.*;
    }
    fn nCaptured(raw: *anyopaque, _: *const G.RequestContext, _: G.CaptureEnd) anyerror!void {
        of(raw).captured_native += 1;
    }
    fn nPublish(raw: *anyopaque, ctx: *const G.RequestContext, p: G.Publication) anyerror!void {
        const w = of(raw);
        w.published[0] += 1;
        w.publish_at += 1;
        w.publish_order[0] = w.publish_at;
        var buf: [32]u8 = undefined;
        for (p.proofs) |v| switch (v.id.kind) {
            .native_segment => try p.dir.writeFile(.{ .sub_path = try std.fmt.bufPrint(&buf, "cpu-{d}.bin", .{v.id.ordinal}), .data = v.bytes }),
            .request => try p.dir.writeFile(.{ .sub_path = "stage-one.bin", .data = v.bytes }),
            else => {},
        };
        // The final replica holds every segment's claims slot.
        for (0..ctx.exchange.segments) |seg| {
            const slot = try ctx.exchange.claims(@intCast(seg));
            if (p.exchange[slot.offset] != seg * 1000) return error.ClaimsNotInExchange;
        }
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
    const rec_vt = G.RecursionFactory.VTable{ .warm = rWarm, .class_of = rClass, .truth = rTruth, .node = rNode, .captured = rCaptured, .publish = rPublish, .shape = rShape };
    fn rShape(_: *anyopaque, _: G.WarmBlock, keys: []const G.ClassKey) anyerror!G.RecursionShape {
        for (keys) |k| if (!std.mem.eql(u8, &k, &k_native)) return error.UnexpectedNativeClass;
        return .{ .truths = 1, .fold_arity = 2 };
    }
    const rec_vt2 = blk: {
        var v = rec_vt;
        v.truth_stage2 = rTruth2;
        break :blk v;
    };
    fn rTruth2(raw: *anyopaque, ctx: *const G.RequestContext, t: u32, d: u32) anyerror!api.Job {
        return of(raw).make(.truth2, ctx, t, d, .{ .kind = .truth, .ordinal = t }, &.{});
    }
    fn rCaptured(raw: *anyopaque, _: *const G.RequestContext, _: G.CaptureEnd) anyerror!void {
        of(raw).captured_recursion += 1;
    }
    fn rPublish(raw: *anyopaque, _: *const G.RequestContext, p: G.Publication) anyerror!void {
        const w = of(raw);
        w.published[1] += 1;
        w.publish_at += 1;
        w.publish_order[1] = w.publish_at;
        var buf: [32]u8 = undefined;
        try p.dir.makePath("recursion-om31");
        for (p.proofs) |v| switch (v.id.kind) {
            .truth => try p.dir.writeFile(.{ .sub_path = try std.fmt.bufPrint(&buf, "truth-{d}.bin", .{v.id.ordinal}), .data = v.bytes }),
            .leaf, .fold => try p.dir.writeFile(.{ .sub_path = try std.fmt.bufPrint(&buf, "recursion-om31/node-{d:0>6}.proof", .{v.id.ordinal}), .data = v.bytes }),
            .root => try p.dir.writeFile(.{ .sub_path = "recursion-om31/root.proof", .data = v.bytes }),
            else => {},
        };
    }
    fn rWarm(raw: *anyopaque, cache: *G.ClassCache) anyerror!void {
        for ([_]G.ClassKey{ k_truth, k_leaf, k_fold, k_root }) |k| _ = try cache.warm(k, .{ .ctx = raw, .build = build });
    }
    fn rClass(_: *anyopaque, id: G.ProofId, _: []const G.ClassKey) anyerror!G.ClassKey {
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
        return initWithPartials(world, true);
    }
    fn initWithPartials(world: *World, partials: bool) !Rig {
        const a = testing.allocator;
        var ws: [2]*W.Worker = undefined;
        ws[0] = try W.Worker.create(a, &F.ops, .{ .plan_from_env = false, .device = 0, .arena_words = 1 << 10, .pinned_slot_words = 1 << 10 });
        errdefer ws[0].destroy();
        ws[1] = try W.Worker.create(a, &F.ops, .{ .plan_from_env = false, .device = 1, .arena_words = 1 << 10, .pinned_slot_words = 1 << 10 });
        errdefer ws[1].destroy();
        const drv = try R.Driver.install(a, &F.ops, &F.peer, &ws, world.nativeFactory(), world.recursionFactory(), .{ .capacity_words = &.{ 1 << 20, 1 << 20 }, .max_segments = 8, .exchange_partials = partials, .max_jobs_per_device = 32, .slab_words = 1 << 13, .reserve_words = 1 << 10, .graph_exec_words = 1 << 10, .arena_cap_words = 1 << 15, .stage_one_base_bytes = 512 });
        return .{ .workers = ws, .world = world, .driver = drv };
    }
    fn deinit(self: *Rig) void {
        self.driver.deinit();
        for (self.workers) |w| w.destroy();
    }
};

// 3 segments, 1 truth; leaves: {s0}, {s1}, {s2, t0}; folds (0,1) -> 3; root (3,2) -> 4.
const topology = [_]D.RecursionNode{ .{ .segments = &.{0} }, .{ .segments = &.{1} }, .{ .segments = &.{2}, .truths = &.{0} }, .{ .children = &.{ 0, 1 } }, .{ .children = &.{ 3, 2 } } };

test "D1: flat manifest needs no partials and still refuses an unset proof check" {
    var world = World{ .a = testing.allocator };
    var rig = try Rig.initWithPartials(&world, false);
    defer rig.deinit();
    var out = try rig.driver.serve(&request(801));
    // Seal + root/claims per segment; no unproduced partial flags.
    try testing.expectEqual(@as(u64, 7), out.receipt.peer_publishes);
    out.deinit();
    world.reset();
    world.skip_check = .public_claims;
    try testing.expectError(error.GpuNativeProofRejected, rig.driver.serve(&request(802)));
}

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
    // Capture starts before the request is planned (the service prepares the
    // stream first; chunks wait for the driver's bind).
    try cap.prepare(r.segment_rows);
    const t = try std.Thread.spawn(.{}, Capture.full, .{ cap, r.segment_rows });
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

const Capture = struct {
    /// A complete capture of `rows` (one chunk per segment), `done` on every path.
    fn full(s: *C.Stream, rows: []const u64) void {
        const sink = s.sink();
        defer sink.done(sink.ctx, @intCast(rows.len)) catch {};
        for (rows, 0..) |n, seg| {
            std.Thread.sleep(2 * std.time.ns_per_ms);
            const words = [_]u32{ 1, 2, 3, 4 };
            sink.chunk(sink.ctx, .{ .segment = @intCast(seg), .sequence = 0, .first_row = 0, .rows = @intCast(n), .last = true, .words = &words }) catch return;
            sink.sealed_segment(sink.ctx, @intCast(seg), n) catch return;
        }
    }
    /// The same through the capture ring: one pinned buffer per segment.
    fn ringed(s: *C.Stream, rows: []const u64) void {
        const sink = s.sink();
        defer sink.done(sink.ctx, @intCast(rows.len)) catch {};
        for (rows, 0..) |n, seg| {
            const buf = s.acquire(@intCast(seg)) catch return;
            sink.chunk(sink.ctx, .{ .segment = @intCast(seg), .sequence = 0, .first_row = 0, .rows = @intCast(n), .last = true, .words = buf[0..4] }) catch return;
            sink.sealed_segment(sink.ctx, @intCast(seg), n) catch return;
        }
    }
};

test "D1: a failed Stage1 with a ring smaller than the segment count fails closed instead of hanging" {
    var world = World{ .a = testing.allocator };
    var rig = try Rig.init(&world);
    defer rig.deinit();
    const ring = try C.Ring.init(testing.allocator, &F.ops.wait, 2, 16);
    defer ring.deinit();
    const cap = try C.Stream.create(testing.allocator, world.nativeFactory(), ring, 8);
    defer cap.destroy();
    world.capture = cap;
    var r = request(201);
    r.capture = cap;
    world.refuse_stage1 = 0;
    try cap.prepare(r.segment_rows);
    const t = try std.Thread.spawn(.{}, Capture.ringed, .{ cap, r.segment_rows });
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
    const t2 = try std.Thread.spawn(.{}, Capture.ringed, .{ cap, r.segment_rows });
    var ok = try rig.driver.serve(&r);
    t2.join();
    ok.deinit();
    try testing.expectEqual(@as(usize, 2), ring.free_count);
}

test "D1: a request whose segments all sit on one GPU proves (the idle GPU owns no partial)" {
    var world = World{ .a = testing.allocator };
    var rig = try Rig.init(&world);
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
    var world = World{ .a = testing.allocator };
    var rig = try Rig.init(&world);
    defer rig.deinit();
    const r1 = request(401);
    const f1 = try rig.driver.begin(&r1);
    var bad = request(402);
    bad.segment_rows = &.{ 1 << 10, 999, 1 << 9 };
    try testing.expectError(error.GpuNativeClassNotWarmed, rig.driver.begin(&bad));
    world.reset();
    const r3 = request(403);
    const f3 = try rig.driver.begin(&r3);
    var o1 = try rig.driver.finish(f1);
    o1.deinit();
    var o3 = try rig.driver.finish(f3);
    o3.deinit();
}

test "D1: teardown with a request in flight quiesces and aborts it" {
    var world = World{ .a = testing.allocator };
    var rig = try Rig.init(&world);
    _ = try rig.driver.begin(&request(501));
    rig.deinit();
    try testing.expectEqual(@as(usize, 3 + 1 + 3 + 1 + 5), world.aborted);
}

test "D1: install sizes main_resident per GPU from placement, and plans against measured memory" {
    var world = World{ .a = testing.allocator };
    var rig = try Rig.init(&world);
    // max_segments 8 on 2 GPUs: at most 4 segments' MAIN per GPU.
    for (rig.driver.lanes) |l| try testing.expectEqual(@as(usize, 4 * main_words), l.main.words);
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
    var world = World{ .a = testing.allocator };
    var rig = try Rig.init(&world);
    defer rig.deinit();
    // Generations 1 (parity 0) and 2 (parity 1) publish every flag.
    for ([_]u64{ 61, 62 }) |id| {
        world.reset();
        var o = try rig.driver.serve(&request(id));
        o.deinit();
    }
    // Generation 3 reuses parity 0, whose replica still holds generation 1's
    // flags (replicas are never zeroed per request). Device 1's partial is
    // withheld: only the tag tells the stale flag from a landed one.
    world.reset();
    world.withhold_partial = 1;
    try testing.expectError(error.GpuNativeProofRejected, rig.driver.serve(&request(63)));
    world.withhold_partial = null;
    world.reset();
    var ok = try rig.driver.serve(&request(64));
    ok.deinit();
}

test "D1: a Stage1 refused at stage poisons its dependents (the seal never enqueues)" {
    var world = World{ .a = testing.allocator };
    var rig = try Rig.init(&world);
    defer rig.deinit();
    world.refuse_stage1 = 1;
    // The first failed job in batch order names the request's error: the
    // refused Stage1 or a dependent poisoned by it (never a seal that ran).
    if (rig.driver.serve(&request(71))) |o| {
        var out = o;
        out.deinit();
        return error.TestExpectedRefusal;
    } else |err| try testing.expect(err == error.JobFootprintExceedsArena or err == error.BatchDependencyFailed);
    try testing.expect(!world.seal_enqueued);
    try testing.expect(!world.seal_ran);
    world.refuse_stage1 = null;
    world.reset();
    var ok = try rig.driver.serve(&request(72));
    ok.deinit();
    try testing.expect(world.seal_ran);
}

test "D1: plan phases keep stable arena epochs across requests; a plan worker never parks" {
    var world = World{ .a = testing.allocator };
    var rig = try Rig.init(&world);
    defer rig.deinit();
    var seen: [2]u64 = undefined;
    for (0..2) |i| {
        world.reset();
        var o = try rig.driver.serve(&request(80 + i));
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
    var world = World{ .a = testing.allocator };
    const Hook = struct {
        fn installed(raw: *anyopaque, cache: *G.ClassCache, info: *const G.Installed) anyerror!void {
            const w: *World = @ptrCast(@alignCast(raw));
            w.installed_info = info.*;
            w.installed_sealed = cache.phase == .request;
        }
    };
    var vt = World.native_vt;
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
    try testing.expect(drv.classes.phase == .request);
    for (drv.lanes, 0..) |l, d| {
        try testing.expectEqual(l.main.ptr, info.main_resident[d].ptr);
        try testing.expectEqual(ws[d].planPhaseEpochs(), info.arena_epochs[d]);
    }
}

test "D1: a capture stream is refused while the other in-flight request holds it; receipts are per request" {
    var world = World{ .a = testing.allocator };
    var rig = try Rig.init(&world);
    defer rig.deinit();
    const cap = try C.Stream.create(testing.allocator, world.nativeFactory(), null, 8);
    defer cap.destroy();
    var r1 = request(91);
    r1.capture = cap;
    try cap.prepare(r1.segment_rows);
    const t = try std.Thread.spawn(.{}, Capture.full, .{ cap, r1.segment_rows });
    const f1 = try rig.driver.begin(&r1);
    t.join();
    var r2 = request(92);
    r2.capture = cap;
    try testing.expectError(error.GpuNativeCaptureStreamInFlight, rig.driver.begin(&r2));
    world.reset();
    const f2 = try rig.driver.begin(&request(93));
    var o1 = try rig.driver.finish(f1);
    defer o1.deinit();
    var o2 = try rig.driver.finish(f2);
    defer o2.deinit();
    // Each receipt counts its own request's peer traffic (9 slots each),
    // although request 93 began before request 91 finished.
    try testing.expectEqual(@as(u64, 9), o1.receipt.peer_publishes);
    try testing.expectEqual(@as(u64, 9), o2.receipt.peer_publishes);
}

fn captureEnd(segments: u32) G.CaptureEnd {
    const dummy = struct {
        var x: u8 = 0;
    };
    return .{ .segments = segments, .owner = &dummy.x, .image = &dummy.x, .program = &dummy.x, .config = &dummy.x };
}

/// A capture thread driving the Feed the way the GE adapter does: packed
/// segments in order (Stage1 released per segment), then the capture end
/// (factories' captured hooks), then done.
fn feedCapture(s: *C.Stream, rows: []const u64) void {
    var f = s.feed();
    defer f.finish(null);
    for (rows, 0..) |*n, seg| {
        std.Thread.sleep(std.time.ns_per_ms);
        f.segment(.{ .segment = @intCast(seg), .native = n, .events = n }) catch return;
    }
    f.end(captureEnd(@intCast(rows.len))) catch return;
}

test "D1: streamed capture (Feed) + end-gated truth + stage-one region + publish hooks write the artifacts" {
    var world = World{ .a = testing.allocator, .stage_one = true, .truth_end = true };
    var rig = try Rig.init(&world);
    defer rig.deinit();
    const ring = try C.Ring.init(testing.allocator, &F.ops.wait, 4, 16);
    defer ring.deinit();
    const cap = try C.Stream.create(testing.allocator, world.nativeFactory(), ring, 8);
    defer cap.destroy();
    cap.recursion = world.recursionFactory();
    world.capture = cap;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var r = request(601);
    r.capture = cap;
    r.out = tmp.dir;
    r.block = 26235156;
    const before = F.counters;
    try cap.prepare(r.segment_rows);
    var out = blk: {
        const t = try std.Thread.spawn(.{}, feedCapture, .{ cap, r.segment_rows });
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
    try testing.expectEqual(@as(u64, stage_one_written), out.receipt.stage_one_bytes);
    // Native publishes before recursion; each exactly once.
    try testing.expectEqual([2]usize{ 1, 1 }, world.published);
    try testing.expect(world.publish_order[0] < world.publish_order[1]);
    const stage = try tmp.dir.readFileAlloc(testing.allocator, "stage-one.bin", 1 << 16);
    defer testing.allocator.free(stage);
    try testing.expectEqual(@as(usize, stage_one_written), stage.len);
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
    var world = World{ .a = testing.allocator, .stage_one = true, .truth_end = true, .stage_one_empty = true };
    var rig = try Rig.init(&world);
    defer rig.deinit();
    try testing.expectError(error.GpuNativeEncodedEmpty, rig.driver.serve(&request(611)));
    try testing.expectEqual([2]usize{ 0, 0 }, world.published);
    // The capture dies after segment 0: Stage1(1..2) and the truth fail closed.
    world.reset();
    world.stage_one_empty = false;
    const cap = try C.Stream.create(testing.allocator, world.nativeFactory(), null, 8);
    defer cap.destroy();
    world.capture = cap;
    var r = request(612);
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
    const t2 = try std.Thread.spawn(.{}, feedCapture, .{ cap, r.segment_rows });
    var ok = try rig.driver.serve(&r);
    t2.join();
    ok.deinit();
}

test "D1: a capture that fails after its last seal (no end-gated job) refuses publication" {
    var world = World{ .a = testing.allocator, .stage_one = true };
    var rig = try Rig.init(&world);
    defer rig.deinit();
    const ring = try C.Ring.init(testing.allocator, &F.ops.wait, 4, 16);
    defer ring.deinit();
    const cap = try C.Stream.create(testing.allocator, world.nativeFactory(), ring, 8);
    defer cap.destroy();
    cap.recursion = world.recursionFactory();
    world.capture = cap;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var r = request(621);
    r.capture = cap;
    r.out = tmp.dir;
    const Late = struct {
        /// Every segment sealed and the end handed over; then GE's final
        /// checks fail (terminal state / collector equivalence).
        fn run(s: *C.Stream, rows: []const u64, skip_end: bool) void {
            var f = s.feed();
            for (rows, 0..) |*n, seg| f.segment(.{ .segment = @intCast(seg), .native = n, .events = n }) catch return f.finish(null);
            if (!skip_end) f.end(captureEnd(@intCast(rows.len))) catch {};
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
    const t2 = try std.Thread.spawn(.{}, feedCapture, .{ cap, r.segment_rows });
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
    var world = World{ .a = testing.allocator, .two_stage = true };
    const a = testing.allocator;
    var ws: [2]*W.Worker = undefined;
    ws[0] = try W.Worker.create(a, &F.ops, .{ .plan_from_env = false, .device = 0, .arena_words = 1 << 10, .pinned_slot_words = 1 << 10 });
    defer ws[0].destroy();
    ws[1] = try W.Worker.create(a, &F.ops, .{ .plan_from_env = false, .device = 1, .arena_words = 1 << 10, .pinned_slot_words = 1 << 10 });
    defer ws[1].destroy();
    const drv = try R.Driver.install(a, &F.ops, &F.peer, &ws, world.nativeFactory(), .{ .ctx = &world, .vtable = &World.rec_vt2 }, .{ .capacity_words = &.{ 1 << 20, 1 << 20 }, .max_segments = 8, .max_truths = 4, .max_jobs_per_device = 32, .slab_words = 1 << 13, .reserve_words = 1 << 10, .graph_exec_words = 1 << 10, .arena_cap_words = 1 << 15 });
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
        try testing.expectEqual(@as(usize, encoded_bytes), p.bytes.len);
    };
    try testing.expectEqual(@as(usize, 2), truths);
    // 2 segments x 2 slots + 2 partials + 2 truth roots + seal.
    try testing.expectEqual(@as(u64, 2 * 2 + 2 + 2 + 1), out.receipt.peer_publishes);
    // Too many truths for the install capacity fails before device work.
    const r5 = R.Request{ .id = 702, .segment_rows = &.{ 1 << 10, 1 << 9 }, .truths = 5, .recursion = &.{.{ .segments = &.{0} }}, .root = 0 };
    try testing.expectError(error.GpuNativeTruthsExceedPlan, drv.serve(&r5));
}

/// The service's capture source on the host model: warm captures report a
/// segment count per block; a request capture is a thread driving the Feed.
const FakeSource = struct {
    segments: u32 = 3,
    warmed: std.ArrayListUnmanaged(u64) = .empty,
    released: usize = 0,
    started: usize = 0,
    joined: usize = 0,
    fail_start: bool = false,
    rows: [8]u64 = undefined,
    const Run = struct { thread: std.Thread };
    fn of(raw: *anyopaque) *FakeSource {
        return @ptrCast(@alignCast(raw));
    }
    fn warm(raw: *anyopaque, block: u64) anyerror!G.CaptureEnd {
        const self = of(raw);
        if (block == 13) return error.WarmCaptureFailed;
        try self.warmed.append(testing.allocator, block);
        return captureEnd(self.segments);
    }
    fn releaseWarm(raw: *anyopaque, _: u64) void {
        of(raw).released += 1;
    }
    fn start(raw: *anyopaque, _: u64, stream: *C.Stream) anyerror!*anyopaque {
        const self = of(raw);
        if (self.fail_start) return error.CaptureStartFailed;
        for (self.rows[0..self.segments], 0..) |*r, i| r.* = if (i + 1 == self.segments) 1 << 9 else 1 << 10;
        const run = try testing.allocator.create(Run);
        run.thread = try std.Thread.spawn(.{}, feedCapture, .{ stream, self.rows[0..self.segments] });
        self.started += 1;
        return run;
    }
    fn join(raw: *anyopaque, h: *anyopaque) void {
        const run: *Run = @ptrCast(@alignCast(h));
        run.thread.join();
        testing.allocator.destroy(run);
        of(raw).joined += 1;
    }
    const vt = S.CaptureSource.VTable{ .warm = warm, .release_warm = releaseWarm, .start = start, .join = join };
    fn source(self: *FakeSource) S.CaptureSource {
        return .{ .ctx = self, .vtable = &vt };
    }
};

fn serviceConfig() R.Config {
    return .{ .capacity_words = &.{ 1 << 20, 1 << 20 }, .max_segments = 8, .max_jobs_per_device = 32, .slab_words = 1 << 13, .reserve_words = 1 << 10, .graph_exec_words = 1 << 10, .arena_cap_words = 1 << 15, .stage_one_base_bytes = 512 };
}

test "driver: final admission uses class peaks updated by resource measurement" {
    const Hooks = struct {
        fn warm(raw: *anyopaque, cache: *G.ClassCache) anyerror!void {
            try World.nWarm(raw, cache);
            cache.map.get(k_native).?.arena_peak_words = 1 << 19;
        }
        fn nativeResources(_: *anyopaque, _: *G.ClassCache, _: u32) anyerror!void {}
        fn recursionResources(_: *anyopaque, cache: *G.ClassCache, _: u32) anyerror!void {
            // Installation measured a smaller class than its initial estimate.
            cache.map.get(k_native).?.arena_peak_words = 256;
        }
    };
    const a = testing.allocator;
    var world = World{ .a = a };
    var native_vt = World.native_vt;
    native_vt.warm = Hooks.warm;
    native_vt.resources = Hooks.nativeResources;
    var recursion_vt = World.rec_vt;
    recursion_vt.resources = Hooks.recursionResources;
    const worker = try W.Worker.create(a, &F.ops, .{ .plan_from_env = false, .device = 0, .arena_words = 1 << 10, .pinned_slot_words = 1 << 10 });
    defer worker.destroy();
    var config = serviceConfig();
    config.capacity_words = &.{1 << 20};
    config.prewarm_resources = true;
    const driver = try R.Driver.install(a, &F.ops, &F.peer, &.{worker}, .{ .ctx = &world, .vtable = &native_vt }, .{ .ctx = &world, .vtable = &recursion_vt }, config);
    defer driver.deinit();
    try testing.expectEqual(@as(usize, 256), (try driver.classes.get(k_native)).arena_peak_words);
    try testing.expect(driver.lanes[0].plan.phase_a_words < 1 << 19);
}

test "serve: install shapes every block from its warm capture; streamed requests pipeline two deep, one wait each" {
    var world = World{ .a = testing.allocator, .stage_one = true, .truth_end = true };
    var src = FakeSource{};
    defer src.warmed.deinit(testing.allocator);
    const a = testing.allocator;
    var ws: [2]*W.Worker = undefined;
    ws[0] = try W.Worker.create(a, &F.ops, .{ .plan_from_env = false, .device = 0, .arena_words = 1 << 10, .pinned_slot_words = 1 << 10 });
    defer ws[0].destroy();
    ws[1] = try W.Worker.create(a, &F.ops, .{ .plan_from_env = false, .device = 1, .arena_words = 1 << 10, .pinned_slot_words = 1 << 10 });
    defer ws[1].destroy();
    const svc = try S.Service.install(a, &F.ops, &F.peer, &ws, world.nativeFactory(), world.recursionFactory(), src.source(), &.{ 26235156, 24628607 }, serviceConfig(), .{ .buffers = 8, .words = 16 });
    defer svc.deinit();
    try testing.expectEqualSlices(u64, &.{ 26235156, 24628607 }, src.warmed.items);
    try testing.expectEqual(@as(usize, 2), src.released);
    const shape = svc.shapeOf(26235156).?;
    try testing.expectEqualSlices(u64, &.{ 1 << 10, 1 << 10, 1 << 9 }, shape.rows);
    try testing.expectEqual(@as(u32, 1), shape.truths);
    // 3 segments + 1 truth leaves, binary carry: 4 leaves + 3 folds.
    try testing.expectEqual(@as(usize, 7), shape.topology.nodes.len);
    try testing.expectError(error.GpuNativeBlockNotWarmed, svc.begin(1, null));
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("r0");
    try tmp.dir.makePath("r1");
    var d0 = try tmp.dir.openDir("r0", .{});
    defer d0.close();
    var d1 = try tmp.dir.openDir("r1", .{});
    defer d1.close();
    const before = F.counters;
    // Two in flight: the second capture + enqueue start before the first finishes.
    const p0 = try svc.begin(26235156, d0);
    const p1 = try svc.begin(24628607, d1);
    try testing.expectError(error.GpuNativePipelineFull, svc.begin(26235156, null));
    var r0 = try svc.finish(p0);
    defer r0.outcome.deinit();
    var r1 = try svc.finish(p1);
    defer r1.outcome.deinit();
    try testing.expectEqual(@as(usize, 2), F.counters.host_waits - before.host_waits);
    try testing.expectEqual(@as(usize, 4), F.counters.d2h - before.d2h);
    for ([_]S.Result{ r0, r1 }) |r| {
        try testing.expectEqual(@as(u32, 1), r.outcome.receipt.host_waits);
        try testing.expectEqual(@as(u32, 2), r.outcome.receipt.d2h);
        try testing.expectEqual(@as(u32, 1), r.outcome.receipt.capture_end_gated);
        try testing.expectEqual(@as(u64, stage_one_written), r.outcome.receipt.stage_one_bytes);
        // 3 natives + 1 truth + 7 nodes.
        try testing.expectEqual(@as(usize, 11), r.outcome.proofs.len);
    }
    try testing.expectEqual(@as(usize, 2), src.started);
    try testing.expectEqual(@as(usize, 2), src.joined);
    for ([_]std.fs.Dir{ d0, d1 }) |d| {
        try d.access("stage-one.bin", .{});
        try d.access("cpu-2.bin", .{});
        try d.access("truth-0.bin", .{});
        try d.access("recursion-om31/root.proof", .{});
    }
    const receipt = try S.receiptJson(a, 26235156, 0, r0);
    defer a.free(receipt);
    try testing.expect(std.mem.indexOf(u8, receipt, "\"host_waits\": 1") != null);
    // A capture that cannot start refuses the request and frees its stream.
    src.fail_start = true;
    try testing.expectError(error.CaptureStartFailed, svc.begin(26235156, null));
    src.fail_start = false;
    var again = try svc.serve(26235156, null);
    again.outcome.deinit();
    try testing.expectEqual(@as(usize, 3), src.joined);
}

test "serve: install refuses a missing shape hook and a failed warm capture" {
    var world = World{ .a = testing.allocator };
    var src = FakeSource{};
    defer src.warmed.deinit(testing.allocator);
    const a = testing.allocator;
    var ws: [2]*W.Worker = undefined;
    ws[0] = try W.Worker.create(a, &F.ops, .{ .plan_from_env = false, .device = 0, .arena_words = 1 << 10, .pinned_slot_words = 1 << 10 });
    defer ws[0].destroy();
    ws[1] = try W.Worker.create(a, &F.ops, .{ .plan_from_env = false, .device = 1, .arena_words = 1 << 10, .pinned_slot_words = 1 << 10 });
    defer ws[1].destroy();
    var bare = World.native_vt;
    bare.shape = null;
    try testing.expectError(error.GpuNativeNativeShapeHookMissing, S.Service.install(a, &F.ops, &F.peer, &ws, .{ .ctx = &world, .vtable = &bare }, world.recursionFactory(), src.source(), &.{1}, serviceConfig(), .{}));
    try testing.expectError(error.WarmCaptureFailed, S.Service.install(a, &F.ops, &F.peer, &ws, world.nativeFactory(), world.recursionFactory(), src.source(), &.{ 1, 13 }, serviceConfig(), .{}));
    try testing.expectError(error.GpuNativeServiceDuplicateBlock, S.Service.install(a, &F.ops, &F.peer, &ws, world.nativeFactory(), world.recursionFactory(), src.source(), &.{ 1, 1 }, serviceConfig(), .{}));
    src.segments = 9;
    try testing.expectError(error.GpuNativeSegmentsExceedPlan, S.Service.install(a, &F.ops, &F.peer, &ws, world.nativeFactory(), world.recursionFactory(), src.source(), &.{2}, serviceConfig(), .{}));
}

test "serve: the spool answers requests in order, refuses malformed and reused names, stops on STOP" {
    var world = World{ .a = testing.allocator, .stage_one = true, .truth_end = true };
    var src = FakeSource{};
    defer src.warmed.deinit(testing.allocator);
    const a = testing.allocator;
    var ws: [2]*W.Worker = undefined;
    ws[0] = try W.Worker.create(a, &F.ops, .{ .plan_from_env = false, .device = 0, .arena_words = 1 << 10, .pinned_slot_words = 1 << 10 });
    defer ws[0].destroy();
    ws[1] = try W.Worker.create(a, &F.ops, .{ .plan_from_env = false, .device = 1, .arena_words = 1 << 10, .pinned_slot_words = 1 << 10 });
    defer ws[1].destroy();
    const svc = try S.Service.install(a, &F.ops, &F.peer, &ws, world.nativeFactory(), world.recursionFactory(), src.source(), &.{26235156}, serviceConfig(), .{ .buffers = 8, .words = 16 });
    defer svc.deinit();
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.makePath("spool/inbox");
    try tmp.dir.makePath("spool/out/0003-26235156");
    try tmp.dir.writeFile(.{ .sub_path = "spool/inbox/0000-26235156.request", .data = "26235156\n" });
    try tmp.dir.writeFile(.{ .sub_path = "spool/inbox/0001-26235156.request", .data = "26235156\n" });
    try tmp.dir.writeFile(.{ .sub_path = "spool/inbox/0002-bad.request", .data = "not-a-block\n" });
    try tmp.dir.writeFile(.{ .sub_path = "spool/inbox/0003-26235156.request", .data = "26235156\n" });
    try tmp.dir.writeFile(.{ .sub_path = "spool/inbox/0004-7.request", .data = "7\n" });
    try tmp.dir.writeFile(.{ .sub_path = "spool/inbox/STOP", .data = "" });
    const path = try tmp.dir.realpathAlloc(a, "spool");
    defer a.free(path);
    try S.serveSpool(svc, path, 1);
    try tmp.dir.access("spool/READY", .{});
    const Expect = struct { name: []const u8, ok: bool, needle: []const u8 };
    for ([_]Expect{
        .{ .name = "0000-26235156", .ok = true, .needle = "\"sequence\":0" },
        .{ .name = "0001-26235156", .ok = true, .needle = "\"sequence\":1" },
        .{ .name = "0002-bad", .ok = false, .needle = "ResidentRequestMalformed" },
        .{ .name = "0003-26235156", .ok = false, .needle = "ResidentRequestNameReused" },
        .{ .name = "0004-7", .ok = false, .needle = "GpuNativeBlockNotWarmed" },
    }) |e| {
        var buf: [128]u8 = undefined;
        const done = try tmp.dir.readFileAlloc(a, try std.fmt.bufPrint(&buf, "spool/done/{s}.json", .{e.name}), 4096);
        defer a.free(done);
        try testing.expect(std.mem.indexOf(u8, done, if (e.ok) "\"ok\":true" else "\"ok\":false") != null);
        try testing.expect(std.mem.indexOf(u8, done, e.needle) != null);
        if (e.ok) {
            try testing.expect(std.mem.indexOf(u8, done, "\"host_waits\":1,\"d2h\":2") != null);
            const jobs = try tmp.dir.readFileAlloc(a, try std.fmt.bufPrint(&buf, "spool/out/{s}/m8-jobs.json", .{e.name}), 1 << 16);
            defer a.free(jobs);
            try testing.expect(std.mem.indexOf(u8, jobs, "rv64-m8-gpu-native-request/v1") != null);
            try tmp.dir.access(try std.fmt.bufPrint(&buf, "spool/out/{s}/26235156/proof/stage-one.bin", .{e.name}), .{});
        }
        try testing.expectError(error.FileNotFound, tmp.dir.access(try std.fmt.bufPrint(&buf, "spool/inbox/{s}.request", .{e.name}), .{}));
    }
    try testing.expectEqual(@as(usize, 2), src.joined);
}
