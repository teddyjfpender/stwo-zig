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
pub const k_native = key(1);
const k_truth = key(2);
const k_leaf = key(3);
const k_fold = key(4);
const k_root = key(5);
pub const encoded_bytes = 96;
pub const stage_one_written = 300;
/// Generations a test runs at most (fake per-request state slots).
const gens = 64;
pub const main_words = 256;

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

pub const World = struct {
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
    installed_cache: ?*G.ClassCache = null,
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

    pub fn reset(self: *World) void {
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
    pub fn nativeFactory(self: *World) G.NativeFactory {
        return .{ .ctx = self, .vtable = &native_vt };
    }
    pub const native_vt = G.NativeFactory.VTable{ .warm = nWarm, .class_of = nClass, .stage1 = nStage1, .stage2 = nStage2, .seal = nSeal, .chunk = nChunk, .pack = nPack, .captured = nCaptured, .publish = nPublish, .shape = nShape };
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
    pub fn nWarm(raw: *anyopaque, cache: *G.ClassCache) anyerror!void {
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
    pub fn recursionFactory(self: *World) G.RecursionFactory {
        return .{ .ctx = self, .vtable = &rec_vt };
    }
    pub const rec_vt = G.RecursionFactory.VTable{ .warm = rWarm, .class_of = rClass, .truth = rTruth, .node = rNode, .captured = rCaptured, .publish = rPublish, .shape = rShape };
    fn rShape(_: *anyopaque, _: G.WarmBlock, keys: []const G.ClassKey) anyerror!G.RecursionShape {
        for (keys) |k| if (!std.mem.eql(u8, &k, &k_native)) return error.UnexpectedNativeClass;
        return .{ .truths = 1, .fold_arity = 2 };
    }
    pub const rec_vt2 = blk: {
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
    pub fn rWarm(raw: *anyopaque, cache: *G.ClassCache) anyerror!void {
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

pub const Rig = struct {
    workers: [2]*W.Worker,
    world: *World,
    driver: *R.Driver,
    pub fn init(world: *World) !Rig {
        return initWithPartials(world, true);
    }
    pub fn initWithPartials(world: *World, partials: bool) !Rig {
        const a = testing.allocator;
        var ws: [2]*W.Worker = undefined;
        ws[0] = try W.Worker.create(a, &F.ops, .{ .plan_from_env = false, .device = 0, .arena_words = 1 << 10, .pinned_slot_words = 1 << 10 });
        errdefer ws[0].destroy();
        ws[1] = try W.Worker.create(a, &F.ops, .{ .plan_from_env = false, .device = 1, .arena_words = 1 << 10, .pinned_slot_words = 1 << 10 });
        errdefer ws[1].destroy();
        const drv = try R.Driver.install(a, &F.ops, &F.peer, &ws, world.nativeFactory(), world.recursionFactory(), .{ .capacity_words = &.{ 1 << 20, 1 << 20 }, .max_segments = 8, .exchange_partials = partials, .max_jobs_per_device = 32, .slab_words = 1 << 13, .reserve_words = 1 << 10, .graph_exec_words = 1 << 10, .arena_cap_words = 1 << 15, .stage_one_base_bytes = 512 });
        return .{ .workers = ws, .world = world, .driver = drv };
    }
    pub fn deinit(self: *Rig) void {
        self.driver.deinit();
        for (self.workers) |w| w.destroy();
    }
};

// 3 segments, 1 truth; leaves: {s0}, {s1}, {s2, t0}; folds (0,1) -> 3; root (3,2) -> 4.
pub const topology = [_]D.RecursionNode{ .{ .segments = &.{0} }, .{ .segments = &.{1} }, .{ .segments = &.{2}, .truths = &.{0} }, .{ .children = &.{ 0, 1 } }, .{ .children = &.{ 3, 2 } } };

pub fn request(id: u64) R.Request {
    return .{ .id = id, .segment_rows = &.{ 1 << 10, 1 << 10, 1 << 9 }, .truths = 1, .recursion = &topology, .root = 4 };
}

pub const Capture = struct {
    /// A complete capture of `rows` (one chunk per segment), `done` on every path.
    pub fn full(s: *C.Stream, rows: []const u64) void {
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
    pub fn ringed(s: *C.Stream, rows: []const u64) void {
        const sink = s.sink();
        defer sink.done(sink.ctx, @intCast(rows.len)) catch {};
        for (rows, 0..) |n, seg| {
            const buf = s.acquire(@intCast(seg)) catch return;
            sink.chunk(sink.ctx, .{ .segment = @intCast(seg), .sequence = 0, .first_row = 0, .rows = @intCast(n), .last = true, .words = buf[0..4] }) catch return;
            sink.sealed_segment(sink.ctx, @intCast(seg), n) catch return;
        }
    }
};

pub fn captureEnd(segments: u32) G.CaptureEnd {
    const dummy = struct {
        var x: u8 = 0;
    };
    return .{ .segments = segments, .owner = &dummy.x, .image = &dummy.x, .program = &dummy.x, .config = &dummy.x };
}

/// A capture thread driving the Feed the way the GE adapter does: packed
/// segments in order (Stage1 released per segment), then the capture end
/// (factories' captured hooks), then done.
pub fn feedCapture(s: *C.Stream, rows: []const u64) void {
    var f = s.feed();
    defer f.finish(null);
    for (rows, 0..) |*n, seg| {
        std.Thread.sleep(std.time.ns_per_ms);
        f.segment(.{ .segment = @intCast(seg), .native = n, .events = n }) catch return;
    }
    f.end(captureEnd(@intCast(rows.len))) catch return;
}

/// The service's capture source on the host model: warm captures report a
/// segment count per block; a request capture is a thread driving the Feed.
pub const FakeSource = struct {
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
    pub fn source(self: *FakeSource) S.CaptureSource {
        return .{ .ctx = self, .vtable = &vt };
    }
};

pub fn serviceConfig() R.Config {
    return .{ .capacity_words = &.{ 1 << 20, 1 << 20 }, .max_segments = 8, .max_jobs_per_device = 32, .slab_words = 1 << 13, .reserve_words = 1 << 10, .graph_exec_words = 1 << 10, .arena_cap_words = 1 << 15, .stage_one_base_bytes = 512 };
}
