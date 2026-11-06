//! D3 (rv64-m8-gpu-native.md §6.3): the GPU-native driver on real GPUs with
//! probe factories whose jobs are pure device work built from the driver's
//! own kernels (peer_ops.cu): they fill exchange slots, publish/await them
//! across GPUs, and write status words and encoded bytes ONLY on the device.
//! Two of the status words are real device checks of the transport:
//!   global_seal      the seal GPU's flags_verdict over every root/claims/
//!                    partial flag in ITS replica, run after its awaits: 0 only
//!                    if every peer copy landed before the seal kernel;
//!   oods_constraint  each Stage2's flags_verdict over the seal flag in its
//!                    own replica after awaiting the seal (cross-GPU edge).
//! A negative run withholds one claims publish (and the seal does not await
//! it): the seal's device check must reject and publication must refuse.
//!
//!   rv64-jobs-channel-parity gpu-native <requests> <segments> [negative]
//! prints one JSON receipt (host waits, D2H, CUDA-event GPU span per device,
//! host plan/make/enqueue/wait/publish ns, peer copies, a peer round-trip
//! microbenchmark).
const std = @import("std");
const api = @import("api.zig");
const G = @import("gpu_native.zig");
const W = @import("worker.zig");
const O = @import("ops.zig");
const R = @import("driver_request.zig");
const D = @import("driver_dag.zig");

fn key(tag: u8) G.ClassKey {
    var k: G.ClassKey = @splat(0x5a);
    k[0] = tag;
    return k;
}
const encoded_bytes = 4096;
const main_words = 1 << 16;

fn noop(_: *anyopaque) void {}

pub const Probe = struct {
    a: std.mem.Allocator,
    peer: *const O.Peer,
    withhold_claims: ?u32 = null,
    partial_done: [G.max_devices]std.atomic.Value(bool) = @splat(.init(false)),
    finished: std.atomic.Value(u64) = .init(0),

    const Job = struct {
        p: *Probe,
        kind: enum { stage1, seal, stage2, truth, node },
        ctx: *const G.RequestContext,
        ordinal: u32,
        device: u32,
        id: G.ProofId = .{ .kind = .request, .ordinal = 0 },

        pub fn classKey(self: *Job) [32]u8 {
            return key(@intFromEnum(self.kind) + 1);
        }
        pub fn footprint(_: *Job) api.Footprint {
            return .{ .device_words = 1 << 12 };
        }
        pub fn stage(_: *Job, _: *api.Stager) !void {}
        pub fn enqueue(self: *Job, e: *api.Enqueue) !void {
            const p = self.p;
            const s = e.stream();
            const seg = self.ctx.segments[self.device];
            const sl = &self.ctx.layout.segments[self.device];
            const rep = seg.ptr + sl.exchange_offset;
            const ex = self.ctx.exchange;
            switch (self.kind) {
                .stage1 => {
                    const main = self.ctx.main_resident[self.ordinal];
                    try O.check(p.peer.fill_u32(main.ptr, 0x4d00 + self.ordinal, main.words, s));
                    const root = try ex.root(self.ordinal);
                    try O.check(p.peer.fill_u32(rep + root.offset, self.ordinal + 1, root.words, s));
                    try self.ctx.peer.publish(self.device, root);
                    if (p.withhold_claims == null or p.withhold_claims.? != self.ordinal) {
                        const claims = try ex.claims(self.ordinal);
                        try O.check(p.peer.fill_u32(rep + claims.offset, 0x100 + self.ordinal, claims.words, s));
                        try self.ctx.peer.publish(self.device, claims);
                    }
                    if (!p.partial_done[self.device].swap(true, .acq_rel)) {
                        const part = try ex.partial(self.device);
                        try O.check(p.peer.fill_u32(rep + part.offset, 0x200 + self.device, part.words, s));
                        try self.ctx.peer.publish(self.device, part);
                    }
                    try self.accept(e, .{ .kind = .native_segment, .ordinal = self.ordinal }, &.{ .witness_status, .binding_authority, .root_match });
                },
                .seal => {
                    for (0..ex.segments) |i| {
                        const src = self.ctx.segment_device[i];
                        try self.ctx.peer.awaitSlot(self.device, src, try ex.root(@intCast(i)));
                        if (p.withhold_claims == null or p.withhold_claims.? != i) try self.ctx.peer.awaitSlot(self.device, src, try ex.claims(@intCast(i)));
                    }
                    for (0..ex.devices) |d| {
                        const part = try ex.partial(@intCast(d));
                        // A GPU without segments publishes no partial; the probe places on both.
                        try self.ctx.peer.awaitSlot(self.device, @intCast(d), part);
                    }
                    // Device check: every root/claims/partial flag landed here.
                    const flags = rep + (ex.words() - ex.flagWords());
                    const n: u32 = @intCast(2 * ex.segments + ex.devices);
                    const word = try sl.statusWord(.{ .kind = .request, .ordinal = 0 }, .global_seal);
                    try O.check(p.peer.flags_verdict(flags, n, seg.ptr + word, G.Verdict.reject(.global_seal, 1), s));
                    const slot = ex.seal();
                    try O.check(p.peer.fill_u32(rep + slot.offset, 0x5ea1, slot.words, s));
                    try self.ctx.peer.publish(self.device, slot);
                },
                .stage2 => {
                    const slot = ex.seal();
                    try self.ctx.peer.awaitSlot(self.device, 0, slot); // seal device 0 (driver default)
                    const id = G.ProofId{ .kind = .native_segment, .ordinal = self.ordinal };
                    // Device check: the seal (other GPU or this one) landed before us.
                    const word = try sl.statusWord(id, .oods_constraint);
                    try O.check(p.peer.flags_verdict(rep + slot.flag, 1, seg.ptr + word, G.Verdict.reject(.oods_constraint, 1), s));
                    try self.accept(e, id, &.{ .channel_order, .global_status, .composition_accept, .public_claims, .pcs_status });
                    try self.encode(e, id);
                },
                .truth => {
                    try self.accept(e, self.id, &.{ .channel_order, .truth_status, .pcs_status });
                    try self.encode(e, self.id);
                },
                .node => {
                    try self.accept(e, self.id, &.{ .channel_order, .seed_tape, .child_binding, .lookup_sum, .node_oods_constraint, .node_pcs_status });
                    try self.encode(e, self.id);
                },
            }
        }
        fn accept(self: *Job, e: *api.Enqueue, id: G.ProofId, checks: []const G.Check) !void {
            const sl = &self.ctx.layout.segments[self.device];
            for (checks) |c| try O.check(self.p.peer.fill_u32(self.ctx.segments[self.device].ptr + try sl.statusWord(id, c), G.Verdict.accepted, 1, e.stream()));
        }
        fn encode(self: *Job, e: *api.Enqueue, id: G.ProofId) !void {
            const sl = &self.ctx.layout.segments[self.device];
            const region = try sl.encodedBuffer(self.ctx.segments[self.device], id);
            try O.check(self.p.peer.fill_u32(region.ptr, encoded_bytes, 1, e.stream()));
            try O.check(self.p.peer.fill_u32(region.ptr + 1, patternOf(id, self.ctx.request), encoded_bytes / 4, e.stream()));
            try self.accept(e, id, &.{.encode_bounds});
        }
        pub fn finish(self: *Job, _: api.SlabView) !void {
            _ = self.p.finished.fetchAdd(1, .monotonic);
            self.p.a.destroy(self);
        }
        pub fn abort(self: *Job) void {
            self.p.a.destroy(self);
        }
    };

    fn make(self: *Probe, kind: @FieldType(Job, "kind"), ctx: *const G.RequestContext, ordinal: u32, device: u32, id: G.ProofId) !api.Job {
        const j = try self.a.create(Job);
        j.* = .{ .p = self, .kind = kind, .ctx = ctx, .ordinal = ordinal, .device = device, .id = id };
        return api.Job.from(Job, j);
    }
    fn of(raw: *anyopaque) *Probe {
        return @ptrCast(@alignCast(raw));
    }
    fn build(_: *anyopaque, _: std.mem.Allocator, k: G.ClassKey) anyerror!G.ClassEntry {
        return .{ .key = k, .plan = @ptrFromInt(16), .destroy = noop, .max_encoded_bytes = encoded_bytes, .main_resident_words = if (k[0] == 1) main_words else 0, .claims_per_segment = if (k[0] == 1) 4 else 0, .cost_us = 10 };
    }
    pub fn native(self: *Probe) G.NativeFactory {
        return .{ .ctx = self, .vtable = &nvt };
    }
    pub fn recursion(self: *Probe) G.RecursionFactory {
        return .{ .ctx = self, .vtable = &rvt };
    }
    const nvt = G.NativeFactory.VTable{ .warm = nWarm, .class_of = nClass, .stage1 = nS1, .stage2 = nS2, .seal = nSeal, .chunk = nChunk };
    const rvt = G.RecursionFactory.VTable{ .warm = rWarm, .class_of = rClass, .truth = rTruth, .node = rNode };
    fn nWarm(raw: *anyopaque, c: *G.ClassCache) anyerror!void {
        _ = try c.warm(key(1), .{ .ctx = raw, .build = build });
    }
    fn nClass(_: *anyopaque, _: u32, _: u64) anyerror!G.ClassKey {
        return key(1);
    }
    fn nS1(raw: *anyopaque, ctx: *const G.RequestContext, s: u32, d: u32) anyerror!api.Job {
        return of(raw).make(.stage1, ctx, s, d, .{ .kind = .native_segment, .ordinal = s });
    }
    fn nS2(raw: *anyopaque, ctx: *const G.RequestContext, s: u32, d: u32) anyerror!api.Job {
        return of(raw).make(.stage2, ctx, s, d, .{ .kind = .native_segment, .ordinal = s });
    }
    fn nSeal(raw: *anyopaque, ctx: *const G.RequestContext, d: u32) anyerror!api.Job {
        return of(raw).make(.seal, ctx, 0, d, .{ .kind = .request, .ordinal = 0 });
    }
    fn nChunk(_: *anyopaque, _: *const G.RequestContext, _: G.TraceChunk, _: u32) anyerror!void {}
    fn rWarm(raw: *anyopaque, c: *G.ClassCache) anyerror!void {
        for ([_]u8{ 4, 5 }) |t| _ = try c.warm(key(t), .{ .ctx = raw, .build = build });
    }
    fn rClass(_: *anyopaque, id: G.ProofId) anyerror!G.ClassKey {
        return if (id.kind == .truth) key(4) else key(5);
    }
    fn rTruth(raw: *anyopaque, ctx: *const G.RequestContext, t: u32, d: u32) anyerror!api.Job {
        return of(raw).make(.truth, ctx, t, d, .{ .kind = .truth, .ordinal = t });
    }
    fn rNode(raw: *anyopaque, ctx: *const G.RequestContext, id: G.ProofId, _: []const G.ProofId, d: u32) anyerror!api.Job {
        return of(raw).make(.node, ctx, id.ordinal, d, id);
    }
};

pub fn patternOf(id: G.ProofId, request: u64) u32 {
    return (@as(u32, @intFromEnum(id.kind)) << 24) | (id.ordinal << 12) | @as(u32, @truncate(request & 0xfff));
}

/// Leaves: one per native segment then one per truth; binary carry folds.
pub fn topology(a: std.mem.Allocator, segments: u32, truths: u32) ![]D.RecursionNode {
    const leaves = segments + truths;
    var nodes: std.ArrayListUnmanaged(D.RecursionNode) = .empty;
    errdefer nodes.deinit(a);
    var level: std.ArrayListUnmanaged(u32) = .empty;
    defer level.deinit(a);
    const ids = try a.alloc(u32, leaves);
    for (ids, 0..) |*x, i| x.* = @intCast(i);
    for (0..leaves) |i| {
        try nodes.append(a, if (i < segments) .{ .segments = ids[i..][0..1] } else .{ .truths = ids[i - segments ..][0..1] });
        try level.append(a, @intCast(i));
    }
    while (level.items.len > 1) {
        var next: std.ArrayListUnmanaged(u32) = .empty;
        var i: usize = 0;
        while (i + 1 < level.items.len) : (i += 2) {
            const kids = try a.alloc(u32, 2);
            kids[0] = level.items[i];
            kids[1] = level.items[i + 1];
            try nodes.append(a, .{ .children = kids });
            try next.append(a, @intCast(nodes.items.len - 1));
        }
        if (i < level.items.len) try next.append(a, level.items[i]);
        level.deinit(a);
        level = next;
    }
    return nodes.toOwnedSlice(a);
}

pub fn run(a: std.mem.Allocator, libs: *O.Libraries, requests: usize, segments: u32, negative: bool) !void {
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const ta = arena_state.allocator();
    const peer = try O.Peer.open(&libs.addon);
    var probe = Probe{ .a = a, .peer = &peer };
    var workers: [2]*W.Worker = undefined;
    for (&workers, 0..) |*w, d| w.* = try W.Worker.create(a, &libs.ops, .{ .device = @intCast(d), .arena_words = 1 << 16, .pinned_slot_words = 1 << 12, .plan_from_env = false });
    defer for (workers) |w| w.destroy();
    // A shared pod: a small plan (arena capped at 256 MiB [default for this
    // probe; it measures transport, not kernels]).
    const cap: u64 = (32 << 30) / 4;
    const drv = try R.Driver.install(a, &libs.ops, &peer, &workers, probe.native(), probe.recursion(), .{ .capacity_words = &.{ cap, cap }, .max_segments = 64, .max_jobs_per_device = 256, .slab_words = 1 << 20, .arena_cap_words = (256 << 20) / 4 });
    defer drv.deinit();
    const truths: u32 = 2;
    const topo = try topology(ta, segments, truths);
    const rows = try ta.alloc(u64, segments);
    @memset(rows, 1 << 20);
    var out: std.Io.Writer.Allocating = .init(a);
    defer out.deinit();
    const Row = struct { request: u64, ok: bool, err: []const u8, receipt: R.Receipt, proofs: usize, wall_ns: u64 };
    var rows_out: std.ArrayListUnmanaged(Row) = .empty;
    defer rows_out.deinit(a);
    var failures: usize = 0;
    for (0..requests) |r| {
        for (&probe.partial_done) |*p| p.store(false, .release);
        probe.withhold_claims = if (negative and r == requests - 1) segments / 2 else null;
        const req = R.Request{ .id = 0x6000 + r, .segment_rows = rows, .truths = truths, .recursion = topo, .root = @intCast(topo.len - 1) };
        var timer = try std.time.Timer.start();
        if (drv.serve(&req)) |o| {
            var outcome = o;
            defer outcome.deinit();
            const wall = timer.read();
            var ok = true;
            for (outcome.proofs) |p| {
                const words = std.mem.bytesAsSlice(u32, p.bytes);
                ok = ok and p.bytes.len == encoded_bytes;
                for (words) |w| ok = ok and std.mem.littleToNative(u32, w) == patternOf(p.id, req.id);
            }
            if (!ok or probe.withhold_claims != null) failures += 1;
            try rows_out.append(a, .{ .request = req.id, .ok = ok, .err = if (ok) "" else "BytesMismatch", .receipt = outcome.receipt, .proofs = outcome.proofs.len, .wall_ns = wall });
        } else |err| {
            const expected = probe.withhold_claims != null and err == error.GpuNativeProofRejected;
            if (!expected) failures += 1;
            try rows_out.append(a, .{ .request = req.id, .ok = expected, .err = @errorName(err), .receipt = .{}, .proofs = 0, .wall_ns = timer.read() });
        }
    }
    const rt = try peerRoundTrip(a, libs, &peer, workers);
    try std.json.Stringify.value(.{ .schema = "rv64-m8-gpu-native-probe/v1", .segments = segments, .truths = truths, .nodes = topo.len, .requests = rows_out.items, .failures = failures, .peer_round_trip = rt, .install_allocations = drv.install_allocations }, .{ .whitespace = .indent_1 }, &out.writer);
    std.debug.print("{s}\n", .{out.written()});
    if (failures != 0) return error.GpuNativeProbeFailed;
}

const RoundTrip = struct { iterations: u32, gpu_us_total: u64, us_per_hop: f64, host_waits: u32 };

/// Peer ping-pong: an 8-word slot GPU0 -> GPU1 -> GPU0 ... `iterations` hops,
/// each hop enqueued on its source GPU's worker thread and ordered by a
/// device-side wait on the previous hop's event; ONE host wait; CUDA-event
/// span on GPU0 [M].
fn peerRoundTrip(a: std.mem.Allocator, libs: *O.Libraries, peer: *const O.Peer, workers: [2]*W.Worker) !RoundTrip {
    _ = a;
    const iterations: u32 = 1000;
    const Ctx = struct {
        libs: *O.Libraries,
        peer: *const O.Peer,
        buf: [2]?[*]u32 = .{ null, null },
        ev: [2]?*anyopaque = .{ null, null },
        t0: ?*anyopaque = null,
        t1: ?*anyopaque = null,
        hop: u32 = 0,
        last: bool = false,
        fn setup(raw: *anyopaque, w: *W.Worker) anyerror!void {
            const c: *@This() = @ptrCast(@alignCast(raw));
            const d = w.device_ordinal;
            // lint:install-begin — the probe's own install.
            try O.check(c.libs.ops.exec.alloc_u32_long(w.context, 64, &c.buf[d]));
            try O.check(c.libs.ops.wait.event_create(&c.ev[d]));
            if (d == 0) {
                try O.check(c.peer.event_create_timed(&c.t0));
                try O.check(c.peer.event_create_timed(&c.t1));
            }
            // lint:install-end
        }
        fn start(raw: *anyopaque, w: *W.Worker) anyerror!void {
            const c: *@This() = @ptrCast(@alignCast(raw));
            try O.check(c.libs.ops.exec.event_record(c.t0.?, w.execStream()));
        }
        fn step(raw: *anyopaque, w: *W.Worker) anyerror!void {
            const c: *@This() = @ptrCast(@alignCast(raw));
            const ex = &c.libs.ops.exec;
            const src = w.device_ordinal;
            const dst = 1 - src;
            if (c.hop > 0) try O.check(ex.stream_wait(w.execStream(), c.ev[dst].?));
            try O.check(c.peer.peer_copy_async(c.buf[dst].?, dst, c.buf[src].?, src, 32, w.execStream()));
            try O.check(ex.event_record(c.ev[src].?, w.execStream()));
        }
        fn stop(raw: *anyopaque, w: *W.Worker) anyerror!void {
            const c: *@This() = @ptrCast(@alignCast(raw));
            const ex = &c.libs.ops.exec;
            try O.check(ex.stream_wait(w.execStream(), c.ev[1].?));
            try O.check(ex.event_record(c.t1.?, w.execStream()));
        }
    };
    var c = Ctx{ .libs = libs, .peer = peer };
    for (workers) |w| try w.call(.{ .ctx = &c, .run = Ctx.setup });
    try workers[0].call(.{ .ctx = &c, .run = Ctx.start });
    while (c.hop < iterations) : (c.hop += 1) try workers[c.hop % 2].call(.{ .ctx = &c, .run = Ctx.step });
    try workers[0].call(.{ .ctx = &c, .run = Ctx.stop });
    _ = try workers[0].requestWait(c.t1.?);
    var us: u64 = 0;
    try O.check(peer.event_elapsed_us(c.t0.?, c.t1.?, &us));
    return .{ .iterations = iterations, .gpu_us_total = us, .us_per_hop = @as(f64, @floatFromInt(us)) / iterations, .host_waits = 1 };
}
