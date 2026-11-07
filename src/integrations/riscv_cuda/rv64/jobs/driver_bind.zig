//! GPU-native service binding (stream gn-bind; rv64-m8-gpu-native.md §3.8,
//! M8-INTERFACES "m8-gn-bind"). driver_ge.serve builds ONE Binding per
//! service: the real device factories of the native and recursion streams,
//! their kernel symbols from the base image + jobs addon, and the composed
//! gpu_native NativeFactory / RecursionFactory the driver installs.
//!
//!   native     native_device.Native with
//!                stage1_hooks = native_device_stage1.Registry.hooks()
//!                (sym, workers, devices, CUDA-event timing bound here)
//!                stage2_hooks = native_device_stage2.Factory.hooks()
//!                (Stage-2 / seal symbols, chain identity, seal device)
//!   recursion  outer_device.Recursion (warm/class_of/node) + truth_factory
//!              .Factory as RecursionFactory.truth / .truth_stage2 (two-stage
//!              truths, r-truth) and the truth class_of.
//!
//! Optional hooks (shape / pack / captured / publish / installed) come from
//! the stream's own vtable when it has landed them; the service may fill the
//! ones still missing with `Fallback` hooks (driver_ge.zig: a fail-closed
//! shape from the warm capture; the artifact writer below for publish). The
//! composed vtables are trampolines, so the sibling streams' vtables stay the
//! single source of their hooks: merging a sibling that lands a hook needs
//! no change here.
//!
//! Per request the Binding releases every factory's request state after the
//! driver finished (success or failure): Registry.release(generation),
//! Factory.endRequest(request), truth Factory.end(request).
const std = @import("std");
const api = @import("api.zig");
const G = @import("gpu_native.zig");
const O = @import("ops.zig");
const W = @import("worker.zig");
const D = @import("driver_dag.zig");
const ND = @import("native_device.zig");
const OD = @import("outer_device.zig");
const S1 = @import("native_device_stage1.zig");
const S2 = @import("native_device_stage2.zig");
const NG = @import("native_gkr.zig");
const NE = @import("native_encode.zig");
const NC = @import("native_commit.zig");
const NP = @import("native_pcs.zig");
const NComp = @import("native_composition.zig");
const NO = @import("native_encode_oods.zig");
const Seed = @import("outer_seed_device.zig");
const Gl = @import("native_global.zig");
const HJ = @import("native_hybrid_jobs.zig");
const TF = @import("truth_factory.zig");
const TJ = @import("truth_job.zig");

/// CUDA events of the base image (the jobs' GPU spans).
pub const Events = @import("../cuda_events.zig").Api;

/// Hooks the service supplies for optional factory entries a stream has not
/// landed yet (null = leave the entry null: the driver/stream treats a
/// missing hook as before, e.g. no packer fails the capture closed).
pub const Fallback = struct {
    ctx: ?*anyopaque = null,
    native_shape: ?*const fn (?*anyopaque, std.mem.Allocator, G.WarmBlock) anyerror![]u64 = null,
    recursion_shape: ?*const fn (?*anyopaque, G.WarmBlock, []const G.ClassKey) anyerror!G.RecursionShape = null,
    /// Artifact writers (default: `writeNative` / `writeRecursion` below).
    native_publish: bool = true,
    recursion_publish: bool = true,
};

pub const Options = struct {
    /// chain.versionIdentity of the service policy (seal chain IV input).
    identity: [32]u8,
    seal_device: u32 = 0,
    /// Bind truth_factory as the two-stage truth jobs.
    truths: bool = true,
};

/// Which hook each composed entry resolved to (install receipt).
pub const Resolution = struct {
    native_shape: Source = .missing,
    native_pack: Source = .missing,
    native_captured: Source = .missing,
    native_publish: Source = .missing,
    recursion_shape: Source = .missing,
    recursion_captured: Source = .missing,
    recursion_publish: Source = .missing,
    truth: Source = .missing,
    pub const Source = enum { stream, fallback, missing };
};

pub const Binding = struct {
    a: std.mem.Allocator,
    s1_sym: S1.Symbols,
    gkr_sym: NG.Symbols,
    s2_sym: S2.Symbols,
    truth_sym: ?TJ.Symbols,
    events: Events,
    timing: HJ.Timing = undefined,
    registry: S1.Registry,
    stage2: S2.Factory,
    truth: ?TF.Factory,
    native: ND.Native = .{},
    recursion: OD.Recursion,
    fallback: Fallback = .{},
    resolution: Resolution = .{},
    /// The composed vtables (copies of the streams' entries + fallbacks).
    native_vt: G.NativeFactory.VTable = undefined,
    recursion_vt: G.RecursionFactory.VTable = undefined,
    /// Inner factories (their own ctx/vtable), resolved at `init`.
    inner_native: G.NativeFactory = undefined,
    inner_recursion: G.RecursionFactory = undefined,
    /// The service's recursion topology of the block being published (the
    /// fallback writer names leaves by their first leaf input). Set by the
    /// service before each request's finish.
    topology: ?*const D.Topology = null,

    /// Install time (before Driver.install): symbols from the libraries the
    /// workers run on, the factories, the composed vtables.
    pub fn init(a: std.mem.Allocator, libs: *O.Libraries, workers: []const *W.Worker, options: Options, fallback: Fallback) !*Binding {
        const self = try a.create(Binding);
        errdefer a.destroy(self);
        self.* = .{
            .a = a,
            .s1_sym = undefined,
            .gkr_sym = try NG.Symbols.load(&libs.base),
            .s2_sym = .{
                .encode = try NE.Symbols.load(&libs.addon),
                .seal = try S2.SealSymbols.load(&libs.addon),
                .commit = try NC.Symbols.load(&libs.base),
                .pcs = try NP.Symbols.load(&libs.addon),
                .composition = try NComp.Symbols.load(&libs.base, &libs.addon),
                .global = try Gl.Symbols.load(&libs.base),
                // gn-s2: Check.oods_constraint kernel (an older addon leaves the word unset).
                .oods = NO.Symbols.load(&libs.addon) catch null,
            },
            .truth_sym = if (options.truths) try TJ.Symbols.load(&libs.base, &libs.addon) else null,
            .events = try Events.load(&libs.base),
            .registry = S1.Registry.init(a),
            .stage2 = undefined,
            .truth = null,
            .recursion = .{ .a = a },
            .fallback = fallback,
        };
        self.s1_sym = try S1.Symbols.load(&libs.base, &libs.addon, &self.gkr_sym);
        self.timing = .{ .ctx = self, .create = tCreate, .record = tRecord, .elapsed = tElapsed, .destroy = tDestroy };
        self.registry.sym = &self.s1_sym;
        self.registry.workers = workers;
        self.registry.devices = @intCast(workers.len);
        self.registry.timing = &self.timing;
        self.stage2 = .{ .a = a, .sym = &self.s2_sym, .identity = options.identity, .seal_device = options.seal_device };
        if (self.truth_sym) |*ts| self.truth = .{ .a = a, .sym = ts };
        self.native = .{ .stage1_hooks = self.registry.hooks(), .stage2_hooks = self.stage2.hooks() };
        self.compose();
        return self;
    }

    /// gn-node: the GPU-native node job's device entry points (seed fill
    /// kernel from the addon, D2D copy from the base, peer copies). An addon
    /// without the seed kernel leaves `node` failing closed.
    pub fn bindNodeOps(self: *Binding, libs: *O.Libraries, peer: O.Peer) void {
        const seed = Seed.Symbols.load(&libs.addon) catch |err| {
            std.debug.print("GPU_M8_GN_BIND node_ops=unbound error={s}\n", .{@errorName(err)});
            return;
        };
        const d2d = libs.base.lookup(OD.Copy, "stwo_exec_context_memcpy_d2d_async") orelse {
            std.debug.print("GPU_M8_GN_BIND node_ops=unbound error=MissingD2dCopy\n", .{});
            return;
        };
        self.recursion.device = .{ .seed = seed, .d2d = d2d, .peer = peer };
    }

    /// gn-shape: the install-time class builder (native_class_build
    /// Builder.hooks()); re-resolves the composed native vtable.
    pub fn bindShape(self: *Binding, hooks: ND.ShapeHooks) void {
        self.native.shape_hooks = hooks;
        self.compose();
    }

    pub fn deinit(self: *Binding) void {
        if (self.truth) |*t| t.deinit();
        self.stage2.deinit();
        self.registry.deinit();
        self.recursion.deinit();
        self.a.destroy(self);
    }

    fn compose(self: *Binding) void {
        self.inner_native = self.native.factory();
        self.inner_recursion = self.recursion.factory();
        const nv = self.inner_native.vtable;
        const rv = self.inner_recursion.vtable;
        var r = Resolution{};
        self.native_vt = .{ .warm = nWarm, .installed = nInstalled, .class_of = nClassOf, .stage1 = nStage1, .stage2 = nStage2, .seal = nSeal, .chunk = nChunk };
        if (nv.class_of_block != null) self.native_vt.class_of_block = nClassOfBlock;
        // native_device.Native always exposes `shape` (unbound it fails with
        // GpuNativeNativeShapeHookMissing): the stream's hook counts only
        // when its shape_hooks are bound.
        if (nv.shape != null and self.native.shape_hooks != null) {
            self.native_vt.shape = nShape;
            r.native_shape = .stream;
        } else if (self.fallback.native_shape != null) {
            self.native_vt.shape = nShape;
            r.native_shape = .fallback;
        }
        if (nv.pack != null) {
            self.native_vt.pack = nPack;
            r.native_pack = .stream;
        }
        if (nv.captured != null) {
            self.native_vt.captured = nCaptured;
            r.native_captured = .stream;
        }
        if (nv.publish != null) {
            self.native_vt.publish = nPublish;
            r.native_publish = .stream;
        } else if (self.fallback.native_publish) {
            self.native_vt.publish = nPublish;
            r.native_publish = .fallback;
        }
        self.recursion_vt = .{ .warm = rWarm, .installed = rInstalled, .class_of = rClassOf, .truth = rTruth, .node = rNode };
        if (self.truth != null) {
            self.recursion_vt.truth_stage2 = rTruth2;
            r.truth = .stream;
        } else if (rv.truth_stage2 != null) {
            self.recursion_vt.truth_stage2 = rTruth2;
            r.truth = .stream;
        }
        if (rv.shape != null) {
            self.recursion_vt.shape = rShape;
            r.recursion_shape = .stream;
        } else if (self.fallback.recursion_shape != null) {
            self.recursion_vt.shape = rShape;
            r.recursion_shape = .fallback;
        }
        if (rv.captured != null) {
            self.recursion_vt.captured = rCaptured;
            r.recursion_captured = .stream;
        }
        if (rv.publish != null) {
            self.recursion_vt.publish = rPublish;
            r.recursion_publish = .stream;
        } else if (self.fallback.recursion_publish) {
            self.recursion_vt.publish = rPublish;
            r.recursion_publish = .fallback;
        }
        self.resolution = r;
    }

    pub fn nativeFactory(self: *Binding) G.NativeFactory {
        return .{ .ctx = self, .vtable = &self.native_vt };
    }
    pub fn recursionFactory(self: *Binding) G.RecursionFactory {
        return .{ .ctx = self, .vtable = &self.recursion_vt };
    }

    /// After the driver finished a request (published or failed).
    /// `generation` 0 = the request never took a driver generation (its
    /// begin was refused before planning): no Stage-1 records exist for it.
    pub fn endRequest(self: *Binding, request: u64, generation: u64) void {
        if (generation != 0) self.registry.release(generation);
        self.recursion.end(request);
        self.stage2.endRequest(request);
        if (self.truth) |*t| t.end(request) catch {};
    }

    /// Install receipt: the Stage-1 arena footprint terms of every
    /// registered native class (S1.Class.jobWords, words), so the plan's
    /// phase peaks can be attributed.
    pub fn reportStage1(self: *Binding) void {
        self.registry.mutex.lock();
        defer self.registry.mutex.unlock();
        var it = self.registry.classes.iterator();
        while (it.next()) |kv| {
            const c = kv.value_ptr.*;
            std.debug.print("GPU_M8_GN_BIND s1_class={x} job_words={d} image_words={d} gkr_staged={d} main_staged={d} compact_words={d} main_device={d} main_coeff_eval={d} gkr_enqueue={d} bind_enqueue={d} resident_words={d}\n", .{ kv.key_ptr.*[0..6].*, c.jobWords(), c.image_words, c.spec.gkr.stagedWords(true), c.main.stagedWords(0), c.spec.compact_words, c.main.deviceWords(), c.main.coefficient_cells + c.main.eval_cells, c.spec.gkr.enqueueWords(), c.bind.enqueueWords(), c.resident.words });
        }
    }

    pub fn report(self: *const Binding, w: *std.Io.Writer) !void {
        try std.json.Stringify.value(.{ .schema = "rv64-m8-gn-bind/v1", .resolution = self.resolution, .truth_factory = self.truth != null }, .{}, w);
    }

    // ---------------- trampolines ----------------
    fn of(raw: *anyopaque) *Binding {
        return @ptrCast(@alignCast(raw));
    }
    fn tCreate(raw: ?*anyopaque, out: *?*anyopaque) c_int {
        return of(raw.?).events.create(out, 0);
    }
    fn tRecord(raw: ?*anyopaque, ev: *anyopaque, stream: *anyopaque) c_int {
        return of(raw.?).events.record(ev, stream);
    }
    fn tElapsed(raw: ?*anyopaque, ms: *f32, b: *anyopaque, e: *anyopaque) c_int {
        return of(raw.?).events.elapsed(ms, b, e);
    }
    fn tDestroy(raw: ?*anyopaque, ev: *anyopaque) void {
        _ = of(raw.?).events.destroy(ev);
    }

    fn nWarm(raw: *anyopaque, cache: *G.ClassCache) anyerror!void {
        const n = of(raw).inner_native;
        try n.vtable.warm(n.ctx, cache);
        // Stage-2 classes (ClassFraming per segment class) registered by the
        // shape hook; an empty registry warms nothing.
        try of(raw).stage2.warm(cache);
    }
    fn nInstalled(raw: *anyopaque, cache: *G.ClassCache, info: *const G.Installed) anyerror!void {
        const n = of(raw).inner_native;
        if (n.vtable.installed) |h| try h(n.ctx, cache, info);
    }
    fn nClassOf(raw: *anyopaque, segment: u32, rows: u64) anyerror!G.ClassKey {
        const n = of(raw).inner_native;
        return n.vtable.class_of(n.ctx, segment, rows);
    }
    fn nStage1(raw: *anyopaque, ctx: *const G.RequestContext, segment: u32, device: u32) anyerror!api.Job {
        const n = of(raw).inner_native;
        return n.vtable.stage1(n.ctx, ctx, segment, device);
    }
    fn nStage2(raw: *anyopaque, ctx: *const G.RequestContext, segment: u32, device: u32) anyerror!api.Job {
        const n = of(raw).inner_native;
        return n.vtable.stage2(n.ctx, ctx, segment, device);
    }
    fn nSeal(raw: *anyopaque, ctx: *const G.RequestContext, device: u32) anyerror!api.Job {
        const n = of(raw).inner_native;
        return n.vtable.seal(n.ctx, ctx, device);
    }
    fn nChunk(raw: *anyopaque, ctx: *const G.RequestContext, c: G.TraceChunk, device: u32) anyerror!void {
        const n = of(raw).inner_native;
        return n.vtable.chunk(n.ctx, ctx, c, device);
    }
    fn nClassOfBlock(raw: *anyopaque, block: u64, segment: u32, rows: u64) anyerror!G.ClassKey {
        const n = of(raw).inner_native;
        return n.vtable.class_of_block.?(n.ctx, block, segment, rows);
    }
    fn nShape(raw: *anyopaque, a: std.mem.Allocator, wb: G.WarmBlock) anyerror![]u64 {
        const self = of(raw);
        const n = self.inner_native;
        if (self.native.shape_hooks != null) return n.vtable.shape.?(n.ctx, a, wb) catch |err| {
            std.debug.print("GPU_M8_GN_BIND native_shape_failed block={d} error={s}\n", .{ wb.block, @errorName(err) });
            return err;
        };
        return self.fallback.native_shape.?(self.fallback.ctx, a, wb);
    }
    fn nPack(raw: *anyopaque, ctx: *const G.RequestContext, cs: G.CapturedSegment, w: G.ChunkWriter) anyerror!u64 {
        const n = of(raw).inner_native;
        return n.vtable.pack.?(n.ctx, ctx, cs, w);
    }
    fn nCaptured(raw: *anyopaque, ctx: *const G.RequestContext, ce: G.CaptureEnd) anyerror!void {
        const n = of(raw).inner_native;
        return n.vtable.captured.?(n.ctx, ctx, ce);
    }
    fn nPublish(raw: *anyopaque, ctx: *const G.RequestContext, p: G.Publication) anyerror!void {
        const n = of(raw).inner_native;
        if (n.vtable.publish) |h| return h(n.ctx, ctx, p);
        return writeNative(p);
    }

    fn rWarm(raw: *anyopaque, cache: *G.ClassCache) anyerror!void {
        const self = of(raw);
        const r = self.inner_recursion;
        try r.vtable.warm(r.ctx, cache);
        if (self.truth) |*t| try t.warm(cache);
    }
    fn rInstalled(raw: *anyopaque, cache: *G.ClassCache, info: *const G.Installed) anyerror!void {
        const r = of(raw).inner_recursion;
        if (r.vtable.installed) |h| try h(r.ctx, cache, info);
    }
    fn rClassOf(raw: *anyopaque, id: G.ProofId, children: []const G.ClassKey) anyerror!G.ClassKey {
        const self = of(raw);
        // Truth classes: the truth factory's per-request roster first, then a
        // class registered under the truth's authority (outer_device).
        if (id.kind == .truth) if (self.truth) |*t| if (t.classOf(id.ordinal)) |k| return k else |_| {};
        const r = self.inner_recursion;
        return r.vtable.class_of(r.ctx, id, children);
    }
    fn rTruth(raw: *anyopaque, ctx: *const G.RequestContext, ordinal: u32, device: u32) anyerror!api.Job {
        const self = of(raw);
        if (self.truth) |*t| return t.stage1(ctx, ordinal, device);
        const r = self.inner_recursion;
        return r.vtable.truth(r.ctx, ctx, ordinal, device);
    }
    fn rTruth2(raw: *anyopaque, ctx: *const G.RequestContext, ordinal: u32, device: u32) anyerror!api.Job {
        const self = of(raw);
        if (self.truth) |*t| return t.stage2(ctx, ordinal, device);
        const r = self.inner_recursion;
        return r.vtable.truth_stage2.?(r.ctx, ctx, ordinal, device);
    }
    fn rNode(raw: *anyopaque, ctx: *const G.RequestContext, id: G.ProofId, children: []const G.ProofId, device: u32) anyerror!api.Job {
        const r = of(raw).inner_recursion;
        return r.vtable.node(r.ctx, ctx, id, children, device);
    }
    fn rShape(raw: *anyopaque, wb: G.WarmBlock, keys: []const G.ClassKey) anyerror!G.RecursionShape {
        const self = of(raw);
        const r = self.inner_recursion;
        if (r.vtable.shape) |h| return h(r.ctx, wb, keys);
        return self.fallback.recursion_shape.?(self.fallback.ctx, wb, keys);
    }
    fn rCaptured(raw: *anyopaque, ctx: *const G.RequestContext, ce: G.CaptureEnd) anyerror!void {
        const r = of(raw).inner_recursion;
        return r.vtable.captured.?(r.ctx, ctx, ce);
    }
    fn rPublish(raw: *anyopaque, ctx: *const G.RequestContext, p: G.Publication) anyerror!void {
        const self = of(raw);
        const r = self.inner_recursion;
        if (r.vtable.publish) |h| return h(r.ctx, ctx, p);
        return writeRecursion(p, self.topology);
    }

};

// ---------------------------------------------------------------------------
// Fallback artifact writers (the published bytes ARE the legacy files:
// cpu-N.bin = WP.encodePhysical of native segment N, stage-one.bin = the
// request pseudo-proof region, truth-N.bin, recursion-om31/*.proof = the om31
// wire encodings). The non-proof files (bundle.json, cells.bin, tree.json,
// report.json, candidate-source-bounds.json) need the streams' publish hooks.
// ---------------------------------------------------------------------------

fn writeFile(dir: std.fs.Dir, name: []const u8, bytes: []const u8) !void {
    try dir.writeFile(.{ .sub_path = name, .data = bytes });
}

pub fn writeNative(p: G.Publication) !void {
    var buf: [64]u8 = undefined;
    for (p.proofs) |pp| switch (pp.id.kind) {
        .request => try writeFile(p.dir, "stage-one.bin", pp.bytes),
        .native_segment => try writeFile(p.dir, try std.fmt.bufPrint(&buf, "cpu-{d}.bin", .{pp.id.ordinal}), pp.bytes),
        else => {},
    };
}

/// Leaf name: the first leaf input in legacy leaf order (segments, then truths).
pub fn leafName(buf: []u8, topology: *const D.Topology, id: u32) ![]const u8 {
    if (id >= topology.nodes.len) return error.GpuNativeRecursionUnknownNode;
    const n = topology.nodes[id];
    const segments: u32 = blk: {
        var s: u32 = 0;
        for (topology.nodes) |x| for (x.segments) |v| {
            s = @max(s, v + 1);
        };
        break :blk s;
    };
    const first: u32 = if (n.segments.len != 0) n.segments[0] else if (n.truths.len != 0) segments + n.truths[0] else return error.GpuNativeRecursionLeafWithoutInputs;
    return std.fmt.bufPrint(buf, "recursion-om31/leaf-{d:0>6}.proof", .{first});
}

pub fn writeRecursion(p: G.Publication, topology: ?*const D.Topology) !void {
    var buf: [96]u8 = undefined;
    var made = false;
    for (p.proofs) |pp| switch (pp.id.kind) {
        .truth => try writeFile(p.dir, try std.fmt.bufPrint(&buf, "truth-{d}.bin", .{pp.id.ordinal}), pp.bytes),
        .leaf, .fold, .root => {
            if (!made) {
                try p.dir.makePath("recursion-om31");
                made = true;
            }
            switch (pp.id.kind) {
                .leaf => try writeFile(p.dir, try leafName(&buf, topology orelse return error.GpuNativeRecursionTopologyMissing, pp.id.ordinal), pp.bytes),
                .fold => try writeFile(p.dir, try std.fmt.bufPrint(&buf, "recursion-om31/fold-{d:0>6}.proof", .{pp.id.ordinal}), pp.bytes),
                else => {
                    try writeFile(p.dir, try std.fmt.bufPrint(&buf, "recursion-om31/fold-{d:0>6}.proof", .{pp.id.ordinal}), pp.bytes);
                    try writeFile(p.dir, "recursion-om31/root.proof", pp.bytes);
                },
            }
        },
        else => {},
    };
}

test "fallback writers name artifacts like the D2 golden" {
    const t = std.testing;
    var tmp = t.tmpDir(.{});
    defer tmp.cleanup();
    // 4 segments + 5 truths, 4-ary carry; leaves are named by first leaf input.
    var topo = try D.Topology.carry(t.allocator, 4, 5, 4);
    defer topo.deinit();
    var proofs: std.ArrayListUnmanaged(G.Published) = .empty;
    defer proofs.deinit(t.allocator);
    try proofs.append(t.allocator, .{ .id = .{ .kind = .request, .ordinal = 0 }, .bytes = "s1" });
    try proofs.append(t.allocator, .{ .id = .{ .kind = .native_segment, .ordinal = 2 }, .bytes = "c2" });
    try proofs.append(t.allocator, .{ .id = .{ .kind = .truth, .ordinal = 4 }, .bytes = "t4" });
    for (topo.nodes, 0..) |n, id| {
        const kind: G.ProofKind = if (id == topo.root) .root else if (n.children.len == 0) .leaf else .fold;
        try proofs.append(t.allocator, .{ .id = .{ .kind = kind, .ordinal = @intCast(id) }, .bytes = "n" });
    }
    const p = G.Publication{ .block = 1, .proofs = proofs.items, .exchange = &.{}, .dir = tmp.dir };
    try writeNative(p);
    try writeRecursion(p, &topo);
    var buf: [16]u8 = undefined;
    try t.expectEqualStrings("s1", try tmp.dir.readFile("stage-one.bin", &buf));
    try t.expectEqualStrings("c2", try tmp.dir.readFile("cpu-2.bin", &buf));
    try t.expectEqualStrings("t4", try tmp.dir.readFile("truth-4.bin", &buf));
    // Leaves: first inputs 0..8 (segments 0..3, then truths as 4..8).
    for (0..9) |leaf| {
        var nb: [64]u8 = undefined;
        _ = try tmp.dir.statFile(try std.fmt.bufPrint(&nb, "recursion-om31/leaf-{d:0>6}.proof", .{leaf}));
    }
    _ = try tmp.dir.statFile("recursion-om31/root.proof");
    try t.expectError(error.GpuNativeRecursionTopologyMissing, writeRecursion(p, null));
}
