//! native_device_stage1 on a REAL GPU worker versus the host scheme (opt-in,
//! env as native_commit_test.zig: STWO_RV64_M8_GPU_BASE, STWO_RV64_M8_JOBS_LIBRARY):
//!
//!   warm     the class FIXED region is committed once (fresh persistent), its
//!            device root equals the host FIXED root;
//!   request  persistent region NOT fresh (adopted), witness from two chunks
//!            (h2d + scatter, one column split across them), FIXED root mixed,
//!            MAIN committed into a caller view: MAIN root and the post-MAIN
//!            channel equal the host; root_match and witness_status accept;
//!   negative a class whose stored authority root is corrupted -> root_match
//!            rejects (0x0208 << 16 | 0x10); a chunk run past the image ->
//!            witness status 1 and witness_status rejects (0x0201 << 16 | 1),
//!            no image word written outside the image.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const api = @import("api.zig");
const W = @import("worker.zig");
const C = @import("native_commit.zig");
const NG = @import("native_gkr.zig");
const S1 = @import("native_device_stage1.zig");
const G = @import("gpu_native.zig");
const D = @import("stwo_riscv_cpu_integration").rv64_device_pcs;
const M = D.M;
const OM = D.O;
const H = D.H;
const Channel = D.Channel;
const MC = struct {
    pub fn mixRoot(channel: *Channel, root: H.Hash) void {
        core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel.mixRoot(&channel.inner, root);
    }
};
const Cpu = @import("stwo_riscv_cpu_integration").CpuProverEngine.Backend;
const Scheme = engine.pcs.ForField(OM).CommitmentSchemeProver(Cpu, H, MC);
const fixed_shapes = [_]C.Shape{ .{ .log_size = 4, .encoding = .coefficients }, .{ .log_size = 6, .encoding = .coefficients }, .{ .log_size = 5, .encoding = .coefficients } };
const main_shapes = [_]C.Shape{ .{ .log_size = 6, .encoding = .evaluations }, .{ .log_size = 3, .encoding = .evaluations }, .{ .log_size = 6, .encoding = .evaluations }, .{ .log_size = 5, .encoding = .evaluations } };

const Mode = enum { warm, request };
const Probe = struct {
    cls: *const S1.Class,
    sym: *const S1.Symbols,
    mode: Mode,
    fixed_plan: C.CommitPlan,
    fixed_inputs: []C.Input,
    class_root: [8]u32 = @splat(0),
    main: C.CommitPlan = undefined,
    inputs: []C.Input = &.{},
    chunks: []const G.TraceChunk = &.{},
    runs: [4]?api.DeviceBuffer = @splat(null),
    seed: [9]u32 = @splat(0),
    region: ?api.DeviceBuffer = null,
    fresh: bool = false,
    seed_buf: ?api.DeviceBuffer = null,
    result: [64]u32 = undefined,

    pub fn classKey(self: *Probe) [32]u8 {
        return self.cls.fixed_key;
    }
    pub fn footprint(_: *Probe) api.Footprint {
        return .{ .device_words = 1 << 21, .staged_words = 1 << 14, .slab_words = 64, .pinned_words = 1 << 16 };
    }
    pub fn stage(self: *Probe, s: *api.Stager) !void {
        const p = try s.persistent(self.cls.fixed_key, self.cls.fixedRegionWords());
        self.region = p.buffer;
        self.fresh = p.fresh;
        switch (self.mode) {
            .warm => {
                if (!p.fresh) return error.TestExpectedFreshRegion;
                try self.fixed_plan.stage(s, self.fixed_inputs);
                try s.upload(try p.buffer.slice(self.cls.fixed.coefficient_cells + 8, 8), &self.class_root);
            },
            .request => {
                if (p.fresh) return error.GpuNativeFixedNotWarmed;
                const b = try s.alloc(9);
                try s.upload(b, &self.seed);
                self.seed_buf = b;
                for (self.inputs) |*i| i.* = .{ .device = @ptrFromInt(@alignOf(u32)) };
                try self.main.stage(s, self.inputs);
                for (self.chunks, 0..) |ch, i| self.runs[i] = try s.alloc(ch.words.len);
            },
        }
    }
    pub fn enqueue(self: *Probe, e: *api.Enqueue) !void {
        const region = self.region.?;
        const c = self.cls;
        @memset(&self.result, 0);
        switch (self.mode) {
            .warm => {
                const root = try region.slice(c.fixed.coefficient_cells, 8);
                _ = try self.fixed_plan.enqueueInto(self.sym.commit, e, self.fixed_inputs, try region.slice(0, c.fixed.coefficient_cells), root, false);
                try cuda(self.sym.commit.copy_d2d(e.ctx(), e.slab.device.ptr, root.ptr, 32));
            },
            .request => {
                const main_view = try e.alloc(c.main.coefficient_cells);
                const root_out = try e.slab.device.slice(8, 8);
                const pro = try S1.enqueuePrologue(c, self.sym, e, self.seed_buf.?, region, .{ .chunks = self.chunks }, self.runs[0..self.chunks.len], &self.main, self.inputs, main_view, root_out);
                try e.channel.snapshot(e.slab, 16);
                var r = S1.CheckSpec{ .check = @intFromEnum(G.Check.root_match) };
                try r.mustEqual(pro.fixed_root, pro.class_root);
                try cuda(self.sym.check(e.ctx(), 0, &r, e.slab.device.ptr + 40));
                var w = S1.CheckSpec{ .check = @intFromEnum(G.Check.witness_status) };
                try w.mustBeZero(pro.witness_status);
                try cuda(self.sym.check(e.ctx(), 0, &w, e.slab.device.ptr + 41));
                try cuda(self.sym.commit.copy_d2d(e.ctx(), e.slab.device.ptr + 42, pro.witness_status.ptr, 4));
                try cuda(self.sym.commit.copy_d2d(e.ctx(), e.slab.device.ptr, pro.fixed_root.ptr, 32));
                e.free(main_view);
            },
        }
    }
    pub fn finish(self: *Probe, v: api.SlabView) !void {
        @memcpy(&self.result, v.words[0..64]);
    }
    pub fn abort(_: *Probe) void {}
};
fn cuda(status: c_int) !void {
    if (status != 0) return error.CudaEnqueueFailed;
}
const Done = struct {
    n: std.atomic.Value(usize) = .init(0),
    err: ?anyerror = null,
    fn onDone(raw: *anyopaque, c: api.Completion) void {
        const self: *Done = @ptrCast(@alignCast(raw));
        if (c.result) |_| {} else |err| self.err = err;
        _ = self.n.fetchAdd(1, .seq_cst);
    }
};
fn run(w: *W.Worker, probe: *Probe) !void {
    var done: Done = .{};
    try w.submit(api.Job.from(Probe, probe), .{ .ctx = &done, .done = Done.onDone });
    while (done.n.load(.seq_cst) == 0) std.Thread.yield() catch {};
    if (done.err) |err| return err;
}
fn columnsOf(ar: std.mem.Allocator, prng: *std.Random.DefaultPrng, shapes: []const C.Shape) !struct { inputs: []C.Input, evals: [][]M, words: [][]const u32 } {
    const inputs = try ar.alloc(C.Input, shapes.len);
    const evals = try ar.alloc([]M, shapes.len);
    const words = try ar.alloc([]const u32, shapes.len);
    for (shapes, inputs, evals, words) |shape, *in, *ev, *wd| {
        const c = try ar.alloc(M, @as(usize, 1) << @intCast(shape.log_size));
        for (c) |*x| x.* = M.fromCanonical(prng.random().uintLessThan(u32, core.fields.m31.Modulus));
        const poly = try engine.poly.circle.CircleCoefficients.initBorrowed(c);
        ev.* = @constCast((try poly.evaluate(ar, core.poly.circle.canonic.CanonicCoset.new(shape.log_size).circleDomain())).values);
        const values = if (shape.encoding == .evaluations) ev.* else c;
        wd.* = @as([*]const u32, @ptrCast(values.ptr))[0..values.len];
        in.* = .{ .host = wd.* };
    }
    return .{ .inputs = inputs, .evals = evals, .words = words };
}
fn hostCommit(a: std.mem.Allocator, ar: std.mem.Allocator, scheme: *Scheme, channel: *Channel, shapes: []const C.Shape, evals: []const []M) ![32]u8 {
    const columns = try ar.alloc(engine.pcs.ColumnEvaluation, shapes.len);
    for (columns, shapes, evals) |*col, shape, ev| col.* = .{ .log_size = shape.log_size, .values = try ar.dupe(M, ev) };
    var builder = scheme.treeBuilder(a);
    defer builder.deinit();
    _ = try builder.extendColumns(columns);
    try builder.commit(channel);
    return scheme.trees.items[scheme.trees.items.len - 1].commitment.root();
}
fn wordsOf(bytes: [32]u8) [8]u32 {
    var out: [8]u32 = undefined;
    for (&out, 0..) |*w, i| w.* = std.mem.readInt(u32, bytes[4 * i ..][0..4], .little);
    return out;
}
/// Chunk ingress v1 for `runs` over `data`.
fn chunk(ar: std.mem.Allocator, runs: []const S1.Run, data: []const u32) ![]u32 {
    const out = try ar.alloc(u32, S1.chunk_header_words + 6 * runs.len + data.len);
    out[0] = @intCast(runs.len);
    out[1] = 0;
    @memcpy(out[S1.chunk_header_words..][0 .. 6 * runs.len], std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(runs)));
    @memcpy(out[S1.chunk_header_words + 6 * runs.len ..], data);
    return out;
}

fn classOf(a: std.mem.Allocator, key_byte: u8, fixed_root: [8]u32) !S1.Class {
    var cls: S1.Class = undefined;
    cls.a = a;
    cls.fixed = try C.CommitPlan.init(a, &fixed_shapes, 1);
    cls.main = try C.CommitPlan.init(a, &main_shapes, 1);
    cls.fixed_key = @splat(key_byte);
    cls.spec.fixed_root = fixed_root;
    cls.image_offsets = try a.alloc(usize, main_shapes.len);
    var at: usize = 0;
    for (main_shapes, cls.image_offsets) |s, *o| {
        o.* = at;
        at += @as(usize, 1) << @intCast(s.log_size);
    }
    cls.image_words = at;
    return cls;
}
fn freeClass(cls: *S1.Class) void {
    cls.a.free(cls.image_offsets);
    cls.main.deinit();
    cls.fixed.deinit();
}

test "GPU: native Stage-1 prologue (warm FIXED, adopted root, chunk witness, MAIN) equals the host; checks fire on corruption" {
    var gpu = (try @import("native_gpu_support_test.zig").Gpu.openNamed("native_device_stage1_gpu_test")) orelse return error.SkipZigTest;
    defer gpu.close();
    const a = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const ar = arena_state.allocator();
    const gsym = try NG.Symbols.load(&gpu.libs.base);
    const sym = try S1.Symbols.load(&gpu.libs.base, &gpu.libs.addon, &gsym);
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 2, .fold_step = 1 } };
    var prng = std.Random.DefaultPrng.init(0x6e31_7374);
    const fixed = try columnsOf(ar, &prng, &fixed_shapes);
    const main = try columnsOf(ar, &prng, &main_shapes);
    var host_seed = Channel.init();
    host_seed.mixU32s(&.{ 0x4e315354, 7 });
    var seed: [9]u32 = undefined;
    for (seed[0..8], 0..) |*w, i| w.* = std.mem.readInt(u32, host_seed.inner.digest[i * 4 ..][0..4], .little);
    seed[8] = host_seed.inner.n_draws;
    // Host reference: seed -> FIXED root mixed -> MAIN root mixed.
    var scheme = try Scheme.init(a, config);
    defer scheme.deinit(a);
    var channel = host_seed;
    const fixed_root = wordsOf(try hostCommit(a, ar, &scheme, &channel, &fixed_shapes, fixed.evals));
    const main_root = wordsOf(try hostCommit(a, ar, &scheme, &channel, &main_shapes, main.evals));

    // Image = MAIN evaluations, original order; two chunks, column 2 split.
    var good = try classOf(a, 0x61, fixed_root);
    defer freeClass(&good);
    const image = try ar.alloc(u32, good.image_words);
    for (main.words, good.image_offsets) |wd, off| @memcpy(image[off..][0..wd.len], wd);
    const split = good.image_offsets[2] + 20;
    const c0 = try chunk(ar, &.{.{ .dst = 0, .src = 0, .words = split }}, image[0..split]);
    const c1 = try chunk(ar, &.{ .{ .dst = split + 10, .src = 10, .words = image.len - split - 10 }, .{ .dst = split, .src = 0, .words = 10 } }, image[split..]);
    try S1.validateChunk(c0, good.image_words);
    try S1.validateChunk(c1, good.image_words);
    const chunks = [_]G.TraceChunk{ .{ .segment = 0, .sequence = 0, .first_row = 0, .rows = 1, .last = false, .words = c0 }, .{ .segment = 0, .sequence = 1, .first_row = 1, .rows = 1, .last = true, .words = c1 } };

    const w = try W.Worker.create(a, &gpu.libs.ops, .{ .device = 0, .arena_words = 1 << 22, .pinned_slot_words = 1 << 16, .max_outstanding = 2 });
    defer w.destroy();
    const inputs = try ar.alloc(C.Input, main_shapes.len);

    // warm (correct class root), then request.
    var warm = Probe{ .cls = &good, .sym = &sym, .mode = .warm, .fixed_plan = good.fixed, .fixed_inputs = fixed.inputs, .class_root = fixed_root };
    try run(w, &warm);
    try std.testing.expect(warm.fresh);
    try std.testing.expectEqualSlices(u32, &fixed_root, warm.result[0..8]);
    var req = Probe{ .cls = &good, .sym = &sym, .mode = .request, .fixed_plan = good.fixed, .fixed_inputs = fixed.inputs, .main = good.main, .inputs = inputs, .chunks = &chunks, .seed = seed };
    try run(w, &req);
    try std.testing.expect(!req.fresh);
    try std.testing.expectEqualSlices(u32, &fixed_root, req.result[0..8]);
    try std.testing.expectEqualSlices(u32, &main_root, req.result[8..16]);
    for (0..8) |i| try std.testing.expectEqual(std.mem.readInt(u32, channel.inner.digest[i * 4 ..][0..4], .little), req.result[16 + i]);
    try std.testing.expectEqual(channel.inner.n_draws, req.result[24]);
    try std.testing.expectEqual(@as(u32, 0), req.result[40]); // root_match accepted
    try std.testing.expectEqual(@as(u32, 0), req.result[41]); // witness_status accepted
    try std.testing.expectEqual(@as(u32, 0), req.result[42]);
    std.debug.print("GPU_M8_N1_PROLOGUE_PARITY fixed_root_equal=1 main_root_equal=1 channel_equal=1 root_match=0x{x} witness_status=0x{x}\n", .{ req.result[40], req.result[41] });

    // Negative 1: corrupted class authority root -> root_match rejects.
    var bad_root = fixed_root;
    bad_root[3] ^= 1;
    var bad = try classOf(a, 0x62, bad_root);
    defer freeClass(&bad);
    var warm_bad = Probe{ .cls = &bad, .sym = &sym, .mode = .warm, .fixed_plan = bad.fixed, .fixed_inputs = fixed.inputs, .class_root = bad_root };
    try run(w, &warm_bad);
    var req_bad = Probe{ .cls = &bad, .sym = &sym, .mode = .request, .fixed_plan = bad.fixed, .fixed_inputs = fixed.inputs, .main = bad.main, .inputs = inputs, .chunks = &chunks, .seed = seed };
    try run(w, &req_bad);
    try std.testing.expectEqual(G.Verdict.reject(.root_match, 0x10), req_bad.result[40]);
    try std.testing.expectEqual(@as(u32, 0), req_bad.result[41]);
    try std.testing.expectEqualSlices(u32, &main_root, req_bad.result[8..16]); // MAIN unaffected

    // Negative 2: a run past the image end -> witness status 1, check rejects.
    const c2 = try chunk(ar, &.{ .{ .dst = 0, .src = 0, .words = split }, .{ .dst = good.image_words - 4, .src = 0, .words = 8 } }, image[0..split]);
    try std.testing.expectError(error.NativeStage1ChunkRunOutOfRange, S1.validateChunk(c2, good.image_words));
    const chunks_bad = [_]G.TraceChunk{ .{ .segment = 0, .sequence = 0, .first_row = 0, .rows = 1, .last = false, .words = c2 }, chunks[1] };
    var req_w = Probe{ .cls = &good, .sym = &sym, .mode = .request, .fixed_plan = good.fixed, .fixed_inputs = fixed.inputs, .main = good.main, .inputs = inputs, .chunks = &chunks_bad, .seed = seed };
    try run(w, &req_w);
    try std.testing.expectEqual(@as(u32, 1), req_w.result[42]);
    try std.testing.expectEqual(G.Verdict.reject(.witness_status, 1), req_w.result[41]);
    try std.testing.expectEqual(@as(u32, 0), req_w.result[40]);
    try std.testing.expectEqualSlices(u32, &main_root, req_w.result[8..16]); // the bad run wrote nothing
    std.debug.print("GPU_M8_N1_NEGATIVES root_match=0x{x} witness_status=0x{x}\n", .{ req_bad.result[40], req_w.result[41] });
}
