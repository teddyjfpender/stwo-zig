//! The native job tail on a REAL GPU worker versus the host engine, end to end:
//! two trees committed on device (roots mixed on the device channel), the OODS
//! point drawn on device, mask/base points on device, the enqueue-only PCS
//! seeded from the device channel; finish decodes the slab with the legacy
//! decoder. The decoded proof must serialize byte-identically to the host
//! engine's `proveValues` proof, and the post-PCS channels must agree.
//! Opt-in like native_commit_test.zig (STWO_RV64_M8_GPU_BASE, STWO_RV64_M8_JOBS_LIBRARY).
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const api = @import("api.zig");
const W = @import("worker.zig");
const C = @import("native_commit.zig");
const N = @import("native_pcs.zig");
const D = @import("stwo_riscv_cpu_integration").rv64_device_pcs;
const M = D.M;
const OM = D.O;
const Point = D.Point;
const H = D.H;
const Channel = D.Channel;
const MC = struct {
    pub fn mixRoot(channel: *Channel, root: H.Hash) void {
        core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel.mixRoot(&channel.inner, root);
    }
};
const Cpu = @import("stwo_riscv_cpu_integration").CpuProverEngine.Backend;
const Scheme = engine.pcs.ForField(OM).CommitmentSchemeProver(Cpu, H, MC);

const tree_shapes = [_][]const C.Shape{
    &.{ .{ .log_size = 4, .encoding = .coefficients }, .{ .log_size = 5, .encoding = .coefficients }, .{ .log_size = 3, .encoding = .coefficients } },
    &.{ .{ .log_size = 5, .encoding = .evaluations }, .{ .log_size = 4, .encoding = .evaluations }, .{ .log_size = 5, .encoding = .evaluations }, .{ .log_size = 3, .encoding = .evaluations } },
};
fn masks(tree: usize, column: usize) []const isize {
    return switch (tree) {
        0 => switch (column) {
            0 => &.{0},
            1 => &.{},
            else => &.{ 0, 1 },
        },
        else => switch (column) {
            0 => &.{ 0, -1 },
            1 => &.{0},
            2 => &.{1},
            else => &.{0},
        },
    };
}
const max_log: u32 = 5;
fn offset(mask: isize) core.circle.CirclePointM31 {
    return core.poly.circle.canonic.CanonicCoset.new(max_log).step().mulSigned(mask);
}
fn maskPoints(a: std.mem.Allocator, oods: Point) !core.pcs.TreeVec([][]Point) {
    const trees = try a.alloc([][]Point, tree_shapes.len);
    for (tree_shapes, trees, 0..) |shapes, *columns, t| {
        columns.* = try a.alloc([]Point, shapes.len);
        for (columns.*, 0..) |*p, c| {
            p.* = try a.alloc(Point, masks(t, c).len);
            for (masks(t, c), p.*) |m, *v| {
                const s = offset(m);
                v.* = oods.add(.{ .x = OM.fromBase(s.x), .y = OM.fromBase(s.y) });
            }
        }
    }
    return core.pcs.TreeVec([][]Point).initOwned(trees);
}
fn freePoints(a: std.mem.Allocator, points: core.pcs.TreeVec([][]Point)) void {
    for (points.items) |columns| {
        for (columns) |p| a.free(p);
        a.free(columns);
    }
    a.free(points.items);
}
fn words(values: []const M) []const u32 {
    return @as([*]const u32, @ptrCast(values.ptr))[0..values.len];
}

const Probe = struct {
    plans: [2]*C.CommitPlan,
    csym: C.Symbols,
    nsym: N.Symbols,
    pcs: *N.PcsJob,
    seed: [9]u32,
    inputs: [2][]C.Input,
    seed_buffer: ?api.DeviceBuffer = null,
    pinned: []u32 = &.{},
    slab_words: usize,
    result: []u32,
    const pcs_at = 64;
    pub fn classKey(_: *Probe) [32]u8 {
        return @splat(9);
    }
    pub fn footprint(self: *Probe) api.Footprint {
        return .{ .device_words = self.plans[0].deviceWords() + self.plans[1].deviceWords() + (1 << 20), .staged_words = 1 << 12, .slab_words = self.slab_words, .pinned_words = @intCast(self.pcs.ingressWords() + (1 << 13)) };
    }
    pub fn stage(self: *Probe, s: *api.Stager) !void {
        const b = try s.alloc(9);
        try s.upload(b, &self.seed);
        self.seed_buffer = b;
        for (self.plans, self.inputs) |plan, inputs| try plan.stage(s, inputs);
        self.pinned = try s.pinned(@intCast(self.pcs.ingressWords()));
    }
    pub fn enqueue(self: *Probe, e: *api.Enqueue) !void {
        try e.channel.initFromCheckpoint(self.seed_buffer.?);
        var committed: [2]C.Committed = undefined;
        for (self.plans, self.inputs, &committed, 0..) |plan, inputs, *out, t| {
            out.* = try plan.enqueue(self.csym, e, inputs, try e.slab.device.slice(8 * t, 8), true);
            for (0..plan.shapes.len) |original| try self.pcs.bindColumn(t, original, out.column(plan, original).ptr);
        }
        try self.pcs.enqueueOpening(self.nsym, e, self.pinned, try e.slab.device.slice(16, N.oods_field_words), try e.slab.device.slice(pcs_at, @intCast(self.pcs.outputWords())));
        for (committed) |c| e.free(c.coefficients);
    }
    pub fn finish(self: *Probe, v: api.SlabView) !void {
        @memcpy(self.result, v.words[0..self.slab_words]);
    }
    pub fn abort(_: *Probe) void {}
};
const Done = struct {
    n: std.atomic.Value(usize) = .init(0),
    err: ?anyerror = null,
    fn onDone(raw: *anyopaque, c: api.Completion) void {
        const self: *Done = @ptrCast(@alignCast(raw));
        if (c.result) |_| {} else |err| self.err = err;
        _ = self.n.fetchAdd(1, .seq_cst);
    }
};

test "GPU: native job tail (device commits + device OODS + enqueue-only PCS) equals the host engine proof" {
    var gpu = (try @import("native_gpu_support_test.zig").Gpu.open()) orelse return error.SkipZigTest;
    defer gpu.close();
    const a = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const ar = arena_state.allocator();
    const csym = try C.Symbols.load(&gpu.libs.base);
    const nsym = try N.Symbols.load(&gpu.libs.addon);
    const pow_bits: u32 = if (std.posix.getenv("STWO_RV64_M8_TAIL_POW_BITS")) |v| try std.fmt.parseInt(u32, v, 10) else 0;
    const config = core.pcs.PcsConfig{ .pow_bits = pow_bits, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 8, .fold_step = 2 } };

    // Host reference transcript and proof.
    var prng = std.Random.DefaultPrng.init(0x7461696c);
    var coefficients: [2][][]M = undefined;
    var evaluations: [2][][]M = undefined;
    for (tree_shapes, &coefficients, &evaluations) |shapes, *cs, *es| {
        cs.* = try ar.alloc([]M, shapes.len);
        es.* = try ar.alloc([]M, shapes.len);
        for (shapes, cs.*, es.*) |shape, *c, *ev| {
            c.* = try ar.alloc(M, @as(usize, 1) << @intCast(shape.log_size));
            for (c.*) |*x| x.* = M.fromCanonical(prng.random().uintLessThan(u32, core.fields.m31.Modulus));
            const poly = try engine.poly.circle.CircleCoefficients.initBorrowed(c.*);
            ev.* = @constCast((try poly.evaluate(ar, core.poly.circle.canonic.CanonicCoset.new(shape.log_size).circleDomain())).values);
        }
    }
    var channel = Channel.init();
    channel.mixU32s(&.{ 0x4d38544c, 7 });
    var seed: [9]u32 = undefined;
    for (seed[0..8], 0..) |*w, i| w.* = std.mem.readInt(u32, channel.inner.digest[i * 4 ..][0..4], .little);
    seed[8] = channel.inner.n_draws;
    var scheme = try Scheme.init(a, config);
    var roots: [2][32]u8 = undefined;
    for (tree_shapes, evaluations, &roots, 0..) |shapes, es, *root, t| {
        const columns = try ar.alloc(engine.pcs.ColumnEvaluation, shapes.len);
        for (columns, shapes, es) |*col, shape, ev| col.* = .{ .log_size = shape.log_size, .values = try ar.dupe(M, ev) };
        var builder = scheme.treeBuilder(a);
        defer builder.deinit();
        _ = try builder.extendColumns(columns);
        try builder.commit(&channel);
        root.* = scheme.trees.items[t].commitment.root();
    }
    const oods = try core.circle.secureFieldPointFromRandomSeedCheckedFor(OM, channel.drawSecureFelt());
    // proveValues consumes the scheme and its sampled points.
    const host_points = try maskPoints(a, oods);
    var extended = try scheme.proveValues(a, host_points, &channel);
    defer extended.deinit(a);
    const host_json = try std.json.Stringify.valueAlloc(a, extended.proof, .{});
    defer a.free(host_json);

    // Job path: framing at a placeholder OODS point, placeholder device columns.
    const placeholder = try N.placeholderPoint();
    const job_points = try maskPoints(a, placeholder);
    defer freePoints(a, job_points);
    var trees: [2]D.Tree = undefined;
    for (tree_shapes, &trees) |shapes, *tree| {
        const columns = try ar.alloc(D.Column, shapes.len);
        for (columns, shapes) |*col, shape| col.* = N.placeholderColumn(shape.log_size);
        tree.* = .{ .root = @splat(0), .columns = columns };
    }
    const request = D.Request{ .config = config, .lifting_log_size = max_log + 1, .trees = &trees, .points = job_points };
    var pcs = try N.PcsJob.prepare(a, nsym, request, placeholder, true);
    defer pcs.deinit(a);
    var plans: [2]C.CommitPlan = undefined;
    for (tree_shapes, &plans) |shapes, *plan| plan.* = try C.CommitPlan.init(a, shapes, 1);
    defer for (&plans) |*plan| plan.deinit();
    var inputs: [2][]C.Input = undefined;
    for (tree_shapes, coefficients, evaluations, &inputs) |shapes, cs, es, *in| {
        in.* = try ar.alloc(C.Input, shapes.len);
        for (shapes, cs, es, in.*) |shape, c, ev, *x| x.* = .{ .host = words(if (shape.encoding == .evaluations) ev else c) };
    }
    const slab_words = Probe.pcs_at + @as(usize, @intCast(pcs.outputWords()));
    const result = try a.alloc(u32, slab_words);
    defer a.free(result);
    var probe = Probe{ .plans = .{ &plans[0], &plans[1] }, .csym = csym, .nsym = nsym, .pcs = &pcs, .seed = seed, .inputs = inputs, .slab_words = slab_words, .result = result };
    const w = try W.Worker.create(a, &gpu.libs.ops, .{ .device = 0, .arena_words = 1 << 24, .pinned_slot_words = 1 << 20, .max_outstanding = 2 });
    var done: Done = .{};
    try w.submit(api.Job.from(Probe, &probe), .{ .ctx = &done, .done = Done.onDone });
    while (done.n.load(.seq_cst) == 0) std.Thread.yield() catch {};
    w.destroy();
    if (done.err) |err| return err;

    for (roots, 0..) |root, t| for (0..8) |i| try std.testing.expectEqual(std.mem.readInt(u32, root[i * 4 ..][0..4], .little), result[8 * t + i]);
    for (oods.x.toM31Array(), 0..) |v, i| try std.testing.expectEqual(v.v, result[16 + i]);
    for (oods.y.toM31Array(), 0..) |v, i| try std.testing.expectEqual(v.v, result[24 + i]);
    try std.testing.expectEqual(@as(u32, 0), result[16 + 32]);
    var decoded = try pcs.decode(a, result[Probe.pcs_at..], &roots);
    defer decoded.proof.deinit(a);
    const job_json = try std.json.Stringify.valueAlloc(a, decoded.proof, .{});
    defer a.free(job_json);
    try std.testing.expectEqualStrings(host_json, job_json);
    try std.testing.expectEqualSlices(u8, &channel.inner.digest, &decoded.channel.inner.digest);
    try std.testing.expectEqual(channel.inner.n_draws, decoded.channel.inner.n_draws);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(job_json, &digest, .{});
    std.debug.print("GPU_M8_NATIVE_TAIL_PARITY trees=2 columns=7 samples={} pow_bits={} pcs_words={} proof_json_bytes={} proof_sha256={x} byte_identical=1 channel_equal=1\n", .{ pcs.plan.samples, pow_bits, pcs.outputWords(), job_json.len, digest });
}
