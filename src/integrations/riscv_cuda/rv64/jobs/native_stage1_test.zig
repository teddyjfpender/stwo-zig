//! NativeStage1 prologue on a REAL GPU worker versus the host scheme: two
//! jobs of one class on one worker share the class-persistent FIXED tree (the
//! first commits it, the second only mixes its root); each job's FIXED root,
//! MAIN root and post-MAIN channel equal the host. Opt-in GPU env as native_commit_test.zig.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const api = @import("api.zig");
const W = @import("worker.zig");
const C = @import("native_commit.zig");
const S1 = @import("native_stage1.zig");
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
const main_shapes = [_]C.Shape{ .{ .log_size = 6, .encoding = .evaluations }, .{ .log_size = 3, .encoding = .evaluations }, .{ .log_size = 6, .encoding = .coefficients }, .{ .log_size = 5, .encoding = .evaluations } };

const Probe = struct {
    stage1: *S1.Stage1,
    fixed_inputs: []const C.Input,
    main_inputs: []const C.Input,
    result: [40]u32 = undefined,
    pub fn classKey(_: *Probe) [32]u8 {
        return @splat(13);
    }
    pub fn footprint(self: *Probe) api.Footprint {
        return .{ .device_words = self.stage1.fixed.plan.deviceWords() + self.stage1.main.deviceWords() + (1 << 16), .staged_words = 1 << 12, .slab_words = 40, .pinned_words = 1 << 14 };
    }
    pub fn stage(self: *Probe, s: *api.Stager) !void {
        try self.stage1.stage(s, self.fixed_inputs, self.main_inputs);
    }
    pub fn enqueue(self: *Probe, e: *api.Enqueue) !void {
        const c = try self.stage1.enqueue(e, self.fixed_inputs, self.main_inputs, try e.slab.device.slice(0, 16));
        try e.channel.snapshot(e.slab, 16);
        e.free(c.main.coefficients);
    }
    pub fn finish(self: *Probe, v: api.SlabView) !void {
        @memcpy(&self.result, v.words[0..40]);
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
fn columnsOf(ar: std.mem.Allocator, prng: *std.Random.DefaultPrng, shapes: []const C.Shape) !struct { inputs: []C.Input, evals: [][]M } {
    const inputs = try ar.alloc(C.Input, shapes.len);
    const evals = try ar.alloc([]M, shapes.len);
    for (shapes, inputs, evals) |shape, *in, *ev| {
        const c = try ar.alloc(M, @as(usize, 1) << @intCast(shape.log_size));
        for (c) |*x| x.* = M.fromCanonical(prng.random().uintLessThan(u32, core.fields.m31.Modulus));
        const poly = try engine.poly.circle.CircleCoefficients.initBorrowed(c);
        ev.* = @constCast((try poly.evaluate(ar, core.poly.circle.canonic.CanonicCoset.new(shape.log_size).circleDomain())).values);
        const values = if (shape.encoding == .evaluations) ev.* else c;
        in.* = .{ .host = @as([*]const u32, @ptrCast(values.ptr))[0..values.len] };
    }
    return .{ .inputs = inputs, .evals = evals };
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

test "GPU: NativeStage1 prologue (staged seed, class-persistent FIXED, MAIN) equals the host for two jobs of one class" {
    var gpu = (try @import("native_gpu_support_test.zig").Gpu.openNamed("native_stage1_test")) orelse return error.SkipZigTest;
    defer gpu.close();
    const a = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const ar = arena_state.allocator();
    const csym = try C.Symbols.load(&gpu.libs.base);
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 2, .fold_step = 1 } };
    var prng = std.Random.DefaultPrng.init(0x73746731);
    const fixed = try columnsOf(ar, &prng, &fixed_shapes);
    var fixed_plan = try C.CommitPlan.init(a, &fixed_shapes, 1);
    defer fixed_plan.deinit();
    var tree = S1.FixedTree{ .plan = &fixed_plan, .key = @splat(0x5a) };
    const w = try W.Worker.create(a, &gpu.libs.ops, .{ .device = 0, .arena_words = 1 << 22, .pinned_slot_words = 1 << 16, .max_outstanding = 2 });
    defer w.destroy();
    for (0..2) |job| {
        const main = try columnsOf(ar, &prng, &main_shapes);
        var channel = Channel.init();
        channel.mixU32s(&.{ 0x4d385331, @intCast(job) });
        var main_plan = try C.CommitPlan.init(a, &main_shapes, 1);
        defer main_plan.deinit();
        var stage1 = S1.Stage1{ .fixed = &tree, .main = &main_plan, .csym = csym, .seed = S1.seedOf(channel) };
        var probe = Probe{ .stage1 = &stage1, .fixed_inputs = fixed.inputs, .main_inputs = main.inputs };
        var done: Done = .{};
        try w.submit(api.Job.from(Probe, &probe), .{ .ctx = &done, .done = Done.onDone });
        while (done.n.load(.seq_cst) == 0) std.Thread.yield() catch {};
        if (done.err) |err| return err;
        try std.testing.expectEqual(job == 0, tree.persistent.?.fresh);
        var scheme = try Scheme.init(a, config);
        defer scheme.deinit(a);
        const fixed_root = try hostCommit(a, ar, &scheme, &channel, &fixed_shapes, fixed.evals);
        const main_root = try hostCommit(a, ar, &scheme, &channel, &main_shapes, main.evals);
        for (0..8) |i| {
            try std.testing.expectEqual(std.mem.readInt(u32, fixed_root[i * 4 ..][0..4], .little), probe.result[i]);
            try std.testing.expectEqual(std.mem.readInt(u32, main_root[i * 4 ..][0..4], .little), probe.result[8 + i]);
            try std.testing.expectEqual(std.mem.readInt(u32, channel.inner.digest[i * 4 ..][0..4], .little), probe.result[16 + i]);
        }
        try std.testing.expectEqual(channel.inner.n_draws, probe.result[24]);
        std.debug.print("GPU_M8_NATIVE_STAGE1_PARITY job={} fixed_fresh={} fixed_root_equal=1 main_root_equal=1 channel_equal=1\n", .{ job, tree.persistent.?.fresh });
    }
}
