//! native_commit on a REAL GPU worker versus the host engine commitment.
//! Opt-in (skipped otherwise): STWO_RV64_M8_GPU_BASE=<libstwo-rv64-native.so>
//! and STWO_RV64_M8_JOBS_LIBRARY=<libstwo-rv64-jobs.so>; run under the pod's
//! GPU lock. Checks the device root, the device channel after mixing it, and
//! the compact coefficient image, word for word.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const api = @import("api.zig");
const W = @import("worker.zig");
const O = @import("ops.zig");
const C = @import("native_commit.zig");
const M = core.fields.m31.M31;
const OM = core.fields.om31.OM31;
const H = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const Channel = core.channel.raw_mod_m31.Om31Channel;
const MC = struct {
    pub fn mixRoot(channel: *Channel, root: H.Hash) void {
        core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleChannel.mixRoot(&channel.inner, root);
    }
};
const Cpu = @import("stwo_riscv_cpu_integration").CpuProverEngine.Backend;
const Scheme = engine.pcs.ForField(OM).CommitmentSchemeProver(Cpu, H, MC);

const shapes = [_]C.Shape{
    .{ .log_size = 5, .encoding = .evaluations },
    .{ .log_size = 3, .encoding = .coefficients },
    .{ .log_size = 5, .encoding = .coefficients },
    .{ .log_size = 4, .encoding = .evaluations },
    .{ .log_size = 3, .encoding = .evaluations },
    .{ .log_size = 5, .encoding = .evaluations },
};

const Probe = struct {
    plan: *C.CommitPlan,
    sym: C.Symbols,
    seed: [9]u32,
    /// Host words per column in its declared encoding; column 2 is device-resident.
    host: [shapes.len][]const u32,
    inputs: [shapes.len]C.Input = undefined,
    device_column: ?api.DeviceBuffer = null,
    seed_buffer: ?api.DeviceBuffer = null,
    slab_words: usize,
    result: []u32,
    pub fn classKey(_: *Probe) [32]u8 {
        return @splat(7);
    }
    pub fn footprint(self: *Probe) api.Footprint {
        return .{ .device_words = self.plan.deviceWords() + 4096, .staged_words = 4096, .slab_words = self.slab_words, .pinned_words = 1 << 14 };
    }
    pub fn stage(self: *Probe, s: *api.Stager) !void {
        const b = try s.alloc(9);
        try s.upload(b, &self.seed);
        self.seed_buffer = b;
        const d = try s.alloc(self.host[2].len);
        try s.upload(d, self.host[2]);
        self.device_column = d;
        for (&self.inputs, self.host, 0..) |*input, words, i| input.* = if (i == 2) .{ .device = d.ptr } else .{ .host = words };
        try self.plan.stage(s, &self.inputs);
    }
    pub fn enqueue(self: *Probe, e: *api.Enqueue) !void {
        try e.channel.initFromCheckpoint(self.seed_buffer.?);
        const root = try e.slab.device.slice(0, 8);
        const committed = try self.plan.enqueue(self.sym, e, &self.inputs, root, true);
        try e.channel.snapshot(e.slab, 8);
        try O.check(self.sym.copy_d2d(e.ctx(), e.slab.device.ptr + 24, committed.coefficients.ptr, committed.coefficients.words * 4));
        e.free(committed.coefficients);
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

test "GPU: enqueue-only trace commit root, device root mix and coefficients equal the host engine" {
    var gpu = (try @import("native_gpu_support_test.zig").Gpu.open()) orelse return error.SkipZigTest;
    defer gpu.close();
    const libs = &gpu.libs;
    const a = std.testing.allocator;
    const sym = try C.Symbols.load(&libs.base);

    // Host reference: random coefficients, evaluations on each canonic domain.
    var prng = std.Random.DefaultPrng.init(0x6d38_636f);
    var coefficients: [shapes.len][]M = undefined;
    var evaluations: [shapes.len][]M = undefined;
    for (shapes, &coefficients, &evaluations) |shape, *c, *ev| {
        c.* = try a.alloc(M, @as(usize, 1) << @intCast(shape.log_size));
        for (c.*) |*x| x.* = M.fromCanonical(prng.random().uintLessThan(u32, core.fields.m31.Modulus));
        const poly = try engine.poly.circle.CircleCoefficients.initBorrowed(c.*);
        ev.* = @constCast((try poly.evaluate(a, core.poly.circle.canonic.CanonicCoset.new(shape.log_size).circleDomain())).values);
    }
    defer for (coefficients, evaluations) |c, ev| {
        a.free(c);
        a.free(ev);
    };
    const config = core.pcs.PcsConfig{ .pow_bits = 0, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 2, .fold_step = 1 } };
    var scheme = try Scheme.init(a, config);
    defer scheme.deinit(a);
    var channel = Channel.init();
    channel.mixU32s(&.{ 0x4d38434d, 1, 2, 3 });
    var seed: [9]u32 = undefined;
    for (seed[0..8], 0..) |*w, i| w.* = std.mem.readInt(u32, channel.inner.digest[i * 4 ..][0..4], .little);
    seed[8] = channel.inner.n_draws;
    {
        // The builder may interpolate in place: give it copies.
        const columns = try a.alloc(engine.pcs.ColumnEvaluation, shapes.len);
        defer a.free(columns);
        for (columns, shapes, evaluations) |*col, shape, ev| col.* = .{ .log_size = shape.log_size, .values = try a.dupe(M, ev) };
        defer for (columns) |col| a.free(col.values);
        var builder = scheme.treeBuilder(a);
        defer builder.deinit();
        _ = try builder.extendColumns(columns);
        try builder.commit(&channel);
    }
    const host_root = scheme.trees.items[0].commitment.root();

    var plan = try C.CommitPlan.init(a, &shapes, 1);
    defer plan.deinit();
    var host_words: [shapes.len][]const u32 = undefined;
    for (&host_words, shapes, coefficients, evaluations) |*w, shape, c, ev| {
        const values = if (shape.encoding == .evaluations) ev else c;
        w.* = @as([*]const u32, @ptrCast(values.ptr))[0..values.len];
    }
    const slab_words = 24 + plan.coefficient_cells;
    const result = try a.alloc(u32, slab_words);
    defer a.free(result);
    var probe = Probe{ .plan = &plan, .sym = sym, .seed = seed, .host = host_words, .slab_words = slab_words, .result = result };
    const w = try W.Worker.create(a, &libs.ops, .{ .device = 0, .arena_words = 1 << 22, .pinned_slot_words = 1 << 16, .max_outstanding = 2 });
    var done: Done = .{};
    try w.submit(api.Job.from(Probe, &probe), .{ .ctx = &done, .done = Done.onDone });
    while (done.n.load(.seq_cst) == 0) std.Thread.yield() catch {};
    w.destroy();
    if (done.err) |err| return err;

    for (0..8) |i| try std.testing.expectEqual(std.mem.readInt(u32, host_root[i * 4 ..][0..4], .little), result[i]);
    for (0..8) |i| try std.testing.expectEqual(std.mem.readInt(u32, channel.inner.digest[i * 4 ..][0..4], .little), result[8 + i]);
    try std.testing.expectEqual(channel.inner.n_draws, result[8 + 8]);
    try std.testing.expectEqual(@as(u32, 0), result[8 + 10]); // channel status
    for (shapes, coefficients, 0..) |_, c, original| {
        const at = 24 + plan.offsets[original];
        for (c, 0..) |x, k| try std.testing.expectEqual(x.v, result[at + k]);
    }
    std.debug.print("GPU_M8_NATIVE_COMMIT_PARITY columns={} coefficient_cells={} eval_log={} root_equal=1 channel_equal=1 coefficients_equal=1\n", .{ shapes.len, plan.coefficient_cells, plan.eval_log });
}
