//! NativeStage2 transcript on a REAL GPU worker versus the host transcript
//! of CpuWorker.complete + the engine (worker_protocol.mixManifestAndClaims,
//! INTER commit, drawSecureFelt, composition commit, OODS, proveValues). The
//! composition producer here commits fixed test columns (the native
//! composition kernels are not ported yet); it records the DEVICE coefficient
//! so the test checks it equals the host draw. Opt-in GPU env as native_commit_test.zig.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const api = @import("api.zig");
const W = @import("worker.zig");
const C = @import("native_commit.zig");
const N = @import("native_pcs.zig");
const S2 = @import("native_stage2.zig");
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
    &.{ .{ .log_size = 4, .encoding = .coefficients }, .{ .log_size = 5, .encoding = .coefficients } }, // FIXED
    &.{ .{ .log_size = 5, .encoding = .evaluations }, .{ .log_size = 4, .encoding = .evaluations }, .{ .log_size = 5, .encoding = .evaluations } }, // MAIN
    &.{ .{ .log_size = 5, .encoding = .evaluations }, .{ .log_size = 3, .encoding = .evaluations } }, // INTER
    &.{ .{ .log_size = 5, .encoding = .coefficients }, .{ .log_size = 5, .encoding = .coefficients }, .{ .log_size = 5, .encoding = .coefficients }, .{ .log_size = 5, .encoding = .coefficients } }, // composition
};
const max_log: u32 = 5;
const claim_count: u32 = 5;
fn masks(tree: usize, column: usize) []const isize {
    return switch (tree) {
        0 => &.{0},
        1 => if (column == 1) &.{ 0, -1 } else &.{0},
        2 => if (column == 0) &.{ -1, 0 } else &.{0},
        else => &.{0},
    };
}
fn maskPoints(a: std.mem.Allocator, oods: Point) !core.pcs.TreeVec([][]Point) {
    const trees = try a.alloc([][]Point, tree_shapes.len);
    for (tree_shapes, trees, 0..) |shapes, *columns, t| {
        columns.* = try a.alloc([]Point, shapes.len);
        for (columns.*, 0..) |*p, c| {
            p.* = try a.alloc(Point, masks(t, c).len);
            for (masks(t, c), p.*) |m, *v| {
                const s = core.poly.circle.canonic.CanonicCoset.new(max_log).step().mulSigned(m);
                v.* = oods.add(.{ .x = OM.fromBase(s.x), .y = OM.fromBase(s.y) });
            }
        }
    }
    return core.pcs.TreeVec([][]Point).initOwned(trees);
}
fn words(values: []const M) []const u32 {
    return @as([*]const u32, @ptrCast(values.ptr))[0..values.len];
}

const Producer = struct {
    plan: *C.CommitPlan,
    csym: C.Symbols,
    inputs: []const C.Input,
    alpha_copy: api.DeviceBuffer = undefined,
    fn enqueue(raw: *anyopaque, e: *api.Enqueue, alpha: api.DeviceBuffer, root_out: api.DeviceBuffer) anyerror!S2.Composition.Committed {
        const self: *Producer = @ptrCast(@alignCast(raw));
        if (self.csym.copy_d2d(e.ctx(), self.alpha_copy.ptr, alpha.ptr, 32) != 0) return error.CudaEnqueueFailed;
        return .{ .plan = self.plan, .tree = try self.plan.enqueue(self.csym, e, self.inputs, root_out, false) };
    }
};

const Probe = struct {
    plans: [4]*C.CommitPlan,
    csym: C.Symbols,
    stage2: *S2.Stage2,
    producer: *Producer,
    manifest: [32]u8,
    seed: [9]u32,
    claims: []const u32,
    inputs: [4][]C.Input,
    seed_buffer: ?api.DeviceBuffer = null,
    claims_buffer: ?api.DeviceBuffer = null,
    slab_words: usize,
    result: []u32,
    pub fn classKey(_: *Probe) [32]u8 {
        return @splat(12);
    }
    pub fn footprint(self: *Probe) api.Footprint {
        var words_needed: usize = 1 << 20;
        for (self.plans) |p| words_needed += p.deviceWords();
        return .{ .device_words = words_needed, .staged_words = 1 << 12, .slab_words = self.slab_words, .pinned_words = @intCast(self.stage2.pcs.ingressWords() + (1 << 13)) };
    }
    pub fn stage(self: *Probe, s: *api.Stager) !void {
        const b = try s.alloc(9);
        try s.upload(b, &self.seed);
        self.seed_buffer = b;
        const c = try s.alloc(self.claims.len);
        try s.upload(c, self.claims);
        self.claims_buffer = c;
        for ([_]usize{ 0, 1, 3 }) |t| try self.plans[t].stage(s, self.inputs[t]);
        try self.stage2.stage(s, self.manifest, self.inputs[2]);
    }
    pub fn enqueue(self: *Probe, e: *api.Enqueue) !void {
        try e.channel.initFromCheckpoint(self.seed_buffer.?);
        const roots = try e.slab.device.slice(0, 32);
        var prior: [2]S2.Composition.Committed = undefined;
        for (&prior, 0..) |*p, t| p.* = .{ .plan = self.plans[t], .tree = try self.plans[t].enqueue(self.csym, e, self.inputs[t], try roots.slice(8 * t, 8), true) };
        self.producer.alpha_copy = try e.slab.device.slice(32, 8);
        const fields = S2.Fields{ .roots = roots, .alpha = try e.slab.device.slice(48, 8), .oods = try e.slab.device.slice(64, N.oods_field_words), .pcs = try e.slab.device.slice(128, @intCast(self.stage2.pcs.outputWords())) };
        try self.stage2.enqueue(e, prior, self.claims_buffer.?, self.inputs[2], .{ .ctx = self.producer, .enqueue = Producer.enqueue }, fields);
        for (prior) |p| e.free(p.tree.coefficients);
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

test "GPU: NativeStage2 transcript (manifest+claims mix, INTER, device coefficient, composition, OODS, PCS) equals the host" {
    var gpu = (try @import("native_gpu_support_test.zig").Gpu.open()) orelse return error.SkipZigTest;
    defer gpu.close();
    const a = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const ar = arena_state.allocator();
    const csym = try C.Symbols.load(&gpu.libs.base);
    const nsym = try N.Symbols.load(&gpu.libs.addon);
    const config = core.pcs.PcsConfig{ .pow_bits = 8, .fri_config = .{ .log_blowup_factor = 1, .log_last_layer_degree_bound = 0, .n_queries = 6, .fold_step = 4 } };

    var prng = std.Random.DefaultPrng.init(0x73746732);
    var coefficients: [4][][]M = undefined;
    var evaluations: [4][][]M = undefined;
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
    var manifest: [32]u8 = undefined;
    prng.random().bytes(&manifest);
    const claims = try ar.alloc(OM, claim_count);
    const claim_words = try ar.alloc(u32, claim_count * 8);
    for (claims, 0..) |*c, i| {
        var limbs: [8]M = undefined;
        for (&limbs) |*l| l.* = M.fromCanonical(prng.random().uintLessThan(u32, core.fields.m31.Modulus));
        c.* = OM.fromM31Array(limbs);
        for (c.toM31Array(), 0..) |v, k| claim_words[8 * i + k] = v.v;
    }

    // Host transcript.
    var channel = Channel.init();
    channel.mixU32s(&.{ 0x4d385332, 2 });
    var seed: [9]u32 = undefined;
    for (seed[0..8], 0..) |*w, i| w.* = std.mem.readInt(u32, channel.inner.digest[i * 4 ..][0..4], .little);
    seed[8] = channel.inner.n_draws;
    var scheme = try Scheme.init(a, config);
    var roots: [4][32]u8 = undefined;
    var alpha: OM = undefined;
    for (tree_shapes, evaluations, &roots, 0..) |shapes, es, *root, t| {
        if (t == 2) {
            // The legacy function itself (CpuWorker.complete calls it before the INTER commit).
            @import("stwo_riscv_cpu_integration").rv64_gkr_worker_protocol.mixManifestAndClaims(&channel, manifest, claims);
        }
        if (t == 3) alpha = channel.drawSecureFelt();
        const columns = try ar.alloc(engine.pcs.ColumnEvaluation, shapes.len);
        for (columns, shapes, es) |*col, shape, ev| col.* = .{ .log_size = shape.log_size, .values = try ar.dupe(M, ev) };
        var builder = scheme.treeBuilder(a);
        defer builder.deinit();
        _ = try builder.extendColumns(columns);
        try builder.commit(&channel);
        root.* = scheme.trees.items[t].commitment.root();
    }
    const oods = try core.circle.secureFieldPointFromRandomSeedCheckedFor(OM, channel.drawSecureFelt());
    var extended = try scheme.proveValues(a, try maskPoints(a, oods), &channel);
    defer extended.deinit(a);
    const host_json = try std.json.Stringify.valueAlloc(a, extended.proof, .{});
    defer a.free(host_json);

    // Job path.
    const placeholder = try N.placeholderPoint();
    const job_points = try maskPoints(ar, placeholder);
    var trees: [4]D.Tree = undefined;
    for (tree_shapes, &trees) |shapes, *tree| {
        const columns = try ar.alloc(D.Column, shapes.len);
        for (columns, shapes) |*col, shape| col.* = N.placeholderColumn(shape.log_size);
        tree.* = .{ .root = @splat(0), .columns = columns };
    }
    var pcs = try N.PcsJob.prepare(a, nsym, .{ .config = config, .lifting_log_size = max_log + 1, .trees = &trees, .points = job_points }, placeholder, true);
    defer pcs.deinit(a);
    var plans: [4]C.CommitPlan = undefined;
    for (tree_shapes, &plans) |shapes, *plan| plan.* = try C.CommitPlan.init(a, shapes, 1);
    defer for (&plans) |*plan| plan.deinit();
    var inputs: [4][]C.Input = undefined;
    for (tree_shapes, coefficients, evaluations, &inputs) |shapes, cs, es, *in| {
        in.* = try ar.alloc(C.Input, shapes.len);
        for (shapes, cs, es, in.*) |shape, c, ev, *x| x.* = .{ .host = words(if (shape.encoding == .evaluations) ev else c) };
    }
    var stage2 = S2.Stage2{ .inter = &plans[2], .pcs = &pcs, .csym = csym, .nsym = nsym, .claim_count = claim_count };
    var producer = Producer{ .plan = &plans[3], .csym = csym, .inputs = inputs[3] };
    const slab_words = 128 + @as(usize, @intCast(pcs.outputWords()));
    const result = try a.alloc(u32, slab_words);
    defer a.free(result);
    var probe = Probe{ .plans = .{ &plans[0], &plans[1], &plans[2], &plans[3] }, .csym = csym, .stage2 = &stage2, .producer = &producer, .manifest = manifest, .seed = seed, .claims = claim_words, .inputs = inputs, .slab_words = slab_words, .result = result };
    const w = try W.Worker.create(a, &gpu.libs.ops, .{ .device = 0, .arena_words = 1 << 24, .pinned_slot_words = 1 << 20, .max_outstanding = 2 });
    var done: Done = .{};
    try w.submit(api.Job.from(Probe, &probe), .{ .ctx = &done, .done = Done.onDone });
    while (done.n.load(.seq_cst) == 0) std.Thread.yield() catch {};
    w.destroy();
    if (done.err) |err| return err;

    for (roots, 0..) |root, t| for (0..8) |i| try std.testing.expectEqual(std.mem.readInt(u32, root[i * 4 ..][0..4], .little), result[8 * t + i]);
    for (alpha.toM31Array(), 0..) |v, i| {
        try std.testing.expectEqual(v.v, result[32 + i]); // what the composition producer saw
        try std.testing.expectEqual(v.v, result[48 + i]); // the slab field
    }
    var decoded = try pcs.decode(a, result[128..], &roots);
    defer decoded.proof.deinit(a);
    const job_json = try std.json.Stringify.valueAlloc(a, decoded.proof, .{});
    defer a.free(job_json);
    try std.testing.expectEqualStrings(host_json, job_json);
    try std.testing.expectEqualSlices(u8, &channel.inner.digest, &decoded.channel.inner.digest);
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(job_json, &digest, .{});
    std.debug.print("GPU_M8_NATIVE_STAGE2_PARITY trees=4 claims={} pow_bits={} alpha_equal=1 roots_equal=1 proof_sha256={x} byte_identical=1 channel_equal=1\n", .{ claim_count, config.pow_bits, digest });
}
