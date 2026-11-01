const std = @import("std");
const core = @import("stwo_core");
const New = @import("gkr_prover.zig");
const Verify = @import("gkr_verifier.zig");
const Pools = @import("../work_pool.zig");
const M = core.fields.m31.M31;
const a = std.testing.allocator;
fn value(comptime S: type, i: usize) S {
    var coordinates: [S.zero().toM31Array().len]M = undefined;
    for (&coordinates, 0..) |*c, j| c.* = M.fromCanonical(@intCast((i * 7919 + j * 977 + 3) % 1048573));
    return S.fromM31Array(coordinates);
}
fn channel(comptime S: type) type {
    return if (S == core.fields.om31.OM31) core.channel.raw_mod_m31.Om31Channel else core.channel.blake2s.Blake2sChannel;
}
fn startChannel(comptime S: type) channel(S) {
    if (S == core.fields.om31.OM31) return channel(S).init();
    return .{};
}
fn layers(comptime G: type, comptime S: type, n: []M, d: []S, ns: []S) [4]G.Layer {
    return .{
        .{ .GrandProduct = .{ .evals = d[0..32768], .owns_evals = false } },
        .{ .LogUpGeneric = .{ .numerators = .{ .evals = ns, .owns_evals = false }, .denominators = .{ .evals = d, .owns_evals = false } } },
        .{ .LogUpMultiplicities = .{ .numerators = .{ .evals = n, .owns_evals = false }, .denominators = .{ .evals = d, .owns_evals = false } } },
        .{ .LogUpSingles = .{ .denominators = .{ .evals = d[0..16384], .owns_evals = false } } },
    };
}
fn fresh(comptime S: type, input: anytype, proof: anytype) !void {
    const V = Verify.ForField(S);
    var ch = startChannel(S);
    var artifact = try V.partiallyVerifyBatch(a, &.{ .GrandProduct, .LogUp, .LogUp, .LogUp }, proof, &ch);
    defer artifact.deinit(a);
    var expected: [4][]S = undefined;
    var initialized: usize = 0;
    defer for (expected[0..initialized]) |e| a.free(e);
    for (input, 0..) |layer, i| {
        const dimensions = layer.nVariables();
        const point = artifact.ood_point[artifact.ood_point.len - dimensions ..];
        expected[i] = switch (layer) {
            .GrandProduct => |x| try a.dupe(S, &.{try x.evalAtPoint(a, point)}),
            inline .LogUpGeneric, .LogUpMultiplicities => |x| try a.dupe(S, &.{ try x.numerators.evalAtPoint(a, point), try x.denominators.evalAtPoint(a, point) }),
            .LogUpSingles => |x| try a.dupe(S, &.{ S.one(), try x.denominators.evalAtPoint(a, point) }),
        };
        initialized += 1;
    }
    try @import("verifier_kernel.zig").verifyTerminalInputs(S, &artifact, &expected, V.NativeChecks{});
}
pub fn exerciseWithBaseline(comptime S: type, comptime Baseline: type) !void {
    const G = New.ForField(S);
    const n = try a.alloc(M, 65536);
    defer a.free(n);
    const d = try a.alloc(S, 65536);
    defer a.free(d);
    const ns = try a.alloc(S, 65536);
    defer a.free(ns);
    for (n, d, ns, 0..) |*numerator, *denominator, *secure_numerator, i| {
        numerator.* = if (i % 3 == 0) M.zero() else if (i % 3 == 1) M.one().neg() else M.fromCanonical(@intCast(i % 7));
        denominator.* = value(S, i);
        secure_numerator.* = value(S, i + 31);
    }
    const old_input = layers(Baseline, S, n, d, ns);
    var old_ch = startChannel(S);
    var timer = try std.time.Timer.start();
    var control = try Baseline.proveBatch(a, &old_ch, &old_input);
    defer control.deinit(a);
    const control_ns = timer.read();
    const control_bytes = try std.json.Stringify.valueAlloc(a, control.proof, .{});
    defer a.free(control_bytes);
    const control_draw = old_ch.drawSecureFelt();
    for ([_]usize{ 1, 2, 4, 8 }) |workers| {
        var pool: Pools.WorkPool = undefined;
        try pool.initInPlaceWithOptions(.{ .worker_count = workers });
        defer pool.deinit();
        var binding = try Pools.ScopedPoolBinding.init(&pool);
        defer binding.deinit();
        var ch = startChannel(S);
        const input = layers(G, S, n, d, ns);
        timer.reset();
        var result = try G.proveBatch(a, &ch, &input);
        defer result.deinit(a);
        const ns_elapsed = timer.read();
        const bytes = try std.json.Stringify.valueAlloc(a, result.proof, .{});
        defer a.free(bytes);
        try std.testing.expectEqualSlices(u8, control_bytes, bytes);
        try std.testing.expect(control_draw.eql(ch.drawSecureFelt()));
        try fresh(S, &input, &result.proof);
        if (std.process.hasEnvVarConstant("STWO_ZIG_BENCH_GKR_ROWS")) std.debug.print("GKR_ROW_CAPTURE field={s} workers={d} control_ns={d} prove_ns={d} json_bytes={d}\n", .{ @typeName(S), workers, control_ns, ns_elapsed, bytes.len });
    }
}
test "Q mixed-gate scoped row kernels preserve complete proof transcript and fresh binding" {
    try exerciseWithBaseline(core.fields.qm31.QM31, New.ForField(core.fields.qm31.QM31));
}
test "OM mixed-gate scoped row kernels preserve complete proof transcript and fresh binding" {
    try exerciseWithBaseline(core.fields.om31.OM31, New.ForField(core.fields.om31.OM31));
}
test "row kernels fall back without a nested lease and use bounded stack payload" {
    const O = core.fields.om31.OM31;
    const Context = struct {
        pub fn sumRange(_: @This(), first: usize, end: usize) [2]O {
            return .{ O.fromBase(M.fromCanonical(@intCast(end - first))), O.zero() };
        }
    };
    var pool: Pools.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4 });
    defer pool.deinit();
    var binding = try Pools.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var outer = try pool.acquire(try Pools.WorkerBudget.init(4));
    defer outer.deinit();
    const result = @import("row_work.zig").reduce(O, 65536, Context{});
    try std.testing.expect(result[0].eql(O.fromBase(M.fromCanonical(65536))));
    try std.testing.expect(@import("row_work.zig").scratchBytes(O) < 4096);
}

test "bounded callback ranges honor explicit grain and publish each ordinal once" {
    const Rows = @import("row_work.zig");
    const Context = struct {
        lengths: [Rows.MAX_SHARDS]usize = @splat(0),
        pub fn runRange(self: *@This(), index: usize, first: usize, end: usize) void {
            self.lengths[index] = end - first;
        }
    };
    var pool: Pools.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4 });
    defer pool.deinit();
    var binding = try Pools.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var context = Context{};
    const shards = Rows.forEachRange(513, &context, .{ .max_shards = 3, .min_rows_per_shard = 64 });
    try std.testing.expectEqual(@as(usize, 3), shards);
    var count: usize = 0;
    for (context.lengths) |n| count += n;
    try std.testing.expectEqual(@as(usize, 513), count);
}
