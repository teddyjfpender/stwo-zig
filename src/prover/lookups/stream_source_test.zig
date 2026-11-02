const std = @import("std");
const core = @import("stwo_core");
const GP = @import("gkr_prover.zig");
const GV = @import("gkr_verifier.zig");
const C = @import("gkr_circuit.zig");
const ML = @import("mle.zig");
const Pools = @import("../work_pool.zig");
const M = core.fields.m31.M31;
const a = std.testing.allocator;
fn dense(comptime S: type, seed: usize) S {
    var c: [S.zero().toM31Array().len]M = undefined;
    for (&c, 0..) |*v, i| v.* = M.fromCanonical(@intCast((seed * 7919 + i * 977 + 3) % 1048573));
    return S.fromM31Array(c);
}
fn Reader(comptime S: type) type {
    return struct {
        variables: u32,
        seed: usize = 0,
        zero_den: bool = false,
        fail_len: usize = 0,
        oom: bool = false,
        fn source(self: *const @This()) GP.ForField(S).MultiplicitiesSource {
            return .{ .variables = self.variables, .context = self, .read_fn = read };
        }
        fn numerator(_: @This(), i: usize) M {
            return if (i % 3 == 0) M.zero() else if (i % 3 == 1) M.one().neg() else M.fromCanonical(@intCast(i % 19));
        }
        fn denominator(self: @This(), i: usize) S {
            return if (self.zero_den and i == 1) S.zero() else if (i % 17 == 0) S.one() else dense(S, i + self.seed);
        }
        fn read(ctx: *const anyopaque, first: usize, n: []M, d: []S) @import("multiplicities_source.zig").Error!void {
            const self: *const @This() = @ptrCast(@alignCast(ctx));
            if (n.len > 64 or n.len != d.len) return error.ShapeMismatch;
            if (self.fail_len != 0 and n.len == self.fail_len) return if (self.oom) error.OutOfMemory else error.ShapeMismatch;
            for (n, d, first..) |*nv, *dv, i| {
                nv.* = self.numerator(i);
                dv.* = self.denominator(i);
            }
        }
        fn layer(self: @This(), allocator: std.mem.Allocator) !GP.ForField(S).Layer {
            const n = try allocator.alloc(M, @as(usize, 1) << @intCast(self.variables));
            errdefer allocator.free(n);
            const d = try allocator.alloc(S, n.len);
            errdefer allocator.free(d);
            for (n, d, 0..) |*nv, *dv, i| {
                nv.* = self.numerator(i);
                dv.* = self.denominator(i);
            }
            return .{ .LogUpMultiplicities = .{ .numerators = try ML.MleFor(S, M).initOwned(n), .denominators = try ML.MleFor(S, S).initOwned(d) } };
        }
    };
}
fn check(comptime S: type, workers: ?usize) !void {
    return checkWithBaseline(S, GP.ForField(S), workers);
}
pub fn checkWithBaseline(comptime S: type, comptime Baseline: type, workers: ?usize) !void {
    const Channel = if (S == core.fields.om31.OM31) core.channel.raw_mod_m31.Om31Channel else core.channel.raw_mod_m31.Qm31Channel;
    const G = GP.ForField(S);
    const V = GV.ForField(S);
    var readers = [_]Reader(S){ .{ .variables = 1 }, .{ .variables = 2, .seed = 31 }, .{ .variables = 16, .seed = 61 }, .{ .variables = 13, .seed = 91 } };
    var sources: [readers.len]G.MultiplicitiesSource = undefined;
    var layers: [readers.len]G.Layer = undefined;
    var done: usize = 0;
    defer for (layers[0..done]) |*layer| layer.deinit(a);
    for (&readers, &sources, &layers) |*r, *s, *layer| {
        s.* = r.source();
        layer.* = try r.layer(a);
        done += 1;
    }
    var old_layers: [readers.len]Baseline.Layer = undefined;
    for (layers, &old_layers) |layer, *old| old.* = .{ .LogUpMultiplicities = .{ .numerators = .{ .evals = layer.LogUpMultiplicities.numerators.evals, .owns_evals = false }, .denominators = .{ .evals = layer.LogUpMultiplicities.denominators.evals, .owns_evals = false } } };
    var expected_channel = Channel.init();
    var expected = try Baseline.proveBatch(a, &expected_channel, &old_layers);
    defer expected.deinit(a);
    var pool: Pools.WorkPool = undefined;
    if (workers) |w| try pool.initInPlaceWithOptions(.{ .worker_count = w, .stack_size = 1024 * 1024 });
    defer if (workers != null) pool.deinit();
    var binding = if (workers != null) try Pools.ScopedPoolBinding.init(&pool) else null;
    defer if (binding) |*b| b.deinit();
    for ([_]bool{ false, true }) |held| {
        var lease = if (held and workers != null) try pool.acquire(try Pools.WorkerBudget.init(workers.?)) else null;
        defer if (lease) |*l| l.deinit();
        var channel = Channel.init();
        var actual = try G.proveBatchSourceCheckpointed(a, &channel, &sources);
        defer actual.deinit(a);
        const old = try std.json.Stringify.valueAlloc(a, .{ expected.proof, expected.artifact }, .{});
        defer a.free(old);
        const new = try std.json.Stringify.valueAlloc(a, .{ actual.proof, actual.artifact }, .{});
        defer a.free(new);
        try std.testing.expectEqualSlices(u8, old, new);
        var old_copy = expected_channel;
        try std.testing.expectEqualDeep(old_copy.drawSecureFelt(), channel.drawSecureFelt());
        var fresh = Channel.init();
        var artifact = try V.partiallyVerifyBatch(a, &.{ .LogUp, .LogUp, .LogUp, .LogUp }, &actual.proof, &fresh);
        defer artifact.deinit(a);
        var terminal: [readers.len][]S = undefined;
        var terminal_done: usize = 0;
        defer for (terminal[0..terminal_done]) |values| a.free(values);
        for (layers, &terminal) |layer, *out| {
            const point = artifact.ood_point[artifact.ood_point.len - layer.nVariables() ..];
            out.* = try a.dupe(S, &.{ try layer.LogUpMultiplicities.numerators.evalAtPoint(a, point), try layer.LogUpMultiplicities.denominators.evalAtPoint(a, point) });
            terminal_done += 1;
        }
        try @import("verifier_kernel.zig").verifyTerminalInputs(S, &artifact, &terminal, V.NativeChecks{});
    }
}
test "streamed bottom Q OM mixed sizes constants and signed padding match dense proof artifact draw and fresh terminal binding" {
    try check(core.fields.qm31.QM31, null);
    try check(core.fields.om31.OM31, null);
}
test "streamed bottom uses joined three worker callbacks and held lease immutable fallback" {
    try check(core.fields.om31.OM31, 3);
}
fn lifecycle(allocator: std.mem.Allocator) !void {
    const S = core.fields.om31.OM31;
    var readers = [_]Reader(S){ .{ .variables = 7 }, .{ .variables = 4, .seed = 31 }, .{ .variables = 1, .seed = 61 } };
    var sources: [readers.len]GP.ForField(S).MultiplicitiesSource = undefined;
    for (&readers, &sources) |*r, *s| s.* = r.source();
    var channel = core.channel.raw_mod_m31.Om31Channel.init();
    var actual = try GP.ForField(S).proveBatchSourceCheckpointed(allocator, &channel, &sources);
    defer actual.deinit(allocator);
}
test "streamed bottom releases every owned checkpoint oracle and result on every OOM" {
    try std.testing.checkAllAllocationFailures(a, lifecycle, .{});
}
test "streamed bottom rejects callback errors and shape violations without escaping borrowed source" {
    const S = core.fields.om31.OM31;
    const G = GP.ForField(S);
    var reader = Reader(S){ .variables = 17 };
    const source = reader.source();
    var ns: [2]M = undefined;
    var ds: [2]S = undefined;
    try std.testing.expectError(error.ShapeMismatch, source.read(source.len(), &ns, &ds));
    try std.testing.expectError(error.ShapeMismatch, source.read(0, &ns, ds[0..1]));
    var malformed = source;
    malformed.variables = 0;
    var ch = core.channel.raw_mod_m31.Om31Channel.init();
    try std.testing.expectError(error.InvalidLayerStructure, G.proveBatchSourceCheckpointed(a, &ch, &.{malformed}));
    try std.testing.expectError(error.EmptyBatch, G.proveBatchSourceCheckpointed(a, &ch, &.{}));
    var pool: Pools.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 3, .stack_size = 1024 * 1024 });
    defer pool.deinit();
    var binding = try Pools.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    for ([_]usize{ 64, 32, 16 }) |fail_len| {
        reader.fail_len = fail_len;
        reader.oom = true;
        ch = core.channel.raw_mod_m31.Om31Channel.init();
        try std.testing.expectError(error.OutOfMemory, G.proveBatchSourceCheckpointed(a, &ch, &.{source}));
    }
}
test "streamed bottom clone materializes independent ownership and zero poles propagate unchanged" {
    const S = core.fields.om31.OM31;
    const CC = C.ForField(S);
    const G = GP.ForField(S);
    var reader = Reader(S){ .variables = 3, .zero_den = true };
    const source = reader.source();
    var eq = try CC.EqEvals.generate(a, &.{ dense(S, 101), dense(S, 131) });
    defer eq.deinit(a);
    var oracle = try CC.sourceOracle(source, false, dense(S, 171), &eq);
    defer oracle.deinit(a);
    var clone = try oracle.cloneOwned(a);
    defer clone.deinit(a);
    try std.testing.expect(clone.source_input == null and clone.input_layer.LogUpMultiplicities.numerators.owns_evals);
    reader.seed = 900;
    try std.testing.expectEqualDeep(dense(S, 2), clone.input_layer.LogUpMultiplicities.denominators.evals[2]);
    var layer = try reader.layer(a);
    defer layer.deinit(a);
    var ch = core.channel.raw_mod_m31.Om31Channel.init();
    var old_ch = ch;
    var expected = try G.proveBatch(a, &old_ch, &.{layer});
    defer expected.deinit(a);
    var actual = try G.proveBatchSourceCheckpointed(a, &ch, &.{source});
    defer actual.deinit(a);
    try std.testing.expect(actual.proof.output_claims_by_instance[0][1].isZero());
    try std.testing.expectEqualDeep(expected.proof, actual.proof);
    try std.testing.expectEqualDeep(old_ch.drawSecureFelt(), ch.drawSecureFelt());
}
