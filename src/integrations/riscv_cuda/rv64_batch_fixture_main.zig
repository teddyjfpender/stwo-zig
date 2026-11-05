//! Cold fixtures from the actual native mixed-height OM31 sumcheck prover.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const G = engine.lookups.gkr_prover.ForField(O);
const S = engine.lookups.sumcheck.ForField(O);
const Mle = engine.lookups.mle.MleFor;
const Channel = core.channel.raw_mod_m31.Om31Channel;
const IO = @import("rv64/fixture_io.zig");
const a = std.heap.page_allocator;
fn random(rng: std.Random) O {
    var coords: [8]M = undefined;
    for (&coords) |*v| v.* = M.fromCanonical(rng.uintLessThan(u32, 2147483647));
    return O.fromM31Array(coords);
}
fn checkpoint(w: anytype, channel: Channel) !void {
    for (0..8) |i| try IO.words(w, &.{std.mem.readInt(u32, channel.inner.digest[i * 4 ..][0..4], .little)});
    try IO.words(w, &.{channel.inner.n_draws});
}
fn fixture(dir: std.fs.Dir, variables: []const u32, id: u32) !void {
    var max_vars: u32 = 0;
    for (variables) |v| max_vars = @max(max_vars, v);
    var channel = Channel.init();
    channel.mixU32s(&.{ 0x42534331, id });
    var alpha = channel.drawSecureFelt();
    var lambda = channel.drawSecureFelt();
    if (id == 9) alpha = O.zero();
    if (id == 10) alpha = O.one();
    if (id == 11) lambda = O.zero();
    const point = try channel.drawSecureFelts(a, max_vars);
    defer a.free(point);
    const initial_channel = channel;
    var eq = try G.EqEvals.generate(a, point);
    defer eq.deinit(a);
    const oracles = try a.alloc(G.GkrMultivariatePolyOracle, variables.len);
    var initialized: usize = 0;
    defer {
        for (oracles[0..initialized]) |*oracle| oracle.deinit(a);
        a.free(oracles);
    }
    const claims = try a.alloc(O, variables.len);
    defer a.free(claims);
    var rng = std.Random.DefaultPrng.init(0x1dc57f + id);
    var data: std.ArrayList(u8) = .empty;
    defer data.deinit(a);
    const w = data.writer(a);
    try IO.words(w, &.{ 0x52564253, 1, @intCast(variables.len), max_vars, id, 0, 0, 0 });
    try checkpoint(w, initial_channel);
    try IO.felts(w, &.{ alpha, lambda });
    try IO.felts(w, point);
    // Claims are serialized before the per-oracle matrices, after all are known.
    var matrices: std.ArrayList(u8) = .empty;
    defer matrices.deinit(a);
    const mw = matrices.writer(a);
    var mixed = O.zero();
    var weight = O.one();
    for (variables, 0..) |v, i| {
        const n = @as(usize, 1) << @intCast(v + 1);
        const base_mode = (id + i) % 2 == 0;
        const denoms = try a.alloc(O, n);
        var denoms_owned = true;
        errdefer if (denoms_owned) a.free(denoms);
        for (denoms) |*x| x.* = random(rng.random());
        var layer: G.Layer = undefined;
        if (base_mode) {
            const nums = try a.alloc(M, n);
            errdefer a.free(nums);
            for (nums) |*x| x.* = if (id == 11) M.zero() else M.fromCanonical(rng.random().uintLessThan(u32, 2147483647));
            layer = .{ .LogUpMultiplicities = .{ .numerators = try Mle(O, M).initOwned(nums), .denominators = try Mle(O, O).initOwned(denoms) } };
        } else {
            const nums = try a.alloc(O, n);
            errdefer a.free(nums);
            for (nums) |*x| x.* = if (id == 11) O.zero() else random(rng.random());
            layer = .{ .LogUpGeneric = .{ .numerators = try Mle(O, O).initOwned(nums), .denominators = try Mle(O, O).initOwned(denoms) } };
        }
        oracles[i] = layer.intoMultivariatePolyOwned(lambda, &eq);
        initialized += 1;
        denoms_owned = false;
        var next = (try layer.nextLayer(a)).?;
        defer next.deinit(a);
        const suffix = point[max_vars - v ..];
        const num = try next.LogUpGeneric.numerators.evalAtPoint(a, suffix);
        const den = try next.LogUpGeneric.denominators.evalAtPoint(a, suffix);
        claims[i] = num.add(lambda.mul(den));
        mixed = mixed.add(weight.mul(claims[i]).mulM31(M.fromCanonical(@as(u32, 1) << @intCast(max_vars - v))));
        weight = weight.mul(alpha);
        try IO.words(mw, &.{ v, @intFromBool(base_mode) });
        switch (layer) {
            .LogUpGeneric => |l| try IO.soa(mw, l.numerators.evals),
            .LogUpMultiplicities => |l| for (l.numerators.evals) |x| try IO.words(mw, &.{x.v}),
            else => unreachable,
        }
        try IO.soa(mw, denoms);
    }
    try IO.felts(w, claims);
    try w.writeAll(matrices.items);
    var result = try S.proveBatch(G.GkrMultivariatePolyOracle, a, claims, oracles, alpha, &channel);
    defer result.deinit(a);
    var fresh = initial_channel;
    var verified = try S.partiallyVerify(a, mixed, &result.proof, &fresh);
    defer verified.deinit(a);
    var expected_final = O.zero();
    weight = O.one();
    for (result.claimed_evals) |claim| {
        expected_final = expected_final.add(weight.mul(claim));
        weight = weight.mul(alpha);
    }
    if (!expected_final.eql(verified.claimed_eval) or !std.mem.eql(u8, &fresh.inner.digest, &channel.inner.digest) or fresh.inner.n_draws != channel.inner.n_draws) return error.NativeBatchFreshVerificationMismatch;
    for (result.proof.round_polys, result.assignment, 0..) |poly, challenge, round| {
        if (poly.coeffsSlice().len > 4) return error.BadNativeDegree;
        var coeffs: [4]O = @splat(O.zero());
        @memcpy(coeffs[0..poly.coeffsSlice().len], poly.coeffsSlice());
        try IO.felts(w, &coeffs);
        try IO.felts(w, &.{challenge});
        try IO.words(w, &.{ @intCast(poly.coeffsSlice().len), @intCast(round), 0, 0 });
    }
    try checkpoint(w, channel);
    try IO.felts(w, &.{expected_final});
    for (result.constant_polys, variables, result.claimed_evals) |oracle, v, claim| {
        var mask = try oracle.tryIntoMask(a);
        defer mask.deinit(a);
        const evaluated = try engine.lookups.gkr_verifier.ForField(O).Gate.LogUp.eval(a, &mask);
        defer a.free(evaluated);
        const at_point = engine.lookups.utils.hornerEval(O, evaluated, lambda);
        const eq_value = try engine.lookups.utils.eq(O, point[max_vars - v ..], result.assignment[max_vars - v ..]);
        if (!at_point.mul(eq_value).eql(claim)) return error.NativeBatchOracleMaskMismatch;
        for (mask.columnsSlice()) |column| try IO.felts(w, &column);
    }
    const file = try std.fmt.allocPrint(a, "case-{}.bin", .{id});
    defer a.free(file);
    try dir.writeFile(.{ .sub_path = file, .data = data.items });
    std.debug.print("batch={} oracles={} variables={} native_fresh_verify=true oracle_mask_checked=true proof_rounds={}\n", .{ id, variables.len, max_vars, result.proof.round_polys.len });
}
pub fn main() !void {
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 2) return error.ExpectedOutputDirectory;
    try std.fs.cwd().makePath(args[1]);
    var dir = try std.fs.cwd().openDir(args[1], .{});
    defer dir.close();
    const cases = [_][]const u32{ &.{0}, &.{1}, &.{ 0, 1 }, &.{ 4, 2, 0 }, &.{ 2, 7, 4, 1 }, &.{ 10, 8, 6, 0 }, &.{ 5, 5, 5, 5, 5 }, &.{ 0, 0, 0 }, &.{ 6, 4, 3 }, &.{ 6, 4, 0 }, &.{ 4, 5, 2 }, &.{ 4, 2, 0 } };
    for (cases, 0..) |vars, id| try fixture(dir, vars, @intCast(id));
    try fixture(dir, &.{ 16, 12, 8, 0 }, 12);
    try fixture(dir, &([_]u32{0} ** 64), 13);
    var mixed_sizes: [64]u32 = undefined;
    for (&mixed_sizes, 0..) |*v, i| v.* = @intCast(i % 7);
    try fixture(dir, &mixed_sizes, 14);
    var expanded: [128]u32 = undefined;
    for (&expanded, 0..) |*v, i| v.* = @intCast(i % 7);
    try fixture(dir, expanded[0..65], 15);
    try fixture(dir, &expanded, 16);
}
