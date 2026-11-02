//! Full unbound native GKR circuit fixtures, with fresh verification and input
//! MLE closure. No Ethereum/PCS authority is claimed by this cold exporter.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const G = engine.lookups.gkr_prover.ForField(O);
const V = engine.lookups.gkr_verifier.ForField(O);
const S = engine.lookups.sumcheck.ForField(O);
const Mle = engine.lookups.mle.MleFor;
const U = engine.lookups.utils;
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
    channel.mixU32s(&.{ 0x474b5231, id });
    const initial_channel = channel;
    const layers = try a.alloc(G.Layer, variables.len);
    var initialized: usize = 0;
    defer {
        for (layers[0..initialized]) |*l| l.deinit(a);
        a.free(layers);
    }
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(a);
    const w = bytes.writer(a);
    try IO.words(w, &.{ 0x5256474b, 1, @intCast(variables.len), max_vars, id, 0, 0, 0 });
    try checkpoint(w, initial_channel);
    var rng = std.Random.DefaultPrng.init(0x752ae0 + id);
    for (variables, 0..) |v, i| {
        const n = @as(usize, 1) << @intCast(v);
        const base_mode = (id + i) % 2 == 0;
        const denoms = try a.alloc(O, n);
        var denoms_owned = true;
        errdefer if (denoms_owned) a.free(denoms);
        for (denoms) |*x| x.* = random(rng.random());
        if (base_mode) {
            const nums = try a.alloc(M, n);
            errdefer a.free(nums);
            for (nums) |*x| x.* = if (id == 6) M.zero() else M.fromCanonical(rng.random().uintLessThan(u32, 2147483647));
            layers[i] = .{ .LogUpMultiplicities = .{ .numerators = try Mle(O, M).initOwned(nums), .denominators = try Mle(O, O).initOwned(denoms) } };
        } else {
            const nums = try a.alloc(O, n);
            errdefer a.free(nums);
            for (nums) |*x| x.* = if (id == 6) O.zero() else random(rng.random());
            layers[i] = .{ .LogUpGeneric = .{ .numerators = try Mle(O, O).initOwned(nums), .denominators = try Mle(O, O).initOwned(denoms) } };
        }
        initialized += 1;
        denoms_owned = false;
        try IO.words(w, &.{ v, @intFromBool(base_mode) });
        switch (layers[i]) {
            .LogUpGeneric => |l| try IO.soa(w, l.numerators.evals),
            .LogUpMultiplicities => |l| for (l.numerators.evals) |x| try IO.words(w, &.{x.v}),
            else => unreachable,
        }
        try IO.soa(w, denoms);
    }
    var result = try G.proveBatch(a, &channel, layers);
    defer result.deinit(a);
    const gates = try a.alloc(V.Gate, layers.len);
    defer a.free(gates);
    @memset(gates, .LogUp);
    var fresh = initial_channel;
    var artifact = try V.partiallyVerifyBatch(a, gates, &result.proof, &fresh);
    defer artifact.deinit(a);
    if (!std.mem.eql(u8, &fresh.inner.digest, &channel.inner.digest) or fresh.inner.n_draws != channel.inner.n_draws) return error.NativeGkrCheckpointMismatch;
    for (layers, variables, artifact.claims_to_verify_by_instance, 0..) |l, v, claims, i| {
        if (artifact.n_variables_by_instance[i] != v) return error.NativeGkrHeightMismatch;
        const suffix = artifact.ood_point[artifact.ood_point.len - v ..];
        const num = switch (l) {
            .LogUpGeneric => |x| try x.numerators.evalAtPoint(a, suffix),
            .LogUpMultiplicities => |x| try x.numerators.evalAtPoint(a, suffix),
            else => unreachable,
        };
        const den = switch (l) {
            .LogUpGeneric => |x| try x.denominators.evalAtPoint(a, suffix),
            .LogUpMultiplicities => |x| try x.denominators.evalAtPoint(a, suffix),
            else => unreachable,
        };
        if (claims.len != 2 or !claims[0].eql(num) or !claims[1].eql(den)) return error.NativeGkrInputClosureMismatch;
    }
    for (result.proof.output_claims_by_instance) |root| try IO.felts(w, root);
    // Replay the already freshly verified native proof solely to capture each
    // inner assignment. The device never receives these expected values.
    var replay = initial_channel;
    const claims = try a.alloc([2]O, layers.len);
    defer a.free(claims);
    for (result.proof.sumcheck_proofs, 0..) |*proof, depth| {
        const remaining = max_vars - @as(u32, @intCast(depth));
        var active: u32 = 0;
        for (variables, 0..) |v, i| {
            if (v == remaining) @memcpy(&claims[i], result.proof.output_claims_by_instance[i]);
            if (v >= remaining) {
                replay.mixFelts(&claims[i]);
                active += 1;
            }
        }
        const alpha = replay.drawSecureFelt();
        const lambda = replay.drawSecureFelt();
        try IO.words(w, &.{ @intCast(depth), active });
        try IO.felts(w, &.{ alpha, lambda });
        try checkpoint(w, replay);
        var mixed = O.zero();
        var weight = O.one();
        for (variables, 0..) |v, i| if (v >= remaining) {
            const c = U.hornerEval(O, &claims[i], lambda);
            try IO.felts(w, &.{c});
            mixed = mixed.add(weight.mul(c).mulM31(M.fromCanonical(@as(u32, 1) << @intCast(max_vars - v))));
            weight = weight.mul(alpha);
        };
        var sc = try S.partiallyVerify(a, mixed, proof, &replay);
        defer sc.deinit(a);
        if (sc.assignment.len != depth) return error.NativeGkrRoundCountMismatch;
        for (proof.round_polys, sc.assignment, 0..) |poly, challenge, round| {
            if (poly.coeffsSlice().len > 4) return error.NativeGkrDegreeMismatch;
            var coefficients: [4]O = @splat(O.zero());
            @memcpy(coefficients[0..poly.coeffsSlice().len], poly.coeffsSlice());
            try IO.felts(w, &coefficients);
            try IO.felts(w, &.{challenge});
            try IO.words(w, &.{ @intCast(poly.coeffsSlice().len), @intCast(round), 0, 0 });
        }
        for (variables, 0..) |v, i| if (v >= remaining) {
            const mask = result.proof.layer_masks_by_instance[i][v - remaining];
            var flat: [4]O = undefined;
            for (mask.columnsSlice(), 0..) |column, c| @memcpy(flat[2 * c ..][0..2], &column);
            try IO.felts(w, &flat);
            replay.mixFelts(&flat);
        };
        const z = replay.drawSecureFelt();
        try checkpoint(w, replay);
        try IO.felts(w, sc.assignment);
        try IO.felts(w, &.{z});
        for (variables, 0..) |v, i| if (v >= remaining) {
            const mask = result.proof.layer_masks_by_instance[i][v - remaining];
            const reduced = try mask.reduceAtPoint(a, z);
            defer a.free(reduced);
            @memcpy(&claims[i], reduced);
            try IO.felts(w, &claims[i]);
        };
    }
    if (!std.mem.eql(u8, &replay.inner.digest, &channel.inner.digest) or replay.inner.n_draws != channel.inner.n_draws) return error.NativeGkrReplayMismatch;
    try IO.felts(w, artifact.ood_point);
    for (artifact.claims_to_verify_by_instance) |c| try IO.felts(w, c);
    const file = try std.fmt.allocPrint(a, "case-{}.bin", .{id});
    defer a.free(file);
    try dir.writeFile(.{ .sub_path = file, .data = bytes.items });
    std.debug.print("gkr={} instances={} layers={} fresh_verification=true input_mle_closure=true\n", .{ id, layers.len, max_vars });
}
pub fn main() !void {
    const args = try std.process.argsAlloc(a);
    defer std.process.argsFree(a, args);
    if (args.len != 2) return error.ExpectedOutputDirectory;
    try std.fs.cwd().makePath(args[1]);
    var dir = try std.fs.cwd().openDir(args[1], .{});
    defer dir.close();
    const cases = [_][]const u32{ &.{1}, &.{ 1, 3, 2 }, &.{ 5, 3, 1 }, &.{ 6, 4, 2, 1 }, &.{ 8, 5, 3, 1 }, &.{ 10, 6, 4, 2 }, &.{ 5, 3, 1 } };
    for (cases, 0..) |v, id| try fixture(dir, v, @intCast(id));
    var mixed: [64]u32 = undefined;
    for (&mixed, 0..) |*v, i| v.* = @intCast(i % 5 + 1);
    try fixture(dir, &mixed, 7);
}
