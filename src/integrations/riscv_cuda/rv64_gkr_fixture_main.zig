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
fn bindingSupplement(dir: std.fs.Dir, variables: []const u32, layers: []const G.Layer, artifact: *const V.GkrArtifact, final_channel: Channel, id: u32) !void {
    const MP = @import("stwo_riscv_cpu_integration").rv64_gkr_constraints.MlePoint;
    var channel = final_channel;
    const eta = channel.drawSecureFelt();
    var bytes: std.ArrayList(u8) = .empty;
    defer bytes.deinit(a);
    const w = bytes.writer(a);
    try IO.words(w, &.{ 0x5256424d, 2, id, @intCast(variables.len * 2), @intCast(artifact.ood_point.len), 0, 0, 0 });
    for (variables, 0..) |v, instance| for (0..2) |mode| {
        const lane_log = @min(v - 1, if (mode == 0) @as(u32, @intCast(instance % 9)) else 8);
        const row_log = v - lane_log;
        const suffix = artifact.ood_point[artifact.ood_point.len - v ..];
        const point = try MP.MleEvalPointFor(O).init(suffix[0..row_log]);
        var reservoir: [260]O = @splat(O.zero());
        const lanes = @as(usize, 1) << @intCast(lane_log);
        for (reservoir[0..lanes], 0..) |*weight, lane| {
            weight.* = O.one();
            for (suffix[row_log..], 0..) |coordinate, k| {
                const bit = (lane >> @intCast(lane_log - 1 - k)) & 1;
                weight.* = weight.mul(if (bit != 0) coordinate else O.one().sub(coordinate));
            }
        }
        reservoir[256] = eta;
        const claims = artifact.claims_to_verify_by_instance[instance];
        reservoir[257] = claims[0].add(eta.mul(claims[1])).mulM31(try M.fromCanonical(@as(u32, 1) << @intCast(row_log)).inv());
        reservoir[258] = point.eq0;
        reservoir[259] = point.eq1;
        try IO.words(w, &.{ @intCast(instance), row_log, lane_log, 0 });
        try IO.felts(w, &reservoir);
        try IO.felts(w, suffix[0..row_log]);
        try IO.felts(w, point.hc0[0..row_log]);
        try IO.felts(w, point.hc1[0..row_log]);
        try checkpoint(w, channel);
        const rows = @as(usize, 1) << @intCast(row_log);
        const eq = try a.alloc(O, rows);
        defer a.free(eq);
        const prefix = try a.alloc(O, rows);
        defer a.free(prefix);
        for (eq, prefix, 0..) |*e, *contribution, physical| {
            e.* = O.one();
            for (suffix[0..row_log], 0..) |coordinate, k| e.* = e.mul(if ((physical >> @intCast(row_log - 1 - k)) & 1 != 0) coordinate else O.one().sub(coordinate));
            var pn = O.zero();
            var pd = O.zero();
            for (0..lanes) |lane| {
                const fact = physical * lanes + lane;
                const n = switch (layers[instance]) {
                    .LogUpMultiplicities => |v_| O.fromBase(v_.numerators.evals[fact]),
                    .LogUpGeneric => |v_| v_.numerators.evals[fact],
                    else => unreachable,
                };
                const d = switch (layers[instance]) {
                    .LogUpMultiplicities => |v_| v_.denominators.evals[fact],
                    .LogUpGeneric => |v_| v_.denominators.evals[fact],
                    else => unreachable,
                };
                pn = pn.add(reservoir[lane].mul(n));
                pd = pd.add(reservoir[lane].mul(d));
            }
            contribution.* = e.mul(pn.add(eta.mul(pd))).sub(reservoir[257]);
        }
        var sum = O.zero();
        for (0..rows) |logical| {
            const physical = core.utils.bitReverseIndex(core.utils.cosetIndexToCircleDomainIndex(logical, row_log), row_log);
            sum = sum.add(prefix[physical]);
            prefix[physical] = sum;
        }
        if (!sum.isZero()) return error.NativeBindingWitnessDebt;
        try IO.soa(w, eq);
        try IO.soa(w, prefix);
    };
    const filename = try std.fmt.allocPrint(a, "binding-{}.bin", .{id});
    defer a.free(filename);
    try dir.writeFile(.{ .sub_path = filename, .data = bytes.items });
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
    try bindingSupplement(dir, variables, layers, &artifact, channel, id);
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
