const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const G = A.main_only.global_classic;
const K = A.crypto.keccak;
const S = A.crypto.secp256k1;
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const lane = @import("om31_circuit_lane.zig");
const W = lane.Lane;
const a = std.testing.allocator;
fn dense(seed: usize) O {
    var c: [8]M = undefined;
    for (&c, 0..) |*v, i| v.* = M.fromCanonical(@intCast(seed * 17 + i * 79 + 3));
    return O.fromM31Array(c);
}
fn array(comptime n: usize, seed: usize, t: usize) [n]O {
    var out: [n]O = undefined;
    for (&out, 0..) |*v, i| v.* = dense(seed + i).add(dense(seed + i + 97).mul(O.fromBase(M.fromCanonical(@intCast(t)))));
    return out;
}
fn coefficients(comptime n: usize) [n]O {
    var out: [n]O = undefined;
    for (&out, 0..) |*v, i| v.* = dense(i + 311);
    return out;
}
const Case = enum { ram_ls, kio_truth, wire_truth, wire_bridge };
fn actual(role: Case, t: usize, values: []O) !usize {
    const current = array(208, 811, t);
    const previous = array(208, 1231, t);
    const first = array(2, 2111, t);
    var sink = E.SinkFor(O){ .values = values };
    switch (role) {
        .ram_ls => {
            const LS = A.memory.load_store_v2;
            const R = A.memory.closed_ram;
            const physical = array(LS.layout.MAIN, 101, t);
            const logical = LS.layout.projection.expandFor(O, &physical);
            const ch = R.types.RamChallengesFor(O){ .offset = dense(71), .coefficients = coefficients(14) };
            const d = [_]O{ ch.denominatorFor(O, R.equations.ramTuple(O, .transition, &logical, false)), ch.denominatorFor(O, R.equations.ramTuple(O, .transition, &logical, true)) };
            try G.linearPairsFor(O, &d, &.{ logical[0], logical[0].neg() }, current[0..16], previous[0..16], first[0], first[1], dense(997), &sink);
        },
        .kio_truth => {
            const f = array(K.layout.FIXED, 1, t);
            const m = array(K.layout.MAIN, 101, t);
            const h = array(3, 1011, t);
            const state = array(K.layout.STATE, 2101, t);
            const row = K.equations.RowFor(O){ .fixed = &f, .main = &m, .previous_header = &h, .state_minus_two = &state, .state_minus_one = &state, .state_plus_one = &state, .state_plus_two = &state };
            var d: [25]O = undefined;
            const weight = K.equations.ioActiveFor(O, row);
            const weights: [25]O = @splat(weight);
            for (&d, 0..) |*v, i| v.* = E.denominatorFor(O, dense(71), &coefficients(11), &K.equations.ioTupleFor(O, row, i), true);
            try G.singlesFor(O, &d, &weights, &current, &previous, first[0], first[1], dense(997), &sink);
        },
        .wire_truth => {
            const f = array(S.layout.FIXED, 1, t);
            const m = array(319, 101, t);
            const row = S.equations.RowFor(O){ .fixed = &f, .main = &m };
            var d: [3]O = undefined;
            var weights: [3]O = undefined;
            for (&d, &weights, 0..) |*v, *w, i| {
                v.* = E.denominatorFor(O, dense(71), &coefficients(35), &S.equations.wireTupleFor(O, .product, S.program.get(.add), row, i), true);
                w.* = S.equations.wireCoefficientFor(O, row, i);
            }
            try G.singlesFor(O, &d, &weights, current[0..32], previous[0..32], first[0], first[1], dense(997), &sink);
        },
        .wire_bridge => {
            const B = S.word16_bridge;
            const f = array(B.layout.FIXED, 1, t);
            const m = array(B.layout.MAIN, 101, t);
            const d = [_]O{ E.denominatorFor(O, dense(71), &coefficients(35), &B.equations.wireTuple(O, .add, &f, &m, false), true), E.denominatorFor(O, dense(71), &coefficients(35), &B.equations.wireTuple(O, .add, &f, &m, true), true) };
            try G.clearedPairFor(O, d, .{ m[0], m[0].mul(f[6]).neg() }, current[0..16], previous[0..16], first[0], first[1], dense(997), &sink);
        },
    }
    return sink.count;
}
test "OM31 global classic actual RAM KIO Wire tuple/weight authorities stay degree3" {
    var samples: [5][32]O = undefined;
    for (std.enums.values(Case)) |role| {
        var n: usize = 0;
        for (0..5) |t| n = try actual(role, t, &samples[t]);
        for (0..3) |order| for (0..4 - order) |t| for (0..n) |i| {
            samples[t][i] = samples[t + 1][i].sub(samples[t][i]);
        };
        var highest = false;
        for (samples[0][0..n]) |v| highest = highest or !v.isZero();
        try std.testing.expect(highest);
        for (0..n) |i| try std.testing.expect(samples[1][i].sub(samples[0][i]).isZero());
    }
}
fn wire(ctx: *lane.Context, value: O) !W {
    return W.guess(ctx, value);
}
fn encode(comptime F: type, ctx: *lane.Context, values: [2]O) ![16]F {
    var out: [16]F = undefined;
    for (values, 0..) |v, i| for (v.toM31Array(), 0..) |c, j| {
        const value = O.fromBase(c);
        out[8 * i + j] = if (F == O) value else try wire(ctx, value);
    };
    return out;
}
fn circuitPair(mutation: enum { none, pole, inverse_high, prefix_high }, cleared: bool) !bool {
    var ctx = try lane.Context.init(a, 0);
    defer ctx.deinit();
    lane.begin(&ctx);
    var bound = true;
    defer if (bound) lane.finish() catch {};
    const d = if (mutation == .pole) O.zero() else dense(31);
    const e = dense(37);
    const weight = if (mutation == .pole) O.zero() else O.one();
    const inverse = d.mul(e).inv() catch O.zero();
    const sum = if (mutation == .pole) O.zero() else (try weight.div(d)).sub(try O.one().div(e));
    var current = try encode(W, &ctx, .{ inverse, sum });
    const previous = try encode(W, &ctx, .{ O.zero(), O.zero() });
    if (mutation == .inverse_high) current[7] = current[7].add(W.one());
    if (mutation == .prefix_high) current[15] = current[15].add(W.one());
    var residuals: [3]W = undefined;
    var sink = E.SinkFor(W){ .values = &residuals };
    const denominators = [_]W{ try wire(&ctx, d), try wire(&ctx, e) };
    const weights = [_]W{ try wire(&ctx, weight), try wire(&ctx, O.one().neg()) };
    if (cleared) try G.clearedPairFor(W, denominators, weights, &current, &previous, W.zero(), W.zero(), W.zero(), &sink) else try G.linearPairsFor(W, &denominators, &weights, &current, &previous, W.zero(), W.zero(), W.zero(), &sink);
    for (residuals[0..sink.count]) |r| {
        try ctx.eq(r.c0.v, ctx.zero());
        try ctx.eq(r.c1.v, ctx.zero());
    }
    bound = false;
    try lane.finish();
    try ctx.finalize(false);
    return ctx.isCircuitValid();
}
test "OM31 global classic actual circuit rejects zero-weight poles and high-coordinate corruptions" {
    for ([_]bool{ false, true }) |cleared| {
        try std.testing.expect(try circuitPair(.none, cleared));
        try std.testing.expect(!try circuitPair(.pole, cleared));
        try std.testing.expect(!try circuitPair(.inverse_high, cleared));
        try std.testing.expect(!try circuitPair(.prefix_high, cleared));
    }
}
test "OM31 global classic costs account for openings and independent claims" {
    const singles = try G.singlesCost(25);
    const pairs = try G.clearedPairsCost(25);
    try std.testing.expectEqual(@as(usize, 208), singles.columns);
    try std.testing.expectEqual(singles.columns, pairs.columns);
    try std.testing.expectEqual(@as(usize, 216), singles.samples);
    try std.testing.expectEqual(@as(usize, 312), pairs.samples);
    try std.testing.expectEqual(@as(usize, 1), singles.physical_claims);
    try std.testing.expectEqual(@as(usize, 13), pairs.physical_claims);
    var ctx = try lane.Context.init(a, 0);
    defer ctx.deinit();
    var sink = E.SinkFor(O){};
    const bad: [8]O = @splat(O.zero());
    try std.testing.expectError(error.InvalidWideGlobalShape, G.clearedPairFor(O, .{ O.one(), O.one() }, .{ O.one(), O.one() }, &bad, &bad, O.zero(), O.zero(), O.zero(), &sink));
}

fn circuitSingles(mutation: enum { none, pole, inverse_high, prefix_high, claim_high }) !bool {
    var ctx = try lane.Context.init(a, 0);
    defer ctx.deinit();
    lane.begin(&ctx);
    var bound = true;
    defer if (bound) lane.finish() catch {};
    const denominators = [_]O{ dense(31), dense(37), if (mutation == .pole) O.zero() else dense(43) };
    const weights = [_]O{ O.one(), O.one().neg(), O.zero() };
    var inverses: [3]O = undefined;
    var total = O.zero();
    for (&inverses, denominators, weights) |*inverse, d, w| {
        inverse.* = d.inv() catch O.zero();
        total = total.add(w.mul(inverse.*));
    }
    const native = [_]O{ inverses[0], inverses[1], inverses[2], O.zero() };
    var current: [32]W = undefined;
    var previous: [32]W = undefined;
    for (native, 0..) |v, i| for (v.toM31Array(), 0..) |coordinate, j| {
        current[8 * i + j] = try wire(&ctx, O.fromBase(coordinate));
        previous[8 * i + j] = try wire(&ctx, O.zero());
    };
    if (mutation == .inverse_high) current[7] = current[7].add(W.one());
    if (mutation == .prefix_high) current[31] = current[31].add(W.one());
    const claim = try wire(&ctx, if (mutation == .claim_high) total.add(O.basis()) else total);
    var d: [3]W = undefined;
    var w: [3]W = undefined;
    for (&d, &w, denominators, weights) |*dv, *wv, dd, ww| {
        dv.* = try wire(&ctx, dd);
        wv.* = try wire(&ctx, ww);
    }
    var residuals: [5]W = undefined;
    var sink = E.SinkFor(W){ .values = &residuals };
    try G.singlesFor(W, &d, &w, &current, &previous, W.one(), W.zero(), claim, &sink);
    for (residuals) |r| {
        try ctx.eq(r.c0.v, ctx.zero());
        try ctx.eq(r.c1.v, ctx.zero());
    }
    bound = false;
    try lane.finish();
    try ctx.finalize(false);
    return ctx.isCircuitValid();
}
test "OM31 global joint prefix strictsingles bind every pole inverse prefix and public claim" {
    try std.testing.expect(try circuitSingles(.none));
    try std.testing.expect(!try circuitSingles(.pole));
    try std.testing.expect(!try circuitSingles(.inverse_high));
    try std.testing.expect(!try circuitSingles(.prefix_high));
    try std.testing.expect(!try circuitSingles(.claim_high));
}
