//! Exact native sumcheck proof/transcript comparison, not GPU execution.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const O = core.fields.om31.OM31;
const G = engine.lookups.gkr_prover.ForField(O);
const S = engine.lookups.sumcheck.ForField(O);
const Mle = engine.lookups.mle.MleFor;
const Channel = core.channel.raw_mod_m31.Om31Channel;
const a = std.testing.allocator;
extern "c" fn rv64_test_inverse(*const [8]u32, *[8]u32) void;
extern "c" fn rv64_test_sumcheck([*]const [8]u32, [*]const [8]u32, u32, u32, [*]const [8]u32, *const [8]u32, *const [8]u32, *const [9]u32, [*]u32, *[40]u32, *[32]u32) void;
extern "c" fn rv64_test_sumcheck_fused([*]const [8]u32, [*]const [8]u32, u32, u32, [*]const [8]u32, *const [8]u32, *const [8]u32, *const [9]u32, [*]u32, *[40]u32, *[32]u32) void;
extern "c" fn rv64_test_round_failure(u32) u32;
fn words(v: O) [8]u32 {
    var out: [8]u32 = undefined;
    for (v.toM31Array(), &out) |c, *d| d.* = c.v;
    return out;
}
fn field(v: []const u32) O {
    var out: [8]M = undefined;
    for (&out, 0..) |*c, i| c.* = M.fromCanonical(v[i]);
    return O.fromM31Array(out);
}
fn value(seed: u32) O {
    var out: [8]M = undefined;
    var x = seed;
    for (&out) |*c| {
        x = x *% 1664525 +% 1013904223;
        c.* = M.fromCanonical(x % core.fields.m31.Modulus);
    }
    return O.fromM31Array(out);
}
test "RV64 CUDA inverse matches native OM31 norm descent" {
    for (0..512) |i| {
        const x = value(@intCast(i));
        var out: [8]u32 = undefined;
        rv64_test_inverse(&words(x), &out);
        try std.testing.expect((try x.inv()).eql(field(&out)));
    }
}
fn exercise(comptime count: usize, comptime base_mode: bool, comptime zero_mode: bool) !void {
    const variables: usize = comptime std.math.log2_int(usize, count) - 1;
    var n: [count]O = undefined;
    var d: [count]O = undefined;
    var bn: [count]M = undefined;
    var nn: [count][8]u32 = undefined;
    var dd: [count][8]u32 = undefined;
    for (0..count) |i| {
        bn[i] = if (zero_mode) M.zero() else M.fromCanonical(@intCast(i * 11));
        n[i] = if (base_mode) O.fromBase(bn[i]) else if (zero_mode) O.zero() else value(@intCast(600 + i));
        d[i] = value(@intCast(100 + i));
        nn[i] = words(n[i]);
        dd[i] = words(d[i]);
    }
    var y: [variables]O = undefined;
    var yw: [variables][8]u32 = undefined;
    for (&y, &yw, 0..) |*v, *w, i| {
        v.* = value(@intCast(2000 + i));
        w.* = words(v.*);
    }
    var eq = try G.EqEvals.generate(a, &y);
    defer eq.deinit(a);
    const lambda = if (zero_mode) O.zero() else value(9000);
    var claim = O.zero();
    for (0..count / 2) |i| {
        const pn = n[2 * i].mul(d[2 * i + 1]).add(n[2 * i + 1].mul(d[2 * i]));
        const pd = d[2 * i].mul(d[2 * i + 1]);
        var weight = O.one();
        for (y, 0..) |v, j| weight = weight.mul(if ((i >> @as(std.math.Log2Int(usize), @intCast(variables - 1 - j))) & 1 != 0) v else O.one().sub(v));
        claim = claim.add(weight.mul(pn.add(lambda.mul(pd))));
    }
    const layer: G.Layer = if (base_mode) .{ .LogUpMultiplicities = .{ .numerators = try Mle(O, M).initBorrowed(&bn), .denominators = try Mle(O, O).initBorrowed(&d) } } else .{ .LogUpGeneric = .{ .numerators = try Mle(O, O).initBorrowed(&n), .denominators = try Mle(O, O).initBorrowed(&d) } };
    const oracle = G.GkrMultivariatePolyOracle{ .eq_evals = eq.borrowed(), .input_layer = layer, .eq_fixed_var_correction = O.one(), .lambda = lambda };
    var channel = Channel.init();
    channel.mixU32s(&.{ 17, 42, 128 });
    _ = channel.drawSecureFelt(); // exercise a nonzero seed draw counter
    var seed: [9]u32 = undefined;
    for (0..8) |i| seed[i] = std.mem.readInt(u32, channel.inner.digest[4 * i ..][0..4], .little);
    seed[8] = channel.inner.n_draws;
    var expected_channel = channel;
    var expected = try S.proveBatch(G.GkrMultivariatePolyOracle, a, &.{claim}, &.{oracle}, value(99), &expected_channel);
    defer expected.deinit(a);
    var records: [variables * 44]u32 = @splat(0xdeadbeef);
    var state: [40]u32 = undefined;
    var terminal: [32]u32 = undefined;
    rv64_test_sumcheck(&nn, &dd, count, @intFromBool(base_mode), &yw, &words(lambda), &words(claim), &seed, &records, &state, &terminal);
    var fused_records: [variables * 44]u32 = @splat(0xdeadbeef);
    var fused_state: [40]u32 = undefined;
    var fused_terminal: [32]u32 = undefined;
    rv64_test_sumcheck_fused(&nn, &dd, count, @intFromBool(base_mode), &yw, &words(lambda), &words(claim), &seed, &fused_records, &fused_state, &fused_terminal);
    try std.testing.expectEqualSlices(u32, &records, &fused_records);
    try std.testing.expectEqualSlices(u32, &state, &fused_state);
    try std.testing.expectEqualSlices(u32, &terminal, &fused_terminal);
    try std.testing.expectEqual(@as(u32, 0), state[10]);
    try std.testing.expectEqual(@as(u32, variables), state[9]);
    for (expected.proof.round_polys, expected.assignment, 0..) |poly, x, i| {
        const r = records[i * 44 ..][0..44];
        try std.testing.expectEqual(@as(u32, @intCast(poly.coeffsSlice().len)), r[40]);
        try std.testing.expectEqual(@as(u32, @intCast(i)), r[41]);
        for (poly.coeffsSlice(), 0..) |coefficient, j| try std.testing.expect(coefficient.eql(field(r[j * 8 ..][0..8])));
        try std.testing.expect(x.eql(field(r[32..40])));
        if (zero_mode) try std.testing.expectEqual(@as(u32, 0), r[40]);
    }
    for (0..8) |i| try std.testing.expectEqual(std.mem.readInt(u32, expected_channel.inner.digest[4 * i ..][0..4], .little), state[i]);
    try std.testing.expectEqual(expected_channel.inner.n_draws, state[8]);
    try std.testing.expect(expected.claimed_evals[0].eql(field(state[12..20])));
    var mask = try expected.constant_polys[0].tryIntoMask(a);
    defer mask.deinit(a);
    for (mask.columns, 0..) |pair, c| for (pair, 0..) |v, j| try std.testing.expect(v.eql(field(terminal[(c * 2 + j) * 8 ..][0..8])));
    // Assemble the compact device format and invoke the existing verifier,
    // including the final numerical LogUp gate relation. This still needs PCS.
    const assembly = @import("../assembly.zig");
    var admitted = try assembly.verifyReadback(a, channel, claim, &y, lambda, &records, &state, &terminal);
    defer admitted.deinit(a);
    try std.testing.expect(admitted.claimed_eval.eql(expected.claimed_evals[0]));
    var malformed_records = records;
    malformed_records[40] = 5;
    try std.testing.expectError(error.InvalidRecordFraming, assembly.verifyReadback(a, channel, claim, &y, lambda, &malformed_records, &state, &terminal));
    malformed_records = records;
    malformed_records[0] = core.fields.m31.Modulus;
    try std.testing.expectError(error.NonCanonicalField, assembly.verifyReadback(a, channel, claim, &y, lambda, &malformed_records, &state, &terminal));
    var failed_state = state;
    failed_state[10] = 3;
    try std.testing.expectError(error.DeviceRoundFailure, assembly.verifyReadback(a, channel, claim, &y, lambda, &records, &failed_state, &terminal));
    failed_state = state;
    failed_state[0] ^= 1;
    try std.testing.expectError(error.DeviceTranscriptMismatch, assembly.verifyReadback(a, channel, claim, &y, lambda, &records, &failed_state, &terminal));
    malformed_records = records;
    malformed_records[32] = core.fields.m31.Modulus;
    try std.testing.expectError(error.NonCanonicalField, assembly.verifyReadback(a, channel, claim, &y, lambda, &malformed_records, &state, &terminal));
    if (!zero_mode) {
        malformed_records = records;
        malformed_records[0] = M.fromCanonical(malformed_records[0]).add(M.one()).v;
        try std.testing.expectError(error.SumInvalid, assembly.verifyReadback(a, channel, claim, &y, lambda, &malformed_records, &state, &terminal));
        var bad_terminal = terminal;
        bad_terminal[0] = M.fromCanonical(bad_terminal[0]).add(M.one()).v;
        try std.testing.expectError(error.TerminalGateMismatch, assembly.verifyReadback(a, channel, claim, &y, lambda, &records, &state, &bad_terminal));
    }
}
test "RV64 CUDA complete resident-round arithmetic matches native proof challenges terminal and transcript" {
    inline for (.{ 4, 8, 16, 64, 256, 2048 }) |count| {
        try exercise(count, true, false);
        try exercise(count, false, false);
    }
    try exercise(16, true, true);
    try exercise(16, false, true);
}
test "RV64 CUDA round poles malformed fields and reordered steps fail closed" {
    for (0..4) |kind| try std.testing.expectEqual(@as(u32, 3), rv64_test_round_failure(@intCast(kind)));
    try std.testing.expectEqual(@as(u32, 2), rv64_test_round_failure(4));
    try std.testing.expectEqual(@as(u32, 1), rv64_test_round_failure(5));
}

fn allocationCase(allocator: std.mem.Allocator) !void {
    const n = [_]O{ value(1), value(2), value(3), value(4) };
    const d = [_]O{ value(101), value(102), value(103), value(104) };
    const y = [_]O{value(2000)};
    const lambda = value(9000);
    const parent0 = n[0].mul(d[1]).add(n[1].mul(d[0])).add(lambda.mul(d[0].mul(d[1])));
    const parent1 = n[2].mul(d[3]).add(n[3].mul(d[2])).add(lambda.mul(d[2].mul(d[3])));
    const claim = O.one().sub(y[0]).mul(parent0).add(y[0].mul(parent1));
    var nn: [4][8]u32 = undefined;
    var dd: [4][8]u32 = undefined;
    for (n, d, &nn, &dd) |nv, dv, *nw, *dw| {
        nw.* = words(nv);
        dw.* = words(dv);
    }
    const channel = Channel.init();
    const digest = channel.inner.digest;
    var seed: [9]u32 = undefined;
    for (0..8) |i| seed[i] = std.mem.readInt(u32, digest[4 * i ..][0..4], .little);
    seed[8] = channel.inner.n_draws;
    var records: [44]u32 = undefined;
    var state: [40]u32 = undefined;
    var terminal: [32]u32 = undefined;
    rv64_test_sumcheck(&nn, &dd, 4, 0, &.{words(y[0])}, &words(lambda), &words(claim), &seed, &records, &state, &terminal);
    var result = try @import("../assembly.zig").verifyReadback(allocator, channel, claim, &y, lambda, &records, &state, &terminal);
    defer result.deinit(allocator);
}
test "RV64 CUDA numerical proof assembly releases partial ownership on every allocation failure" {
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{});
}

extern "c" fn rv64_test_round_polynomial(*const [8]u32, *const [8]u32, *const [8]u32, *const [8]u32, *[32]u32) u32;
test "RV64 CUDA one-inverse cubic correction matches native interpolation on random full-field inputs" {
    for (0..1024) |i| {
        const f0 = value(@intCast(10000 + 4 * i));
        const f2 = value(@intCast(10001 + 4 * i));
        const claim = value(@intCast(10002 + 4 * i));
        const y = value(@intCast(10003 + 4 * i));
        var out: [32]u32 = undefined;
        try std.testing.expectEqual(@as(u32, 0), rv64_test_round_polynomial(&words(f0), &words(f2), &words(claim), &words(y), &out));
        var expected = try G.correctSumAsPolyInFirstVariable(a, f0, f2, claim, &.{y}, 1);
        defer expected.deinit(a);
        for (0..4) |c| {
            const v = if (c < expected.coeffsSlice().len) expected.coeffsSlice()[c] else O.zero();
            try std.testing.expect(v.eql(field(out[c * 8 ..][0..8])));
        }
    }
}

extern "c" fn rv64_test_eq_fused([*]const [8]u32, u32, [*]u32) void;
test "RV64 CUDA fused Eq tiles match native ordering including remainder levels" {
    for (1..15) |variables| {
        const y = try a.alloc(O, variables);
        defer a.free(y);
        const yw = try a.alloc([8]u32, variables);
        defer a.free(yw);
        for (y, yw, 0..) |*v, *w, i| {
            v.* = value(@intCast(300 + i));
            w.* = words(v.*);
        }
        var expected = try G.EqEvals.generate(a, y);
        defer expected.deinit(a);
        const count = @as(usize, 1) << @as(u6, @intCast(variables - 1));
        const out = try a.alloc(u32, 8 * count);
        defer a.free(out);
        rv64_test_eq_fused(yw.ptr, @intCast(variables), out.ptr);
        for (0..count) |i| {
            var actual: [8]u32 = undefined;
            for (&actual, 0..) |*v, c| v.* = out[c * count + i];
            try std.testing.expect(expected.at(i).eql(field(&actual)));
        }
    }
}
