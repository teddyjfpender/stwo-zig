//! Independent polynomial and carried-integer qualification of the OP candidate.
const std = @import("std");
const core = @import("stwo_core");
const Base = @import("../curves/spec.zig");
const C = @import("../curves/mod.zig");
const S = @import("spec.zig");
const Exec = S.execution;
const H = @import("../curves/tests.zig").Harness(Exec.Kind.mul034);
const N = H.N;
const Q = core.fields.qm31.QM31;
const Z = i1024;
const P = Base.BN254_P;

/// Formal monomial reduction. This does not use the executor's Fq2/Fq6
/// products or the AIR's static list of 88 product terms.
fn term(out: *[12]Z, i: usize, u: usize, w: usize, coefficient: Z) void {
    if (w >= 2) return term(out, i, u + 1, w - 2, coefficient);
    if (u >= 3) {
        term(out, i, u - 3, w, 9 * coefficient);
        return term(out, i + 1, u - 3, w, coefficient);
    }
    if (i >= 2) return term(out, i - 2, u, w, -coefficient);
    out[2 * (u + 3 * w) + i] += coefficient;
}
fn oracle(input: *const [18]u256) [12]u256 {
    var coefficients: [12]Z = @splat(0);
    for (0..12) |a| for ([_]usize{ 0, 3, 4 }, 0..) |place, b| for (0..2) |part| {
        term(&coefficients, a % 2 + part, a / 2 % 3 + place % 3, a / 6 + place / 3, @as(Z, input[a]) * input[12 + 2 * b + part]);
    };
    var result: [12]u256 = undefined;
    for (&result, coefficients) |*dst, x| dst.* = @intCast(@mod(x, @as(Z, P)));
    return result;
}
fn packet(input: *const [18]u256) N.Packet {
    var values: [18]Base.Big = undefined;
    for (&values, input.*) |*dst, x| dst.* = x;
    return H.packetOf(&values);
}
fn qualify(input: *const [18]u256) !void {
    const expected = oracle(input);
    try std.testing.expectEqual(expected, Exec.compute(input));
    var main: [H.L.MAIN]Q = undefined;
    const p = packet(input);
    const witness = try H.rowOf(&p, &main);
    for (witness.out, expected) |x, y| try std.testing.expectEqual(@as(Base.Big, y), x);
    try std.testing.expect(H.accepted(&main));
}

test "OP sparse034 explicit ABI and independent basis polynomial agree" {
    // Every one of the 72 input basis products, plus maximal/noncanonical
    // byte-bounded representatives, exercises all signs/nonresidue placements.
    for (0..12) |a| for (0..6) |b| {
        var input: [18]u256 = @splat(0);
        input[a] = 1;
        input[12 + b] = 1;
        try qualify(&input);
    };
    for ([_]u256{ 0, 1, P - 1, P, P + 1, std.math.maxInt(u256) }) |v| {
        const input: [18]u256 = @splat(v);
        try qualify(&input);
    }
    var rng = std.Random.DefaultPrng.init(0x5350415253453033);
    for (0..16) |_| {
        var input: [18]u256 = undefined;
        for (&input) |*x| x.* = rng.random().int(u256);
        try qualify(&input);
    }
}

test "OP sparse034 carried relations reject forged outputs canonicality and carries" {
    var input: [18]u256 = undefined;
    for (&input, 0..) |*x, i| x.* = (@as(u256, 1) << 247) + 731 * i + 29;
    const p = packet(&input);
    var main: [H.L.MAIN]Q = undefined;
    const honest = try H.rowOf(&p, &main);
    var outputs: [12][32]i64 = undefined;
    for (&outputs, honest.out) |*out, x| out.* = H.bytesOf(x);
    for (0..12) |j| {
        const old = outputs[j];
        outputs[j][0] ^= 1;
        H.forge(&p, &outputs, &.{}, &main);
        try std.testing.expect(!H.accepted(&main));
        outputs[j] = H.bytesOf(honest.out[j] + P);
        H.forge(&p, &outputs, &.{}, &main);
        try std.testing.expect(!H.accepted(&main));
        outputs[j] = old;
    }
    inline for (0..H.L.RELATIONS) |r| {
        _ = try H.rowOf(&p, &main);
        main[H.L.CARRY[r]] = main[H.L.CARRY[r]].add(Q.one());
        try std.testing.expect(!H.accepted(&main));
    }
    _ = try H.rowOf(&p, &main);
    main[H.L.ACTIVE] = Q.fromBase(core.fields.m31.M31.fromCanonical(2));
    try std.testing.expect(!H.accepted(&main));
}

test "OP sparse034 bounded executor preserves the read-only line and refuses wrong size" {
    var before: [Exec.WORDS]u64 = undefined;
    for (&before, 0..) |*x, i| x.* = 0x9e3779b97f4a7c15 *% (i + 1);
    const after = try Exec.execute(&before);
    try std.testing.expectEqualSlices(u64, before[Exec.WRITTEN_WORDS..], after[Exec.WRITTEN_WORDS..]);
    try std.testing.expectError(error.TowerPacketShape, Exec.execute(before[0 .. Exec.WORDS - 1]));
    // Legacy per-call captures retain their existing bounded width and roster.
    const legacy = @import("../../../ethereum_services/curves.zig");
    try std.testing.expectEqual(@as(usize, 24), legacy.MAX_WORDS);
    try std.testing.expect(legacy.opOfTag(Exec.TAG) == null);
    try std.testing.expect(H.L.MAIN + H.L.INTERACTION < 13 * (C.Layout(.bn254_fp2_mul).MAIN + C.Layout(.bn254_fp2_mul).INTERACTION));
    std.debug.print("OP_TOWER_COST main={} inter={} constraints={} byte_queries={} legacy13_cells={} direct_cells={} degree={}\n", .{ H.L.MAIN, H.L.INTERACTION, H.L.CONSTRAINTS, H.L.BYTE_QUERIES, 13 * (C.Layout(.bn254_fp2_mul).MAIN + C.Layout(.bn254_fp2_mul).INTERACTION), H.L.MAIN + H.L.INTERACTION, H.L.DEGREE });
}
