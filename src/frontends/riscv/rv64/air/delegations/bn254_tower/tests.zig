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
fn oracle(input: *const [20]u256) [12]u256 {
    var coefficients: [12]Z = @splat(0);
    for (0..12) |a| for ([_]usize{ 0, 3, 4 }, 0..) |place, b| for (0..2) |part| {
        term(&coefficients, a % 2 + part, a / 2 % 3 + place % 3, a / 6 + place / 3, @as(Z, input[a]) * input[12 + 2 * b + part] * (if (b == 0) @as(Z, input[19]) else if (b == 1) @as(Z, input[18]) else 1));
    };
    var result: [12]u256 = undefined;
    for (&result, coefficients) |*dst, x| dst.* = @intCast(@mod(x, @as(Z, P)));
    return result;
}
fn packet(input: *const [20]u256) N.Packet {
    var values: [20]Base.Big = undefined;
    for (&values, input.*) |*dst, x| dst.* = x;
    return H.packetOf(&values);
}
fn qualify(input: *const [20]u256) !void {
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
        var input: [20]u256 = @splat(0);
        input[a] = 1;
        input[12 + b] = 1;
        input[18] = 1;
        input[19] = 1;
        try qualify(&input);
    };
    for ([_]u256{ 0, 1, P - 1, P, P + 1, std.math.maxInt(u256) }) |v| {
        const input: [20]u256 = @splat(v);
        try qualify(&input);
    }
    var rng = std.Random.DefaultPrng.init(0x5350415253453033);
    for (0..16) |_| {
        var input: [20]u256 = undefined;
        for (&input) |*x| x.* = rng.random().int(u256);
        try qualify(&input);
    }
}

test "OP sparse034 carried relations reject forged outputs canonicality and carries" {
    var input: [20]u256 = undefined;
    for (&input, 0..) |*x, i| x.* = (@as(u256, 1) << 247) + 731 * i + 29;
    const p = packet(&input);
    var main: [H.L.MAIN]Q = undefined;
    const honest = try H.rowOf(&p, &main);
    var outputs: [12][32]i64 = undefined;
    for (&outputs, honest.out) |*out, x| out.* = H.bytesOf(x);
    var witnesses: [14][32]i64 = undefined;
    for (&witnesses, honest.wit) |*out, x| out.* = H.bytesOf(x);
    for (0..12) |j| {
        const old = outputs[j];
        outputs[j][0] ^= 1;
        H.forge(&p, &outputs, &witnesses, &main);
        try std.testing.expect(!H.accepted(&main));
        outputs[j] = H.bytesOf(honest.out[j] + P);
        H.forge(&p, &outputs, &witnesses, &main);
        try std.testing.expect(!H.accepted(&main));
        outputs[j] = old;
    }
    for (0..14) |j| {
        const old = witnesses[j];
        witnesses[j][0] ^= 1;
        H.forge(&p, &outputs, &witnesses, &main);
        try std.testing.expect(!H.accepted(&main));
        witnesses[j] = old;
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
    std.debug.print("OP_TOWER_COST main={} inter={} constraints={} byte_queries={} legacy13_cells={} candidate_cells={} degree={}\n", .{ H.L.MAIN, H.L.INTERACTION, H.L.CONSTRAINTS, H.L.BYTE_QUERIES, 13 * (C.Layout(.bn254_fp2_mul).MAIN + C.Layout(.bn254_fp2_mul).INTERACTION), H.L.MAIN + H.L.INTERACTION, H.L.DEGREE });
}

test "OP sparse034 source-owned asymmetric carry intervals are complete and strictly nonwrapping" {
    @setEvalBranchQuota(1000000);
    inline for (H.L.GEOMETRY, 0..) |g, r| {
        const range = @as(u64, 1) << @intCast(g.carry_bits);
        try std.testing.expect(g.carry_offset >= g.honest_negative_carry);
        try std.testing.expect(range - 1 - g.carry_offset >= g.honest_positive_carry);
        try std.testing.expect(g.residual_positive_bound < Base.M31);
        try std.testing.expect(g.residual_negative_bound < Base.M31);
        var main: [H.L.MAIN]Q = @splat(Q.zero());
        main[H.L.ACTIVE] = Q.one();
        const view = H.View{ .fixed_values = @splat(Q.zero()), .main_values = &main, .previous_active = Q.zero() };
        // Both admitted encoded endpoints decode exactly, including an
        // asymmetric negative endpoint that is not a power of two.
        try std.testing.expect(H.Eq.carry(Q, &view, r, 0).eql(@import("../curves/tests.zig").qi(-@as(i64, @intCast(g.carry_offset)))));
        for (0..g.carry_bytes) |b| main[H.L.CARRY[r] + b] = @import("../curves/tests.zig").q(@intCast(((range - 1) >> @intCast(8 * b)) & 0xff));
        try std.testing.expect(H.Eq.carry(Q, &view, r, 0).eql(@import("../curves/tests.zig").qi(@intCast(range - 1 - g.carry_offset))));
        // One step outside either interval cannot hide as a field residue.
        main[H.L.CARRY[r]] = @import("../curves/tests.zig").qi(-1);
        try std.testing.expect(H.outOfRangeQuery(&main));
        for (0..g.carry_bytes) |b| main[H.L.CARRY[r] + b] = @import("../curves/tests.zig").q(@intCast((range >> @intCast(8 * b)) & (if (b + 1 == g.carry_bytes) @as(u64, 0xffff) else 0xff)));
        try std.testing.expect(H.outOfRangeQuery(&main));
    }
    const profile = @import("../../../execution_profile.zig");
    try std.testing.expect(Exec.TAG != profile.KECCAK_SPONGE_TAG);
    for (profile.CURVE_TAGS) |tag| try std.testing.expect(Exec.TAG != tag);
}

test "OP sparse034 packet bridge keeps legacy captures narrow and validates every predecessor" {
    const B = @import("../secp256k1/mod.zig").word16_bridge;
    const allocator = std.testing.allocator;
    var call: B.types.TowerCall = undefined;
    call.pointer = 0x1000;
    call.epoch = 2;
    call.tick = 17;
    for (&call.before, 0..) |*v, i| v.* = 0x9e3779b97f4a7c15 *% (i + 1);
    call.after = try Exec.execute(&call.before);
    for (&call.predecessors, call.before) |*state, value| state.* = .{ .value = value, .epoch = 1, .tick = 13, .rights = 3 };
    try B.source.validateTower(.bn254_sparse034, call);
    var source = try B.source.TowerSource.init(allocator, .bn254_sparse034, &.{call}, 7, 6);
    defer source.deinit();
    try std.testing.expectEqual(@as(usize, 20), B.types.coordinates(source.kind));
    try std.testing.expectEqual(@as(usize, 12), B.types.written(source.kind));
    try std.testing.expectEqual(@as(u32, 0x40001), B.types.tag(source.kind));
    for (0..12) |i| try std.testing.expectEqual(@as(u32, @intCast(20 + i)), B.types.outputWire(source.kind, i));
    try std.testing.expectError(error.InvalidWord16PacketCapacity, B.source.Source.init(allocator, .bn254_sparse034, &.{}, 7, 6));
    try std.testing.expectError(error.InvalidWord16PacketCapacity, B.source.TowerSource.init(allocator, .bn254_fp2_mul, &.{}, 7, 6));
    var bad = call;
    bad.pointer += 1;
    try std.testing.expectError(error.InvalidWord16SecpCall, B.source.validateTower(.bn254_sparse034, bad));
    bad = call;
    bad.pointer = std.math.maxInt(u64) - 31;
    try std.testing.expectError(error.InvalidWord16SecpCall, B.source.validateTower(.bn254_sparse034, bad));
    for (0..Exec.WORDS) |i| {
        bad = call;
        bad.predecessors[i].value ^= 1;
        try std.testing.expectError(error.InvalidWord16SecpPredecessor, B.source.validateTower(.bn254_sparse034, bad));
        bad = call;
        bad.predecessors[i].epoch = 2;
        bad.predecessors[i].tick = 17;
        try std.testing.expectError(error.InvalidWord16SecpPredecessor, B.source.validateTower(.bn254_sparse034, bad));
    }
    for (Exec.WRITTEN_WORDS..Exec.WORDS) |i| {
        bad = call;
        bad.after[i] ^= 1;
        try std.testing.expectError(error.InvalidWord16SecpPredecessor, B.source.validateTower(.bn254_sparse034, bad));
    }
    for (0..Exec.WRITTEN_WORDS) |i| {
        bad = call;
        bad.predecessors[i].rights = 1;
        try std.testing.expectError(error.InvalidWord16SecpPredecessor, B.source.validateTower(.bn254_sparse034, bad));
    }
}
