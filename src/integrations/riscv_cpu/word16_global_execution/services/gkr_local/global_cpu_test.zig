const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const E = A.evaluation;
const G = @import("global_cpu.zig");
const Frame = @import("frame.zig");
const Shared = struct { ram: A.memory.closed_ram.types.RamChallengesFor(O), kio: A.crypto.keccak.equations.IoFor(O), wire: A.crypto.secp256k1.equations.WireFor(O) };
fn value(seed: usize) O {
    var c: [8]M = undefined;
    for (&c, 0..) |*v, i| v.* = M.fromCanonical(@intCast((seed * 719 + i * 79 + 3) % 65521));
    return O.fromM31Array(c);
}
fn shared() Shared {
    var out: Shared = undefined;
    out.ram.offset = value(1);
    for (&out.ram.coefficients, 0..) |*v, i| v.* = value(i + 21);
    out.kio.offset = value(2);
    for (&out.kio.coefficients, 0..) |*v, i| v.* = value(i + 41);
    out.wire.offset = value(3);
    for (&out.wire.coefficients, 0..) |*v, i| v.* = value(i + 61);
    return out;
}
const origins = [_]Frame.Origin{ .{ .core = .ls }, .{ .core = .ls_tail }, .{ .core = .initial }, .{ .core = .terminal }, .{ .bridge = .keccak }, .{ .bridge = .add }, .{ .bridge = .double } };
test "actual CPU RAM KIO and secp Wire queries stay degree three on explicit OM global layouts" {
    const ch = shared();
    var fixed: [8]O = undefined;
    var main: [134]O = undefined;
    var current: [56]O = undefined;
    var previous: [56]O = undefined;
    var samples: [5][16]O = undefined;
    for (origins) |origin| {
        const l = G.layout(origin);
        var count: usize = 0;
        for (0..5) |t| {
            const x = O.fromBase(M.fromCanonical(@intCast(t)));
            for (&fixed, 0..) |*v, i| v.* = value(i + 101).add(value(i + 501).mul(x));
            for (&main, 0..) |*v, i| v.* = value(i + 201).add(value(i + 601).mul(x));
            for (&current, &previous, 0..) |*v, *p, i| {
                v.* = value(i + 301).add(value(i + 701).mul(x));
                p.* = value(i + 401).add(value(i + 801).mul(x));
            }
            var sink = E.SinkFor(O){ .values = &samples[t] };
            const width: usize = if (origin == .core and (origin.core == .ls or origin.core == .ls_tail)) A.memory.load_store_v2.layout.MAIN else if (origin == .core) A.memory.load_store_v2.layout.BOUND_MAIN else if (origin.bridge == .keccak) A.crypto.keccak.word16_bridge.layout.MAIN else A.crypto.secp256k1.word16_bridge.layout.MAIN;
            try G.emitFor(O, origin, ch, .{ .ram = value(911), .kio = value(912), .wire = value(913) }, &fixed, main[0..width], current[0..l.width()], previous[0..l.width()], &sink);
            count = sink.count;
        }
        try std.testing.expectEqual(l.constraints(), count);
        for (0..3) |order| for (0..4 - order) |t| for (0..count) |i| {
            samples[t][i] = samples[t + 1][i].sub(samples[t][i]);
        };
        for (0..count) |i| try std.testing.expect(samples[1][i].sub(samples[0][i]).isZero());
    }
}
test "global layouts retain only real prefix predecessor masks and reject absent claim debt" {
    const expected = [_]usize{ 16, 16, 16, 16, 32, 56, 56 };
    for (origins, expected) |origin, width| {
        const l = G.layout(origin);
        try std.testing.expectEqual(width, l.width());
        var previous: usize = 0;
        for (0..width) |c| previous += @intFromBool(l.previous(c));
        try std.testing.expectEqual(@as(usize, if (l.other_queries == 0) 8 else 16), previous);
        const claims = try G.claimsFromVector(O, origin, if (l.other_queries == 0) &.{O.one()} else &.{ O.one(), O.one() });
        try G.validateClaims(origin, claims);
    }
    var absent = G.ClaimsFor(O).zero();
    absent.kio = O.one();
    try std.testing.expectError(error.NonzeroAbsentWideGlobalClaim, G.validateClaims(.{ .core = .ls }, absent));
    try std.testing.expectError(error.InvalidWideGlobalClaimShape, G.claimsFromVector(O, .{ .core = .cpu }, &.{O.one()}));
}
test "all-padding global rows still reject denominator poles" {
    var ch = shared();
    ch.ram.offset = O.zero();
    ch.ram.coefficients = @splat(O.zero());
    const fixed = [_]O{O.zero()} ** 3;
    const main = [_]O{O.zero()} ** A.memory.load_store_v2.layout.MAIN;
    const inter = [_]O{O.zero()} ** 16;
    var residuals: [3]O = undefined;
    var sink = E.SinkFor(O){ .values = &residuals };
    try G.emitFor(O, .{ .core = .ls }, ch, G.ClaimsFor(O).zero(), &fixed, &main, &inter, &inter, &sink);
    try std.testing.expect(!residuals[0].isZero());
}
