//! arith256_mod Word16 bridge (kind 4) against the arith256 truth: exact
//! Wire35 closure for honest packets, rejection of forged outputs.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const Secp = A.crypto.secp256k1;
const K = Secp.word16_bridge;
const Ar = A.crypto.arith256;
const E = A.evaluation;
const Helpers = @import("../secp/bridge_test.zig");
const M = core.fields.m31.M31;
const Q = E.Q;
const a = std.testing.allocator;
const KIND: K.types.Kind = .arith256_mod;

fn limbs(value: u256) [4]u64 {
    var out: [4]u64 = undefined;
    for (&out, 0..) |*w, i| w.* = @truncate(value >> @intCast(64 * i));
    return out;
}
/// One packet a, b, c, m, r at a 32-byte aligned pointer; r gets `result`.
fn call(input: Ar.native.Input, result: u256, tick: u24) K.types.Call {
    var c: K.types.Call = .{ .pointer = 0x1000, .epoch = 2, .tick = tick, .before = @splat(0), .after = @splat(0), .predecessors = undefined };
    const values = [5]u256{ input.a, input.b, input.c, input.m, input.r_before };
    for (values, 0..) |v, coord| for (limbs(v), 0..) |w, lane| {
        c.before[4 * coord + lane] = w;
        c.after[4 * coord + lane] = w;
    };
    for (limbs(result), 0..) |w, lane| c.after[16 + lane] = w;
    for (0..20) |i| c.predecessors[i] = .{ .value = c.before[i], .epoch = 1, .tick = @intCast(4 + 4 * i), .rights = if (i >= 16) 3 else 1 };
    for (20..24) |i| c.predecessors[i] = .{ .value = 0, .epoch = 0, .tick = 0, .rights = 0 };
    return c;
}
fn truthChallenges(ch: K.types.Challenges) Ar.equations.Challenges {
    return .{ .bytes = Q.fromPartialEvals(.{ Q.fromBase(M.fromCanonical(91)), Q.fromBase(M.fromCanonical(5)), Q.zero(), Q.one() }), .wire = ch.wire };
}
fn inputs(rng: std.Random, out: []Ar.native.Input) void {
    for (out, 0..) |*x, i| {
        x.* = .{ .a = rng.int(u256), .b = rng.int(u256), .c = rng.int(u256), .m = if (i == 1) 0 else rng.int(u256) >> rng.int(u8), .r_before = rng.int(u256) };
    }
}

test "arith256_mod bridge geometry: five coordinates, only r written, tag 0x30021" {
    try std.testing.expectEqual(@as(usize, 5), K.types.coordinates(KIND));
    try std.testing.expectEqual(@as(u32, 0x30021), K.types.tag(KIND));
    try std.testing.expectEqual(@as(u8, Ar.layout.PROGRAM_KIND), @intFromEnum(KIND));
    for (0..5) |coord| try std.testing.expectEqual(coord == 4, K.types.isWritten(KIND, coord));
    try std.testing.expectEqual(Ar.layout.OUTPUT_WIRE, K.types.outputWire(KIND, 4));
    // v2 kinds keep their leading-written geometry.
    for ([_]K.types.Kind{ .add, .double }) |kind| for (0..6) |coord| {
        try std.testing.expectEqual(coord < 3, K.types.isWritten(kind, coord));
    };
}

test "arith256_mod bridge and truth close Wire35 exactly; forged results do not" {
    const ch = Helpers.challenges();
    const d16 = try Helpers.dict(a, 65536, ch.range16);
    defer a.free(d16);
    const d8 = try Helpers.dict(a, 256, ch.range8);
    defer a.free(d8);
    var prng = std.Random.DefaultPrng.init(0xb41d6e);
    const rng = prng.random();
    var xs: [6]Ar.native.Input = undefined;
    inputs(rng, &xs);
    var calls: [6]K.types.Call = undefined;
    for (&calls, xs, 0..) |*c, x, i| c.* = call(x, Ar.native.reference(x.a, x.b, x.c, x.m), @intCast(400 + 4 * i));
    const first_id: u32 = 7;
    var bridge = try K.source.Source.init(a, KIND, &calls, first_id, 6);
    defer bridge.deinit();
    const claims = try bridge.generate(ch, d16, d8);
    try checkBridgeRows(&bridge, @intCast(calls.len), ch, claims);
    var truth = try Ar.trace.Source.init(a, &xs, first_id, Ar.layout.MIN_LOG);
    defer truth.deinit();
    const claim = try truth.generateInteraction(truthChallenges(ch));
    try std.testing.expect(claims.wire.add(claim).isZero());
    // A locally valid bridge that writes a wrong r (the bridge alone never
    // computes) leaves the joint Wire35 sum nonzero.
    var forged = calls;
    forged[3].after[17] +%= 1;
    var bad = try K.source.Source.init(a, KIND, &forged, first_id, 6);
    defer bad.deinit();
    const bad_claims = try bad.generate(ch, d16, d8);
    try checkBridgeRows(&bad, @intCast(forged.len), ch, bad_claims);
    try std.testing.expect(!bad_claims.wire.add(claim).isZero());
    // A truth row over a different r_before (or any input) does not match.
    var other = xs;
    other[2].r_before +%= 1;
    var shifted = try Ar.trace.Source.init(a, &other, first_id, Ar.layout.MIN_LOG);
    defer shifted.deinit();
    try std.testing.expect(!claims.wire.add(try shifted.generateInteraction(truthChallenges(ch))).isZero());
    // An offset call-ID span does not match either.
    var late = try Ar.trace.Source.init(a, &xs, first_id + 1, Ar.layout.MIN_LOG);
    defer late.deinit();
    try std.testing.expect(!claims.wire.add(try late.generateInteraction(truthChallenges(ch))).isZero());
}

test "arith256_mod bridge rejects writes to read-only coordinates and unwritable r" {
    const x = Ar.native.Input{ .a = 3, .b = 4, .c = 5, .m = 7 };
    var c = call(x, Ar.native.reference(x.a, x.b, x.c, x.m), 400);
    c.after[5] +%= 1; // b changes
    try std.testing.expectError(error.InvalidWord16SecpPredecessor, K.source.Source.init(a, KIND, &.{c}, 1, 5));
    c = call(x, Ar.native.reference(x.a, x.b, x.c, x.m), 400);
    c.predecessors[18].rights = 1; // r not writable
    try std.testing.expectError(error.InvalidWord16SecpPredecessor, K.source.Source.init(a, KIND, &.{c}, 1, 5));
    c = call(x, Ar.native.reference(x.a, x.b, x.c, x.m), 400);
    c.pointer += 8; // packets are 32-byte aligned
    try std.testing.expectError(error.InvalidWord16SecpCall, K.source.Source.init(a, KIND, &.{c}, 1, 5));
}

fn checkBridgeRows(s: *const K.source.Source, count: u32, ch: K.types.Challenges, claims: K.types.Claims) !void {
    const n = s.size();
    for (0..n) |row| {
        const p = A.witness.physical(row, s.log_size);
        const prev = A.witness.physical((row + n - 1) % n, s.log_size);
        var f: [K.layout.FIXED]Q = undefined;
        var m: [K.layout.MAIN]Q = undefined;
        var pm: [K.layout.MAIN]Q = undefined;
        var inter: [K.layout.INTERACTION]Q = undefined;
        var pi: [K.layout.INTERACTION]Q = undefined;
        for (&f, 0..) |*v, c| v.* = Q.fromBase(s.fixed[c * n + p]);
        for (&m, &pm, 0..) |*v, *old, c| {
            v.* = Q.fromBase(s.main[c * n + p]);
            old.* = Q.fromBase(s.main[c * n + prev]);
        }
        for (&inter, &pi, 0..) |*v, *old, c| {
            v.* = Q.fromBase(s.interaction[c * n + p]);
            old.* = Q.fromBase(s.interaction[c * n + prev]);
        }
        var residual: [K.layout.CONSTRAINTS]Q = undefined;
        var sink = E.Sink{ .values = &residual };
        K.equations.emitFor(Q, s.kind, &f, &m, &pm, &inter, &pi, count, s.first_id, claims, ch, &sink);
        for (residual, 0..) |v, index| if (!v.isZero()) {
            std.debug.print("arith256 bridge row{d} residual{d}\n", .{ row, index });
            return error.InvalidArith256BridgeResidual;
        };
    }
}
