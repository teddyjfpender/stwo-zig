//! secp256k1 RCB row truth (`spec.secpDef`, Wire35 kinds 1/2): semantic
//! agreement with the RCB program authority, group-law self checks, and the
//! adversarial cases the generic curve tests cannot reach (zero-output
//! aliases, raw-coordinate residues, Wire35 identity against the bridge).
const std = @import("std");
const core = @import("stwo_core");
const E = @import("../../evaluation.zig");
const spec = @import("spec.zig");
const Base = @import("layout.zig");
const tests = @import("tests.zig");
const Bridge = @import("../secp256k1/word16_bridge/types.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Big = spec.Big;
const K = spec.SecpKind;
const P: u256 = spec.SECP256K1_P;
const q = tests.q;

const GX: u256 = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798;
const GY: u256 = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8;
const Fp = @import("native.zig").Secp;

fn packet(comptime kind: K, values: []const u256) tests.Harness(kind).N.Packet {
    const H = tests.Harness(kind);
    var vals: [H.d.inputs]Big = undefined;
    for (&vals, values) |*v, x| v.* = x;
    return H.packetOf(&vals);
}
fn rawWord(rng: std.Random) u256 {
    const x = (@as(u256, rng.int(u128)) << 128) | rng.int(u128);
    return switch (rng.uintLessThan(u8, 9)) {
        0 => 0,
        1 => P,
        2 => P - 1,
        3 => std.math.maxInt(u256),
        4 => P + rng.int(u32) % (std.math.maxInt(u256) - P),
        5 => rng.int(u64),
        else => x,
    };
}
/// Projective equality (X1 Z2 = X2 Z1, Y1 Z2 = Y2 Z1) of canonical triples.
fn sameProjective(a: [3]u256, b: [3]u256) bool {
    return Fp.mul(a[0], b[2]) == Fp.mul(b[0], a[2]) and Fp.mul(a[1], b[2]) == Fp.mul(b[1], a[2]);
}
fn onCurve(x: u256, y: u256, z: u256) bool {
    // Homogeneous: Y^2 Z = X^3 + 7 Z^3.
    const lhs = Fp.mul(Fp.mul(y, y), z);
    const rhs = Fp.add(Fp.mul(Fp.mul(x, x), x), Fp.mul(7, Fp.mul(Fp.mul(z, z), z)));
    return lhs == rhs;
}
fn cat(a: [3]u256, b: [3]u256) [6]u256 {
    return .{ a[0], a[1], a[2], b[0], b[1], b[2] };
}
fn run(comptime kind: K, values: []const u256) ![3]u256 {
    const H = tests.Harness(kind);
    const p = packet(kind, values);
    var main: [H.L.MAIN]Q = undefined;
    const w = try H.rowOf(&p, &main);
    if (!H.accepted(&main)) return error.HonestRowRejected;
    var out: [3]u256 = undefined;
    for (&out, w.out) |*o, x| o.* = @intCast(x);
    return out;
}

test "secp row truth geometry: certified carries and cells per call" {
    inline for (.{ K.add, K.double }) |kind| {
        const L = Base.Layout(kind);
        try std.testing.expectEqual(@as(u32, @intFromEnum(kind)), L.PROGRAM_KIND);
        try std.testing.expectEqual(Bridge.tag(Bridge.kindOf(kind)), L.TAG);
        try std.testing.expectEqual(Bridge.coordinates(Bridge.kindOf(kind)), L.COORDS);
        try std.testing.expectEqual(Bridge.written(Bridge.kindOf(kind)), L.WRITTEN);
        std.debug.print("secp row {s}: main {d} interaction {d} cells/row {d} byte queries {d} relations {d} constraints {d}\n", .{ @tagName(kind), L.MAIN, L.INTERACTION, L.MAIN + L.INTERACTION, L.BYTE_QUERIES, L.RELATIONS, L.CONSTRAINTS });
        // Locked layout: three fractions per degree-4 batch.
        try std.testing.expectEqual(@as(usize, 3), L.BATCH);
        try std.testing.expectEqual(@as(usize, if (kind == .add) 4433 else 3463), L.MAIN + L.INTERACTION);
        inline for (L.GEOMETRY, 0..) |g, r| std.debug.print("  relation {d}: group {d} groups {d} carry bytes {d} q bytes {d}\n", .{ r, g.group, g.groups, g.carry_bytes, g.q_bytes });
    }
}

test "secp row truth equals the RCB program on raw (unreduced) coordinates" {
    var prng = std.Random.DefaultPrng.init(0x5ec9);
    const rng = prng.random();
    inline for (.{ K.add, K.double }) |kind| {
        const program = spec.secp.get(kind);
        for (0..200) |_| {
            var raw: [6]u256 = undefined;
            for (raw[0..program.inputs]) |*x| x.* = rawWord(rng);
            const values = try spec.secp.execute(program, raw[0..program.inputs]);
            const got = try run(kind, raw[0..program.inputs]);
            for (got, program.outputs) |x, wire| try std.testing.expectEqual(values[wire], x);
            for (got) |x| try std.testing.expect(x < P);
        }
    }
}

test "secp row truth group law: complete ADD(P,P) = DOUBLE(P), P + (-P) at infinity, scalar walk stays on curve" {
    // Z = 1 generator, and a non-trivial projective representative.
    const lambda: u256 = 0x1234567890abcdef;
    const g = [3]u256{ GX, GY, 1 };
    const g2 = [3]u256{ Fp.mul(GX, lambda), Fp.mul(GY, lambda), lambda };
    const dbl = try run(.double, &g);
    try std.testing.expect(onCurve(dbl[0], dbl[1], dbl[2]) and dbl[2] != 0);
    const self_add = try run(.add, &cat(g, g2));
    try std.testing.expect(sameProjective(dbl, self_add));
    // P + (-P): Z3 = 0 (the identity, complete formula; no exception path).
    const neg = try run(.add, &cat(g, .{ GX, P - GY, 1 }));
    try std.testing.expectEqual(@as(u256, 0), neg[2]);
    // Identity (0 : 1 : 0) is neutral.
    const id = try run(.add, &cat(g, .{ 0, 1, 0 }));
    try std.testing.expect(sameProjective(id, g));
    // A walk of mixed adds/doubles stays on the curve.
    var acc = g;
    for (0..24) |i| {
        acc = if (i % 3 == 0) try run(.double, &acc) else try run(.add, &cat(acc, g));
        try std.testing.expect(onCurve(acc[0], acc[1], acc[2]));
    }
}

test "adversarial secp: zero outputs forged as p (non-canonical alias) are rejected" {
    inline for (.{ K.add, K.double }) |kind| {
        const H = tests.Harness(kind);
        const d = H.d;
        // ADD of two all-zero inputs, DOUBLE of (X, 0, Z): X3 = Z3 = 0.
        const values: []const u256 = if (kind == .add) &.{ 0, 0, 0, 0, 0, 0 } else &.{ GX, 0, 5 };
        const p = packet(kind, values);
        const w = try H.N.compute(&p);
        var outs: [d.outputs][d.limbs]i64 = undefined;
        var wits: [d.witnesses][d.limbs]i64 = undefined;
        for (&outs, w.out) |*o, x| o.* = H.bytesOf(x);
        for (&wits, w.wit) |*o, x| o.* = H.bytesOf(x);
        var main: [H.L.MAIN]Q = undefined;
        H.forge(&p, &outs, &wits, &main);
        try std.testing.expect(H.accepted(&main));
        var aliased: usize = 0;
        for (0..d.outputs) |j| if (w.out[j] == 0) {
            var bad = outs;
            bad[j] = H.bytesOf(P);
            H.forge(&p, &bad, &wits, &main);
            // Same residue: every carried relation still holds, and the
            // canonical equation x + D + 1 = p forces D = -1, whose bytes
            // leave the BYTE range (the only obstruction).
            try std.testing.expect(!H.accepted(&main));
            try std.testing.expect(H.outOfRangeQuery(&main));
            aliased += 1;
        };
        try std.testing.expect(aliased >= 2);
        // Witness aliases (w + p) are harmless residues; a wrong witness residue is not.
        var wbad = wits;
        wbad[0] = H.bytesOf((w.wit[0] + 1) % P);
        H.forge(&p, &outs, &wbad, &main);
        try std.testing.expect(!H.accepted(&main));
    }
}

test "adversarial secp: a wrong limb in any output or witness is rejected" {
    var prng = std.Random.DefaultPrng.init(0xdead5ec9);
    const rng = prng.random();
    inline for (.{ K.add, K.double }) |kind| {
        const H = tests.Harness(kind);
        const d = H.d;
        for (0..16) |_| {
            var raw: [6]u256 = undefined;
            for (raw[0..d.inputs]) |*x| x.* = rawWord(rng);
            const p = packet(kind, raw[0..d.inputs]);
            const w = try H.N.compute(&p);
            var outs: [d.outputs][d.limbs]i64 = undefined;
            var wits: [d.witnesses][d.limbs]i64 = undefined;
            for (&outs, w.out) |*o, x| o.* = H.bytesOf(x);
            for (&wits, w.wit) |*o, x| o.* = H.bytesOf(x);
            var main: [H.L.MAIN]Q = undefined;
            for (0..d.outputs + d.witnesses) |v| {
                var o2 = outs;
                var w2 = wits;
                const limb = rng.uintLessThan(usize, d.limbs);
                const delta: i64 = if (rng.boolean()) 1 else -1;
                if (v < d.outputs) o2[v][limb] += delta else w2[v - d.outputs][limb] += delta;
                H.forge(&p, &o2, &w2, &main);
                try std.testing.expect(!H.accepted(&main));
            }
        }
    }
}

test "secp row truth Wire35 identity equals the Word16 bridge's (kind, wire IDs)" {
    inline for (.{ K.add, K.double }) |kind| {
        const L = Base.Layout(kind);
        const bk = Bridge.kindOf(kind);
        for (0..L.COORDS) |c| try std.testing.expectEqual(@as(u32, @intCast(c)), L.wireLabel(c));
        for (0..L.WRITTEN) |c| try std.testing.expectEqual(Bridge.outputWire(bk, c), L.wireLabel(L.COORDS + c));
        // Output labels are distinct from every input label (no self-cancellation).
        for (0..L.WRITTEN) |c| try std.testing.expect(L.wireLabel(L.COORDS + c) >= L.COORDS);
    }
}
