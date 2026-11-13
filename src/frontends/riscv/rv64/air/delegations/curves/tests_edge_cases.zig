//! edge cases cases; fixture authority is shared with the other test owners.
//! Constraint-level authority tests for the curve/field truth AIRs. The
//! reference is an independent std.math.big oracle (Fermat inverses, plain
//! big-integer reduction), plus self-certifying group-law checks.
const std = @import("std");
const core = @import("stwo_core");
const spec = @import("spec.zig");
const Base = @import("layout.zig");
const TraceOf = @import("trace.zig");
const Q = core.fields.qm31.QM31;
const Op = spec.Op;

const Support = @import("tests_support.zig");
const oracle = Support.oracle;
const Harness = Support.Harness;
const challenges = Support.challenges;

test "edge cases: P = Q and P = -Q reject in add, (0,0) is evaluated as an ordinary point" {
    // The ABI has no point at infinity: the guest handles O, P = Q and
    // P = -Q before calling. (0,0) as an input is just the formula's point;
    // the AIR must accept exactly the executor's result, nothing else.
    inline for (.{ .{ Op.bn254_g1_add, Op.bn254_g1_double }, .{ Op.bls12_381_g1_add, Op.bls12_381_g1_double } }) |pair| {
        const HA = Harness(pair[0]);
        const HD = Harness(pair[1]);
        const p = HA.d.modulus.constant;
        var prng = std.Random.DefaultPrng.init(0x1f + @as(u64, @intFromEnum(pair[0])));
        const rng = prng.random();
        var main_a: [HA.L.MAIN]Q = undefined;
        var main_d: [HD.L.MAIN]Q = undefined;
        for (0..8) |_| {
            const x = HA.randomBelow(rng, p);
            const y = HA.randomBelow(rng, p);
            const neg_y = (p - y) % p;
            // P = Q and P = -Q: equal x, no nonzero proof, executor traps.
            inline for (.{ 0, 1 }) |neg| {
                const packet = HA.packetOf(&.{ x, y, x, if (neg == 1) neg_y else y });
                try std.testing.expectError(error.CurveDomain, HA.N.compute(&packet));
                const outs = [_][HA.d.limbs]i64{ HA.bytesOf(rng.int(u64)), HA.bytesOf(rng.int(u64)) };
                HA.forge(&packet, &outs, &.{HA.bytesOf(HA.randomBelow(rng, p))}, &main_a);
                try std.testing.expect(!HA.accepted(&main_a));
            }
            // (0,0) + Q with x_Q != 0, and 2 (0, y): honest rows accept and
            // equal the oracle; flipping an output bit rejects.
            if (x != 0) {
                const packet = HA.packetOf(&.{ 0, 0, x, y });
                const w = try HA.rowOf(&packet, &main_a);
                try std.testing.expect(HA.accepted(&main_a));
                const expected = (try oracle(pair[0], std.testing.allocator, &packet)).?;
                for (w.out, expected) |got, want| try std.testing.expectEqual(want, got);
                var outs: [2][HA.d.limbs]i64 = .{ HA.bytesOf(w.out[0]), HA.bytesOf(w.out[1]) };
                outs[1][0] ^= 1;
                HA.forge(&packet, &outs, &.{HA.bytesOf(w.wit[0])}, &main_a);
                try std.testing.expect(!HA.accepted(&main_a));
            }
            if (y != 0) {
                const packet = HD.packetOf(&.{ 0, y });
                const w = try HD.rowOf(&packet, &main_d);
                try std.testing.expect(HD.accepted(&main_d));
                const expected = (try oracle(pair[1], std.testing.allocator, &packet)).?;
                for (w.out, expected) |got, want| try std.testing.expectEqual(want, got);
            }
            // Doubling (0,0) and (x,0): y = 0 traps and no row is accepted.
            const zero = HD.packetOf(&.{ x, 0 });
            try std.testing.expectError(error.CurveDomain, HD.N.compute(&zero));
        }
    }
}

test "mismatched op tag: tags map to distinct kinds and a wrong-kind Wire35 sum never cancels the truth claim" {
    const a = std.testing.allocator;
    // Tags: injective, curve-only, and every non-curve tag maps to no op.
    inline for (spec.ALL, 0..) |op, i| {
        try std.testing.expectEqual(@as(?Op, op), spec.opOfTag(spec.tag(op)));
        try std.testing.expectEqual(@as(u32, @intCast(i + 5)), Base.Layout(op).PROGRAM_KIND);
        inline for (spec.ALL, 0..) |other, j| if (i != j) try std.testing.expect(spec.tag(op) != spec.tag(other));
    }
    for ([_]u64{ 0, 0x30000, 0x30001, 0x30002, 0x30003, 0x30010, 0x30020, 0x30103, 0x30113, 0x30120, 0x30122, 0x30130, 0x130100 }) |raw|
        try std.testing.expectEqual(@as(?Op, null), spec.opOfTag(raw));
    // The same packet claimed by the bridge under another op's kind (same
    // coordinate count): the truth claim does not cancel it.
    const pairs = .{ .{ Op.bn254_g1_add, Op.bn254_fp2_mul }, .{ Op.bls12_381_fp2_mul, Op.bls12_381_g1_add } };
    inline for (pairs) |pair| {
        const H = Harness(pair[0]);
        const T = TraceOf.Trace(pair[0]);
        const W = Base.Layout(pair[1]);
        comptime std.debug.assert(W.COORDS == H.L.COORDS);
        var prng = std.Random.DefaultPrng.init(0x7a6);
        var packets: [3]H.N.Packet = undefined;
        for (&packets) |*p| p.* = H.randomPacket(prng.random());
        var source = try T.Source.init(a, &packets, 5, Base.MIN_LOG);
        defer source.deinit();
        const ch = challenges();
        const claim = try source.generateInteraction(ch);
        var wrong = Q.zero();
        for (&packets, 0..) |*p, r| {
            const after = try H.N.after(p);
            for (0..H.L.WIRE_FRACTIONS) |id| {
                const inv = try ch.wire.denominator(&TraceOf.externalTuple(W.PROGRAM_KIND, 5 + @as(u32, @intCast(r)), id, H.N.wireBytes(p, &after, id))).inv();
                wrong = if (id >= H.L.COORDS) wrong.add(inv) else wrong.sub(inv);
            }
        }
        try std.testing.expect(!claim.eql(wrong));
    }
}
