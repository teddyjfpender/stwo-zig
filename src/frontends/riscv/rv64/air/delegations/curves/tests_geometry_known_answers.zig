//! geometry known answers cases; fixture authority is shared with the other test owners.
//! Constraint-level authority tests for the curve/field truth AIRs. The
//! reference is an independent std.math.big oracle (Fermat inverses, plain
//! big-integer reduction), plus self-certifying group-law checks.
const std = @import("std");
const core = @import("stwo_core");
const spec = @import("spec.zig");
const Base = @import("layout.zig");
const Candidate = @import("../../../services/call_abi.zig").curves.arithmetic;
const Q = core.fields.qm31.QM31;
const Big = spec.Big;
const Op = spec.Op;
const MODULUS = core.fields.m31.Modulus;

const Support = @import("tests_support.zig");
const oracle = Support.oracle;
const Harness = Support.Harness;
const KEYS = Support.KEYS;
const BN_ORDER = Support.BN_ORDER;
const BLS_ORDER = Support.BLS_ORDER;
const BLS_GX = Support.BLS_GX;
const BLS_GY = Support.BLS_GY;
const scalarMul = Support.scalarMul;

test "geometry: exact carry certificates, widths and degree budget" {
    inline for (KEYS) |op| {
        const L = Base.Layout(op);
        inline for (L.GEOMETRY) |g| {
            const radix: u64 = @as(u64, 1) << @intCast(8 * g.group);
            try std.testing.expect(g.group_bound + (@as(u64, 1) << @intCast(g.carry_bits - 1)) * (radix + 1) < MODULUS);
            try std.testing.expect(g.honest_carry < (@as(u64, 1) << @intCast(g.carry_bits - 1)));
        }
        try std.testing.expect(L.QUERIES.len == L.BYTE_QUERIES);
        // Curve ops keep two fractions per degree-3 batch (unchanged bytes).
        if (comptime @TypeOf(op) == Op) try std.testing.expectEqual(@as(usize, 2), L.BATCH);
        try std.testing.expect(L.MAIN < 4096 and L.CONSTRAINTS > L.MAIN_CONSTRAINTS);
        std.debug.print("{s}: main {d} interaction {d} cells/row {d} constraints {d} byte queries {d}\n", .{ @tagName(op), L.MAIN, L.INTERACTION, L.MAIN + L.INTERACTION, L.CONSTRAINTS, L.BYTE_QUERIES });
    }
}

test "known answers: every op agrees with the independent big-integer oracle and the candidate executor" {
    const a = std.testing.allocator;
    inline for (spec.ALL) |op| {
        const H = Harness(op);
        var prng = std.Random.DefaultPrng.init(0xc0ffee + @as(u64, @intFromEnum(op)));
        const rng = prng.random();
        var main: [H.L.MAIN]Q = undefined;
        for (0..60) |_| {
            const packet = H.randomPacket(rng);
            const w = try H.rowOf(&packet, &main);
            const expected = (try oracle(op, a, &packet)) orelse return error.OracleRejectedValidPacket;
            for (w.out, expected) |x, y| try std.testing.expectEqual(y, x);
            try std.testing.expect(H.accepted(&main));
        }
    }
}

test "group law: BN254 [r-1]G = -G and BLS12-381 [r-1]G = -G (Montgomery) through accepted rows" {
    const bn_p = spec.BN254_P;
    const minus = try scalarMul(.bn254_g1_add, .bn254_g1_double, .{ 1, 2 }, BN_ORDER - 1);
    try std.testing.expectEqual(@as(Big, 1), minus[0]);
    try std.testing.expectEqual(@as(Big, bn_p - 2), minus[1]);
    // 2G and 3G lie on y^2 = x^3 + 3.
    for ([_]u256{ 2, 3, 5 }) |k| {
        const p = try scalarMul(.bn254_g1_add, .bn254_g1_double, .{ 1, 2 }, k);
        const x: u256 = @intCast(p[0]);
        const y: u256 = @intCast(p[1]);
        const Bn = @import("native.zig").Bn;
        try std.testing.expectEqual(Bn.mul(y, y), Bn.add(Bn.mul(Bn.mul(x, x), x), 3));
    }
    const Bls = @import("native.zig").Bls;
    const R = @import("native.zig").BLS_R;
    const RI = @import("native.zig").BLS_R_INV;
    try std.testing.expectEqual(Bls.mul(BLS_GY, BLS_GY), Bls.add(Bls.mul(Bls.mul(BLS_GX, BLS_GX), BLS_GX), 4));
    const g = [2]Big{ Bls.mul(BLS_GX, R), Bls.mul(BLS_GY, R) };
    const neg = try scalarMul(.bls12_381_g1_add, .bls12_381_g1_double, g, BLS_ORDER - 1);
    try std.testing.expectEqual(@as(Big, BLS_GX), Bls.mul(@intCast(neg[0]), RI));
    try std.testing.expectEqual(@as(Big, spec.BLS12_381_P - BLS_GY), Bls.mul(@intCast(neg[1]), RI));
    // 2G and 3G on y^2 = x^3 + 4 (plain form).
    for ([_]u256{ 2, 3 }) |k| {
        const p = try scalarMul(.bls12_381_g1_add, .bls12_381_g1_double, g, k);
        const x = Bls.mul(@intCast(p[0]), RI);
        const y = Bls.mul(@intCast(p[1]), RI);
        try std.testing.expectEqual(Bls.mul(y, y), Bls.add(Bls.mul(Bls.mul(x, x), x), 4));
    }
}

test "candidate executor agreement: native packets equal the execution-only candidate semantics" {
    inline for (spec.ALL) |op| {
        const H = Harness(op);
        const d = H.d;
        var prng = std.Random.DefaultPrng.init(0xca11 + @as(u64, @intFromEnum(op)));
        const rng = prng.random();
        for (0..40) |_| {
            const packet = H.randomPacket(rng);
            const w = try H.N.compute(&packet);
            var in: [d.inputs]Big = undefined;
            for (&in, 0..) |*x, i| x.* = H.N.operand(&packet, i);
            const C = Candidate;
            const expected: [d.outputs]Big = switch (op) {
                .bn254_g1_add => blk: {
                    const r = C.affineAdd(C.Bn254, u256, @intCast(in[0]), @intCast(in[1]), @intCast(in[2]), @intCast(in[3]));
                    break :blk .{ r[0], r[1] };
                },
                .bn254_g1_double => blk: {
                    const r = C.affineDouble(C.Bn254, u256, @intCast(in[0]), @intCast(in[1]));
                    break :blk .{ r[0], r[1] };
                },
                .bn254_fp2_mul => blk: {
                    const r = C.fp2Mul(C.Bn254, u256, .{ C.Bn254.reduce(@intCast(in[0])), C.Bn254.reduce(@intCast(in[1])) }, .{ C.Bn254.reduce(@intCast(in[2])), C.Bn254.reduce(@intCast(in[3])) });
                    break :blk .{ r[0], r[1] };
                },
                .bls12_381_fp2_mul => blk: {
                    const r = C.fp2Mul(C.Bls, u384, .{ C.Bls.reduce(@intCast(in[0])), C.Bls.reduce(@intCast(in[1])) }, .{ C.Bls.reduce(@intCast(in[2])), C.Bls.reduce(@intCast(in[3])) });
                    const ri = C.Bls.inv(@import("native.zig").BLS_R);
                    break :blk .{ C.Bls.mul(r[0], ri), C.Bls.mul(r[1], ri) };
                },
                .arith384_mont => .{C.mont384(@intCast(in[0]), @intCast(in[1]), @intCast(in[2]))},
                .bls12_381_g1_add, .bls12_381_g1_double => blk: {
                    const ri = C.Bls.inv(@import("native.zig").BLS_R);
                    const R = @import("native.zig").BLS_R;
                    const r = if (op == .bls12_381_g1_add) C.affineAdd(C.Bls, u384, C.Bls.mul(@intCast(in[0]), ri), C.Bls.mul(@intCast(in[1]), ri), C.Bls.mul(@intCast(in[2]), ri), C.Bls.mul(@intCast(in[3]), ri)) else C.affineDouble(C.Bls, u384, C.Bls.mul(@intCast(in[0]), ri), C.Bls.mul(@intCast(in[1]), ri));
                    break :blk .{ C.Bls.mul(r[0], R), C.Bls.mul(r[1], R) };
                },
            };
            for (w.out, expected) |x, y| try std.testing.expectEqual(y, x);
        }
    }
}
