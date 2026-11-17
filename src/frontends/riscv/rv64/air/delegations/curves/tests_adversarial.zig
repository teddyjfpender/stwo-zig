//! adversarial cases; fixture authority is shared with the other test owners.
//! Constraint-level authority tests for the curve/field truth AIRs. The
//! reference is an independent std.math.big oracle (Fermat inverses, plain
//! big-integer reduction), plus self-certifying group-law checks.
const std = @import("std");
const core = @import("stwo_core");
const E = @import("../../evaluation.zig");
const spec = @import("spec.zig");
const Q = core.fields.qm31.QM31;
const Big = spec.Big;
const Op = spec.Op;

const Support = @import("tests_support.zig");
const q = Support.q;
const qi = Support.qi;
const Harness = Support.Harness;
const KEYS = Support.KEYS;

test "adversarial: wrong outputs, non-canonical outputs and wrong slopes are rejected" {
    inline for (KEYS) |op| {
        const H = Harness(op);
        const d = H.d;
        var prng = std.Random.DefaultPrng.init(0xbad + @as(u64, @intFromEnum(op)));
        const rng = prng.random();
        var main: [H.L.MAIN]Q = undefined;
        var non_canonical: usize = 0;
        for (0..24) |_| {
            const packet = H.randomPacket(rng);
            const w = try H.N.compute(&packet);
            var outs: [d.outputs][d.limbs]i64 = undefined;
            var wits: [d.witnesses][d.limbs]i64 = undefined;
            for (&outs, w.out) |*o, x| o.* = H.bytesOf(x);
            for (&wits, w.wit) |*o, x| o.* = H.bytesOf(x);
            // The forger reproduces the honest row.
            H.forge(&packet, &outs, &wits, &main);
            try std.testing.expect(H.accepted(&main));
            // Wrong output: any other value fails a relation or a range.
            const j = rng.uintLessThan(usize, d.outputs);
            var bad = outs;
            bad[j] = H.bytesOf(w.out[j] ^ (@as(Big, 1) << rng.uintLessThan(u9, @intCast(8 * d.limbs - 8))));
            H.forge(&packet, &bad, &wits, &main);
            try std.testing.expect(!H.accepted(&main));
            // Non-canonical output (x + M, same residue): relations hold, the
            // canonical check rejects.
            const m: Big = switch (d.modulus) {
                .constant => |p| p,
                .variable => |mi| H.N.operand(&packet, mi),
            };
            if (w.out[j] + m < (@as(Big, 1) << @intCast(8 * d.limbs))) {
                var alias = outs;
                alias[j] = H.bytesOf(w.out[j] + m);
                H.forge(&packet, &alias, &wits, &main);
                try std.testing.expect(!H.accepted(&main));
                non_canonical += 1;
            }
            // Wrong slope.
            if (d.witnesses == 1) {
                var slope = wits;
                slope[0] = H.bytesOf((w.wit[0] + 1) % d.modulus.constant);
                H.forge(&packet, &outs, &slope, &main);
                try std.testing.expect(!H.accepted(&main));
            }
        }
        // secp outputs are almost never below 2^256 - p; the aliases are
        // exercised on crafted zero outputs in secp_tests.zig.
        if (comptime @TypeOf(op) == Op) try std.testing.expect(non_canonical > 0);
    }
}

test "adversarial: equal x (add) and y = 0 (double) admit no nonzero proof; non-canonical inputs fail" {
    inline for (.{ Op.bn254_g1_add, Op.bn254_g1_double, Op.bls12_381_g1_add, Op.bls12_381_g1_double }) |op| {
        const H = Harness(op);
        const d = H.d;
        const p = d.modulus.constant;
        var prng = std.Random.DefaultPrng.init(0xe0 + @as(u64, @intFromEnum(op)));
        const rng = prng.random();
        var main: [H.L.MAIN]Q = undefined;
        for (0..16) |_| {
            var vals: [d.inputs]Big = undefined;
            for (&vals) |*v| v.* = H.randomBelow(rng, p);
            if (d.inputs == 4) vals[2] = vals[0] else vals[1] = 0;
            const packet = H.packetOf(&vals);
            try std.testing.expectError(error.CurveDomain, H.N.compute(&packet));
            // Any slope, consistent outputs; every one-hot choice fails.
            const l = H.randomBelow(rng, p);
            var outs: [d.outputs][d.limbs]i64 = undefined;
            outs[0] = H.bytesOf(rng.int(u64));
            outs[1] = H.bytesOf(rng.int(u64));
            const wits = [_][d.limbs]i64{H.bytesOf(l)};
            H.forge(&packet, &outs, &wits, &main);
            for (0..H.L.CHUNKS) |i| {
                for (0..H.L.CHUNKS) |k| main[H.L.SEL + k] = q(@intFromBool(k == i));
                main[H.L.INV] = qi(rng.int(u31));
                try std.testing.expect(H.firstFailure(&main) != null);
            }
        }
        // Non-canonical input x + p with the honest residue: rejected.
        for (0..8) |_| {
            const packet = H.randomPacket(rng);
            var vals: [d.inputs]Big = undefined;
            for (&vals, 0..) |*v, i| v.* = H.N.operand(&packet, i);
            const i = rng.uintLessThan(usize, d.inputs);
            if (vals[i] + p >= (@as(Big, 1) << @intCast(8 * d.limbs))) continue;
            vals[i] += p;
            const bad = H.packetOf(&vals);
            try std.testing.expectError(error.CurveDomain, H.N.compute(&bad));
            const w = try H.N.compute(&packet);
            var outs: [d.outputs][d.limbs]i64 = undefined;
            for (&outs, w.out) |*o, x| o.* = H.bytesOf(x);
            const wits = [_][d.limbs]i64{H.bytesOf(w.wit[0])};
            H.forge(&bad, &outs, &wits, &main);
            try std.testing.expect(!H.accepted(&main));
        }
    }
}

test "adversarial: arith384_mont even modulus, r >= m and non-canonical quotient limbs" {
    const H = Harness(.arith384_mont);
    var prng = std.Random.DefaultPrng.init(0x384);
    const rng = prng.random();
    var main: [H.L.MAIN]Q = undefined;
    var exercised: [3]usize = @splat(0);
    for (0..32) |_| {
        var packet = H.randomPacket(rng);
        const w = try H.N.compute(&packet);
        const m = H.N.operand(&packet, 2);
        // r + m (same residue) when it fits: the r < m check rejects.
        if (w.out[0] + m < (@as(Big, 1) << 384)) {
            H.forge(&packet, &.{H.bytesOf(w.out[0] + m)}, &.{}, &main);
            try std.testing.expect(!H.accepted(&main));
            exercised[0] += 1;
        }
        // Even modulus: honest compute traps; any row fails the odd check.
        packet[2 * 48] &= 0xfe;
        if (H.N.operand(&packet, 2) != 0) {
            try std.testing.expectError(error.CurveDomain, H.N.compute(&packet));
            H.forge(&packet, &.{H.bytesOf(0)}, &.{}, &main);
            for (0..256) |h| {
                main[H.L.HALF] = q(@intCast(h));
                try std.testing.expect(!H.accepted(&main));
            }
            exercised[1] += 1;
        }
    }
    // Non-canonical q limbs: q_i + 256, q_{i+1} - 1 keeps the integer q. A
    // cheating prover re-derives the carries for the shifted limbs (the
    // per-group sums change even though q does not), so every MAIN residual
    // holds and ONLY the BYTE range check of q_i rejects.
    for (0..16) |_| {
        const packet = H.randomPacket(rng);
        const w = try H.N.compute(&packet);
        var vals = H.forgeValues(&packet, &.{H.bytesOf(w.out[0])}, &.{});
        H.setQuotient(0, &vals);
        H.deriveCarriesAndChecks(&vals);
        for (&main, vals) |*dst, v| dst.* = qi(v);
        try std.testing.expect(H.accepted(&main));
        const base = H.L.QUOTIENT[0];
        const i = rng.uintLessThan(usize, H.L.GEOMETRY[0].q_bytes - 1);
        if (vals[base + i + 1] == 0) continue;
        vals[base + i] += 256;
        vals[base + i + 1] -= 1;
        H.deriveCarriesAndChecks(&vals);
        for (&main, vals) |*dst, v| dst.* = qi(v);
        try std.testing.expectEqual(@as(?usize, null), H.firstFailure(&main));
        try std.testing.expect(H.outOfRangeQuery(&main));
        exercised[2] += 1;
    }
    for (exercised) |e| try std.testing.expect(e > 0);
}

test "every single-cell perturbation of an honest row violates a MAIN residual or a lookup" {
    inline for (KEYS) |op| {
        const H = Harness(op);
        var prng = std.Random.DefaultPrng.init(0xce11 + @as(u64, @intFromEnum(op)));
        const rng = prng.random();
        var packet = H.randomPacket(rng);
        // Nonzero operands so every input byte reaches a product.
        while (true) : (packet = H.randomPacket(rng)) {
            var all = true;
            for (0..H.d.inputs) |i| all = all and H.N.operand(&packet, i) > (@as(Big, 1) << @intCast(8 * H.d.limbs - 16));
            if (all) break;
        }
        var main: [H.L.MAIN]Q = undefined;
        _ = try H.rowOf(&packet, &main);
        try std.testing.expect(H.accepted(&main));
        for (0..H.L.MAIN) |c| {
            const saved = main[c];
            main[c] = main[c].add(q(1));
            defer main[c] = saved;
            // Packet bytes beyond the inputs are bound only by Wire35; MULT
            // only by the BYTE chain.
            const unbound = (c >= H.L.PACKET + H.d.inputs * H.d.limbs and c < H.L.OUT) or c == H.L.MULT;
            if (unbound) {
                try std.testing.expect(H.accepted(&main));
                continue;
            }
            if (H.accepted(&main)) {
                std.debug.print("{s}: perturbing column {d} accepted\n", .{ @tagName(op), c });
                return error.UnboundColumn;
            }
        }
    }
}

test "activity prefix: exactly rows 0..calls-1 may be active" {
    const H = Harness(.bn254_fp2_mul);
    var prng = std.Random.DefaultPrng.init(7);
    const packet = H.randomPacket(prng.random());
    var main: [H.L.MAIN]Q = undefined;
    _ = try H.rowOf(&packet, &main);
    const Eq = H.Eq;
    const check = struct {
        fn f(m: []const Q, fixed: [4]Q, previous: Q) bool {
            const view = H.View{ .fixed_values = fixed, .main_values = m, .previous_active = previous };
            var values: [H.L.MAIN_CONSTRAINTS]Q = undefined;
            var sink = E.Sink{ .values = &values };
            Eq.emitMain(Q, &view, .{ .calls = 1000, .first_id = 1 }, &sink);
            for (values) |v| if (!v.isZero()) return false;
            return true;
        }
    }.f;
    var zero: [H.L.MAIN]Q = @splat(Q.zero());
    _ = &zero;
    try std.testing.expect(!check(&zero, .{ q(0), q(1), q(0), q(0) }, q(0))); // row 0 must be active
    try std.testing.expect(!check(&main, .{ q(5), q(0), q(0), q(5) }, q(0))); // no 0 -> 1
    try std.testing.expect(!check(&zero, .{ q(999), q(0), q(0), q(999 & 255) }, q(1))); // 1 -> 0 only at calls
    try std.testing.expect(check(&zero, .{ q(1000), q(0), q(0), q(1000 & 255) }, q(1)));
    try std.testing.expect(!check(&main, .{ q(4), q(0), q(1), q(4) }, q(1))); // LAST inactive
    try std.testing.expect(check(&main, .{ q(4), q(0), q(0), q(4) }, q(1)));
}
