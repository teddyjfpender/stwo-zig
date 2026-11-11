const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const C = A.crypto.bn254_pairing_mac12.fixture;
const N = @import("../op_pairing_mac12/native.zig");
const P = @import("../op_pairing_mac12/projection.zig");
const T = @import("typed_projection.zig");
const O = core.fields.om31.OM31;
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
fn View(comptime F: type) type {
    return struct {
        values: [1106]F,
        fixed_values: [40]F,
        pub fn main(v: *const @This(), i: usize) F {
            return v.values[i];
        }
        pub fn fixed(v: *const @This(), i: usize) F {
            return v.fixed_values[i];
        }
    };
}
fn randomO(r: std.Random) O {
    var words: [8]M = undefined;
    for (&words) |*x| x.* = M.fromCanonical(r.int(u32) % 2147483647);
    return O.fromM31Array(words);
}
fn randomView(r: std.Random) View(O) {
    var v: View(O) = undefined;
    for (&v.values) |*x| x.* = randomO(r);
    for (&v.fixed_values) |*x| x.* = randomO(r);
    return v;
}
fn params(r: std.Random, instance: N.Instance, weights: []O) T.ParamsFor(O) {
    for (weights) |*x| x.* = randomO(r);
    var p = T.ParamsFor(O){ .instance = instance, .weights = weights, .beta = randomO(r), .ssa = .{ .offset = randomO(r), .coefficients = undefined }, .eta = randomO(r), .target = randomO(r) };
    for (&p.ssa.coefficients) |*x| x.* = randomO(r);
    return p;
}
fn native(p: *const T.ParamsFor(O)) P.Data {
    return .{ .allocator = std.testing.allocator, .instance = p.instance, .weights = @constCast(p.weights), .point = P.MP.MleEvalPointFor(O).init(&.{O.fromBase(M.fromCanonical(2))}) catch unreachable, .beta = p.beta, .ssa = .{ .offset = p.ssa.offset, .coefficients = p.ssa.coefficients }, .eta = p.eta, .target = p.target };
}
fn compare(v: anytype, p: *const T.ParamsFor(O), eq: O) !O {
    const old = try P.evaluate(O, v, &native(p));
    const new = try T.evaluate(O, v, p);
    try std.testing.expect(old[0].eql(new.numerator));
    try std.testing.expect(old[1].eql(new.denominator));
    const actual = T.bindingResidual(O, new, p, eq);
    try std.testing.expect(actual.eql(eq.mul(old[0].add(p.eta.mul(old[1]))).sub(p.target)));
    return actual;
}
test "MAC12 typed R7 projection all six original expressions arbitrary full OM31" {
    var rng = std.Random.DefaultPrng.init(0x747970656450726f);
    var weights: [512]O = undefined;
    for (N.INSTANCES) |instance| for (0..3) |case| {
        var v = randomView(rng.random());
        if (case == 1) {
            v.values[0] = O.zero();
            v.fixed_values[0] = O.zero();
        }
        if (case == 2) {
            v.values[0] = O.one();
            v.fixed_values[0] = O.one();
        }
        const p = params(rng.random(), instance, weights[0..instance.lanes()]);
        _ = try compare(&v, &p, randomO(rng.random()));
        for (0..instance.lanes()) |lane| {
            const pair = try T.fraction(O, &v, &p, lane);
            const old = if (instance.family == .bytes) switch (instance.role) {
                .arithmetic => C.byteFraction(.arithmetic, O, &v, p.beta, lane),
                .hints => C.byteFraction(.hints, O, &v, p.beta, lane),
                .table => C.byteFraction(.table, O, &v, p.beta, lane),
                else => unreachable,
            } else switch (instance.role) {
                .arithmetic => C.ssaFraction(.arithmetic, O, &v, native(&p).ssa, lane),
                .hints => C.ssaFraction(.hints, O, &v, native(&p).ssa, lane),
                .frontier => C.ssaFraction(.frontier, O, &v, native(&p).ssa, lane),
                else => unreachable,
            };
            try std.testing.expect(pair[0].eql(old[0]) and pair[1].eql(old[1]));
            const dummy = if (instance.family == .bytes) instance.role == .arithmetic and lane >= 353 else instance.role == .arithmetic and lane > 25;
            if (dummy) try std.testing.expect(pair[0].isZero() and pair[1].eql(O.one()));
        }
    };
}
// Numeric external contract wrapper, not a circuit proof. Dynamic values carry
// dependency labels; constants cannot smuggle a native beta/wire/weight into it.
const Wire = struct {
    pub const rv64_external_lane = true;
    pub const rv64_extension_degree = 8;
    x: O,
    deps: u8 = 0,
    pub fn zero() Wire {
        return .{ .x = O.zero() };
    }
    pub fn one() Wire {
        return .{ .x = O.one() };
    }
    pub fn fromU32(v: u32) Wire {
        return .{ .x = O.fromBase(M.fromCanonical(v)) };
    }
    pub fn fromBase(v: M) Wire {
        return .{ .x = O.fromBase(v) };
    }
    pub fn fromQm31(v: Q) Wire {
        return .{ .x = O.fromInner(v) };
    }
    pub fn fromPartialEvals(v: [8]Wire) Wire {
        var a: [8]O = undefined;
        var deps: u8 = 0;
        for (v, &a) |w, *x| {
            x.* = w.x;
            deps |= w.deps;
        }
        return .{ .x = O.fromPartialEvals(a), .deps = deps };
    }
    pub fn add(a: Wire, b: Wire) Wire {
        return .{ .x = a.x.add(b.x), .deps = a.deps | b.deps };
    }
    pub fn sub(a: Wire, b: Wire) Wire {
        return .{ .x = a.x.sub(b.x), .deps = a.deps | b.deps };
    }
    pub fn mul(a: Wire, b: Wire) Wire {
        return .{ .x = a.x.mul(b.x), .deps = a.deps | b.deps };
    }
    pub fn neg(a: Wire) Wire {
        return .{ .x = a.x.neg(), .deps = a.deps };
    }
    pub fn square(a: Wire) Wire {
        return a.mul(a);
    }
    pub fn inv(a: Wire) Wire {
        return .{ .x = a.x.inv() catch unreachable, .deps = a.deps };
    }
};
fn external(v: *const View(O), p: *const T.ParamsFor(O), eq: O) !Wire {
    comptime E.lane.assertExternalLane(Wire);
    var ev: View(Wire) = undefined;
    for (v.values, &ev.values) |a, *b| b.* = .{ .x = a, .deps = 32 };
    for (v.fixed_values, &ev.fixed_values) |a, *b| b.* = .{ .x = a, .deps = 32 };
    var ws: [512]Wire = undefined;
    for (p.weights, ws[0..p.weights.len]) |a, *b| b.* = .{ .x = a, .deps = 8 };
    var ep = T.ParamsFor(Wire){ .instance = p.instance, .weights = ws[0..p.weights.len], .beta = .{ .x = p.beta, .deps = 1 }, .ssa = .{ .offset = .{ .x = p.ssa.offset, .deps = 2 }, .coefficients = undefined }, .eta = .{ .x = p.eta, .deps = 4 }, .target = .{ .x = p.target, .deps = 16 } };
    for (p.ssa.coefficients, &ep.ssa.coefficients) |a, *b| b.* = .{ .x = a, .deps = 2 };
    const out = try T.evaluate(Wire, &ev, &ep);
    return T.bindingResidual(Wire, out, &ep, .{ .x = eq, .deps = 64 });
}
test "MAC12 typed R7 dynamic external parameter mutations follow original native" {
    var rng = std.Random.DefaultPrng.init(0x64796e616d6963);
    var weights: [512]O = undefined;
    for (N.INSTANCES) |instance| {
        const v = randomView(rng.random());
        var p = params(rng.random(), instance, weights[0..instance.lanes()]);
        const eq = randomO(rng.random());
        for (0..7) |mutation| {
            switch (mutation) {
                0 => {},
                1 => p.beta = randomO(rng.random()),
                2 => p.ssa.offset = randomO(rng.random()),
                3 => {
                    for (&p.ssa.coefficients) |*c| c.* = randomO(rng.random());
                },
                4 => p.eta = randomO(rng.random()),
                5 => weights[0] = randomO(rng.random()),
                6 => p.target = randomO(rng.random()),
                else => unreachable,
            }
            const value = try external(&v, &p, eq);
            try std.testing.expect(value.x.eql(try compare(&v, &p, eq)));
            const required: u8 = (if (instance.family == .bytes) @as(u8, 1) else @as(u8, 2)) | 4 | 8 | 16 | 32 | 64;
            try std.testing.expectEqual(required, value.deps);
        }
    }
}
test "MAC12 typed R7 rejects unknown source geometry and malformed weight vector" {
    var rng = std.Random.DefaultPrng.init(0x626164);
    var weights: [512]O = undefined;
    const v = randomView(rng.random());
    var p = params(rng.random(), N.INSTANCES[0], &weights);
    p.weights = weights[0..511];
    try std.testing.expectError(error.PairingR7ProjectionWeights, T.evaluate(O, &v, &p));
    p.weights = &weights;
    p.instance.row_log -= 1;
    try std.testing.expectError(error.PairingR7ProjectionShape, T.evaluate(O, &v, &p));
    p.instance = N.INSTANCES[0];
    try std.testing.expectError(error.PairingR7ProjectionLane, T.fraction(O, &v, &p, 512));
}
test "MAC12 typed R7 packed base16 agrees original secure projection and scalar lanes" {
    const Packed = E.PackedFields.PackedOmBase;
    const LANES = E.PackedFields.LANES;
    var rng = std.Random.DefaultPrng.init(0x7061636b656442);
    var pv: View(Packed) = undefined;
    var sv: [LANES]View(O) = undefined;
    for (&pv.values, 0..) |*x, i| {
        var base: [LANES]M = undefined;
        for (&base, 0..) |*b, lane| {
            b.* = M.fromCanonical(rng.random().int(u32) % 2147483647);
            sv[lane].values[i] = O.fromBase(b.*);
        }
        x.* = Packed.fromLanes(base);
    }
    for (&pv.fixed_values, 0..) |*x, i| {
        var base: [LANES]M = undefined;
        for (&base, 0..) |*b, lane| {
            b.* = M.fromCanonical(rng.random().int(u32) % 2147483647);
            sv[lane].fixed_values[i] = O.fromBase(b.*);
        }
        x.* = Packed.fromLanes(base);
    }
    var weights: [512]O = undefined;
    for (N.INSTANCES) |instance| {
        const p = params(rng.random(), instance, weights[0..instance.lanes()]);
        const old = try P.evaluate(Packed, &pv, &native(&p));
        const new = try T.evaluate(Packed, &pv, &p);
        var eqs: [LANES]O = undefined;
        for (&eqs) |*x| x.* = randomO(rng.random());
        const residual = T.bindingResidual(Packed, new, &p, E.PackedFields.PackedOmSecure.fromLanes(eqs));
        for (&sv, eqs, 0..) |*scalar, eq, lane| {
            try std.testing.expect(old[0].lane(lane).eql(new.numerator.lane(lane)));
            try std.testing.expect(old[1].lane(lane).eql(new.denominator.lane(lane)));
            try std.testing.expect(residual.lane(lane).eql(try compare(scalar, &p, eq)));
        }
    }
}
