const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const S = A.crypto.bn254_mac12.source;
const W = A.crypto.bn254_mac12.witness;
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const H = @import("fold.zig");
const FIRST = S.MAIN + 1;
fn constants(comptime F: type) H.Constants(F) {
    var p: [32]F = undefined;
    for (&p, 0..) |*x, i| x.* = E.qFor(F, @intCast((S.B.P >> @intCast(8 * i)) & 255));
    return .{ .one = F.one(), .radix = E.qFor(F, 256), .offset = E.qFor(F, @intCast(S.B.OFFSET)), .modulus = p };
}
fn View(comptime F: type) type {
    return struct {
        values: [S.MAIN]F,
        coefficients: [S.FIXED]F,
        pub fn main(v: *const @This(), i: usize) F {
            return v.values[i];
        }
        pub fn fixed(v: *const @This(), i: usize) F {
            return v.coefficients[i];
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
    for (&v.coefficients) |*x| x.* = randomO(r);
    return v;
}
fn Sink(comptime F: type) type {
    return struct {
        values: [65]F = undefined,
        n: usize = 0,
        pub fn emit(s: *@This(), x: F) void {
            if (s.n >= FIRST and s.n < FIRST + 65) s.values[s.n - FIRST] = x;
            s.n += 1;
        }
    };
}
fn reference(comptime F: type, v: anytype, alpha: F) F {
    var sink = Sink(F){};
    S.emit(F, v, &sink);
    std.debug.assert(sink.n == S.CONSTRAINTS);
    var sum = F.zero();
    for (sink.values) |x| sum = sum.mul(alpha).add(x);
    return sum;
}
fn compare(v: *const View(O), alpha: O) !void {
    const old = reference(O, v, alpha);
    const new = H.folded(O, v, alpha, constants(O));
    try std.testing.expect(old.eql(new));
    // Preserve a preceding sink accumulator as well as the isolated zero-start.
    const previous = v.values[0];
    var sink = Sink(O){};
    S.emit(O, v, &sink);
    var joined = previous;
    var power = O.one();
    for (sink.values) |x| {
        joined = joined.mul(alpha).add(x);
        power = power.mul(alpha);
    }
    try std.testing.expect(joined.eql(previous.mul(power).add(new)));
}
test "MAC12 Horner prototype same65 residuals arbitrary full OM31 and alpha zero one" {
    var rng = std.Random.DefaultPrng.init(0x486f726e65723635);
    for (0..20) |_| {
        const v = randomView(rng.random());
        try compare(&v, O.zero());
        try compare(&v, O.one());
        try compare(&v, O.one().neg());
        try compare(&v, randomO(rng.random()));
    }
}
fn fromRow(row: *const S.Row, cs: W.Coefficients) View(O) {
    var v: View(O) = .{ .values = undefined, .coefficients = @splat(O.zero()) };
    for (&v.values, row) |*x, n| x.* = O.fromBase(M.fromCanonical(n));
    v.coefficients[S.FIX_ACTIVE] = O.one();
    for (cs, 0..) |n, i| {
        const x = O.fromBase(M.fromCanonical(@intCast(@abs(n))));
        v.coefficients[S.COEFFICIENT + i] = if (n < 0) x.neg() else x;
    }
    return v;
}
test "MAC12 Horner prototype honest signed rows and forged extension witnesses" {
    var rng = std.Random.DefaultPrng.init(0x7369676e6564);
    for ([_]W.Coefficients{ @splat(18), @splat(-18), @splat(0), .{ 18, -18, 1, -1, 0, 2, -2, 3, -3, 4, -4, 5 } }) |cs| {
        const input: W.Inputs = @splat(S.B.P - 1);
        const row = try W.fill(&input, cs);
        var v = fromRow(&row, cs);
        const alpha = randomO(rng.random());
        try std.testing.expect(reference(O, &v, alpha).isZero());
        try compare(&v, alpha);
        for ([_]usize{ S.ACTIVE, S.INPUT, S.INPUT + 31, S.INPUT + 32, S.INPUT + 32 * 24, S.OUTPUT, S.SIGN, S.QUOTIENT, S.QUOTIENT + 32, S.CARRY, S.CARRY + 191 }) |i| {
            const old = v.values[i];
            v.values[i] = old.add(randomO(rng.random()));
            try compare(&v, alpha);
            v.values[i] = old;
        }
        v.coefficients[S.COEFFICIENT + 11] = randomO(rng.random());
        try compare(&v, alpha);
    }
}
const Counts = struct {
    add: usize = 0,
    sub: usize = 0,
    mul: usize = 0,
    fn minus(a: Counts, b: Counts) Counts {
        return .{ .add = a.add - b.add, .sub = a.sub - b.sub, .mul = a.mul - b.mul };
    }
};
const Count = struct {
    pub const rv64_external_lane = true;
    pub const rv64_extension_degree = 8;
    var ops: Counts = .{};
    x: O,
    pub fn zero() Count {
        return .{ .x = O.zero() };
    }
    pub fn one() Count {
        return .{ .x = O.one() };
    }
    pub fn fromU32(n: u32) Count {
        return .{ .x = O.fromBase(M.fromCanonical(n)) };
    }
    pub fn add(a: Count, b: Count) Count {
        ops.add += 1;
        return .{ .x = a.x.add(b.x) };
    }
    pub fn sub(a: Count, b: Count) Count {
        ops.sub += 1;
        return .{ .x = a.x.sub(b.x) };
    }
    pub fn mul(a: Count, b: Count) Count {
        ops.mul += 1;
        return .{ .x = a.x.mul(b.x) };
    }
};
const CountSink = struct {
    n: usize = 0,
    before: Counts = .{},
    after: Counts = .{},
    values: [65]Count = undefined,
    pub fn emit(s: *@This(), x: Count) void {
        if (s.n == FIRST - 1) s.before = Count.ops;
        if (s.n >= FIRST and s.n < FIRST + 65) s.values[s.n - FIRST] = x;
        if (s.n == FIRST + 64) s.after = Count.ops;
        s.n += 1;
    }
};
test "MAC12 Horner prototype external secure operation census same source slice" {
    var rng = std.Random.DefaultPrng.init(0x636f756e74);
    const original = randomView(rng.random());
    var v: View(Count) = undefined;
    for (&v.values, original.values) |*a, b| a.* = .{ .x = b };
    for (&v.coefficients, original.coefficients) |*a, b| a.* = .{ .x = b };
    const alpha = Count{ .x = randomO(rng.random()) };
    Count.ops = .{};
    var sink = CountSink{};
    S.emit(Count, &v, &sink);
    const source = sink.after.minus(sink.before);
    Count.ops = .{};
    var old = Count.zero();
    for (sink.values) |x| old = old.mul(alpha).add(x);
    const fold_ops = Count.ops;
    Count.ops = .{};
    const new = H.folded(Count, &v, alpha, constants(Count));
    const fast = Count.ops;
    try std.testing.expect(old.x.eql(new.x));
    try std.testing.expectEqual(@as(usize, 65), fold_ops.mul);
    try std.testing.expect(fast.mul < 1200);
    try std.testing.expect(source.mul + fold_ops.mul > 10 * fast.mul);
    std.debug.print("MAC12_HORNER_OPS original_slice={any} original_fold={any} factored={any}\n", .{ source, fold_ops, fast });
}
test "MAC12 Horner prototype packed secure16 independent lane parity" {
    const Packed = E.PackedFields.PackedOmSecure;
    const LANES = E.PackedFields.LANES;
    var rng = std.Random.DefaultPrng.init(0x7061636b6564);
    var scalar: [LANES]View(O) = undefined;
    var alphas: [LANES]O = undefined;
    for (&scalar, &alphas, 0..) |*v, *alpha, i| {
        v.* = randomView(rng.random());
        alpha.* = switch (i % 4) {
            0 => O.zero(),
            1 => O.one(),
            2 => O.one().neg(),
            else => randomO(rng.random()),
        };
    }
    var v: View(Packed) = undefined;
    for (&v.values, 0..) |*x, i| {
        var lanes: [LANES]O = undefined;
        for (&lanes, scalar) |*a, b| a.* = b.values[i];
        x.* = Packed.fromLanes(lanes);
    }
    for (&v.coefficients, 0..) |*x, i| {
        var lanes: [LANES]O = undefined;
        for (&lanes, scalar) |*a, b| a.* = b.coefficients[i];
        x.* = Packed.fromLanes(lanes);
    }
    const alpha = Packed.fromLanes(alphas);
    const fast = H.folded(Packed, &v, alpha, constants(Packed));
    const old = reference(Packed, &v, alpha);
    for (&scalar, alphas, 0..) |*sv, sa, i| {
        try std.testing.expect(fast.lane(i).eql(old.lane(i)));
        try std.testing.expect(fast.lane(i).eql(reference(O, sv, sa)));
    }
}
