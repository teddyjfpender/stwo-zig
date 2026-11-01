const std = @import("std");
const core = @import("stwo_core");
const E = @import("../../../evaluation.zig");
const L = @import("layout.zig");
const A = @import("equations.zig");
const W = @import("witness.zig");
const Q = E.Q;
fn reference(op: usize, a: u64, b: u64) u64 {
    const word = op >= 4;
    const rem = op % 4 >= 2;
    const mask: u64 = if (word) std.math.maxInt(u32) else std.math.maxInt(u64);
    const x = a & mask;
    const y = b & mask;
    var value: u64 = undefined;
    if (op % 2 != 0) {
        value = if (y == 0) (if (rem) x else mask) else if (rem) x % y else x / y;
    } else {
        const sx: i64 = if (word) @as(i32, @bitCast(@as(u32, @truncate(x)))) else @bitCast(x);
        const sy: i64 = if (word) @as(i32, @bitCast(@as(u32, @truncate(y)))) else @bitCast(y);
        const minimum: i64 = if (word) std.math.minInt(i32) else std.math.minInt(i64);
        const signed_result = if (sy == 0) (if (rem) sx else @as(i64, -1)) else if (sx == minimum and sy == -1) (if (rem) @as(i64, 0) else minimum) else if (rem) @rem(sx, sy) else @divTrunc(sx, sy);
        value = @bitCast(signed_result);
    }
    return if (word) @bitCast(@as(i64, @as(i32, @bitCast(@as(u32, @truncate(value)))))) else value;
}
fn qrow(main: [L.MAIN]core.fields.m31.M31) [L.MAIN]Q {
    var out: [L.MAIN]Q = undefined;
    for (&out, main) |*v, m| v.* = Q.fromBase(m);
    return out;
}
fn residuals(main: []const Q) [L.ARITHMETIC_CONSTRAINTS]Q {
    var result: [L.ARITHMETIC_CONSTRAINTS]Q = undefined;
    var sink = E.Sink{ .values = &result };
    A.emitFor(Q, &.{ Q.zero(), Q.one(), Q.one() }, main, Q.zero(), Q.one(), &sink);
    std.debug.assert(sink.count == L.ARITHMETIC_CONSTRAINTS);
    return result;
}
fn check(op: usize, a: u64, b: u64) !void {
    const r = try W.row(.{ .opcode = L.OPCODES[op], .a = a, .b = b, .result = reference(op, a, b) });
    const m = qrow(r.main);
    for (residuals(&m), 0..) |v, i| {
        if (!v.isZero()) std.debug.print("op{} a{x} b{x} residual{}\n", .{ op, a, b, i });
        try std.testing.expect(v.isZero());
    }
    for (A.rangeValuesFor(Q, &m)) |v| try std.testing.expect((try v.tryIntoM31()).v < 65536);
    for (r.support, 0..) |s, i| {
        const p: u128 = @as(u128, s.a) * s.b;
        try std.testing.expectEqual(if (i == 0) @as(u64, @truncate(p)) else @as(u64, @intCast(p >> 64)), s.result);
    }
}
test "Word16 product DIV all8 policies match independent signed integer reference on extrema and random words" {
    const values = [_]u64{ 0, 1, 2, 3, 4, 0x7fff, 0x8000, 0xffff, 0x7fffffff, 0x80000000, 0xffffffff, 0x100000000, 0x7fffffffffffffff, 0x8000000000000000, 0xffffffffffffffff };
    for (0..8) |op| for (values) |a| for (values) |b| try check(op, a, b);
    var random = std.Random.DefaultPrng.init(0x91581a670011);
    for (0..4096) |i| try check(i % 8, random.random().int(u64), random.random().int(u64));
}
test "Word16 product DIV count padding output and zero-divisor ghosts reject" {
    var m = qrow((try W.row(.{ .opcode = .DIVU, .a = 15, .b = 4, .result = 3 })).main);
    for ([_]usize{ L.C, L.PRODUCT_HIGH, L.CARRY_SUM + 3, L.ZERO, L.NEG_A, L.COUNT }) |index| {
        var bad = m;
        bad[index] = bad[index].add(Q.one());
        var dirty = false;
        for (residuals(&bad)) |v| dirty = dirty or !v.isZero();
        try std.testing.expect(dirty);
    }
    m = @splat(Q.zero());
    var result: [L.ARITHMETIC_CONSTRAINTS]Q = undefined;
    var sink = E.Sink{ .values = &result };
    A.emitFor(Q, &.{ Q.zero(), Q.one(), Q.one() }, &m, Q.zero(), Q.zero(), &sink);
    for (result) |v| try std.testing.expect(v.isZero());
}
test "Word16 product DIV arithmetic residuals have degree at most3 at arbitrary full extension coordinates" {
    var channel = core.channel.blake2s.Blake2sChannel{};
    const N = L.MAIN + L.FIXED + 2;
    var origin: [N]Q = undefined;
    var slope: [N]Q = undefined;
    for (&origin, &slope) |*o, *s| {
        o.* = channel.drawSecureFelt();
        s.* = channel.drawSecureFelt();
    }
    var result: [5][L.ARITHMETIC_CONSTRAINTS]Q = undefined;
    for (0..5) |i| {
        var values: [N]Q = undefined;
        for (&values, origin, slope) |*v, o, s| v.* = o.add(s.mul(E.q(@intCast(i))));
        var sink = E.Sink{ .values = &result[i] };
        A.emitFor(Q, values[0..3], values[3..][0..L.MAIN], values[N - 2], values[N - 1], &sink);
    }
    var cubic = false;
    for (0..L.ARITHMETIC_CONSTRAINTS) |c| {
        const fourth = result[0][c].sub(result[1][c].mul(E.q(4))).add(result[2][c].mul(E.q(6))).sub(result[3][c].mul(E.q(4))).add(result[4][c]);
        try std.testing.expect(fourth.isZero());
        const third = result[3][c].sub(result[2][c].mul(E.q(3))).add(result[1][c].mul(E.q(3))).sub(result[0][c]);
        cubic = cubic or !third.isZero();
    }
    try std.testing.expect(cubic);
}
test "Word16 product DIV local equations cannot replace the MUL support truth obligation" {
    var r = try W.row(.{ .opcode = .DIVU, .a = 15, .b = 4, .result = 4 });
    r.main[L.QUOTIENT] = core.fields.m31.M31.fromCanonical(4);
    r.main[L.OUT] = core.fields.m31.M31.fromCanonical(4);
    const m = qrow(r.main);
    for (residuals(&m)) |v| try std.testing.expect(v.isZero());
    const support = A.tupleFor(Q, &m, false);
    try std.testing.expectEqual(Q.fromBase(r.main[L.QUOTIENT]), support[1]);
    const q: u64 = (try support[1].tryIntoM31()).v;
    const b: u64 = (try support[5].tryIntoM31()).v;
    const wrong_product: u64 = (try support[9].tryIntoM31()).v;
    try std.testing.expect(q * b != wrong_product);
}

test "Word16 product DIV requires high MUL truth even when low product is exact" {
    const wrapped_q: u64 = (@as(u64, 1) << 62) + 3;
    var row = try W.row(.{ .opcode = .DIVU, .a = 15, .b = 4, .result = wrapped_q });
    for (0..4) |i| {
        const limb: u16 = @truncate(wrapped_q >> @as(u6, @intCast(16 * i)));
        row.main[L.QUOTIENT + i] = core.fields.m31.M31.fromCanonical(limb);
        row.main[L.OUT + i] = core.fields.m31.M31.fromCanonical(limb);
    }
    const m = qrow(row.main);
    for (residuals(&m)) |v| try std.testing.expect(v.isZero());
    const low = A.tupleFor(Q, &m, false);
    const high = A.tupleFor(Q, &m, true);
    const product: u128 = @as(u128, wrapped_q) * 4;
    try std.testing.expectEqual(@as(u64, 12), @as(u64, @truncate(product)));
    try std.testing.expectEqual(E.q(12), low[9]);
    try std.testing.expectEqual(Q.zero(), high[9]);
    try std.testing.expectEqual(@as(u64, 1), @as(u64, @intCast(product >> 64)));
}

test "Word16 product DIV complete lookup authority remains cubic at arbitrary extension coordinates" {
    const P = @import("lookup.zig");
    var channel = core.channel.blake2s.Blake2sChannel{};
    var ch: P.Challenges = undefined;
    ch.function.offset = channel.drawSecureFelt();
    for (&ch.function.coefficients) |*v| v.* = channel.drawSecureFelt();
    ch.range16 = .{ .offset = channel.drawSecureFelt(), .coefficient = channel.drawSecureFelt() };
    const N = L.FIXED + L.MAIN + L.INTERACTION + 6;
    var origin: [N]Q = undefined;
    var slope: [N]Q = undefined;
    for (&origin, &slope) |*o, *s| {
        o.* = channel.drawSecureFelt();
        s.* = channel.drawSecureFelt();
    }
    var values: [5][L.CONSTRAINTS]Q = undefined;
    const claim = channel.drawSecureFelt();
    for (0..5) |i| {
        var row: [N]Q = undefined;
        for (&row, origin, slope) |*v, o, s| v.* = o.add(s.mul(E.q(@intCast(i))));
        const public = row[N - 6 ..];
        var sink = E.Sink{ .values = &values[i] };
        P.emitFor(Q, row[0..3], row[3..][0..L.MAIN], public[0], public[1], row[3 + L.MAIN ..][0..L.INTERACTION], Q.fromPartialEvals(public[2..6].*), claim, ch, &sink);
        try std.testing.expectEqual(L.CONSTRAINTS, sink.count);
    }
    var cubic = false;
    for (0..L.CONSTRAINTS) |c| {
        const fourth = values[0][c].sub(values[1][c].mul(E.q(4))).add(values[2][c].mul(E.q(6))).sub(values[3][c].mul(E.q(4))).add(values[4][c]);
        try std.testing.expect(fourth.isZero());
        const third = values[3][c].sub(values[2][c].mul(E.q(3))).add(values[1][c].mul(E.q(3))).sub(values[0][c]);
        cubic = cubic or !third.isZero();
    }
    try std.testing.expect(cubic);
}

test "Word16 product DIV concrete component binds degree3 masks and native dispatch" {
    const C = @import("component.zig").Component;
    const a = std.testing.allocator;
    var c = C{ .log_size = 5, .count = 1, .fixed_offset = 0, .main_offset = 0, .interaction_offset = 0, .claim = Q.zero(), .challenges = .{ .function = .{ .offset = Q.one(), .coefficients = @splat(Q.zero()) }, .range16 = .{ .offset = Q.one(), .coefficient = Q.zero() } } };
    _ = c.asProverComponent();
    _ = c.asVerifierComponent();
    try std.testing.expectEqual(@as(usize, L.CONSTRAINTS), c.nConstraints());
    try std.testing.expectEqual(@as(u32, 6), c.maxConstraintLogDegreeBound());
    var logs = try c.traceLogDegreeBounds(a);
    defer logs.deinitDeep(a);
    const point = core.circle.secureFieldPointFromRandomSeed(Q.fromU32Unchecked(7, 11, 13, 17));
    var masks = try c.maskPoints(a, point, 6);
    defer masks.deinitDeep(a);
    for ([_]usize{ L.FIXED, L.MAIN, L.INTERACTION }, 0..) |width, tree| {
        try std.testing.expectEqual(width, masks.items[tree].len);
        for (masks.items[tree], 0..) |mask, col| try std.testing.expectEqual(@as(usize, if ((tree == 1 and col == L.COUNT) or (tree == 2 and col >= L.PREFIX)) 2 else 1), mask.len);
    }
    c.count = 33;
    try std.testing.expectError(error.InvalidDivisionProductShape, c.traceLogDegreeBounds(a));
}
