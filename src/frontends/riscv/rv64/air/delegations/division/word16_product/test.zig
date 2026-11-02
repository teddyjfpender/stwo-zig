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
    for ([_]usize{ L.C, L.CARRY_SUM + 3, L.ZERO, L.NEG_A, L.COUNT }) |index| {
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

fn localClean(m: *const [L.MAIN]Q) !void {
    for (residuals(m)) |v| try std.testing.expect(v.isZero());
    for (A.rangeValuesFor(Q, m)) |v| try std.testing.expect((try v.tryIntoM31()).v < 65536);
}
fn noncanonical(v: Q) !bool {
    return (try v.tryIntoM31()).v >= 65536;
}

test "DIV operand A/B limbs have no local range: aliased signed and W-upper limbs pass every retained local obligation" {
    // These rows are locally valid AND satisfy every retained U16 query, yet
    // their FUNCTION tuple carries non-canonical A/B limbs. Only the closed
    // CPU FUNCTION relation (canonical REG reads + ROM) excludes them; see
    // word16_execution/division_product_integration_test.zig for real proofs.
    const p = core.fields.m31.Modulus;
    // Signed A: move one radix unit from limb0 into limb1 (0xfff1 -> -15, 0xffff -> 65536).
    var r = try W.row(.{ .opcode = .DIV, .a = @bitCast(@as(i64, -15)), .b = 4, .result = @bitCast(@as(i64, -3)) });
    const honest_a = qrow(r.main);
    try localClean(&honest_a);
    r.main[L.A] = core.fields.m31.M31.fromCanonical(p - 15);
    r.main[L.A + 1] = core.fields.m31.M31.fromCanonical(65536);
    r.main[L.CARRY_A] = core.fields.m31.M31.zero();
    var m = qrow(r.main);
    try localClean(&m);
    try std.testing.expectEqualDeep(A.rangeValuesFor(Q, &honest_a), A.rangeValuesFor(Q, &m));
    try std.testing.expect(try noncanonical(m[L.A]) and try noncanonical(m[L.A + 1]));
    try std.testing.expect(!std.meta.eql(A.tupleFor(Q, &honest_a, null), A.tupleFor(Q, &m, null)));
    // Signed B, same alias with NEG_B=1: ABS_B (MUL-ranged) is unchanged.
    r = try W.row(.{ .opcode = .DIV, .a = 0x8000000000000000, .b = 0xffffffffffffffff, .result = 0x8000000000000000 });
    const honest_b = qrow(r.main);
    r.main[L.B] = core.fields.m31.M31.fromCanonical(p - 1);
    r.main[L.B + 1] = core.fields.m31.M31.fromCanonical(65536);
    r.main[L.CARRY_B] = core.fields.m31.M31.zero();
    m = qrow(r.main);
    try localClean(&m);
    try std.testing.expectEqualDeep(A.tupleFor(Q, &honest_b, false), A.tupleFor(Q, &m, false));
    try std.testing.expect(try noncanonical(m[L.B]));
    // W policies ignore upper input limbs entirely.
    r = try W.row(.{ .opcode = .DIVW, .a = 0x1234567880000000, .b = 0xabcdef01ffffffff, .result = 0xffffffff80000000 });
    r.main[L.A + 3] = core.fields.m31.M31.fromCanonical(p - 1);
    r.main[L.B + 2] = core.fields.m31.M31.fromCanonical(1 << 20);
    m = qrow(r.main);
    try localClean(&m);
    // Unsigned non-W A is still locally pinned: ABS_A = A limbwise and ABS_A is ranged.
    r = try W.row(.{ .opcode = .DIVU, .a = 0x10000, .b = 4, .result = 0x4000 });
    r.main[L.A] = core.fields.m31.M31.fromCanonical(65536);
    r.main[L.A + 1] = core.fields.m31.M31.zero();
    m = qrow(r.main);
    var dirty = false;
    for (residuals(&m)) |v| dirty = dirty or !v.isZero();
    try std.testing.expect(dirty);
}

test "DIV ABS_B negation carries are unique when NEG_B=1 for canonical B and canonical ABS_B" {
    const values = [_]u64{ 1, 0xffff, 0x10000, 0x8000000000000000, 0xffffffffffffffff, 0xfffffffffffffffe, 0xffff0000ffff0000, 0x8000, 0x80000000, 0xffffffff80000000, 0x0001000000000000 };
    const ops = [_]struct { op: E.O, a: u64 }{ .{ .op = .DIV, .a = 0x123456789abcdef }, .{ .op = .REM, .a = 0x123456789abcdef }, .{ .op = .DIVW, .a = 0x12345678 }, .{ .op = .REMW, .a = 0x12345678 } };
    var checked: usize = 0;
    for (ops) |case| for (values) |b| {
        const r = try W.row(.{ .opcode = case.op, .a = case.a, .b = b, .result = 0 });
        if (r.main[L.NEG_B].v != 1) continue;
        const word = case.op == .DIVW or case.op == .REMW;
        // Solve the four negation residuals for every Boolean carry vector.
        var honest_count: usize = 0;
        for (0..16) |bits| {
            var abs: [4]i64 = undefined;
            var canonical = true;
            for (0..4) |i| {
                const c: i64 = @intCast((bits >> @as(u2, @intCast(i))) & 1);
                const prev: i64 = if (i == 0) 0 else @intCast((bits >> @as(u2, @intCast(i - 1))) & 1);
                const prior: i64 = if (word and i == 2) 0 else prev;
                const eff: i64 = if (word and i >= 2) 0 else r.main[L.B + i].v;
                abs[i] = 65536 * c - eff - prior;
                canonical = canonical and abs[i] >= 0 and abs[i] < 65536;
            }
            if (!canonical) continue;
            honest_count += 1;
            for (0..4) |i| {
                try std.testing.expectEqual(@as(i64, r.main[L.ABS_B + i].v), abs[i]);
                if (!(word and i >= 2)) try std.testing.expectEqual(@as(u32, @intCast((bits >> @as(u2, @intCast(i))) & 1)), r.main[L.CARRY_B + i].v);
            }
        }
        try std.testing.expect(honest_count >= 1);
        // The actual AIR rejects any flipped carry against the honest ABS_B.
        for (0..4) |i| {
            var bad = qrow(r.main);
            bad[L.CARRY_B + i] = Q.one().sub(bad[L.CARRY_B + i]);
            var dirty = false;
            for (residuals(&bad)) |v| dirty = dirty or !v.isZero();
            try std.testing.expect(dirty);
        }
        checked += 1;
    };
    try std.testing.expect(checked >= 20);
}

test "DIV support coordinates stay byte ranged by the MUL provider and PRODUCT_HIGH is a constant zero tuple" {
    // DIV QUOTIENT, ABS_B and PRODUCT_LOW have NO DIV range query. Their only
    // canonicality authority is the MUL provider: tuple coordinates1..24 are
    // MAIN[0..24] (A,B,RESULT bytes) and every one is a direct BYTE query.
    // Removing any MUL A/B/RESULT byte query breaks DIV soundness: this fails.
    const ML = @import("../../multiplication/layout.zig");
    const MP = @import("../../multiplication/provider.zig");
    const MD = @import("../../multiplication/degree3_layout.zig");
    const MT = @import("../../multiplication/trace.zig");
    comptime std.debug.assert(ML.A == 0 and ML.B == 8 and ML.RESULT == 16 and ML.TUPLE == 25);
    comptime std.debug.assert(2 * MD.BYTE_PAIRS == ML.BYTE_QUERIES and ML.BYTE_QUERIES >= 24);
    for (0..24) |column| {
        var main: [ML.MAIN]Q = @splat(Q.zero());
        main[column] = E.q(@intCast(1000 + column));
        const bytes = MP.byteValuesFor(Q, &main);
        try std.testing.expect(bytes[column].eql(main[column]));
        try std.testing.expect(MP.tupleFor(Q, &main)[1 + column].eql(main[column]));
        var native: [ML.MAIN]core.fields.m31.M31 = @splat(core.fields.m31.M31.zero());
        native[column] = core.fields.m31.M31.fromCanonical(256);
        try std.testing.expectError(error.InvalidRv64MultiplicationByte, MT.byteValuesNative(&native));
    }
    var channel = core.channel.blake2s.Blake2sChannel{};
    var m: [L.MAIN]Q = undefined;
    for (&m) |*v| v.* = channel.drawSecureFelt();
    for ([_]bool{ false, true }) |high| {
        const t = A.tupleFor(Q, &m, high);
        for (0..4) |i| {
            try std.testing.expect(t[1 + i].eql(m[L.QUOTIENT + i]));
            try std.testing.expect(t[5 + i].eql(m[L.ABS_B + i]));
            try std.testing.expect(t[9 + i].eql(if (high) Q.zero() else m[L.PRODUCT_LOW + i]));
        }
    }
    // No retained DIV U16 query is a direct membership of QUOTIENT, ABS_B,
    // PRODUCT_LOW, A or B limbs (only the doubled selected A/B tops remain).
    for ([_]usize{ L.QUOTIENT, L.ABS_B, L.PRODUCT_LOW, L.A, L.B }) |start| for (0..4) |i| {
        var probe: [L.MAIN]Q = @splat(Q.zero());
        probe[start + i] = E.q(@intCast(70000 + start + i));
        for (A.rangeValuesFor(Q, &probe)) |v| try std.testing.expect(!v.eql(probe[start + i]));
    };
}

test "DIV canonical support dependency reaches production degree3 MUL byte and FUNCTION residuals" {
    // Exercise the production emitter, rather than only its helper accessors:
    // a later degree3-provider rewrite must not silently stop authenticating
    // any A/B/RESULT coordinate that DIV relies on for canonicality.
    const ML = @import("../../multiplication/degree3_layout.zig");
    const MP = @import("../../multiplication/degree3_provider.zig");
    const alpha = E.q(4096);
    const byte_inverse = try alpha.mul(alpha).inv();
    for (0..24) |column| {
        var main: [ML.MAIN]Q = @splat(Q.zero());
        main[column] = E.q(256);
        var interaction: [ML.INTERACTION]Q = @splat(Q.zero());
        for (0..ML.BYTE_PAIRS) |pair| {
            for (byte_inverse.toM31Array(), 0..) |limb, i| interaction[4 * pair + i] = Q.fromBase(limb);
        }
        // FUNCTION inverse for the all-zero tuple; the selected coordinate's
        // coefficient makes the same input mutation visible in that argument.
        const offset = E.q(1024);
        const fn_inverse = try offset.inv();
        for (fn_inverse.toM31Array(), 0..) |limb, i| interaction[ML.FUNCTION_INVERSE + i] = Q.fromBase(limb);
        var ch: MP.Challenges = .{ .offset = offset, .coefficients = @splat(Q.zero()) };
        ch.coefficients[1 + column] = Q.one();
        var values: [ML.CONSTRAINTS]Q = undefined;
        var sink: E.Sink = .{ .values = &values };
        MP.evaluateFor(Q, .{ Q.zero(), Q.one(), Q.one() }, &main, &interaction, Q.zero(), Q.zero(), Q.zero(), ch, alpha, Q.zero(), &sink);
        try std.testing.expectEqual(ML.CONSTRAINTS, sink.count);
        const expected_byte = alpha.sub(E.q(256)).mul(alpha).mul(byte_inverse).sub(Q.one());
        try std.testing.expect(!expected_byte.isZero());
        try std.testing.expect(values[ML.ARITHMETIC_CONSTRAINTS + column / 2].eql(expected_byte));
        const expected_function = fn_inverse.mul(offset.add(E.q(256))).sub(Q.one());
        try std.testing.expect(!expected_function.isZero());
        try std.testing.expect(values[ML.ARITHMETIC_CONSTRAINTS + ML.BYTE_PAIRS].eql(expected_function));
    }
}
