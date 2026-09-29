//! Tests of `simd.zig`: `crates/circuits/src/simd_test.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230). `expect!` snapshots are kept
//! verbatim.

const std = @import("std");
const stwo_core = @import("stwo_core");
const context_mod = @import("context.zig");
const ivalue = @import("ivalue.zig");
const simd = @import("simd.zig");
const wrappers = @import("wrappers.zig");
const extract_bits = @import("extract_bits.zig");
const testing = @import("testing.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const NoValue = ivalue.NoValue;
const Simd = simd.Simd;
const Var = context_mod.Var;
const TraceContext = context_mod.Context(QM31);
const gpa = std.testing.allocator;

/// `test_utils::simd_from_u32s`: one `new_var` per four values, zero-padded.
pub fn simdFromU32s(ctx: *TraceContext, values: []const u32) !Simd {
    const n = std.math.divCeil(usize, values.len, 4) catch unreachable;
    const data = try ctx.scratch().alloc(Var, n);
    for (data, 0..) |*v, i| {
        var lanes = [_]u32{0} ** 4;
        for (0..4) |j| {
            if (4 * i + j < values.len) lanes[j] = values[4 * i + j];
        }
        v.* = try ctx.newVar(ivalue.qm31FromU32s(lanes[0], lanes[1], lanes[2], lanes[3]));
    }
    return .fromPacked(data, values.len);
}

/// `test_utils::packed_values` compared with `expected`.
pub fn expectPacked(ctx: *const TraceContext, a: Simd, expected: []const QM31) !void {
    try std.testing.expectEqual(expected.len, a.data.len);
    for (a.data, expected) |v, e| try std.testing.expect(ctx.get(v).eql(e));
}

fn guessNoValues(ctx: *context_mod.Context(NoValue), n: usize) ![]Var {
    const data = try ctx.scratch().alloc(Var, n);
    for (data) |*v| v.* = try ctx.guess(.{});
    return data;
}

fn q(a: u32, b: u32, c: u32, d: u32) QM31 {
    return ivalue.qm31FromU32s(a, b, c, d);
}

fn inverse(x: u32) M31 {
    return M31.fromCanonical(x).inv() catch unreachable;
}

test "simd: repeat, zero and one" {
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    const twos = try simd.repeat(QM31, &ctx, M31.fromCanonical(2), 6);
    try std.testing.expectEqual(@as(usize, 6), twos.len);
    try expectPacked(&ctx, twos, &.{ q(2, 2, 2, 2), q(2, 2, 2, 2) });
    try expectPacked(&ctx, try simd.zero(QM31, &ctx, 6), &.{ q(0, 0, 0, 0), q(0, 0, 0, 0) });
    try expectPacked(&ctx, try simd.one(QM31, &ctx, 6), &.{ q(1, 1, 1, 1), q(1, 1, 1, 1) });
    try std.testing.expect(try ctx.isCircuitValid());
}

test "simd: basic ops" {
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    const a = try simdFromU32s(&ctx, &.{ 1, 2, 3, 4, 5, 6 });
    const b = try simdFromU32s(&ctx, &.{ 7, 9, 11, 13, 15, 17 });
    try std.testing.expectEqual(@as(usize, 6), a.len);
    try expectPacked(&ctx, try simd.add(QM31, &ctx, a, b), &.{ q(8, 11, 14, 17), q(20, 23, 0, 0) });
    try expectPacked(&ctx, try simd.sub(QM31, &ctx, b, a), &.{ q(6, 7, 8, 9), q(10, 11, 0, 0) });
    try expectPacked(&ctx, try simd.mul(QM31, &ctx, a, b), &.{ q(7, 18, 33, 52), q(75, 102, 0, 0) });
    try std.testing.expect(try ctx.isCircuitValid());
}

test "simd: eq circuit with 8 lanes" {
    var ctx = try context_mod.Context(NoValue).init(gpa, 0);
    defer ctx.deinit();
    const a = Simd.fromPacked(try guessNoValues(&ctx, 2), 8);
    const b = Simd.fromPacked(try guessNoValues(&ctx, 2), 8);
    try simd.eq(NoValue, &ctx, a, b);
    try testing.expectVars("[[3], [4]]", a.data);
    try testing.expectVars("[[5], [6]]", b.data);
    try testing.expectCircuit(&ctx.circuit,
        \\[3] = [5]
        \\[4] = [6]
        \\output [2]
        \\
    );
}

test "simd: eq circuit with 7 lanes" {
    var ctx = try context_mod.Context(NoValue).init(gpa, 0);
    defer ctx.deinit();
    const a = Simd.fromPacked(try guessNoValues(&ctx, 2), 7);
    const b = Simd.fromPacked(try guessNoValues(&ctx, 2), 7);
    try simd.eq(NoValue, &ctx, a, b);
    try testing.expectVars("[[3], [4]]", a.data);
    try testing.expectVars("[[5], [6]]", b.data);
    try testing.expectConstants(NoValue, &ctx,
        \\{
        \\    (0 + 0i) + (0 + 0i)u: [0],
        \\    (1 + 0i) + (0 + 0i)u: [1],
        \\    (0 + 0i) + (1 + 0i)u: [2],
        \\    (1 + 1i) + (1 + 0i)u: [8],
        \\}
    );
    try testing.expectCircuit(&ctx.circuit,
        \\[7] = [4] - [6]
        \\[9] = [7] x [8]
        \\[3] = [5]
        \\[9] = [0]
        \\output [2]
        \\
    );
}

test "simd: eq checks exactly the first len lanes" {
    for (0..9) |len| {
        const n_wires = std.math.divCeil(usize, len, 4) catch unreachable;
        for (0..4 * n_wires) |wrong_coord| {
            var ctx = try TraceContext.init(gpa, 0);
            defer ctx.deinit();
            var vals: [8]u32 = .{ 0, 1, 2, 3, 4, 5, 6, 7 };
            const a = [2]Var{ try ctx.guess(q(vals[0], vals[1], vals[2], vals[3])), try ctx.guess(q(vals[4], vals[5], vals[6], vals[7])) };
            vals[wrong_coord] += 1;
            const b = [2]Var{ try ctx.guess(q(vals[0], vals[1], vals[2], vals[3])), try ctx.guess(q(vals[4], vals[5], vals[6], vals[7])) };
            try simd.eq(QM31, &ctx, .fromPacked(a[0..n_wires], len), .fromPacked(b[0..n_wires], len));
            try std.testing.expectEqual(wrong_coord >= len, try ctx.isCircuitValid());
        }
    }
}

test "simd: guess_inv_or_zero is an unconstrained hint" {
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    const a = try simdFromU32s(&ctx, &.{ 2, 0, 3 });
    const a_inv = try simd.guessInvOrZero(QM31, &ctx, a);
    try std.testing.expectEqual(@as(usize, 3), a_inv.len);
    try expectPacked(&ctx, a_inv, &.{QM31.fromM31(inverse(2), M31.zero(), inverse(3), M31.zero())});
    try std.testing.expect(try ctx.isCircuitValid());
    // Nothing constrains the hint: a changed value still satisfies the circuit.
    ctx.value_table.items[a_inv.data[0].idx] = ctx.value_table.items[a_inv.data[0].idx].add(QM31.one());
    try std.testing.expect(try ctx.isCircuitValid());
}

test "simd: inv proves every lane non-zero" {
    for ([_]?usize{ null, 2, 5 }) |zero_idx| {
        var ctx = try TraceContext.init(gpa, 0);
        defer ctx.deinit();
        var input = [_]u32{ 2, 3, 4, 5, 6, 7 };
        var expected: [6]M31 = undefined;
        for (&expected, input) |*e, x| e.* = inverse(x);
        if (zero_idx) |i| {
            input[i] = 0;
            expected[i] = M31.zero();
        }
        const a = try simdFromU32s(&ctx, &input);
        const a_inv = try simd.inv(QM31, &ctx, a);
        try std.testing.expectEqual(@as(usize, 6), a_inv.len);
        try expectPacked(&ctx, a_inv, &.{ QM31.fromM31(expected[0], expected[1], expected[2], expected[3]), QM31.fromM31(expected[4], expected[5], M31.zero(), M31.zero()) });
        try std.testing.expectEqual(zero_idx == null, try ctx.isCircuitValid());
    }
}

test "simd: inv circuit" {
    var ctx = try context_mod.Context(NoValue).init(gpa, 0);
    defer ctx.deinit();
    const input = Simd.fromPacked(try guessNoValues(&ctx, 2), 6);
    const res = try simd.inv(NoValue, &ctx, input);
    try testing.expectFormat("Simd { data: [[3], [4]], len: 6 }", input);
    try testing.expectFormat("Simd { data: [[5], [6]], len: 6 }", res);
    try testing.expectConstants(NoValue, &ctx,
        \\{
        \\    (0 + 0i) + (0 + 0i)u: [0],
        \\    (1 + 0i) + (0 + 0i)u: [1],
        \\    (0 + 0i) + (1 + 0i)u: [2],
        \\    (1 + 1i) + (1 + 1i)u: [9],
        \\    (1 + 1i) + (0 + 0i)u: [11],
        \\}
    );
    try testing.expectCircuit(&ctx.circuit,
        \\[10] = [8] - [9]
        \\[7] = [5] x [3]
        \\[8] = [6] x [4]
        \\[12] = [10] x [11]
        \\[7] = [9]
        \\[12] = [0]
        \\output [2]
        \\
    );
}

test "simd: assert_bits ignores lanes past len" {
    const cases = [_]struct { [4]u32, bool }{
        .{ .{ 0, 0, 0, 0 }, true },
        .{ .{ 1, 1, 1, 0 }, true },
        .{ .{ 1, 0, 1, 0 }, true },
        .{ .{ 2, 0, 0, 0 }, false },
        .{ .{ 0, 0, 0, 2 }, true },
    };
    for (cases) |case| {
        var ctx = try TraceContext.init(gpa, 0);
        defer ctx.deinit();
        const wire = [1]Var{try ctx.guess(q(case[0][0], case[0][1], case[0][2], case[0][3]))};
        try simd.assertBits(QM31, &ctx, .fromPacked(&wire, 3));
        try std.testing.expectEqual(case[1], try ctx.isCircuitValid());
    }
}

test "simd: guess_lsb" {
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    const a = try simdFromU32s(&ctx, &.{ 7, 1, 4, 6, 11, 8 });
    const b = try simd.guessLsb(QM31, &ctx, a);
    try std.testing.expectEqual(@as(usize, 6), b.len);
    try expectPacked(&ctx, b, &.{ q(1, 1, 0, 0), q(1, 0, 0, 0) });
    try std.testing.expect(try ctx.isCircuitValid());
}

test "simd: select" {
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    const selector = try simdFromU32s(&ctx, &.{ 1, 0, 1 });
    const if_zero = try simdFromU32s(&ctx, &.{ 1, 2, 3 });
    const if_one = try simdFromU32s(&ctx, &.{ 4, 5, 6 });
    const result = try simd.select(QM31, &ctx, selector, if_zero, if_one);
    try std.testing.expectEqual(@as(usize, 3), result.len);
    try expectPacked(&ctx, result, &.{q(4, 2, 6, 0)});
    try std.testing.expect(try ctx.isCircuitValid());
}

test "simd: unpack and unpack_idx" {
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    const input = [_]u32{ 12, 6, 5, 20, 1 };
    const packed_input = try simdFromU32s(&ctx, &input);
    const lanes = try simd.unpack(QM31, &ctx, packed_input);
    try std.testing.expectEqual(@as(usize, 5), lanes.len);
    for (lanes, input) |lane, x| try std.testing.expect(ctx.get(lane).eql(q(x, 0, 0, 0)));
    for (input, 0..) |x, i| try std.testing.expect(ctx.get(try simd.unpackIdx(QM31, &ctx, packed_input, i)).eql(q(x, 0, 0, 0)));
}

test "simd: unpack circuit" {
    var ctx = try context_mod.Context(NoValue).init(gpa, 0);
    defer ctx.deinit();
    const input = Simd.fromPacked(try guessNoValues(&ctx, 2), 6);
    const res = try simd.unpack(NoValue, &ctx, input);
    try testing.expectFormat("Simd { data: [[3], [4]], len: 6 }", input);
    try testing.expectVars("[[5], [9], [12], [16], [17], [19]]", res);
    try testing.expectConstants(NoValue, &ctx,
        \\{
        \\    (0 + 0i) + (0 + 0i)u: [0],
        \\    (1 + 0i) + (0 + 0i)u: [1],
        \\    (0 + 0i) + (1 + 0i)u: [2],
        \\    (0 + 1i) + (0 + 0i)u: [6],
        \\    (0 + 2147483646i) + (0 + 0i)u: [8],
        \\    (0 + 0i) + (1717986918 + 1288490188i)u: [11],
        \\    (0 + 0i) + (0 + 1i)u: [13],
        \\    (0 + 0i) + (1288490188 + 429496729i)u: [15],
        \\}
    );
    try testing.expectCircuit(&ctx.circuit,
        \\[9] = [7] * [8]
        \\[12] = [10] * [11]
        \\[16] = [14] * [15]
        \\[19] = [18] * [8]
        \\[5] = [3] x [1]
        \\[7] = [3] x [6]
        \\[10] = [3] x [2]
        \\[14] = [3] x [13]
        \\[17] = [4] x [1]
        \\[18] = [4] x [6]
        \\output [2]
        \\
    );
}

fn guessM31s(ctx: *TraceContext, values: []const u32) ![]wrappers.M31Wrapper(Var) {
    const out = try ctx.scratch().alloc(wrappers.M31Wrapper(Var), values.len);
    for (out, values) |*w, x| w.* = try wrappers.guessM31(QM31, ctx, wrappers.m31Value(QM31, M31.fromCanonical(x)));
    return out;
}

test "simd: pack" {
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    const input = try guessM31s(&ctx, &.{ 12, 6, 5, 20, 1, 4, 8, 10 });
    try std.testing.expectEqual(@as(usize, 0), (try simd.pack(QM31, &ctx, input[0..0])).len);
    try expectPacked(&ctx, try simd.pack(QM31, &ctx, input[0..1]), &.{q(12, 0, 0, 0)});
    try expectPacked(&ctx, try simd.pack(QM31, &ctx, input[0..2]), &.{q(12, 6, 0, 0)});
    try expectPacked(&ctx, try simd.pack(QM31, &ctx, input[0..3]), &.{q(12, 6, 5, 0)});
    try expectPacked(&ctx, try simd.pack(QM31, &ctx, input[0..4]), &.{q(12, 6, 5, 20)});
    try expectPacked(&ctx, try simd.pack(QM31, &ctx, input[0..5]), &.{ q(12, 6, 5, 20), q(1, 0, 0, 0) });
    try expectPacked(&ctx, try simd.pack(QM31, &ctx, input[0..8]), &.{ q(12, 6, 5, 20), q(1, 4, 8, 10) });
    try std.testing.expect(try ctx.isCircuitValid());
}

test "simd: pack circuit" {
    var ctx = try context_mod.Context(NoValue).init(gpa, 0);
    defer ctx.deinit();
    const guessed = try guessNoValues(&ctx, 6);
    const input = try ctx.scratch().alloc(wrappers.M31Wrapper(Var), 6);
    for (input, guessed) |*w, v| w.* = .newUnsafe(v);
    const res = try simd.pack(NoValue, &ctx, input);
    try testing.expectFormat("Simd { data: [[16], [18]], len: 6 }", res);
    try testing.expectConstants(NoValue, &ctx,
        \\{
        \\    (0 + 0i) + (0 + 0i)u: [0],
        \\    (1 + 0i) + (0 + 0i)u: [1],
        \\    (0 + 0i) + (1 + 0i)u: [2],
        \\    (0 + 1i) + (0 + 0i)u: [9],
        \\    (0 + 0i) + (0 + 1i)u: [10],
        \\}
    );
    try testing.expectCircuit(&ctx.circuit,
        \\[12] = [3] + [11]
        \\[14] = [12] + [13]
        \\[16] = [14] + [15]
        \\[18] = [7] + [17]
        \\[11] = [9] * [4]
        \\[13] = [2] * [5]
        \\[15] = [10] * [6]
        \\[17] = [9] * [8]
        \\output [2]
        \\
    );
}

test "simd: scalar_mul circuit" {
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    const scalar = try wrappers.guessM31(QM31, &ctx, wrappers.m31Value(QM31, M31.fromCanonical(5)));
    const input = try simdFromU32s(&ctx, &.{ 12, 6, 5, 3, 4 });
    const res = try simd.scalarMul(QM31, &ctx, input, scalar);
    try std.testing.expectEqual(@as(usize, 5), res.len);
    try expectPacked(&ctx, res, &.{ q(60, 30, 25, 15), q(20, 0, 0, 0) });
    try testing.expectConstants(QM31, &ctx,
        \\{
        \\    (0 + 0i) + (0 + 0i)u: [0],
        \\    (1 + 0i) + (0 + 0i)u: [1],
        \\    (0 + 0i) + (1 + 0i)u: [2],
        \\}
    );
    try testing.expectCircuit(&ctx.circuit,
        \\[6] = [4] * [3]
        \\[7] = [5] * [3]
        \\output [2]
        \\
    );
}

test "simd: pow2 of extracted bits" {
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    const input = try simdFromU32s(&ctx, &.{ 12, 6, 5, 3, 4 });
    const bits = try extract_bits.extractBits(QM31, &ctx, input, 5);
    const res = try simd.pow2(QM31, &ctx, bits);
    try std.testing.expectEqual(@as(usize, 5), res.len);
    try expectPacked(&ctx, res, &.{ q(1 << 12, 1 << 6, 1 << 5, 1 << 3), q(1 << 4, 1, 1, 1) });
}

test "simd: combine_bits inverts extract_bits" {
    var ctx = try TraceContext.init(gpa, 0);
    defer ctx.deinit();
    const input = try simdFromU32s(&ctx, &.{ 12, 6, 5, 3, 4 });
    const bits = try extract_bits.extractBits(QM31, &ctx, input, 5);
    const res = try simd.combineBits(QM31, &ctx, bits);
    for (input.data, res.data) |a, b| try std.testing.expect(ctx.get(a).eql(ctx.get(b)));
}

test "simd: mark_partly_used exempts every wire from the use check" {
    for ([_]bool{ false, true }) |mark| {
        var ctx = try TraceContext.init(gpa, 0);
        defer ctx.deinit();
        const a = try simdFromU32s(&ctx, &.{ 1, 2, 3, 4, 5 });
        if (mark) {
            try simd.markPartlyUsed(QM31, &ctx, a);
            try ctx.finalize(true);
        } else {
            try std.testing.expectError(error.UnusedVarNotMarked, ctx.finalize(true));
        }
    }
}
