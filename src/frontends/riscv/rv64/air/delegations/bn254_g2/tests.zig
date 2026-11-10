const std = @import("std");
const S = @import("spec.zig");
const W = @import("witness.zig");
const P = S.B.BN254_P;
fn plus(a: u256, b: u256) u256 {
    return @intCast((@as(S.B.Big, a) + b) % P);
}
fn minus(a: u256, b: u256) u256 {
    return @intCast((@as(S.B.Big, a) + P - b) % P);
}
fn times(a: u256, b: u256) u256 {
    return @intCast(@as(S.B.Big, a) * b % P);
}
fn add(a: S.FQ2, b: S.FQ2) S.FQ2 {
    return .{ plus(a[0], b[0]), plus(a[1], b[1]) };
}
fn sub(a: S.FQ2, b: S.FQ2) S.FQ2 {
    return .{ minus(a[0], b[0]), minus(a[1], b[1]) };
}
fn mul(a: S.FQ2, b: S.FQ2) S.FQ2 {
    return .{ minus(times(a[0], b[0]), times(a[1], b[1])), plus(times(a[0], b[1]), times(a[1], b[0])) };
}
fn scale(a: S.FQ2, k: u256) S.FQ2 {
    return .{ times(a[0], k), times(a[1], k) };
}
const Result = struct { point: S.Point, line: [3]S.FQ2 };
fn referenceDouble(point: S.Point) Result {
    const x = point[0];
    const y = point[1];
    const z = point[2];
    const a = scale(mul(x, y), (P + 1) / 2);
    const b = mul(y, y);
    const c = mul(z, z);
    const e = scale(mul(S.TWIST_B, c), 3);
    const g = scale(add(b, scale(e, 3)), (P + 1) / 2);
    const h = scale(mul(y, z), 2);
    const j = mul(x, x);
    return .{ .point = .{ mul(a, sub(b, scale(e, 3))), sub(mul(g, g), scale(mul(e, e), 3)), mul(b, h) }, .line = .{ sub(.{ 0, 0 }, h), scale(j, 3), sub(e, b) } };
}
fn referenceAdd(point: S.Point, q: [2]S.FQ2) Result {
    const x = point[0];
    const y = point[1];
    const z = point[2];
    const theta = sub(y, mul(q[1], z));
    const lambda = sub(x, mul(q[0], z));
    const c = mul(theta, theta);
    const d = mul(lambda, lambda);
    const e = mul(lambda, d);
    const f = mul(z, c);
    const g = mul(x, d);
    const h = sub(add(e, f), scale(g, 2));
    return .{ .point = .{ mul(lambda, h), sub(mul(theta, sub(g, h)), mul(e, y)), mul(z, e) }, .line = .{ lambda, sub(.{ 0, 0 }, theta), sub(mul(theta, q[0]), mul(lambda, q[1])) } };
}
test "G2 quadratic source program exact homogeneous point and line canonical witnesses" {
    @setEvalBranchQuota(2_000_000);
    inline for (.{ S.Kind.doubling, S.Kind.addition }) |kind| {
        const program = comptime S.program(kind);
        const L = W.Layout(kind);
        try std.testing.expectEqual(S.rows(kind), program.count);
        try std.testing.expectEqual(@as(usize, 33), L.G.q_bytes);
        try std.testing.expectEqual(@as(u32, 17), L.G.carry_bits);
        try std.testing.expectEqual(@as(u64, 67424), L.G.carry_offset);
        try std.testing.expectEqual(@as(u64, if (kind == .doubling) 29809248 else 29809262), L.G.residual_positive_bound);
        try std.testing.expectEqual(@as(u64, if (kind == .doubling) 29809756 else 29809501), L.G.residual_negative_bound);
        try std.testing.expectEqual(@as(usize, if (kind == .doubling) 498 else 626), L.MAIN);
        try std.testing.expect(L.G.residual_positive_bound < S.B.M31 and L.G.residual_negative_bound < S.B.M31);
        const fanout = comptime S.fanout(kind);
        var reads: u32 = 12; // six point and six canonical line-preimage exports
        inline for (0..comptime S.rows(kind)) |step| {
            const writer = program.operations[step].writer;
            try std.testing.expectEqual(@as(u8, @intCast(S.initialCount(kind) + step)), writer);
            for (comptime S.operandIds(kind, step)) |id| if (id != S.UNUSED) {
                try std.testing.expect(id < writer);
                reads += 1;
            };
        }
        var writes: u32 = 0;
        for (fanout) |count| writes += count;
        try std.testing.expectEqual(reads, writes);
        for (0..20) |seed| {
            var point: S.Point = undefined;
            var q: [2]S.FQ2 = undefined;
            for (&point, 0..) |*pair, i| for (pair, 0..) |*value, j| {
                value.* = if (seed == 0) 0 else if (seed == 1) P - 1 else @as(u256, seed + 3) * (i * 31 + j * 17 + 19);
            };
            for (&q, 0..) |*pair, i| for (pair, 0..) |*value, j| {
                value.* = if (seed == 2) P - 1 else @as(u256, seed + 29) * (i * 13 + j * 7 + 11);
            };
            const witness = try W.Witness(kind).init(point, q);
            const expected = if (kind == .doubling) referenceDouble(point) else referenceAdd(point, q);
            try std.testing.expectEqual(expected.point, witness.point());
            try std.testing.expectEqual(expected.line, witness.line());
            inline for (0..comptime S.rows(kind)) |step| {
                const row = witness.arithmetic[step];
                try std.testing.expect(L.valid(step, &row));
                var forged = row;
                forged[L.OUTPUT] ^= 1;
                try std.testing.expect(!L.valid(step, &forged));
                forged = row;
                forged[L.QUOTIENT] ^= 1;
                try std.testing.expect(!L.valid(step, &forged));
                forged = row;
                forged[L.CARRY] ^= 1;
                try std.testing.expect(!L.valid(step, &forged));
            }
        }
    }
}
test "G2 canonical congruent writer mutation and source-owned constant policy" {
    inline for (.{ S.Kind.doubling, S.Kind.addition }) |kind| {
        const witness = try W.Witness(kind).init(.{ .{ 1, 2 }, .{ 3, 4 }, .{ 5, 6 } }, .{ .{ 7, 8 }, .{ 9, 10 } });
        const L = W.Layout(kind);
        inline for (0..comptime S.rows(kind)) |step| {
            const operands = witness.operands(step);
            const forged = L.congruentForgeryForTesting(step, &operands);
            try std.testing.expect(L.rangeValid(&forged));
            try std.testing.expect(L.carriedValid(step, &forged));
            try std.testing.expect(!L.valid(step, &forged));
        }
        try std.testing.expectError(error.NonCanonicalG2FixtureInput, W.Witness(kind).init(.{ .{ P, 0 }, .{ 1, 0 }, .{ 1, 0 } }, .{ .{ 1, 0 }, .{ 1, 0 } }));
    }
}

test "G2 quadratic transition matches pinned existing oracle generator and homogeneous cases" {
    inline for (@import("vectors.zig").DATA) |v| {
        const witness = try W.Witness(v.kind).init(v.input, v.q);
        try std.testing.expectEqual(v.point, witness.point());
        try std.testing.expectEqual(v.line, witness.line());
    }
}
