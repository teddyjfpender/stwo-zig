const std = @import("std");
const S = @import("spec.zig");
const R = @import("row.zig");
const F = u256;
const P = S.B.BN254_P;
const F2 = [2]F;
const F6 = [3]F2;
const F12 = [2]F6;
fn add(a: F, b: F) F {
    return @intCast((@as(S.B.Big, a) + b) % P);
}
fn sub(a: F, b: F) F {
    return @intCast((@as(S.B.Big, a) + P - b) % P);
}
fn mul(a: F, b: F) F {
    return @intCast((@as(S.B.Big, a) * b) % P);
}
fn a2(a: F2, b: F2) F2 {
    return .{ add(a[0], b[0]), add(a[1], b[1]) };
}
fn m2(a: F2, b: F2) F2 {
    return .{ sub(mul(a[0], b[0]), mul(a[1], b[1])), add(mul(a[0], b[1]), mul(a[1], b[0])) };
}
fn nr(a: F2) F2 {
    return m2(a, .{ 9, 1 });
}
fn a6(a: F6, b: F6) F6 {
    return .{ a2(a[0], b[0]), a2(a[1], b[1]), a2(a[2], b[2]) };
}
fn m6(a: F6, b: F6) F6 {
    var c: [5]F2 = @splat(.{ 0, 0 });
    for (0..3) |i| for (0..3) |j| {
        c[i + j] = a2(c[i + j], m2(a[i], b[j]));
    };
    return .{ a2(c[0], nr(c[3])), a2(c[1], nr(c[4])), c[2] };
}
fn v6(a: F6) F6 {
    return .{ nr(a[2]), a[0], a[1] };
}
fn m12(a: F12, b: F12) F12 {
    return .{ a6(m6(a[0], b[0]), v6(m6(a[1], b[1]))), a6(m6(a[0], b[1]), m6(a[1], b[0])) };
}
fn unflat(a: *const [12]F) F12 {
    var r: F12 = undefined;
    for (0..12) |i| r[i / 6][(i / 2) % 3][i % 2] = a[i] % P;
    return r;
}
fn flat(a: F12) [12]F {
    var r: [12]F = undefined;
    for (0..12) |i| r[i] = a[i / 6][(i / 2) % 3][i % 2];
    return r;
}
test "direct dense source coefficients canonical witness and coherent forgeries" {
    inline for (.{ S.Kind.square, S.Kind.multiply }) |kind| {
        const L = R.Layout(kind);
        try std.testing.expect(L.G.group == 1 and L.G.residual_positive_bound < P and L.G.residual_positive_bound < S.B.M31 and L.G.residual_negative_bound < S.B.M31);
        for (0..16) |seed| {
            var a: [12]F = undefined;
            var b: [12]F = undefined;
            for (0..12) |i| {
                a[i] = if (seed == 0) 0 else if (seed == 1) P - 1 else if (seed == 2) std.math.maxInt(F) else @as(F, seed + 1) * 0x123456789abcdef + i;
                b[i] = if (seed == 0) P - 1 else if (seed == 1) std.math.maxInt(F) else @as(F, seed + 19) * 0x987654321 + i;
            }
            var input: [S.inputs(kind)]F = undefined;
            @memcpy(input[0..12], &a);
            if (kind == .multiply) @memcpy(input[12..24], &b);
            const independent = flat(m12(unflat(&a), if (kind == .square) unflat(&a) else unflat(&b)));
            inline for (0..12) |coordinate| {
                const row = L.fill(coordinate, &input);
                try std.testing.expect(L.valid(coordinate, &row));
                try std.testing.expectEqual(independent[coordinate], @as(F, @intCast(L.read(&row, L.OUTPUT, 32))));
                var forged = row;
                forged[L.OUTPUT] ^= 1;
                try std.testing.expect(!L.valid(coordinate, &forged));
                forged = row;
                forged[L.QUOTIENT] ^= 1;
                try std.testing.expect(!L.valid(coordinate, &forged));
                forged = row;
                forged[L.CARRY] ^= 1;
                try std.testing.expect(!L.valid(coordinate, &forged));
                forged = row;
                forged[L.BORROW] ^= 1;
                try std.testing.expect(!L.valid(coordinate, &forged));
                forged = row;
                forged[L.ACTIVE] = 0;
                try std.testing.expect(!L.valid(coordinate, &forged));
                const padding: L.Row = @splat(0);
                try std.testing.expect(L.valid(coordinate, &padding));
            }
        }
    }
}

test "all dense basis monomials and common source carry envelope" {
    inline for (.{ S.Kind.square, S.Kind.multiply }) |kind| {
        const L = R.Layout(kind);
        try std.testing.expectEqual(@as(usize, 34), L.G.q_bytes);
        try std.testing.expectEqual(@as(u32, 21), L.G.carry_bits);
        for (0..12) |x| for (0..12) |y| {
            var a: [12]F = @splat(0);
            var b: [12]F = @splat(0);
            a[x] = 1;
            b[y] = 1;
            if (kind == .square) a[y] = add(a[y], 1);
            var input: [S.inputs(kind)]F = undefined;
            @memcpy(input[0..12], &a);
            if (kind == .multiply) @memcpy(input[12..24], &b);
            const want = flat(m12(unflat(&a), if (kind == .square) unflat(&a) else unflat(&b)));
            inline for (0..12) |out| {
                const row = L.fill(out, &input);
                try std.testing.expect(L.valid(out, &row));
                try std.testing.expectEqual(want[out], @as(F, @intCast(L.read(&row, L.OUTPUT, 32))));
            }
        };
    }
}
