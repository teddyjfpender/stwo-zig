//! Isolated source-cost authority for direct dense tower polynomials.
//! No opcode, execution profile or production admission is defined here.
const std = @import("std");
pub const B = @import("../curves/spec.zig");
pub const Kind = enum { square, multiply };
pub const OUTPUTS = 12;
pub fn inputs(comptime kind: Kind) usize {
    return if (kind == .square) 12 else 24;
}
/// Exact basis reduction in i²=-1, v³=9+i, w²=v.
pub fn basis(x: usize, y: usize) [OUTPUTS]i32 {
    std.debug.assert(x < 12 and y < 12);
    var out: [OUTPUTS]i32 = @splat(0);
    const imaginary = x % 2 + y % 2;
    var v = (x / 2) % 3 + (y / 2) % 3;
    const w = x / 6 + y / 6;
    v += w / 2;
    const reduced_v = v % 3;
    const index = imaginary % 2 + 2 * reduced_v + 6 * (w % 2);
    const sign: i32 = if ((imaginary / 2) % 2 == 0) 1 else -1;
    if (v < 3) {
        out[index] += sign;
    } else {
        out[index] += 9 * sign;
        const shifted = imaginary + 1;
        out[shifted % 2 + 2 * reduced_v + 6 * (w % 2)] += if ((shifted / 2) % 2 == 0) @as(i32, 1) else -1;
    }
    return out;
}
pub fn terms(comptime kind: Kind, comptime coordinate: usize) []const B.Term {
    @setEvalBranchQuota(1_000_000);
    if (coordinate >= 12) @compileError("dense output coordinate");
    const result = comptime blk: {
        var coefficients: [24][24]i32 = @splat(@splat(0));
        for (0..12) |x| for (0..12) |y| {
            const c = basis(x, y)[coordinate];
            const a = if (kind == .square) @min(x, y) else x;
            const b = if (kind == .square) @max(x, y) else 12 + y;
            coefficients[a][b] += c;
        };
        var list: [145]B.Term = undefined;
        var n: usize = 0;
        for (0..24) |a| for (0..24) |b| {
            if (coefficients[a][b] != 0) {
                list[n] = .{ .a = .{ .in = @intCast(a) }, .b = .{ .in = @intCast(b) }, .coef = coefficients[a][b] };
                n += 1;
            }
        };
        list[n] = .{ .a = .{ .out = 0 }, .coef = -1 };
        n += 1;
        break :blk list[0..n].*;
    };
    return &result;
}
pub fn definition(comptime kind: Kind, comptime coordinate: usize) B.Def {
    return .{ .limbs = 32, .coords = inputs(kind), .written = 1, .inputs = inputs(kind), .outputs = 1, .witnesses = 0, .modulus = .{ .constant = B.BN254_P }, .relations = &.{terms(kind, coordinate)}, .asymmetric_carries = true };
}
pub fn geometry(comptime kind: Kind, comptime coordinate: usize) B.RelationGeometry {
    return B.deriveRelation(definition(kind, coordinate), terms(kind, coordinate));
}
pub const RowCost = struct { main: usize, byte_queries: usize, carry_groups: usize, carry_bits: u32, carry_bytes: usize, quotient_bytes: usize, terms: usize, residual_positive: u64, residual_negative: u64 };
pub fn rowCost(comptime kind: Kind, comptime coordinate: usize) RowCost {
    const g = comptime geometry(kind, coordinate);
    // Inputs inherit BYTE range through the authenticated frontier/local SSA;
    // outputs must have their own range and strict <p certificate.
    return .{ .main = 1 + 32 * inputs(kind) + 32 + g.q_bytes + g.carries * g.carry_bytes + 32 + 15 + 1, .byte_queries = 32 + g.q_bytes + g.carries * g.carry_bytes + (if (g.top_bits < 8) g.carries else 0) + 32, .carry_groups = g.groups, .carry_bits = g.carry_bits, .carry_bytes = g.carry_bytes, .quotient_bytes = g.q_bytes, .terms = terms(kind, coordinate).len - 1, .residual_positive = g.residual_positive_bound, .residual_negative = g.residual_negative_bound };
}
/// One source-owned envelope for all twelve coordinate rows. Coefficient-wise
/// bounds depend on absolute positive/negative coefficient mass; all products
/// have identical byte-vector widths. The same K*p, quotient/carry range and
/// offset must be used in every coordinate, never producer-selected.
pub fn envelope(comptime kind: Kind) B.Def {
    const masses = comptime blk: {
        var positive: i32 = 0;
        var negative: i32 = 0;
        for (0..12) |coordinate| {
            var p: i32 = 0;
            var n: i32 = 0;
            for (terms(kind, coordinate)) |term| if (term.b != null) {
                if (term.coef > 0) p += term.coef else n -= term.coef;
            };
            positive = @max(positive, p);
            negative = @max(negative, n);
        }
        break :blk .{ positive, negative };
    };
    return .{ .limbs = 32, .coords = inputs(kind), .written = 1, .inputs = inputs(kind), .outputs = 1, .witnesses = 0, .modulus = .{ .constant = B.BN254_P }, .asymmetric_carries = true, .relations = &.{&.{
        .{ .a = .{ .in = 0 }, .b = .{ .in = 1 }, .coef = masses[0] },
        .{ .a = .{ .in = 2 }, .b = .{ .in = 3 }, .coef = -masses[1] },
        .{ .a = .{ .out = 0 }, .coef = -1 },
    }} };
}
pub fn commonGeometry(comptime kind: Kind) B.RelationGeometry {
    const d = envelope(kind);
    return B.deriveRelation(d, d.relations[0]);
}
