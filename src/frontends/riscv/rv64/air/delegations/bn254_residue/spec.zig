//! Fixed positive-residue certificate z*c*seed^L=ONE in canonical BN254 Fq12.
//! Tower order: i²=-1,v³=9+i,w²=v, index=i+2*v+6*w. Fp6 is coords0..5.
//! Scale upper coords alias a source-owned ZERO writer, not free hint fields.
const std = @import("std");
pub const Dense = @import("../bn254_dense/spec.zig");
pub const B = Dense.B;
pub const Frobenius = @import("frobenius.zig");
pub const Kind = enum { square, multiply, frobenius };
pub const X: u128 = 4965661367192848881;
pub const K: u128 = 6 * X + 2;
pub const R: u256 = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
const P_WIDE: u1024 = B.BN254_P;
pub const LAMBDA: u1024 = P_WIDE * P_WIDE * P_WIDE - P_WIDE * P_WIDE + P_WIDE + K;
pub const SQUARES = 64;
pub const MULTIPLIES: usize = (@as(usize, @popCount(K)) - 1) + 1 + 5;
pub const FROBENIUS_CALLS = 3;
pub const OPS = SQUARES + MULTIPLIES + FROBENIUS_CALLS;
pub const SQUARE_ROWS = SQUARES * 12;
pub const MULTIPLY_ROWS = MULTIPLIES * 12;
pub const FROBENIUS_ROWS = 36;
pub const INITIAL = 12 + Frobenius.POOL.len;
pub const PRIVATE_HINTS = 30; // seed12, c_low6, inverse(seed^p²)12
pub const VALUES = INITIAL + PRIVATE_HINTS + SQUARE_ROWS + MULTIPLY_ROWS + FROBENIUS_ROWS;
pub const ID = u16;
pub const UNUSED = std.math.maxInt(ID);
pub const Vector = [12]ID;
pub const ZERO: ID = 12;
pub const ONE: ID = 13;
comptime {
    if (std.math.log2_int(u128, K) + 1 != 65 or MULTIPLIES != 42 or LAMBDA % R != 0) @compileError("residue exponent authority drift");
    const p: u4096 = B.BN254_P;
    const p2 = p * p;
    const p6 = p2 * p2 * p2;
    if (((p6 * p6 - 1) / R) % (p6 - 1) != 0) @compileError("Fp6 must vanish under the final exponent");
    if (Frobenius.POOL[0] != 0 or Frobenius.POOL[1] != 1) @compileError("literal ZERO/ONE authority drift");
}
pub fn inputs(kind: Kind) usize {
    return switch (kind) {
        .square => 12,
        .multiply => 24,
        .frobenius => 4,
    };
}
pub fn rows(kind: Kind) usize {
    return if (kind == .frobenius) 36 else 12;
}
pub fn terms(comptime kind: Kind, comptime coordinate: usize) []const B.Term {
    if (kind == .square) return Dense.terms(.square, coordinate);
    if (kind == .multiply) return Dense.terms(.multiply, coordinate);
    const result = comptime blk: {
        if (coordinate >= 36) @compileError("Frobenius coordinate out of source range");
        const power = coordinate / 12 + 1;
        const imaginary = coordinate % 2 == 1;
        const conjugate = power % 2 == 1;
        break :blk [_]B.Term{
            .{ .a = .{ .in = 0 }, .b = .{ .in = if (imaginary) 3 else 2 }, .coef = 1 },
            .{ .a = .{ .in = 1 }, .b = .{ .in = if (imaginary) 2 else 3 }, .coef = if (imaginary == conjugate) -1 else 1 },
            .{ .a = .{ .out = 0 }, .coef = -1 },
        };
    };
    return &result;
}
pub fn commonGeometry(comptime kind: Kind) B.RelationGeometry {
    if (kind == .square) return Dense.commonGeometry(.square);
    if (kind == .multiply) return Dense.commonGeometry(.multiply);
    const relation = &[_]B.Term{ .{ .a = .{ .in = 0 }, .b = .{ .in = 1 }, .coef = 6 }, .{ .a = .{ .in = 2 }, .b = .{ .in = 3 }, .coef = -6 }, .{ .a = .{ .out = 0 }, .coef = -1 } };
    const d = B.Def{ .limbs = 32, .coords = 4, .written = 1, .inputs = 4, .outputs = 1, .witnesses = 0, .modulus = .{ .constant = B.BN254_P }, .asymmetric_carries = true, .relations = &.{relation} };
    // Conservative6/6 bounds deliberately retain the qualified byte-carry
    // interpreter. The actual Frobenius products have masses at most2/1.
    const geometry = B.deriveRelation(d, relation);
    if (geometry.group != 1) @compileError("residue source requires byte carry groups");
    return geometry;
}
pub const Node = struct { writer: ID, input: [24]ID, opcode: u8, pin_one: bool };
pub const Operation = struct { kind: Kind, row_start: usize, frobenius_power: u8 = 0, output: Vector };
pub const Program = struct {
    squares: [SQUARE_ROWS]Node = undefined,
    multiplies: [MULTIPLY_ROWS]Node = undefined,
    frobenius: [FROBENIUS_ROWS]Node = undefined,
    operations: [OPS]Operation = undefined,
    square_count: usize = 0,
    multiply_count: usize = 0,
    frobenius_count: usize = 0,
    operation_count: usize = 0,
    next: ID = INITIAL + PRIVATE_HINTS,
    seed: Vector = undefined,
    scale: Vector = undefined,
    inverse2: Vector = undefined,
    seed1: Vector = undefined,
    seed2: Vector = undefined,
    seed3: Vector = undefined,
    inverse_check: Vector = undefined,
    scaled: Vector = undefined,
    final: Vector = undefined,
    fn append(self: *Program, comptime kind: Kind, left: Vector, right: Vector, power: u8, pin_one: bool) Vector {
        var out: Vector = undefined;
        const first = self.next;
        const row_start = switch (kind) {
            .square => self.square_count,
            .multiply => self.multiply_count,
            .frobenius => self.frobenius_count,
        };
        for (0..12) |coordinate| {
            const opcode = if (kind == .frobenius) 12 * (@as(usize, power) - 1) + coordinate else coordinate;
            var node = Node{ .writer = @intCast(first + coordinate), .input = @splat(UNUSED), .opcode = @intCast(opcode), .pin_one = pin_one };
            if (kind == .frobenius) {
                const pair = coordinate / 2;
                node.input[0] = left[2 * pair];
                node.input[1] = left[2 * pair + 1];
                node.input[2] = 12 + Frobenius.INDICES[power - 1][pair][0];
                node.input[3] = 12 + Frobenius.INDICES[power - 1][pair][1];
            } else {
                @memcpy(node.input[0..12], &left);
                if (kind == .multiply) @memcpy(node.input[12..24], &right);
            }
            switch (kind) {
                .square => {
                    self.squares[self.square_count] = node;
                    self.square_count += 1;
                },
                .multiply => {
                    self.multiplies[self.multiply_count] = node;
                    self.multiply_count += 1;
                },
                .frobenius => {
                    self.frobenius[self.frobenius_count] = node;
                    self.frobenius_count += 1;
                },
            }
            out[coordinate] = node.writer;
        }
        self.next += 12;
        self.operations[self.operation_count] = .{ .kind = kind, .row_start = row_start, .frobenius_power = power, .output = out };
        self.operation_count += 1;
        return out;
    }
};
fn vector(first: ID) Vector {
    var out: Vector = undefined;
    for (&out, 0..) |*id, i| id.* = @intCast(first + i);
    return out;
}
pub fn program() Program {
    @setEvalBranchQuota(5_000_000);
    var p = Program{};
    p.seed = vector(INITIAL);
    p.scale = @splat(ZERO);
    @memcpy(p.scale[0..6], &vector(INITIAL + 12)[0..6].*);
    p.inverse2 = vector(INITIAL + 18);
    const z = vector(0);
    p.seed1 = p.append(.frobenius, p.seed, @splat(UNUSED), 1, false);
    p.seed2 = p.append(.frobenius, p.seed, @splat(UNUSED), 2, false);
    p.seed3 = p.append(.frobenius, p.seed, @splat(UNUSED), 3, false);
    p.inverse_check = p.append(.multiply, p.seed2, p.inverse2, 0, true);
    var power = p.seed;
    for (0..64) |i| {
        power = p.append(.square, power, @splat(UNUSED), 0, false);
        if (((K >> @intCast(63 - i)) & 1) != 0) power = p.append(.multiply, power, p.seed, 0, false);
    }
    power = p.append(.multiply, power, p.seed1, 0, false);
    power = p.append(.multiply, power, p.inverse2, 0, false);
    power = p.append(.multiply, power, p.seed3, 0, false);
    const scaled = p.append(.multiply, z, p.scale, 0, false);
    p.scaled = scaled;
    p.final = p.append(.multiply, scaled, power, 0, true);
    std.debug.assert(p.square_count == SQUARE_ROWS and p.multiply_count == MULTIPLY_ROWS and p.frobenius_count == FROBENIUS_ROWS and p.operation_count == OPS and p.next == VALUES);
    return p;
}
pub fn fanout(p: *const Program) [VALUES]u32 {
    @setEvalBranchQuota(100_000);
    var out: [VALUES]u32 = @splat(0);
    for (p.squares) |node| for (node.input[0..12]) |id| {
        out[id] += 1;
    };
    for (p.multiplies) |node| for (node.input) |id| {
        out[id] += 1;
    };
    for (p.frobenius) |node| for (node.input[0..4]) |id| {
        out[id] += 1;
    };
    return out;
}
