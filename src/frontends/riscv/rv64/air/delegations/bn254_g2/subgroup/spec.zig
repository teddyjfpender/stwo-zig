//! Immutable conditional affine [r-1]Q=-Q program. Source only; no VM/AIR admission.
const std = @import("std");
pub const B = @import("../../curves/spec.zig");
pub const G2 = @import("../spec.zig");
pub const R: u256 = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
pub const SCALAR = R - 1;
pub const SSA_NAMESPACE: u32 = 0x47325347; // source-only; no global/VM tag
pub const INITIAL = 7; // Qx.re/im,Qy.re/im,twistB.re/im,one
pub const MAX_NODES = 4400;
pub const MAX_ASSERTIONS = 360;
pub const ID = u16;
pub const NONE = std.math.maxInt(ID);
pub const Kind = enum { quadratic };
pub const Op = enum(u8) {
    mul_real,
    mul_imag,
    norm_double,
    norm_difference,
    inverse_check,
    inverse_double_real,
    inverse_double_imag,
    inverse_difference_real,
    inverse_difference_imag,
    lambda_double_real,
    lambda_double_imag,
    lambda_add_real,
    lambda_add_imag,
    x_double_real,
    x_double_imag,
    x_add_real,
    x_add_imag,
    y_real,
    y_imag,
    residual,
    difference,
    sum,
    /// Free canonical scalar writer, NOT a trusted inverse. norm*t-1 is a
    /// separate immutable arithmetic writer bound to a literal-zero assertion.
    hint_norm_inverse,
};
pub const OPCODES = @intFromEnum(Op.hint_norm_inverse);
pub fn inputs(_: Kind) usize {
    return 7;
}
pub fn rows(_: Kind) usize {
    return OPCODES;
}
fn linear(a: u8, c: i32) B.Term {
    return .{ .a = .{ .in = a }, .coef = c };
}
fn product(a: u8, b: u8, c: i32) B.Term {
    return .{ .a = .{ .in = a }, .b = .{ .in = b }, .coef = c };
}
pub fn terms(comptime _: Kind, comptime opcode: usize) []const B.Term {
    const expression = comptime switch (@as(Op, @enumFromInt(opcode))) {
        .mul_real => &[_]B.Term{ product(0, 1, 1), product(2, 3, -1) },
        .mul_imag => &[_]B.Term{ product(0, 1, 1), product(2, 3, 1) },
        .norm_double => &[_]B.Term{ product(0, 0, 4), product(1, 1, 4) },
        .norm_difference => &[_]B.Term{ product(0, 0, 1), product(1, 1, 1), product(0, 1, -2), product(2, 2, 1), product(3, 3, 1), product(2, 3, -2) },
        .inverse_check => &[_]B.Term{ product(0, 1, 1), linear(2, -1) },
        .inverse_double_real => &[_]B.Term{product(0, 1, 2)},
        .inverse_double_imag => &[_]B.Term{product(0, 1, -2)},
        .inverse_difference_real => &[_]B.Term{ product(0, 2, 1), product(1, 2, -1) },
        .inverse_difference_imag => &[_]B.Term{ product(0, 2, -1), product(1, 2, 1) },
        .lambda_double_real => &[_]B.Term{ product(0, 1, 3), product(2, 3, -3) },
        .lambda_double_imag => &[_]B.Term{ product(0, 1, 3), product(2, 3, 3) },
        .lambda_add_real => &[_]B.Term{ product(0, 2, 1), product(1, 2, -1), product(3, 5, -1), product(4, 5, 1) },
        .lambda_add_imag => &[_]B.Term{ product(0, 2, 1), product(1, 2, -1), product(3, 5, 1), product(4, 5, -1) },
        .x_double_real => &[_]B.Term{ product(0, 0, 1), product(1, 1, -1), linear(2, -2) },
        .x_double_imag => &[_]B.Term{ product(0, 1, 2), linear(2, -2) },
        .x_add_real => &[_]B.Term{ product(0, 0, 1), product(1, 1, -1), linear(2, -1), linear(3, -1) },
        .x_add_imag => &[_]B.Term{ product(0, 1, 2), linear(2, -1), linear(3, -1) },
        .y_real => &[_]B.Term{ product(0, 1, 1), product(0, 2, -1), product(3, 4, -1), product(3, 5, 1), linear(6, -1) },
        .y_imag => &[_]B.Term{ product(0, 1, 1), product(0, 2, -1), product(3, 4, 1), product(3, 5, -1), linear(6, -1) },
        .residual => &[_]B.Term{ linear(0, 1), linear(1, -1), linear(2, -1) },
        .difference => &[_]B.Term{ linear(0, 1), linear(1, -1) },
        .sum => &[_]B.Term{ linear(0, 1), linear(1, 1) },
        .hint_norm_inverse => @compileError("free hints need their own canonical writer authority, not arithmetic terms"),
    };
    const result = comptime expression.* ++ [_]B.Term{.{ .a = .{ .out = 0 }, .coef = -1 }};
    return &result;
}
pub fn arity(op: Op) usize {
    return switch (op) {
        .mul_real, .mul_imag, .lambda_double_real, .lambda_double_imag, .norm_difference, .x_add_real, .x_add_imag => 4,
        .norm_double, .inverse_double_real, .inverse_double_imag, .difference, .sum => 2,
        .inverse_check, .inverse_difference_real, .inverse_difference_imag, .x_double_real, .x_double_imag, .residual => 3,
        .lambda_add_real, .lambda_add_imag => 6,
        .y_real, .y_imag => 7,
        .hint_norm_inverse => 0, // denominator metadata is not an SSA read
    };
}
pub fn envelope(_: Kind) B.Def {
    const mass = comptime blk: {
        var maximum: [4]i32 = @splat(0);
        for (0..OPCODES) |op| {
            var current: [4]i32 = @splat(0);
            for (terms(.quadratic, op)) |t| current[(if (t.b != null) @as(usize, 0) else 2) + @as(usize, @intFromBool(t.coef < 0))] += @intCast(@abs(t.coef));
            for (&maximum, current) |*a, b| a.* = @max(a.*, b);
        }
        break :blk maximum;
    };
    const relation = &[_]B.Term{ product(0, 1, mass[0]), product(2, 3, -mass[1]), linear(4, mass[2]), .{ .a = .{ .out = 0 }, .coef = -mass[3] } };
    return .{ .limbs = 32, .coords = 7, .written = 1, .inputs = 7, .outputs = 1, .witnesses = 0, .modulus = .{ .constant = B.BN254_P }, .asymmetric_carries = true, .relations = &.{relation} };
}
pub fn commonGeometry(kind: Kind) B.RelationGeometry {
    const def = envelope(kind);
    return B.deriveRelation(def, def.relations[0]);
}
/// Mandatory future physical canonical-free-writer contract. No input read
/// authority is claimed by a hint. Its output alone enters the SSA writer bus.
pub const CanonicalHint = struct {
    pub const output_bytes = 32;
    pub const distance_bytes = 32;
    pub const borrow_bits = 15;
    pub const modulus = B.BN254_P;
    pub const ssa_reads = 0;
    pub const ssa_writers = 1;
    // Native/AIR gate must enforce each byte in BYTE, Boolean borrow bits,
    // output+distance+1=modulus and source-fixed active/writer/fanout.
};
pub const HintObligation = struct { writer: ID, denominator: ID, zero_residual: ID };
pub const Node = struct { op: Op, writer: ID, input: [7]ID };
pub const Point = [2][2]ID;
pub const Program = struct {
    nodes: [MAX_NODES]Node = undefined,
    count: usize = 0,
    assertions: [MAX_ASSERTIONS]ID = undefined,
    assertion_count: usize = 0,
    hints: usize = 0,
    doubles: usize = 0,
    additions: usize = 0,
    final_point: Point = undefined,
    pub fn hintObligation(p: *const Program, index: usize) !HintObligation {
        if (index + 1 >= p.count or p.nodes[index].op != .hint_norm_inverse) return error.SubgroupHintSource;
        const hint = p.nodes[index];
        const check = p.nodes[index + 1];
        if (check.op != .inverse_check or check.input[0] != hint.input[0] or check.input[1] != hint.writer or check.input[2] != 6 or std.mem.indexOfScalar(ID, p.assertions[0..p.assertion_count], check.writer) == null) return error.SubgroupHintSource;
        return .{ .writer = hint.writer, .denominator = hint.input[0], .zero_residual = check.writer };
    }
    fn write(p: *Program, op: Op, input: []const ID) ID {
        std.debug.assert(p.count < MAX_NODES and input.len == (if (op == .hint_norm_inverse) @as(usize, 1) else arity(op)));
        const id: ID = @intCast(INITIAL + p.count);
        var node = Node{ .op = op, .writer = id, .input = @splat(NONE) };
        for (input, 0..) |value, i| {
            std.debug.assert(value < id);
            node.input[i] = value;
        }
        p.nodes[p.count] = node;
        p.count += 1;
        if (op == .hint_norm_inverse) p.hints += 1;
        return id;
    }
    fn zero(p: *Program, id: ID) void {
        std.debug.assert(p.assertion_count < MAX_ASSERTIONS);
        p.assertions[p.assertion_count] = id;
        p.assertion_count += 1;
    }
    fn mul(p: *Program, a: [2]ID, b: [2]ID) [2]ID {
        return .{ p.write(.mul_real, &.{ a[0], b[0], a[1], b[1] }), p.write(.mul_imag, &.{ a[0], b[1], a[1], b[0] }) };
    }
    fn inverseHint(p: *Program, norm: ID) ID {
        const hint = p.write(.hint_norm_inverse, &.{norm});
        p.zero(p.write(.inverse_check, &.{ norm, hint, 6 }));
        return hint;
    }
    fn transition(p: *Program, point: Point, comptime double: bool) Point {
        const x = point[0];
        const y = point[1];
        var lambda: [2]ID = undefined;
        if (double) {
            p.doubles += 1;
            const xx = p.mul(x, x);
            const norm = p.write(.norm_double, &.{ y[0], y[1] });
            const t = p.inverseHint(norm);
            const inv = [2]ID{ p.write(.inverse_double_real, &.{ y[0], t }), p.write(.inverse_double_imag, &.{ y[1], t }) };
            lambda = .{ p.write(.lambda_double_real, &.{ xx[0], inv[0], xx[1], inv[1] }), p.write(.lambda_double_imag, &.{ xx[0], inv[1], xx[1], inv[0] }) };
        } else {
            p.additions += 1;
            const norm = p.write(.norm_difference, &.{ 0, x[0], 1, x[1] });
            const t = p.inverseHint(norm);
            const inv = [2]ID{ p.write(.inverse_difference_real, &.{ 0, x[0], t }), p.write(.inverse_difference_imag, &.{ 1, x[1], t }) };
            lambda = .{ p.write(.lambda_add_real, &.{ 2, y[0], inv[0], 3, y[1], inv[1] }), p.write(.lambda_add_imag, &.{ 2, y[0], inv[1], 3, y[1], inv[0] }) };
        }
        const nx: [2]ID = if (double) .{ p.write(.x_double_real, &.{ lambda[0], lambda[1], x[0] }), p.write(.x_double_imag, &.{ lambda[0], lambda[1], x[1] }) } else .{ p.write(.x_add_real, &.{ lambda[0], lambda[1], x[0], 0 }), p.write(.x_add_imag, &.{ lambda[0], lambda[1], x[1], 1 }) };
        const ny: [2]ID = .{ p.write(.y_real, &.{ lambda[0], x[0], nx[0], lambda[1], x[1], nx[1], y[0] }), p.write(.y_imag, &.{ lambda[0], x[1], nx[1], lambda[1], x[0], nx[0], y[1] }) };
        return .{ nx, ny };
    }
};
pub fn program() Program {
    @setEvalBranchQuota(1_000_000);
    var p = Program{};
    const q: Point = .{ .{ 0, 1 }, .{ 2, 3 } };
    const xx = p.mul(q[0], q[0]);
    const xxx = p.mul(xx, q[0]);
    const yy = p.mul(q[1], q[1]);
    p.zero(p.write(.residual, &.{ yy[0], xxx[0], 4 }));
    p.zero(p.write(.residual, &.{ yy[1], xxx[1], 5 }));
    var point = q;
    for (0..253) |step| {
        point = p.transition(point, true);
        const bit = 252 - step;
        if ((SCALAR >> @intCast(bit)) & 1 != 0) point = p.transition(point, false);
    }
    for (0..2) |i| p.zero(p.write(.difference, &.{ point[0][i], q[0][i] }));
    for (0..2) |i| p.zero(p.write(.sum, &.{ point[1][i], q[1][i] }));
    p.final_point = point;
    std.debug.assert(p.count == 4390 and p.hints == 352 and p.doubles == 253 and p.additions == 99 and p.assertion_count == 358);
    return p;
}
pub fn fanout(p: *const Program) [INITIAL + MAX_NODES]u32 {
    var uses: [INITIAL + MAX_NODES]u32 = @splat(0);
    for (p.nodes[0..p.count]) |node| for (node.input[0..arity(node.op)]) |id| {
        uses[id] += 1;
    };
    for (p.assertions[0..p.assertion_count]) |id| uses[id] += 1;
    return uses;
}
pub fn initialValues(q: [2][2]u256) ![INITIAL]u256 {
    for (q) |pair| for (pair) |value| if (value >= B.BN254_P) return error.NonCanonicalSubgroupInput;
    if (q[0][0] == 0 and q[0][1] == 0 and q[1][0] == 0 and q[1][1] == 0) return error.SubgroupInfinityExcluded;
    return .{ q[0][0], q[0][1], q[1][0], q[1][1], G2.TWIST_B[0], G2.TWIST_B[1], 1 };
}
