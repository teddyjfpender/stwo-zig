//! Comptime `eval!` trees for the hand-written evaluators.
//!
//! The Rust macro `eval!(ctx, (a) op (b))` emits the left subtree, the right
//! subtree, then the op; a literal is `ctx.constant(v)`. Writing the
//! hand-written constraints as comptime trees keeps them textually parallel to
//! the Rust source, and `emit` unrolls each tree into exactly that call order.

const stwo_core = @import("stwo_core");

const QM31 = stwo_core.fields.qm31.QM31;
const M31 = stwo_core.fields.m31.M31;

pub const Node = union(enum) {
    /// Index into the caller's operand array.
    operand: usize,
    literal: u32,
    add: [2]*const Node,
    sub: [2]*const Node,
    mul: [2]*const Node,
};

/// `ctx.constant(M31::from(value).into())`: the literal of `eval!` and of
/// every hand-written relation id and offset.
pub fn constantM31(ctx: anytype, value: u32) !@TypeOf(ctx.*).Var {
    return ctx.constant(QM31.fromBase(M31.fromCanonical(value)));
}

pub fn x(comptime index: usize) Node {
    return .{ .operand = index };
}

pub fn lit(comptime value: u32) Node {
    return .{ .literal = value };
}

pub fn add(comptime lhs: Node, comptime rhs: Node) Node {
    return .{ .add = .{ &lhs, &rhs } };
}

pub fn sub(comptime lhs: Node, comptime rhs: Node) Node {
    return .{ .sub = .{ &lhs, &rhs } };
}

pub fn mul(comptime lhs: Node, comptime rhs: Node) Node {
    return .{ .mul = .{ &lhs, &rhs } };
}

pub fn emit(comptime node: Node, ctx: anytype, operands: []const @TypeOf(ctx.*).Var) !@TypeOf(ctx.*).Var {
    switch (node) {
        .operand => |index| return operands[index],
        .literal => |value| return constantM31(ctx, value),
        inline .add, .sub, .mul => |children, op| {
            const lhs = try emit(children[0].*, ctx, operands);
            const rhs = try emit(children[1].*, ctx, operands);
            return switch (op) {
                .add => ctx.add(lhs, rhs),
                .sub => ctx.sub(lhs, rhs),
                .mul => ctx.mul(lhs, rhs),
                else => comptime unreachable,
            };
        },
    }
}
