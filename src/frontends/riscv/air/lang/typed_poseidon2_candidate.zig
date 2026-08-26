//! Structural candidate matching for Poseidon2 compatibility slots.

const std = @import("std");
const expr = @import("expr.zig");
const ir = @import("ir.zig");
const materializer = @import("degree3_materializer.zig");
const source = @import("source.zig");
const types = @import("types.zig");

pub const Error = error{
    CandidateAmbiguous,
    CandidateMissing,
    UnknownCandidate,
};

pub const Shape = union(enum) {
    shifted: u32,
    first_square: u32,
    square_of: types.ValueId,
    exact: types.ValueId,
};

pub fn find(
    arena: *const ir.Arena,
    plan_value: *const materializer.Plan,
    used: []const bool,
    expected_span: source.SourceSpan,
    shape: Shape,
) Error!usize {
    var result: ?usize = null;
    for (plan_value.materializations, 0..) |item, index| {
        if (used[index] or !std.meta.eql(item.source_span, expected_span)) continue;
        const node = arena.node(item.source_value) orelse
            return error.UnknownCandidate;
        if (!matches(arena, item.source_value, node, shape)) continue;
        if (result != null) return error.CandidateAmbiguous;
        result = index;
    }
    return result orelse error.CandidateMissing;
}

pub fn addHasFieldConstant(
    arena: *const ir.Arena,
    node: expr.Node,
    expected_constant: u32,
) bool {
    const binary = switch (node.key.op) {
        .add => |value| value,
        else => return false,
    };
    return isFieldConstant(arena, binary.lhs, expected_constant) or
        isFieldConstant(arena, binary.rhs, expected_constant);
}

pub fn squareOperand(node: expr.Node) ?types.ValueId {
    return switch (node.key.op) {
        .mul => |binary| if (binary.lhs == binary.rhs) binary.lhs else null,
        else => null,
    };
}

fn matches(
    arena: *const ir.Arena,
    value: types.ValueId,
    node: expr.Node,
    shape: Shape,
) bool {
    return switch (shape) {
        .shifted => |constant| addHasFieldConstant(arena, node, constant),
        .first_square => |constant| blk: {
            const operand = squareOperand(node) orelse break :blk false;
            const operand_node = arena.node(operand) orelse break :blk false;
            break :blk addHasFieldConstant(arena, operand_node, constant);
        },
        .square_of => |operand| squareOperand(node) == operand,
        .exact => |expected_value| value == expected_value,
    };
}

fn isFieldConstant(
    arena: *const ir.Arena,
    value: types.ValueId,
    expected_constant: u32,
) bool {
    const node = arena.node(value) orelse return false;
    return switch (node.key.op) {
        .constant => |constant| switch (constant) {
            .field => |field| field == expected_constant,
            .unsigned => false,
        },
        else => false,
    };
}
