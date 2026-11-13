//! Cold scalar replay of typed field-polynomial definitions.
//! The caller owns returned scratch and supplies an explicit input binding.
const std = @import("std");
const ir = @import("ir.zig");
const types = @import("types.zig");
const M31 = @import("stwo_core").fields.m31.M31;
pub fn evaluate(comptime S: type, allocator: std.mem.Allocator, arena: *const ir.Arena, inputs: []const types.ValueId, arguments: []const S) ![]S {
    if (inputs.len != arguments.len) return error.TypedPolynomialInputCountMismatch;
    const values = try allocator.alloc(S, arena.nodes.items.len);
    errdefer allocator.free(values);
    for (arena.nodes.items, 0..) |node, index| values[index] = switch (node.key.op) {
        .input => blk: {
            for (inputs, arguments) |input, value| if (types.idIndex(input) == index) break :blk value;
            return error.TypedPolynomialUnknownInput;
        },
        .constant => |constant| switch (constant) {
            .field => |word| if (S == M31) M31.fromCanonical(word) else S.fromBase(M31.fromCanonical(word)),
            else => return error.TypedPolynomialUnsupportedExpression,
        },
        .add => |b| values[types.idIndex(b.lhs)].add(values[types.idIndex(b.rhs)]),
        .sub => |b| values[types.idIndex(b.lhs)].sub(values[types.idIndex(b.rhs)]),
        .mul => |b| values[types.idIndex(b.lhs)].mul(values[types.idIndex(b.rhs)]),
        .neg => |v| values[types.idIndex(v)].neg(),
        else => return error.TypedPolynomialUnsupportedExpression,
    };
    return values;
}
