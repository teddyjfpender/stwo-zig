//! Scalar evaluator shared by recursion typed-AIR component tests.
//!
//! It interprets the canonical typed DAG directly; tests never transcribe a
//! second copy of a component's constraints.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const ir = @import("../../air/lang/ir.zig");
const types = @import("../../air/lang/types.zig");
const qm31_mul = @import("qm31_mul.zig");

pub const Error = std.mem.Allocator.Error || error{
    UnsupportedNode,
    UnmappedInput,
};

pub fn evaluateQm31Mul(
    allocator: std.mem.Allocator,
    definition: *const qm31_mul.Definition,
    row: *const [qm31_mul.PHYSICAL_COLUMN_COUNT]M31,
) Error![]M31 {
    return evaluateArena(allocator, &definition.arena, row);
}

pub fn evaluateArena(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
    input_values: []const M31,
) Error![]M31 {
    const values = try allocator.alloc(M31, arena.nodeCount());
    errdefer allocator.free(values);
    var input_index: usize = 0;
    for (arena.nodesView(), 0..) |node, index| {
        values[index] = switch (node.key.op) {
            .input => blk: {
                if (input_index >= input_values.len) return error.UnmappedInput;
                defer input_index += 1;
                break :blk input_values[input_index];
            },
            .constant => |constant| switch (constant) {
                .field, .unsigned => |value| M31.fromU64(value),
            },
            .add => |binary| at(values, binary.lhs).add(at(values, binary.rhs)),
            .sub => |binary| at(values, binary.lhs).sub(at(values, binary.rhs)),
            .mul => |binary| at(values, binary.lhs).mul(at(values, binary.rhs)),
            .neg => |value| at(values, value).neg(),
            .select => |selection| if (at(values, selection.selector).isZero())
                at(values, selection.when_false)
            else
                at(values, selection.when_true),
            .hint_output, .call_output, .machine_derived => return error.UnsupportedNode,
        };
    }
    if (input_index != input_values.len) return error.UnmappedInput;
    return values;
}

pub fn constraintAt(
    arena: *const ir.Arena,
    constraints: []const types.ConstraintId,
    values: []const M31,
    index: usize,
) M31 {
    const constraint = arena.constraint(constraints[index]).?;
    return at(values, constraint.root);
}

pub fn constraintValue(
    definition: *const qm31_mul.Definition,
    values: []const M31,
    index: usize,
) M31 {
    const constraint = definition.arena.constraint(definition.constraints[index]).?;
    return at(values, constraint.root);
}

pub fn rowFor(a: @import("stwo_core").fields.qm31.QM31, b: @import("stwo_core").fields.qm31.QM31) [qm31_mul.PHYSICAL_COLUMN_COUNT]M31 {
    const a_coordinates = a.toM31Array();
    const b_coordinates = b.toM31Array();
    const c_coordinates = a.mul(b).toM31Array();
    return a_coordinates ++ b_coordinates ++ c_coordinates;
}

fn at(values: []const M31, id: types.ValueId) M31 {
    return values[types.idIndex(id)];
}

comptime {
    _ = ir.Arena;
}
