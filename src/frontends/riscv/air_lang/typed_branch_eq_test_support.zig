//! Allocation-conscious replay helpers for native BRANCH_EQ semantic tests.

const M31 = @import("stwo_core").fields.m31.M31;
const expr = @import("expr.zig");
const ir = @import("ir.zig");
const typed = @import("typed_branch_eq.zig");
const types = @import("types.zig");

pub const ROW_WIDTH: usize = typed.MAIN_COLUMN_COUNT + 1;
pub const BINDING_COUNT: usize = typed.MAIN_COLUMN_COUNT + 1;
pub const Binding = struct { value: types.ValueId, column: u32 };

pub fn typedBindings(definition: *const typed.Definition) [BINDING_COUNT]Binding {
    var bindings: [BINDING_COUNT]Binding = undefined;
    for (definition.columns.physical(), bindings[0..typed.MAIN_COLUMN_COUNT], 0..) |
        value,
        *binding,
        column,
    | binding.* = .{ .value = value, .column = @intCast(column) };
    bindings[typed.MAIN_COLUMN_COUNT] = .{
        .value = definition.is_active,
        .column = typed.MAIN_COLUMN_COUNT,
    };
    return bindings;
}

pub fn evaluateInto(
    arena: *const ir.Arena,
    bindings: []const Binding,
    columns: []const M31,
    values: []M31,
) !void {
    if (columns.len != ROW_WIDTH or values.len != arena.nodeCount())
        return error.InvalidScratchShape;
    for (arena.nodesView(), 0..) |node, index| {
        const id = try types.idFromIndex(types.ValueId, index);
        values[index] = if (columnFor(bindings, id)) |column|
            columns[column]
        else switch (node.key.op) {
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
            .machine_derived => |derived| evaluateDerived(values, derived),
            .input => return error.UnmappedInput,
            .hint_output, .call_output => return error.UnsupportedNode,
        };
    }
}

pub fn rowAccepted(definition: *const typed.Definition, values: []const M31) bool {
    for (definition.model.constraints) |id| {
        const constraint = definition.arena.constraint(id) orelse return false;
        if (!at(values, constraint.root).isZero()) return false;
    }
    return true;
}

pub fn at(values: []const M31, id: types.ValueId) M31 {
    return values[types.idIndex(id)];
}

fn evaluateDerived(values: []const M31, derived: expr.MachineDerived) M31 {
    return switch (derived) {
        .register_address => |address| at(values, address.index),
        .aligned_word_address => |address| at(values, address.word_index)
            .mul(M31.fromCanonical(4)),
        .access_clock => |clock| at(values, clock.instruction_clock)
            .sub(M31.one()).mul(M31.fromCanonical(4))
            .add(M31.fromCanonical(@intFromEnum(clock.phase))),
        .strict_clock_gap => |gap| at(values, gap.current_clock)
            .sub(at(values, gap.previous_clock)).sub(M31.one()),
        .instruction_next_pc => |next| at(values, next.current)
            .add(M31.fromCanonical(4)),
        .instruction_next_clock => |next| at(values, next.current).add(M31.one()),
    };
}

fn columnFor(bindings: []const Binding, value: types.ValueId) ?usize {
    for (bindings) |binding| if (binding.value == value) return binding.column;
    return null;
}
