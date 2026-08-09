//! Logical polynomial-degree analysis for validated typed AIR programs.
//!
//! This pass describes the authored expression graph. Final lowering must add
//! row masks, boundaries, materialization equalities, relation numerators, and
//! interaction recurrences before enforcing a backend degree budget.

const std = @import("std");
const ir = @import("ir.zig");
const types = @import("types.zig");
const validate = @import("validate.zig");

pub const Degree = u32;

pub const ConstraintDegree = struct {
    expression: Degree,
    gate: ?Degree,
    total: Degree,
};

pub const Error = std.mem.Allocator.Error || validate.Error || error{
    DegreeOverflow,
};

pub const Analysis = struct {
    allocator: std.mem.Allocator,
    value_degrees: []Degree,
    constraint_degrees: []ConstraintDegree,

    pub fn deinit(self: *Analysis) void {
        self.allocator.free(self.constraint_degrees);
        self.allocator.free(self.value_degrees);
        self.* = undefined;
    }

    pub fn value(self: *const Analysis, id: types.ValueId) ?Degree {
        const index = types.idIndex(id);
        if (index >= self.value_degrees.len) return null;
        return self.value_degrees[index];
    }

    pub fn constraint(
        self: *const Analysis,
        id: types.ConstraintId,
    ) ?ConstraintDegree {
        const index = types.idIndex(id);
        if (index >= self.constraint_degrees.len) return null;
        return self.constraint_degrees[index];
    }

    pub fn maximumValueDegree(self: *const Analysis) Degree {
        var maximum: Degree = 0;
        for (self.value_degrees) |item| maximum = @max(maximum, item);
        return maximum;
    }

    pub fn maximumConstraintDegree(self: *const Analysis) Degree {
        var maximum: Degree = 0;
        for (self.constraint_degrees) |item| maximum = @max(maximum, item.total);
        return maximum;
    }
};

pub fn analyze(
    allocator: std.mem.Allocator,
    arena: *const ir.Arena,
) Error!Analysis {
    try validate.validate(arena);
    const value_degrees = try allocator.alloc(Degree, arena.nodesView().len);
    errdefer allocator.free(value_degrees);
    const constraint_degrees = try allocator.alloc(
        ConstraintDegree,
        arena.constraintsView().len,
    );
    errdefer allocator.free(constraint_degrees);

    for (arena.nodesView(), 0..) |node, index| {
        value_degrees[index] = switch (node.key.op) {
            .constant => 0,
            .input, .hint_output, .call_output => 1,
            .add, .sub => |binary| @max(
                value_degrees[types.idIndex(binary.lhs)],
                value_degrees[types.idIndex(binary.rhs)],
            ),
            .mul => |binary| try add(
                value_degrees[types.idIndex(binary.lhs)],
                value_degrees[types.idIndex(binary.rhs)],
            ),
            .neg => |value| value_degrees[types.idIndex(value)],
            .select => |selection| try add(
                value_degrees[types.idIndex(selection.selector)],
                @max(
                    value_degrees[types.idIndex(selection.when_true)],
                    value_degrees[types.idIndex(selection.when_false)],
                ),
            ),
            .machine_derived => |derived| switch (derived) {
                .register_address => |address| value_degrees[types.idIndex(address.index)],
                .aligned_word_address => |address| value_degrees[types.idIndex(address.word_index)],
                .access_clock => |clock| value_degrees[types.idIndex(clock.instruction_clock)],
                .strict_clock_gap => |gap| @max(
                    value_degrees[types.idIndex(gap.current_clock)],
                    value_degrees[types.idIndex(gap.previous_clock)],
                ),
            },
        };
    }

    for (arena.constraintsView(), constraint_degrees) |constraint, *result| {
        const expression = value_degrees[types.idIndex(constraint.root)];
        const gate = if (constraint.gate) |gate_id|
            value_degrees[types.idIndex(gate_id)]
        else
            null;
        result.* = .{
            .expression = expression,
            .gate = gate,
            .total = if (gate) |gate_degree|
                try add(expression, gate_degree)
            else
                expression,
        };
    }

    return .{
        .allocator = allocator,
        .value_degrees = value_degrees,
        .constraint_degrees = constraint_degrees,
    };
}

fn add(lhs: Degree, rhs: Degree) error{DegreeOverflow}!Degree {
    return std.math.add(Degree, lhs, rhs) catch error.DegreeOverflow;
}
