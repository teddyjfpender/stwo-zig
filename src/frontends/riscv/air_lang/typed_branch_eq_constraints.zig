//! Compatibility-exact direct polynomial authorship for RV32 BEQ/BNE.

const std = @import("std");
const ir = @import("ir.zig");
const range_refinement = @import("range_refinement.zig");
const source = @import("source.zig");
const types = @import("types.zig");

pub const SEMANTIC_CONSTRAINT_COUNT: usize = 17;
pub const DIRECT_CONSTRAINT_COUNT: usize = SEMANTIC_CONSTRAINT_COUNT + 1;

pub const Result = struct {
    active: types.ValueId,
    active_selector: types.ValueId,
    comparison_equal: types.ValueId,
    opcode: types.ValueId,
    constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId,
    roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId,
};

const Author = struct {
    arena: *ir.Arena,
    span: source.SourceSpan,
    one: types.ValueId,

    fn add(self: Author, lhs: types.ValueId, rhs: types.ValueId) !types.ValueId {
        return self.arena.add(lhs, rhs, self.span);
    }

    fn sub(self: Author, lhs: types.ValueId, rhs: types.ValueId) !types.ValueId {
        return self.arena.sub(lhs, rhs, self.span);
    }

    fn mul(self: Author, lhs: types.ValueId, rhs: types.ValueId) !types.ValueId {
        return self.arena.mul(lhs, rhs, self.span);
    }

    fn q(self: Author, value: u32) !types.ValueId {
        return self.arena.constantField(value, self.span);
    }

    fn bit(self: Author, value: types.ValueId) !types.ValueId {
        return self.mul(value, try self.sub(value, self.one));
    }

    fn assertDirect(
        self: Author,
        index: usize,
        root: types.ValueId,
    ) !types.ConstraintId {
        var name_buffer: [64]u8 = undefined;
        const name = try std.fmt.bufPrint(
            &name_buffer,
            "compat.riscv.branch_eq.direct.{d}",
            .{index},
        );
        return self.arena.assertZero(name, root, null, .semantic, self.span);
    }
};

pub fn author(
    arena: *ir.Arena,
    columns: anytype,
    is_active: types.ValueId,
    span: source.SourceSpan,
) !Result {
    @setEvalBranchQuota(50_000);
    const one = try arena.constantField(1, span);
    const a = Author{ .arena = arena, .span = span, .one = one };
    const c27 = try a.q(27);
    const c28 = try a.q(28);

    const active = try a.add(columns.is_beq, columns.is_bne);
    const not_comparison = try a.sub(one, columns.cmp_result);
    const comparison_equal = try a.add(
        try a.mul(columns.cmp_result, columns.is_beq),
        try a.mul(not_comparison, columns.is_bne),
    );
    const opcode = try a.add(
        try a.mul(columns.is_beq, c27),
        try a.mul(columns.is_bne, c28),
    );

    var roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId = undefined;
    var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
    var n: usize = 0;
    roots[n] = try a.bit(active);
    constraints[n] = try a.assertDirect(n, roots[n]);
    const active_selector = try range_refinement.booleanFromConstraint(
        arena,
        active,
        constraints[n],
        span,
    );
    n += 1;
    roots[n] = try a.bit(columns.is_beq);
    n += 1;
    roots[n] = try a.bit(columns.is_bne);
    n += 1;
    roots[n] = try a.bit(columns.cmp_result);
    n += 1;
    for (columns.rs1.next, columns.rs2.next) |lhs, rhs| {
        roots[n] = try a.mul(comparison_equal, try a.sub(lhs, rhs));
        n += 1;
    }
    var inverse_sum = comparison_equal;
    for (columns.rs1.next, columns.rs2.next, columns.diff_inverse_markers) |
        lhs,
        rhs,
        inverse,
    | {
        inverse_sum = try a.add(
            inverse_sum,
            try a.mul(try a.sub(lhs, rhs), inverse),
        );
    }
    roots[n] = try a.mul(active, try a.sub(one, inverse_sum));
    n += 1;
    for (columns.rs1.next, columns.rs1.previous) |next, previous| {
        roots[n] = try a.mul(active_selector, try a.sub(next, previous));
        n += 1;
    }
    for (columns.rs2.next, columns.rs2.previous) |next, previous| {
        roots[n] = try a.mul(active_selector, try a.sub(next, previous));
        n += 1;
    }
    roots[n] = try a.sub(active_selector, is_active);
    n += 1;
    std.debug.assert(n == roots.len);

    for (constraints[1..], roots[1..], 1..) |*constraint, root, index|
        constraint.* = try a.assertDirect(index, root);

    return .{
        .active = active,
        .active_selector = active_selector,
        .comparison_equal = comparison_equal,
        .opcode = opcode,
        .constraints = constraints,
        .roots = roots,
    };
}
