//! Compatibility-exact direct polynomial authorship for RV32 SLT/SLTU.

const std = @import("std");
const ir = @import("ir.zig");
const range_refinement = @import("range_refinement.zig");
const source = @import("source.zig");
const types = @import("types.zig");

pub const SEMANTIC_CONSTRAINT_COUNT: usize = 35;
pub const DIRECT_CONSTRAINT_COUNT: usize = SEMANTIC_CONSTRAINT_COUNT + 1;

pub const Result = struct {
    active: types.ValueId,
    active_selector: types.ValueId,
    rs1_msl_shifted: types.ValueId,
    rs2_msl_shifted: types.ValueId,
    prefix_sum: types.ValueId,
    positive_difference: types.ValueId,
    opcode: types.ValueId,
    constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId,
    roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId,
};

const Author = struct {
    arena: *ir.Arena,
    span: source.SourceSpan,
    zero: types.ValueId,
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
            "compat.riscv.lt_reg.direct.{d}",
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
    @setEvalBranchQuota(100_000);
    const zero = try arena.constantField(0, span);
    const one = try arena.constantField(1, span);
    const a = Author{ .arena = arena, .span = span, .zero = zero, .one = one };
    const c2 = try a.q(2);
    const c3 = try a.q(3);
    const c4 = try a.q(4);
    const c128 = try a.q(128);
    const c256 = try a.q(256);

    const active = try a.add(columns.is_slt, columns.is_sltu);
    const rs1_msl_gap = try a.sub(columns.rs1.next[3], columns.rs1_msl_felt);
    const rs2_msl_gap = try a.sub(columns.rs2.next[3], columns.rs2_msl_felt);
    const rs1_msl_shifted = try a.add(
        columns.rs1_msl_felt,
        try a.mul(columns.is_slt, c128),
    );
    const rs2_msl_shifted = try a.add(
        columns.rs2_msl_felt,
        try a.mul(columns.is_slt, c128),
    );
    var prefix_sum = zero;
    for (columns.diff_markers) |marker| prefix_sum = try a.add(prefix_sum, marker);
    const cmp_sign = try a.sub(try a.mul(columns.cmp_result, c2), one);
    const opcode = try a.add(
        try a.mul(columns.is_slt, c3),
        try a.mul(columns.is_sltu, c4),
    );
    const positive_difference = try a.sub(columns.diff_val, one);

    var roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId = undefined;
    var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
    roots[0] = try a.bit(active);
    constraints[0] = try a.assertDirect(0, roots[0]);
    const active_selector = try range_refinement.booleanFromConstraint(
        arena,
        active,
        constraints[0],
        span,
    );
    var n: usize = 1;
    roots[n] = try a.bit(columns.is_slt);
    n += 1;
    roots[n] = try a.bit(columns.is_sltu);
    n += 1;
    roots[n] = try a.bit(columns.cmp_result);
    n += 1;
    for (columns.diff_markers) |marker| {
        roots[n] = try a.bit(marker);
        n += 1;
    }
    roots[n] = try a.mul(rs1_msl_gap, try a.sub(c256, rs1_msl_gap));
    n += 1;
    roots[n] = try a.mul(rs2_msl_gap, try a.sub(c256, rs2_msl_gap));
    n += 1;

    const lhs = [4]types.ValueId{
        columns.rs1.next[0],
        columns.rs1.next[1],
        columns.rs1.next[2],
        columns.rs1_msl_felt,
    };
    const rhs = [4]types.ValueId{
        columns.rs2.next[0],
        columns.rs2.next[1],
        columns.rs2.next[2],
        columns.rs2_msl_felt,
    };
    var more_significant = zero;
    var limb: usize = 4;
    while (limb > 0) {
        limb -= 1;
        const marker = columns.diff_markers[limb];
        const oriented = try a.mul(cmp_sign, try a.sub(rhs[limb], lhs[limb]));
        roots[n] = try a.mul(
            try a.sub(try a.sub(one, more_significant), marker),
            oriented,
        );
        n += 1;
        roots[n] = try a.mul(marker, try a.sub(columns.diff_val, oriented));
        n += 1;
        more_significant = try a.add(more_significant, marker);
    }
    roots[n] = try a.mul(prefix_sum, try a.sub(one, prefix_sum));
    const prefix_constraint_index = n;
    n += 1;
    roots[n] = try a.mul(try a.sub(one, prefix_sum), columns.cmp_result);
    n += 1;
    roots[n] = try a.bit(columns.destination_nonzero);
    n += 1;
    roots[n] = try a.mul(
        columns.rd.addr,
        try a.sub(one, columns.destination_nonzero),
    );
    n += 1;
    roots[n] = try a.sub(
        try a.mul(columns.rd.addr, columns.destination_inverse),
        columns.destination_nonzero,
    );
    n += 1;
    const result = [4]types.ValueId{ columns.cmp_result, zero, zero, zero };
    for (columns.rd.next, result) |actual, computed| {
        roots[n] = try a.sub(
            actual,
            try a.mul(columns.destination_nonzero, computed),
        );
        n += 1;
    }
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
    std.debug.assert(prefix_constraint_index == 18);

    return .{
        .active = active,
        .active_selector = active_selector,
        .rs1_msl_shifted = rs1_msl_shifted,
        .rs2_msl_shifted = rs2_msl_shifted,
        .prefix_sum = prefix_sum,
        .positive_difference = positive_difference,
        .opcode = opcode,
        .constraints = constraints,
        .roots = roots,
    };
}
