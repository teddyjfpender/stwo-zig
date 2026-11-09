//! Compatibility-exact direct polynomial authorship for RV32 branch compares.

const std = @import("std");
const ir = @import("ir.zig");
const range_refinement = @import("range_refinement.zig");
const source = @import("source.zig");
const types = @import("types.zig");

pub const SEMANTIC_CONSTRAINT_COUNT: usize = 32;
pub const DIRECT_CONSTRAINT_COUNT: usize = SEMANTIC_CONSTRAINT_COUNT + 1;

pub const Result = struct {
    active: types.ValueId,
    active_selector: types.ValueId,
    signed: types.ValueId,
    prefix_sum: types.ValueId,
    positive_difference: types.ValueId,
    opcode: types.ValueId,
    selected_target: types.ValueId,
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
            "compat.riscv.branch_lt.direct.{d}",
            .{index},
        );
        return self.arena.assertZero(name, root, null, .semantic, self.span);
    }
};

pub fn author(
    arena: *ir.Arena,
    columns: anytype,
    pc_polynomial: types.ValueId,
    branch_target_polynomial: types.ValueId,
    is_active: types.ValueId,
    span: source.SourceSpan,
) !Result {
    @setEvalBranchQuota(100_000);
    const one = try arena.constantField(1, span);
    const a = Author{ .arena = arena, .span = span, .one = one };
    const c2 = try a.q(2);
    const c4 = try a.q(4);
    const c29 = try a.q(29);
    const c30 = try a.q(30);
    const c31 = try a.q(31);
    const c32 = try a.q(32);
    const c256 = try a.q(256);

    var active = try a.add(columns.is_blt, columns.is_bltu);
    active = try a.add(active, columns.is_bge);
    active = try a.add(active, columns.is_bgeu);
    const signed = try a.add(columns.is_blt, columns.is_bge);
    const not_cmp = try a.sub(one, columns.cmp_result);
    const taken_offset = try a.mul(columns.imm_felt, columns.cmp_result);
    var selected_target = try a.add(pc_polynomial, taken_offset);
    selected_target = try a.add(selected_target, try a.mul(c4, not_cmp));
    const rs1_msl_gap = try a.sub(columns.rs1.next[3], columns.rs1_msl_felt);
    const rs2_msl_gap = try a.sub(columns.rs2.next[3], columns.rs2_msl_felt);
    var prefix_sum = try a.add(columns.diff_markers[0], columns.diff_markers[1]);
    prefix_sum = try a.add(prefix_sum, columns.diff_markers[2]);
    prefix_sum = try a.add(prefix_sum, columns.diff_markers[3]);
    const lt_sign = try a.sub(try a.mul(c2, columns.cmp_lt), one);
    const diff3 = try a.mul(
        lt_sign,
        try a.sub(columns.rs2_msl_felt, columns.rs1_msl_felt),
    );
    const diff2 = try a.mul(
        lt_sign,
        try a.sub(columns.rs2.next[2], columns.rs1.next[2]),
    );
    const diff1 = try a.mul(
        lt_sign,
        try a.sub(columns.rs2.next[1], columns.rs1.next[1]),
    );
    const diff0 = try a.mul(
        lt_sign,
        try a.sub(columns.rs2.next[0], columns.rs1.next[0]),
    );
    const lt = try a.add(columns.is_blt, columns.is_bltu);
    const ge = try a.add(columns.is_bge, columns.is_bgeu);
    const expected_cmp_lt = try a.add(
        try a.mul(columns.cmp_result, lt),
        try a.mul(not_cmp, ge),
    );
    var opcode = try a.add(
        try a.mul(columns.is_blt, c29),
        try a.mul(columns.is_bltu, c31),
    );
    opcode = try a.add(opcode, try a.mul(columns.is_bge, c30));
    opcode = try a.add(opcode, try a.mul(columns.is_bgeu, c32));
    const positive_difference = try a.sub(columns.diff_val, one);

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
    inline for (.{
        columns.is_blt,
        columns.is_bltu,
        columns.is_bge,
        columns.is_bgeu,
    }) |flag| {
        roots[n] = try a.bit(flag);
        n += 1;
    }
    roots[n] = try a.bit(columns.cmp_result);
    n += 1;
    for (columns.diff_markers) |marker| {
        roots[n] = try a.bit(marker);
        n += 1;
    }
    roots[n] = try a.mul(
        active,
        try a.sub(branch_target_polynomial, selected_target),
    );
    n += 1;
    roots[n] = try a.mul(rs1_msl_gap, try a.sub(c256, rs1_msl_gap));
    n += 1;
    roots[n] = try a.mul(rs2_msl_gap, try a.sub(c256, rs2_msl_gap));
    n += 1;

    const m0 = columns.diff_markers[0];
    const m1 = columns.diff_markers[1];
    const m2 = columns.diff_markers[2];
    const m3 = columns.diff_markers[3];
    roots[n] = try a.mul(try a.sub(one, m3), diff3);
    n += 1;
    roots[n] = try a.mul(m3, try a.sub(columns.diff_val, diff3));
    n += 1;
    roots[n] = try a.mul(try a.sub(try a.sub(one, m3), m2), diff2);
    n += 1;
    roots[n] = try a.mul(m2, try a.sub(columns.diff_val, diff2));
    n += 1;
    roots[n] = try a.mul(
        try a.sub(try a.sub(try a.sub(one, m3), m2), m1),
        diff1,
    );
    n += 1;
    roots[n] = try a.mul(m1, try a.sub(columns.diff_val, diff1));
    n += 1;
    roots[n] = try a.mul(try a.sub(one, prefix_sum), diff0);
    n += 1;
    roots[n] = try a.mul(m0, try a.sub(columns.diff_val, diff0));
    n += 1;
    roots[n] = try a.bit(prefix_sum);
    const prefix_constraint_index = n;
    n += 1;
    roots[n] = try a.mul(try a.sub(one, prefix_sum), columns.cmp_lt);
    n += 1;
    roots[n] = try a.sub(columns.cmp_lt, expected_cmp_lt);
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
    std.debug.assert(prefix_constraint_index == 21);

    for (constraints[1..], roots[1..], 1..) |*constraint, root, index|
        constraint.* = try a.assertDirect(index, root);

    return .{
        .active = active,
        .active_selector = active_selector,
        .signed = signed,
        .prefix_sum = prefix_sum,
        .positive_difference = positive_difference,
        .opcode = opcode,
        .selected_target = selected_target,
        .constraints = constraints,
        .roots = roots,
    };
}
