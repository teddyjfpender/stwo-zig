//! Compatibility-exact direct polynomial authorship for RV32 JAL.
//!
//! The nine shipped semantic roots and placement root stay in production
//! order. The scalar PC view is bound to physical column two by the enclosing
//! native definition's compatibility adapter; effects use the nominal `.pc`
//! column directly.

const std = @import("std");
const ir = @import("ir.zig");
const source = @import("source.zig");
const types = @import("types.zig");

pub const SEMANTIC_CONSTRAINT_COUNT: usize = 9;
pub const DIRECT_CONSTRAINT_COUNT: usize = SEMANTIC_CONSTRAINT_COUNT + 1;

pub const Result = struct {
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

    fn composeU32(
        self: Author,
        limbs: [4]types.ValueId,
        radix: types.ValueId,
    ) !types.ValueId {
        var value = limbs[3];
        value = try self.add(try self.mul(value, radix), limbs[2]);
        value = try self.add(try self.mul(value, radix), limbs[1]);
        return self.add(try self.mul(value, radix), limbs[0]);
    }

    fn assertDirect(
        self: Author,
        index: usize,
        root: types.ValueId,
    ) !types.ConstraintId {
        var name_buffer: [64]u8 = undefined;
        const name = try std.fmt.bufPrint(
            &name_buffer,
            "compat.riscv.jal.direct.{d}",
            .{index},
        );
        return self.arena.assertZero(name, root, null, .semantic, self.span);
    }
};

pub fn author(
    arena: *ir.Arena,
    columns: anytype,
    pc_polynomial: types.ValueId,
    is_active: types.ValueId,
    span: source.SourceSpan,
) !Result {
    @setEvalBranchQuota(50_000);
    const one = try arena.constantField(1, span);
    const a = Author{ .arena = arena, .span = span, .one = one };
    const c4 = try a.q(4);
    const c256 = try a.q(1 << 8);

    var roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId = undefined;
    var n: usize = 0;
    roots[n] = try a.bit(columns.enabler);
    n += 1;
    roots[n] = try a.mul(
        columns.enabler,
        try a.sub(
            try a.composeU32(columns.result, c256),
            try a.add(pc_polynomial, c4),
        ),
    );
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
    for (0..4) |limb| {
        roots[n] = try a.sub(
            columns.rd.next[limb],
            try a.mul(columns.destination_nonzero, columns.result[limb]),
        );
        n += 1;
    }
    roots[n] = try a.sub(columns.enabler, is_active);
    n += 1;
    std.debug.assert(n == roots.len);

    var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
    for (&constraints, roots, 0..) |*constraint, root, index|
        constraint.* = try a.assertDirect(index, root);

    return .{
        .opcode = try a.q(33),
        .constraints = constraints,
        .roots = roots,
    };
}
