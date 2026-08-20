//! Compatibility-exact direct polynomial authorship for RV32 AUIPC.
//!
//! The sixteen shipped semantic roots and the placement root remain in
//! production order. Word decomposition, signed-immediate reconstruction,
//! byte carries, and destination gating are authored directly over the typed
//! physical columns; no witness writer participates in this definition.

const std = @import("std");
const ir = @import("ir.zig");
const source = @import("source.zig");
const types = @import("types.zig");

pub const SEMANTIC_CONSTRAINT_COUNT: usize = 16;
pub const DIRECT_CONSTRAINT_COUNT: usize = SEMANTIC_CONSTRAINT_COUNT + 1;

pub const Result = struct {
    carries: [4]types.ValueId,
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
            "compat.riscv.auipc.direct.{d}",
            .{index},
        );
        return self.arena.assertZero(name, root, null, .semantic, self.span);
    }
};

/// `pc_polynomial` is the exact scalar view of physical PC column two. The
/// compatibility binding is authenticated by `typed_auipc.Definition`.
pub fn author(
    arena: *ir.Arena,
    columns: anytype,
    pc_polynomial: types.ValueId,
    is_active: types.ValueId,
    span: source.SourceSpan,
) !Result {
    @setEvalBranchQuota(100_000);
    const zero = try arena.constantField(0, span);
    const one = try arena.constantField(1, span);
    const a = Author{ .arena = arena, .span = span, .zero = zero, .one = one };
    const c2 = try a.q(2);
    const c36 = try a.q(36);
    const c256 = try a.q(1 << 8);
    const inv256 = try a.q(1 << 23);

    var roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId = undefined;
    var n: usize = 0;
    roots[n] = try a.bit(columns.enabler);
    n += 1;
    roots[n] = try a.sub(
        try a.composeU32(columns.pc_limbs, c256),
        pc_polynomial,
    );
    n += 1;
    roots[n] = try a.sub(
        try a.sub(
            try a.composeU32(columns.imm_limbs, c256),
            columns.imm_felt,
        ),
        try a.mul(columns.imm_sign, c2),
    );
    n += 1;
    roots[n] = try a.bit(columns.imm_sign);
    n += 1;
    roots[n] = try a.mul(columns.enabler, columns.imm_limbs[0]);
    n += 1;

    var carries: [4]types.ValueId = undefined;
    var carry = zero;
    for (0..4) |limb| {
        const numerator = try a.sub(
            try a.add(
                try a.add(columns.pc_limbs[limb], columns.imm_limbs[limb]),
                carry,
            ),
            columns.result[limb],
        );
        carry = try a.mul(numerator, inv256);
        carries[limb] = carry;
        roots[n] = try a.bit(carry);
        n += 1;
    }

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
        .carries = carries,
        .opcode = c36,
        .constraints = constraints,
        .roots = roots,
    };
}
