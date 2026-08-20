//! Compatibility-exact direct polynomial authorship for RV32 JALR.
//!
//! The 22 shipped semantic roots and placement root remain in production
//! order. Target reconstruction, low-bit clearing, byte carries, link result,
//! destination gating, and source read-only equations are explicit here.

const std = @import("std");
const ir = @import("ir.zig");
const source = @import("source.zig");
const types = @import("types.zig");

pub const SEMANTIC_CONSTRAINT_COUNT: usize = 22;
pub const DIRECT_CONSTRAINT_COUNT: usize = SEMANTIC_CONSTRAINT_COUNT + 1;

pub const Result = struct {
    target_word: types.ValueId,
    jump_target: types.ValueId,
    immediate_limbs: [4]types.ValueId,
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

    fn composeU32(self: Author, limbs: [4]types.ValueId, radix: types.ValueId) !types.ValueId {
        var value = limbs[3];
        value = try self.add(try self.mul(value, radix), limbs[2]);
        value = try self.add(try self.mul(value, radix), limbs[1]);
        return self.add(try self.mul(value, radix), limbs[0]);
    }

    fn assertDirect(self: Author, index: usize, root: types.ValueId) !types.ConstraintId {
        var name_buffer: [64]u8 = undefined;
        const name = try std.fmt.bufPrint(
            &name_buffer,
            "compat.riscv.jalr.direct.{d}",
            .{index},
        );
        return self.arena.assertZero(name, root, null, .semantic, self.span);
    }
};

/// `pc_polynomial` is the exact field view of physical PC column two. The
/// compatibility binding is owned by `typed_jalr.Definition`.
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
    const c4 = try a.q(4);
    const c34 = try a.q(34);
    const c240 = try a.q(240);
    const c255 = try a.q(255);
    const c256 = try a.q(256);
    const c4096 = try a.q(4096);
    const c2Pow20 = try a.q(1 << 20);
    const inv256 = try a.q(1 << 23);

    const target_word = try a.add(
        columns.target_word_low_20,
        try a.mul(columns.target_word_high_8, c2Pow20),
    );
    const jump_target = try a.mul(c4, target_word);
    const immediate_limbs = [4]types.ValueId{
        columns.imm_byte_0,
        try a.add(columns.imm_nibble, try a.mul(columns.imm_sign, c240)),
        try a.mul(columns.imm_sign, c255),
        try a.mul(columns.imm_sign, c255),
    };

    var roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId = undefined;
    var n: usize = 0;
    roots[n] = try a.bit(columns.enabler);
    n += 1;
    roots[n] = try a.bit(columns.to_pc_lsb);
    n += 1;
    roots[n] = try a.bit(columns.imm_sign);
    n += 1;
    roots[n] = try a.sub(
        try a.sub(
            try a.add(
                columns.imm_byte_0,
                try a.mul(columns.imm_nibble, c256),
            ),
            try a.mul(columns.imm_sign, c4096),
        ),
        columns.imm_felt,
    );
    n += 1;
    roots[n] = try a.sub(
        try a.composeU32(columns.target_limbs, c256),
        jump_target,
    );
    n += 1;
    roots[n] = try a.sub(columns.to_pc_over_two, try a.mul(target_word, c2));
    n += 1;

    var carries: [4]types.ValueId = undefined;
    var carry = zero;
    for (0..4) |limb| {
        const result_limb = try a.add(
            columns.target_limbs[limb],
            if (limb == 0) columns.to_pc_lsb else zero,
        );
        carry = try a.mul(
            try a.sub(
                try a.add(
                    try a.add(columns.rs1.next[limb], immediate_limbs[limb]),
                    carry,
                ),
                result_limb,
            ),
            inv256,
        );
        carries[limb] = carry;
        roots[n] = try a.bit(carry);
        n += 1;
    }

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
    for (0..4) |limb| {
        roots[n] = try a.mul(
            columns.enabler,
            try a.sub(columns.rs1.next[limb], columns.rs1.previous[limb]),
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
        .target_word = target_word,
        .jump_target = jump_target,
        .immediate_limbs = immediate_limbs,
        .carries = carries,
        .opcode = c34,
        .constraints = constraints,
        .roots = roots,
    };
}
