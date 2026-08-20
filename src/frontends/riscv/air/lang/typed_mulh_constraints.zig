//! Compatibility-exact direct polynomial authorship for RV32 high-word multiply.
//!
//! Covers `MULH`, `MULHSU`, and `MULHU`. The full eight-byte schoolbook
//! product is represented by physical low/high bytes plus eight derived carries;
//! only the shipped 23 semantic roots and placement are direct constraints.

const std = @import("std");
const ir = @import("ir.zig");
const source = @import("source.zig");
const types = @import("types.zig");

pub const SEMANTIC_CONSTRAINT_COUNT: usize = 23;
pub const DIRECT_CONSTRAINT_COUNT: usize = SEMANTIC_CONSTRAINT_COUNT + 1;

pub const Result = struct {
    active: types.ValueId,
    signed_rs1: types.ValueId,
    carries: [8]types.ValueId,
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

    fn booleanOneMinus(self: Author, value: types.ValueId) !types.ValueId {
        return self.mul(value, try self.sub(self.one, value));
    }

    fn booleanValueMinus(self: Author, value: types.ValueId) !types.ValueId {
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
            "compat.riscv.mulh.direct.{d}",
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
    const a = Author{ .arena = arena, .span = span, .one = one };
    const c38 = try a.q(38);
    const c39 = try a.q(39);
    const c40 = try a.q(40);
    const c255 = try a.q(255);
    const inv256 = try a.q(1 << 23);

    // Preserve the production sums while retaining the selector proof needed
    // by effect liveness and read-only access validation.
    const active = try arena.oneHotSelector(
        &.{ columns.is_mulh, columns.is_mulhsu, columns.is_mulhu },
        span,
    );
    const signed_rs1 = try arena.oneHotSelector(
        &.{ columns.is_mulh, columns.is_mulhsu },
        span,
    );
    const a_fill = try a.mul(columns.rs1_sign, c255);
    const b_fill = try a.mul(columns.rs2_sign, c255);
    var lhs: [8]types.ValueId = undefined;
    var rhs: [8]types.ValueId = undefined;
    var product: [8]types.ValueId = undefined;
    @memcpy(lhs[0..4], &columns.rs1.next);
    @memcpy(rhs[0..4], &columns.rs2.next);
    @memcpy(product[0..4], &columns.low_product);
    @memcpy(product[4..8], &columns.result);
    for (4..8) |limb| {
        lhs[limb] = a_fill;
        rhs[limb] = b_fill;
    }

    var carries: [8]types.ValueId = undefined;
    var previous = zero;
    for (0..8) |output_limb| {
        var numerator = previous;
        for (0..output_limb + 1) |lhs_limb| {
            numerator = try a.add(
                numerator,
                try a.mul(lhs[lhs_limb], rhs[output_limb - lhs_limb]),
            );
        }
        carries[output_limb] = try a.mul(
            try a.sub(numerator, product[output_limb]),
            inv256,
        );
        previous = carries[output_limb];
    }

    var opcode = try a.add(
        try a.mul(columns.is_mulh, c38),
        try a.mul(columns.is_mulhsu, c39),
    );
    opcode = try a.add(opcode, try a.mul(columns.is_mulhu, c40));

    var roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId = undefined;
    var n: usize = 0;
    roots[n] = try a.booleanOneMinus(active);
    n += 1;
    inline for (.{ columns.is_mulh, columns.is_mulhsu, columns.is_mulhu }) |flag| {
        roots[n] = try a.booleanOneMinus(flag);
        n += 1;
    }
    roots[n] = try a.booleanOneMinus(columns.rs1_sign);
    n += 1;
    roots[n] = try a.booleanOneMinus(columns.rs2_sign);
    n += 1;
    roots[n] = try a.mul(
        try a.sub(try a.sub(one, columns.is_mulh), columns.is_mulhsu),
        columns.rs1_sign,
    );
    n += 1;
    roots[n] = try a.mul(
        try a.sub(one, columns.is_mulh),
        columns.rs2_sign,
    );
    n += 1;
    roots[n] = try a.booleanValueMinus(columns.destination_nonzero);
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
    inline for (0..4) |limb| {
        roots[n] = try a.sub(
            columns.rd.next[limb],
            try a.mul(columns.destination_nonzero, columns.result[limb]),
        );
        n += 1;
    }
    inline for (0..4) |limb| {
        roots[n] = try a.mul(
            active,
            try a.sub(columns.rs1.next[limb], columns.rs1.previous[limb]),
        );
        n += 1;
    }
    inline for (0..4) |limb| {
        roots[n] = try a.mul(
            active,
            try a.sub(columns.rs2.next[limb], columns.rs2.previous[limb]),
        );
        n += 1;
    }
    roots[n] = try a.sub(active, is_active);
    n += 1;
    std.debug.assert(n == roots.len);

    var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
    for (&constraints, roots, 0..) |*constraint, root, index|
        constraint.* = try a.assertDirect(index, root);

    return .{
        .active = active,
        .signed_rs1 = signed_rs1,
        .carries = carries,
        .opcode = opcode,
        .constraints = constraints,
        .roots = roots,
    };
}
