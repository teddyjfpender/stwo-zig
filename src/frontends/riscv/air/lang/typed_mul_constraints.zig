//! Compatibility-exact direct polynomial authorship for RV32 `MUL`.
//!
//! The low-word product is closed by four `range_check_8_11` requests over
//! derived schoolbook carries.  Those carries are deliberately not committed:
//! this module authors only the shipped sixteen semantic roots plus placement.

const std = @import("std");
const ir = @import("ir.zig");
const source = @import("source.zig");
const types = @import("types.zig");

pub const SEMANTIC_CONSTRAINT_COUNT: usize = 16;
pub const DIRECT_CONSTRAINT_COUNT: usize = SEMANTIC_CONSTRAINT_COUNT + 1;

pub const Result = struct {
    carries: [4]types.ValueId,
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

    fn assertDirect(
        self: Author,
        index: usize,
        root: types.ValueId,
    ) !types.ConstraintId {
        var name_buffer: [64]u8 = undefined;
        const name = try std.fmt.bufPrint(
            &name_buffer,
            "compat.riscv.mul.direct.{d}",
            .{index},
        );
        return self.arena.assertZero(name, root, null, .semantic, self.span);
    }
};

/// Authors roots in the exact `air/semantics/mul.zig` production order.
/// `columns` is structural to keep this file independent of the physical
/// layout module and avoid an import cycle.
pub fn author(
    arena: *ir.Arena,
    columns: anytype,
    is_active: types.ValueId,
    span: source.SourceSpan,
) !Result {
    @setEvalBranchQuota(100_000);
    const zero = try arena.constantField(0, span);
    const one = try arena.constantField(1, span);
    const inv256 = try arena.constantField(1 << 23, span);
    const a = Author{ .arena = arena, .span = span, .zero = zero, .one = one };

    const lhs = columns.rs1.next;
    const rhs = columns.rs2.next;
    const result = columns.result;
    var carries: [4]types.ValueId = undefined;
    carries[0] = try a.mul(
        try a.sub(try a.mul(lhs[0], rhs[0]), result[0]),
        inv256,
    );
    carries[1] = try a.mul(
        try a.sub(
            try a.add(
                try a.add(carries[0], try a.mul(lhs[1], rhs[0])),
                try a.mul(lhs[0], rhs[1]),
            ),
            result[1],
        ),
        inv256,
    );
    carries[2] = try a.mul(
        try a.sub(
            try a.add(
                try a.add(
                    try a.add(carries[1], try a.mul(lhs[2], rhs[0])),
                    try a.mul(lhs[1], rhs[1]),
                ),
                try a.mul(lhs[0], rhs[2]),
            ),
            result[2],
        ),
        inv256,
    );
    carries[3] = try a.mul(
        try a.sub(
            try a.add(
                try a.add(
                    try a.add(
                        try a.add(carries[2], try a.mul(lhs[3], rhs[0])),
                        try a.mul(lhs[2], rhs[1]),
                    ),
                    try a.mul(lhs[1], rhs[2]),
                ),
                try a.mul(lhs[0], rhs[3]),
            ),
            result[3],
        ),
        inv256,
    );

    var roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId = undefined;
    var n: usize = 0;
    // The first root is intentionally `enabler * (1 - enabler)`, matching the
    // shipped sign and expression shape rather than a generic bit helper.
    roots[n] = try a.mul(columns.enabler, try a.sub(one, columns.enabler));
    n += 1;
    roots[n] = try a.mul(
        columns.destination_nonzero,
        try a.sub(columns.destination_nonzero, one),
    );
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
            columns.enabler,
            try a.sub(columns.rs1.next[limb], columns.rs1.previous[limb]),
        );
        n += 1;
    }
    inline for (0..4) |limb| {
        roots[n] = try a.mul(
            columns.enabler,
            try a.sub(columns.rs2.next[limb], columns.rs2.previous[limb]),
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
        .constraints = constraints,
        .roots = roots,
    };
}
