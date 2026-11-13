//! Compatibility-exact direct polynomial authorship for RV32 DIV/REM.
//!
//! Kept separate from the physical/effect definition so the 79-root algebra
//! remains small enough to review against `air/semantics/div.zig` linearly.

const std = @import("std");
const ir = @import("ir.zig");
const program = @import("program.zig");
const source = @import("source.zig");
const types = @import("types.zig");

pub const SEMANTIC_CONSTRAINT_COUNT: usize = 78;
pub const DIRECT_CONSTRAINT_COUNT: usize = SEMANTIC_CONSTRAINT_COUNT + 1;

pub const Result = struct {
    active: types.ValueId,
    is_division: types.ValueId,
    is_signed: types.ValueId,
    special_case: types.ValueId,
    valid_not_zero_divisor: types.ValueId,
    valid_not_special: types.ValueId,
    q_sum: types.ValueId,
    c_sum: types.ValueId,
    r_sum: types.ValueId,
    diffs: [4]types.ValueId,
    result: [4]types.ValueId,
    negation_carries: [4]types.ValueId,
    prefixes: [4]types.ValueId,
    product_carries: [8]types.ValueId,
    sign_checks: [2]types.ValueId,
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

    fn neg(self: Author, value: types.ValueId) !types.ValueId {
        return self.arena.neg(value, self.span);
    }

    fn q(self: Author, value: u32) !types.ValueId {
        return self.arena.constantField(value, self.span);
    }

    fn sum4(self: Author, values: [4]types.ValueId) !types.ValueId {
        return self.add(try self.add(try self.add(values[0], values[1]), values[2]), values[3]);
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
            "compat.riscv.div.direct.{d}",
            .{index},
        );
        return self.arena.assertZero(name, root, null, .semantic, self.span);
    }
};

/// Authors the shipped 78 semantic roots followed by the placement root.
/// `columns` is structural: `typed_div.Columns` is accepted without importing
/// it here and creating a module cycle.
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
    const c41 = try a.q(41);
    const c42 = try a.q(42);
    const c43 = try a.q(43);
    const c44 = try a.q(44);
    const c128 = try a.q(128);
    const c255 = try a.q(255);
    const c256 = try a.q(256);
    const inv256 = try a.q(1 << 23);

    const active = try arena.oneHotSelector(&.{
        columns.is_div,
        columns.is_divu,
        columns.is_rem,
        columns.is_remu,
    }, span);
    const is_division = try a.add(columns.is_div, columns.is_divu);
    const is_signed = try a.add(columns.is_div, columns.is_rem);
    const special_case = try a.add(columns.zero_divisor, columns.r_zero);
    const valid_not_zero = try a.sub(active, columns.zero_divisor);
    const valid_not_special = try a.sub(active, special_case);
    const q_sum = try a.sum4(columns.q);
    const c_sum = try a.sum4(columns.rs2.next);
    const r_sum = try a.sum4(columns.r);
    const sign_factor = try a.sub(one, try a.mul(columns.c_sign, c2));

    var diffs: [4]types.ValueId = undefined;
    var result: [4]types.ValueId = undefined;
    var negation_carries: [4]types.ValueId = undefined;
    for (0..4) |limb| {
        diffs[limb] = try a.mul(
            sign_factor,
            try a.sub(columns.rs2.next[limb], columns.r_abs[limb]),
        );
        result[limb] = try a.add(
            try a.mul(is_division, columns.q[limb]),
            try a.mul(try a.sub(one, is_division), columns.r[limb]),
        );
        const previous = if (limb == 0) zero else negation_carries[limb - 1];
        negation_carries[limb] = try a.mul(
            try a.add(try a.add(previous, columns.r[limb]), columns.r_abs[limb]),
            inv256,
        );
    }

    var prefixes: [4]types.ValueId = undefined;
    var prefix = special_case;
    var scan: usize = 4;
    while (scan > 0) {
        scan -= 1;
        prefix = try a.add(prefix, columns.lt_markers[scan]);
        prefixes[scan] = prefix;
    }

    const c_hi = try a.mul(columns.c_sign, c255);
    const q_hi = try a.mul(columns.q_sign, c255);
    const b_hi = try a.mul(columns.b_sign, c255);
    const r_hi = try a.mul(
        try a.mul(columns.b_sign, try a.sub(one, columns.r_zero)),
        c255,
    );
    const b = columns.rs1.next;
    const c = columns.rs2.next;
    const q = columns.q;
    const r = columns.r;
    var carry: [8]types.ValueId = undefined;
    carry[0] = try a.mul(
        try a.sub(try a.add(try a.mul(c[0], q[0]), r[0]), b[0]),
        inv256,
    );
    carry[1] = try a.mul(
        try a.sub(
            try a.add(
                try a.add(try a.add(carry[0], try a.mul(c[0], q[1])), try a.mul(c[1], q[0])),
                r[1],
            ),
            b[1],
        ),
        inv256,
    );
    carry[2] = try a.mul(
        try a.sub(
            try a.add(
                try a.add(
                    try a.add(try a.add(carry[1], try a.mul(c[0], q[2])), try a.mul(c[1], q[1])),
                    try a.mul(c[2], q[0]),
                ),
                r[2],
            ),
            b[2],
        ),
        inv256,
    );
    carry[3] = try a.mul(
        try a.sub(
            try a.add(
                try a.add(
                    try a.add(
                        try a.add(try a.add(carry[2], try a.mul(c[0], q[3])), try a.mul(c[1], q[2])),
                        try a.mul(c[2], q[1]),
                    ),
                    try a.mul(c[3], q[0]),
                ),
                r[3],
            ),
            b[3],
        ),
        inv256,
    );
    carry[4] = try a.mul(
        try a.sub(
            try a.add(
                try a.add(
                    try a.add(
                        try a.add(
                            try a.add(try a.add(carry[3], try a.mul(c[0], q_hi)), try a.mul(c[1], q[3])),
                            try a.mul(c[2], q[2]),
                        ),
                        try a.mul(c[3], q[1]),
                    ),
                    try a.mul(c_hi, q[0]),
                ),
                r_hi,
            ),
            b_hi,
        ),
        inv256,
    );
    carry[5] = try a.mul(
        try a.sub(
            try a.add(
                try a.add(
                    try a.add(
                        try a.add(
                            try a.add(
                                carry[4],
                                try a.mul(try a.add(c[0], c[1]), q_hi),
                            ),
                            try a.mul(c[2], q[3]),
                        ),
                        try a.mul(c[3], q[2]),
                    ),
                    try a.mul(c_hi, try a.add(q[0], q[1])),
                ),
                r_hi,
            ),
            b_hi,
        ),
        inv256,
    );
    carry[6] = try a.mul(
        try a.sub(
            try a.add(
                try a.add(
                    try a.add(
                        try a.add(carry[5], try a.mul(try a.sub(c_sum, c[3]), q_hi)),
                        try a.mul(c[3], q[3]),
                    ),
                    try a.mul(c_hi, try a.sub(q_sum, q[3])),
                ),
                r_hi,
            ),
            b_hi,
        ),
        inv256,
    );
    carry[7] = try a.mul(
        try a.sub(
            try a.add(
                try a.add(
                    try a.add(carry[6], try a.mul(c_sum, q_hi)),
                    try a.mul(c_hi, q_sum),
                ),
                r_hi,
            ),
            b_hi,
        ),
        inv256,
    );
    const sign_checks = [2]types.ValueId{
        try a.mul(
            try a.mul(is_signed, try a.sub(b[3], try a.mul(columns.b_sign, c128))),
            c2,
        ),
        try a.mul(
            try a.mul(is_signed, try a.sub(c[3], try a.mul(columns.c_sign, c128))),
            c2,
        ),
    };

    var roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId = undefined;
    var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
    var n: usize = 0;
    roots[n] = try a.booleanOneMinus(active);
    n += 1;
    inline for (.{ columns.is_div, columns.is_divu, columns.is_rem, columns.is_remu }) |flag| {
        roots[n] = try a.booleanOneMinus(flag);
        n += 1;
    }
    inline for (.{
        columns.zero_divisor,
        columns.r_zero,
        columns.b_sign,
        columns.c_sign,
        columns.q_sign,
        columns.sign_xor,
    }) |flag| {
        roots[n] = try a.booleanOneMinus(flag);
        n += 1;
    }
    inline for (columns.lt_markers) |marker| {
        roots[n] = try a.booleanOneMinus(marker);
        n += 1;
    }
    inline for (.{ special_case, valid_not_zero, valid_not_special }) |flag| {
        roots[n] = try a.booleanOneMinus(flag);
        n += 1;
    }
    inline for (columns.rs2.next) |limb| {
        roots[n] = try a.mul(columns.zero_divisor, limb);
        n += 1;
    }
    inline for (columns.q) |limb| {
        roots[n] = try a.mul(columns.zero_divisor, try a.sub(limb, c255));
        n += 1;
    }
    roots[n] = try a.mul(valid_not_zero, try a.sub(try a.mul(c_sum, columns.c_sum_inv), one));
    n += 1;
    inline for (columns.r) |limb| {
        roots[n] = try a.mul(columns.r_zero, limb);
        n += 1;
    }
    roots[n] = try a.mul(valid_not_special, try a.sub(try a.mul(r_sum, columns.r_sum_inv), one));
    n += 1;
    roots[n] = try a.mul(try a.sub(one, is_signed), columns.b_sign);
    n += 1;
    roots[n] = try a.mul(try a.sub(one, is_signed), columns.c_sign);
    n += 1;
    roots[n] = try a.mul(
        active,
        try a.add(
            try a.sub(try a.sub(columns.sign_xor, columns.b_sign), columns.c_sign),
            try a.mul(try a.mul(columns.b_sign, columns.c_sign), c2),
        ),
    );
    n += 1;
    roots[n] = try a.mul(
        try a.mul(try a.sub(one, columns.zero_divisor), q_sum),
        try a.sub(columns.q_sign, columns.sign_xor),
    );
    n += 1;
    roots[n] = try a.mul(
        try a.mul(
            try a.sub(one, columns.zero_divisor),
            try a.sub(columns.q_sign, columns.sign_xor),
        ),
        columns.q_sign,
    );
    n += 1;
    roots[n] = try a.mul(
        columns.zero_divisor,
        try a.sub(columns.q_sign, is_signed),
    );
    n += 1;

    inline for (0..4) |limb| {
        const previous = if (limb == 0) zero else negation_carries[limb - 1];
        const carry_value = negation_carries[limb];
        roots[n] = try a.mul(
            try a.sub(one, columns.sign_xor),
            try a.sub(columns.r_abs[limb], columns.r[limb]),
        );
        n += 1;
        roots[n] = if (limb == 0)
            try a.mul(
                try a.mul(columns.sign_xor, carry_value),
                try a.sub(carry_value, one),
            )
        else
            try a.mul(
                try a.mul(
                    columns.sign_xor,
                    try a.sub(carry_value, previous),
                ),
                try a.sub(carry_value, one),
            );
        n += 1;
        roots[n] = try a.mul(
            try a.mul(columns.sign_xor, try a.sub(one, carry_value)),
            columns.r_abs[limb],
        );
        n += 1;
        roots[n] = try a.mul(
            columns.sign_xor,
            try a.sub(
                try a.mul(try a.sub(columns.r_abs[limb], c256), columns.r_inv[limb]),
                one,
            ),
        );
        n += 1;
    }
    scan = 4;
    while (scan > 0) {
        scan -= 1;
        roots[n] = try a.mul(try a.sub(one, prefixes[scan]), diffs[scan]);
        n += 1;
        roots[n] = try a.mul(
            columns.lt_markers[scan],
            try a.sub(columns.lt_diff, diffs[scan]),
        );
        n += 1;
    }
    roots[n] = try a.mul(active, try a.sub(one, prefixes[0]));
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
            try a.mul(columns.destination_nonzero, result[limb]),
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
    std.debug.assert(n == SEMANTIC_CONSTRAINT_COUNT);
    roots[n] = try a.sub(active, is_active);
    n += 1;
    std.debug.assert(n == DIRECT_CONSTRAINT_COUNT);
    for (roots, &constraints, 0..) |root, *constraint, index| {
        constraint.* = try a.assertDirect(index, root);
    }

    const opcode = try a.add(
        try a.add(
            try a.add(try a.mul(columns.is_div, c41), try a.mul(columns.is_divu, c42)),
            try a.mul(columns.is_rem, c43),
        ),
        try a.mul(columns.is_remu, c44),
    );
    return .{
        .active = active,
        .is_division = is_division,
        .is_signed = is_signed,
        .special_case = special_case,
        .valid_not_zero_divisor = valid_not_zero,
        .valid_not_special = valid_not_special,
        .q_sum = q_sum,
        .c_sum = c_sum,
        .r_sum = r_sum,
        .diffs = diffs,
        .result = result,
        .negation_carries = negation_carries,
        .prefixes = prefixes,
        .product_carries = carry,
        .sign_checks = sign_checks,
        .opcode = opcode,
        .constraints = constraints,
        .roots = roots,
    };
}
