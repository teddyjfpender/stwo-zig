//! Native typed constraint authorship shared by immediate/register shifts.
//!
//! The 65 roots below are a direct structural transcription of the pinned
//! Stark-V shift core. Keeping the core in one typed source prevents witness,
//! immediate, and register variants from drifting independently.

const std = @import("std");
const ir = @import("ir.zig");
const source = @import("source.zig");
const types = @import("types.zig");

pub const CONSTRAINT_COUNT: usize = 65;

pub const AccessColumns = struct {
    addr: types.ValueId,
    previous: [4]types.ValueId,
    previous_clock: types.ValueId,
    next: [4]types.ValueId,
};

pub const Columns = struct {
    rd: AccessColumns,
    rs1: AccessColumns,
    rs1_sign: types.ValueId,
    is_sll: types.ValueId,
    is_srl: types.ValueId,
    is_sra: types.ValueId,
    bit_multiplier_left: types.ValueId,
    bit_multiplier_right: types.ValueId,
    bit_markers: [8]types.ValueId,
    limb_markers: [4]types.ValueId,
    carries: [4]types.ValueId,
    result: [4]types.ValueId,
    destination_nonzero: types.ValueId,
    destination_inverse: types.ValueId,
};

pub const Derived = struct {
    active: types.ValueId,
    right_shift: types.ValueId,
    bit_multiplier: types.ValueId,
    bit_shift: types.ValueId,
    limb_shift: types.ValueId,
    shift_amount: types.ValueId,
    bit_marker_sum: types.ValueId,
    limb_marker_sum: types.ValueId,
};

pub fn derive(
    arena: *ir.Arena,
    columns: Columns,
    span: source.SourceSpan,
) !Derived {
    const zero = try arena.constantField(0, span);
    var bit_multiplier = zero;
    var bit_shift = zero;
    var bit_marker_sum = zero;
    inline for (columns.bit_markers, 0..) |marker, index| {
        bit_multiplier = try arena.add(
            bit_multiplier,
            try arena.mul(marker, try arena.constantField(@as(u32, 1) << @intCast(index), span), span),
            span,
        );
        bit_shift = try arena.add(
            bit_shift,
            try arena.mul(marker, try arena.constantField(index, span), span),
            span,
        );
        bit_marker_sum = try arena.add(bit_marker_sum, marker, span);
    }
    var limb_shift = zero;
    var limb_marker_sum = zero;
    inline for (columns.limb_markers, 0..) |marker, index| {
        limb_shift = try arena.add(
            limb_shift,
            try arena.mul(marker, try arena.constantField(index, span), span),
            span,
        );
        limb_marker_sum = try arena.add(limb_marker_sum, marker, span);
    }
    const active = try arena.oneHotSelector(&.{
        columns.is_sll,
        columns.is_srl,
        columns.is_sra,
    }, span);
    const right_shift = try arena.add(columns.is_srl, columns.is_sra, span);
    return .{
        .active = active,
        .right_shift = right_shift,
        .bit_multiplier = bit_multiplier,
        .bit_shift = bit_shift,
        .limb_shift = limb_shift,
        .shift_amount = try arena.add(
            try arena.mul(limb_shift, try arena.constantField(8, span), span),
            bit_shift,
            span,
        ),
        .bit_marker_sum = bit_marker_sum,
        .limb_marker_sum = limb_marker_sum,
    };
}

pub fn constraintRoots(
    arena: *ir.Arena,
    columns: Columns,
    derived: Derived,
    span: source.SourceSpan,
) ![CONSTRAINT_COUNT]types.ValueId {
    @setEvalBranchQuota(100_000);
    const one = try arena.constantField(1, span);
    const c255 = try arena.constantField(255, span);
    const c256 = try arena.constantField(256, span);
    var roots: [CONSTRAINT_COUNT]types.ValueId = undefined;
    var n: usize = 0;
    roots[n] = try bitPolynomial(arena, derived.active, one, span);
    n += 1;
    inline for (.{ columns.is_sll, columns.is_srl, columns.is_sra }) |flag| {
        roots[n] = try bitPolynomial(arena, flag, one, span);
        n += 1;
    }
    roots[n] = try bitPolynomial(arena, columns.rs1_sign, one, span);
    n += 1;
    roots[n] = try arena.mul(
        try arena.sub(one, columns.is_sra, span),
        columns.rs1_sign,
        span,
    );
    n += 1;
    inline for (columns.bit_markers) |marker| {
        roots[n] = try bitPolynomial(arena, marker, one, span);
        n += 1;
    }
    inline for (columns.limb_markers) |marker| {
        roots[n] = try bitPolynomial(arena, marker, one, span);
        n += 1;
    }
    roots[n] = try arena.sub(derived.bit_marker_sum, derived.active, span);
    n += 1;
    roots[n] = try arena.sub(derived.limb_marker_sum, derived.active, span);
    n += 1;
    roots[n] = try arena.sub(
        columns.bit_multiplier_left,
        try arena.mul(columns.is_sll, derived.bit_multiplier, span),
        span,
    );
    n += 1;
    roots[n] = try arena.sub(
        columns.bit_multiplier_right,
        try arena.mul(derived.right_shift, derived.bit_multiplier, span),
        span,
    );
    n += 1;

    inline for (0..4) |i| {
        const marker = columns.limb_markers[i];
        inline for (0..4) |j| {
            if (j < i) {
                roots[n] = try arena.mul(
                    try arena.mul(columns.is_sll, marker, span),
                    columns.result[j],
                    span,
                );
            } else if (j == i) {
                roots[n] = try arena.sub(
                    try arena.mul(
                        try arena.mul(columns.is_sll, marker, span),
                        try arena.add(
                            columns.result[j],
                            try arena.mul(c256, columns.carries[0], span),
                            span,
                        ),
                        span,
                    ),
                    try arena.mul(
                        try arena.mul(marker, columns.rs1.next[0], span),
                        columns.bit_multiplier_left,
                        span,
                    ),
                    span,
                );
            } else {
                const k = j - i;
                const carry_term = try arena.sub(
                    columns.carries[k - 1],
                    try arena.mul(c256, columns.carries[k], span),
                    span,
                );
                roots[n] = try arena.sub(
                    try arena.mul(
                        try arena.mul(columns.is_sll, marker, span),
                        try arena.sub(columns.result[j], carry_term, span),
                        span,
                    ),
                    try arena.mul(
                        try arena.mul(marker, columns.rs1.next[k], span),
                        columns.bit_multiplier_left,
                        span,
                    ),
                    span,
                );
            }
            n += 1;
        }
    }

    inline for (0..4) |i| {
        const marker = columns.limb_markers[i];
        inline for (0..4) |j| {
            const input = i + j;
            if (input < 3) {
                roots[n] = try arena.mul(
                    marker,
                    try arena.sub(
                        try arena.add(
                            try arena.mul(
                                try arena.mul(
                                    columns.carries[input + 1],
                                    derived.right_shift,
                                    span,
                                ),
                                c256,
                                span,
                            ),
                            try arena.mul(
                                derived.right_shift,
                                try arena.sub(
                                    columns.rs1.next[input],
                                    columns.carries[input],
                                    span,
                                ),
                                span,
                            ),
                            span,
                        ),
                        try arena.mul(
                            columns.result[j],
                            columns.bit_multiplier_right,
                            span,
                        ),
                        span,
                    ),
                    span,
                );
            } else if (input == 3) {
                roots[n] = try arena.mul(
                    marker,
                    try arena.sub(
                        try arena.add(
                            try arena.mul(
                                try arena.mul(
                                    columns.rs1_sign,
                                    try arena.sub(columns.bit_multiplier_right, one, span),
                                    span,
                                ),
                                c256,
                                span,
                            ),
                            try arena.mul(
                                derived.right_shift,
                                try arena.sub(columns.rs1.next[3], columns.carries[3], span),
                                span,
                            ),
                            span,
                        ),
                        try arena.mul(
                            columns.result[j],
                            columns.bit_multiplier_right,
                            span,
                        ),
                        span,
                    ),
                    span,
                );
            } else {
                roots[n] = try arena.mul(
                    try arena.mul(derived.right_shift, marker, span),
                    try arena.sub(
                        columns.result[j],
                        try arena.mul(columns.rs1_sign, c255, span),
                        span,
                    ),
                    span,
                );
            }
            n += 1;
        }
    }

    roots[n] = try bitPolynomial(arena, columns.destination_nonzero, one, span);
    n += 1;
    roots[n] = try arena.mul(
        columns.rd.addr,
        try arena.sub(one, columns.destination_nonzero, span),
        span,
    );
    n += 1;
    roots[n] = try arena.sub(
        try arena.mul(columns.rd.addr, columns.destination_inverse, span),
        columns.destination_nonzero,
        span,
    );
    n += 1;
    inline for (0..4) |limb| {
        roots[n] = try arena.sub(
            columns.rd.next[limb],
            try arena.mul(columns.destination_nonzero, columns.result[limb], span),
            span,
        );
        n += 1;
    }
    inline for (0..4) |limb| {
        roots[n] = try arena.mul(
            derived.active,
            try arena.sub(columns.rs1.next[limb], columns.rs1.previous[limb], span),
            span,
        );
        n += 1;
    }
    std.debug.assert(n == roots.len);
    return roots;
}

pub fn carryUpper(
    arena: *ir.Arena,
    derived: Derived,
    span: source.SourceSpan,
) !types.ValueId {
    return arena.sub(derived.bit_multiplier, derived.active, span);
}

pub fn signHigh(
    arena: *ir.Arena,
    columns: Columns,
    span: source.SourceSpan,
) !types.ValueId {
    return arena.sub(
        columns.rs1.next[3],
        try arena.mul(columns.rs1_sign, try arena.constantField(128, span), span),
        span,
    );
}

fn bitPolynomial(
    arena: *ir.Arena,
    value: types.ValueId,
    one: types.ValueId,
    span: source.SourceSpan,
) !types.ValueId {
    return arena.mul(value, try arena.sub(value, one, span), span);
}
