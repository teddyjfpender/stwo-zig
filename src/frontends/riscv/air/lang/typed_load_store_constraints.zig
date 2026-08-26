//! Compatibility-exact direct polynomial authorship for RV32 load/store.
//!
//! This is a literal typed transcription of `air/semantics/load_store.zig`:
//! 62 family roots followed by the placement root. Keeping it separate makes
//! the byte/half/word masks and sign-extension equations reviewable in their
//! production order.

const std = @import("std");
const ir = @import("ir.zig");
const source = @import("source.zig");
const types = @import("types.zig");

pub const SEMANTIC_CONSTRAINT_COUNT: usize = 62;
pub const DIRECT_CONSTRAINT_COUNT: usize = SEMANTIC_CONSTRAINT_COUNT + 1;
pub const SOURCE_ADDRESS_CONSTRAINT_INDEX: usize = 16;
pub const DESTINATION_ADDRESS_CONSTRAINT_INDEX: usize = 17;

pub const Result = struct {
    active: types.ValueId,
    opcode_b: types.ValueId,
    opcode_h: types.ValueId,
    opcode_w: types.ValueId,
    is_signed: types.ValueId,
    load_b: types.ValueId,
    load_h: types.ValueId,
    is_store: types.ValueId,
    is_load: types.ValueId,
    mem_addr: types.ValueId,
    marker_sum: types.ValueId,
    shift_id: types.ValueId,
    signed_mask: types.ValueId,
    aligned_addr_quarter: types.ValueId,
    opcode_id: types.ValueId,
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

    fn sum(self: Author, values: []const types.ValueId) !types.ValueId {
        std.debug.assert(values.len != 0);
        var result = values[0];
        for (values[1..]) |value| result = try self.add(result, value);
        return result;
    }

    fn bit(self: Author, value: types.ValueId) !types.ValueId {
        return self.mul(value, try self.sub(value, self.one));
    }

    fn composeU32(self: Author, limbs: [4]types.ValueId, byte_radix: types.ValueId) !types.ValueId {
        var value = limbs[3];
        value = try self.add(try self.mul(value, byte_radix), limbs[2]);
        value = try self.add(try self.mul(value, byte_radix), limbs[1]);
        return self.add(try self.mul(value, byte_radix), limbs[0]);
    }

    fn assertDirect(self: Author, index: usize, root: types.ValueId) !types.ConstraintId {
        var name_buffer: [72]u8 = undefined;
        const name = try std.fmt.bufPrint(
            &name_buffer,
            "compat.riscv.load_store.direct.{d}",
            .{index},
        );
        return self.arena.assertZero(name, root, null, .semantic, self.span);
    }
};

/// Authors the shipped roots over a structural `typed_load_store.Columns`.
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
    const c5 = try a.q(5);
    const c19 = try a.q(19);
    const c20 = try a.q(20);
    const c21 = try a.q(21);
    const c22 = try a.q(22);
    const c23 = try a.q(23);
    const c24 = try a.q(24);
    const c25 = try a.q(25);
    const c26 = try a.q(26);
    const c255 = try a.q(255);
    const c256 = try a.q(256);
    const inv2 = try a.q(1 << 30);
    const inv4 = try a.q(1 << 29);

    const flags = [_]types.ValueId{
        columns.is_lb,
        columns.is_lh,
        columns.is_lbu,
        columns.is_lhu,
        columns.is_lw,
        columns.is_sb,
        columns.is_sh,
        columns.is_sw,
    };
    const active = try a.sum(&flags);
    const opcode_b = try a.sum(&.{ columns.is_lbu, columns.is_lb, columns.is_sb });
    const opcode_h = try a.sum(&.{ columns.is_lhu, columns.is_lh, columns.is_sh });
    const opcode_w = try a.add(columns.is_lw, columns.is_sw);
    const is_signed = try a.add(columns.is_lb, columns.is_lh);
    const load_b = try a.add(columns.is_lb, columns.is_lbu);
    const load_h = try a.add(columns.is_lh, columns.is_lhu);
    const is_store = try a.sum(&.{ columns.is_sb, columns.is_sh, columns.is_sw });
    const is_load = try a.sub(active, is_store);
    const mem_addr = try a.add(
        try a.composeU32(columns.rs1.value, c256),
        columns.imm_felt,
    );
    var marker_sum = zero;
    for (columns.markers) |marker| marker_sum = try a.add(marker_sum, marker);
    var shift_id = zero;
    for (columns.markers, 0..) |marker, index| {
        shift_id = try a.add(shift_id, try a.mul(marker, try a.q(@intCast(index))));
    }
    const signed_mask = try a.mul(try a.mul(is_signed, columns.src_msb), c255);
    const aligned_addr_quarter = try a.mul(
        try a.sub(
            try a.add(columns.src_addr_selector, columns.dst_addr_selector),
            columns.r2_idx,
        ),
        inv4,
    );
    const opcode_id = try a.sum(&.{
        try a.mul(columns.is_lb, c19),
        try a.mul(columns.is_lh, c20),
        try a.mul(columns.is_lw, c21),
        try a.mul(columns.is_lbu, c22),
        try a.mul(columns.is_lhu, c23),
        try a.mul(columns.is_sb, c24),
        try a.mul(columns.is_sh, c25),
        try a.mul(columns.is_sw, c26),
    });

    var roots: [DIRECT_CONSTRAINT_COUNT]types.ValueId = undefined;
    var n: usize = 0;
    roots[n] = try a.bit(active);
    n += 1;
    for (flags) |flag| {
        roots[n] = try a.bit(flag);
        n += 1;
    }
    roots[n] = try a.bit(columns.src_msb);
    n += 1;
    roots[n] = try a.mul(try a.sub(one, is_signed), columns.src_msb);
    n += 1;
    for (columns.markers) |marker| {
        roots[n] = try a.bit(marker);
        n += 1;
    }
    roots[n] = try a.sub(
        columns.shift_amount,
        try a.add(
            try a.mul(opcode_b, shift_id),
            try a.mul(try a.mul(opcode_h, try a.sub(shift_id, one)), inv2),
        ),
    );
    n += 1;
    roots[n] = try a.sub(
        columns.src_addr_selector,
        try a.add(
            try a.mul(is_load, try a.sub(mem_addr, columns.shift_amount)),
            try a.mul(is_store, columns.r2_idx),
        ),
    );
    n += 1;
    roots[n] = try a.sub(
        columns.dst_addr_selector,
        try a.add(
            try a.mul(is_load, columns.r2_idx),
            try a.mul(is_store, try a.sub(mem_addr, columns.shift_amount)),
        ),
    );
    n += 1;
    roots[n] = try a.mul(opcode_b, try a.sub(one, marker_sum));
    n += 1;
    roots[n] = try a.mul(opcode_h, try a.sub(c2, marker_sum));
    n += 1;
    roots[n] = try a.mul(
        try a.mul(opcode_h, try a.sub(one, shift_id)),
        try a.sub(c5, shift_id),
    );
    n += 1;

    for (1..4) |limb| {
        roots[n] = try a.mul(load_b, try a.sub(signed_mask, columns.result[limb]));
        n += 1;
    }
    for (0..4) |limb| {
        roots[n] = try a.mul(
            try a.mul(load_b, try a.sub(columns.result[0], columns.src.value[limb])),
            columns.markers[limb],
        );
        n += 1;
        roots[n] = try a.mul(
            try a.mul(columns.is_sb, try a.sub(columns.dst.next[limb], columns.src.value[0])),
            columns.markers[limb],
        );
        n += 1;
    }
    for (2..4) |limb| {
        roots[n] = try a.mul(load_h, try a.sub(signed_mask, columns.result[limb]));
        n += 1;
    }

    const low_half = try a.mul(try a.sub(c5, shift_id), inv4);
    const high_half = try a.mul(try a.sub(shift_id, one), inv4);
    roots[n] = try a.mul(
        try a.mul(load_h, low_half),
        try a.sub(columns.result[0], columns.src.value[0]),
    );
    n += 1;
    roots[n] = try a.mul(
        try a.mul(load_h, low_half),
        try a.sub(columns.result[1], columns.src.value[1]),
    );
    n += 1;
    roots[n] = try a.mul(
        try a.mul(load_h, high_half),
        try a.sub(columns.result[0], columns.src.value[2]),
    );
    n += 1;
    roots[n] = try a.mul(
        try a.mul(load_h, high_half),
        try a.sub(columns.result[1], columns.src.value[3]),
    );
    n += 1;
    roots[n] = try a.mul(
        try a.mul(columns.is_sh, low_half),
        try a.sub(columns.dst.next[0], columns.src.value[0]),
    );
    n += 1;
    roots[n] = try a.mul(
        try a.mul(columns.is_sh, low_half),
        try a.sub(columns.dst.next[1], columns.src.value[1]),
    );
    n += 1;
    roots[n] = try a.mul(
        try a.mul(columns.is_sh, high_half),
        try a.sub(columns.dst.next[2], columns.src.value[0]),
    );
    n += 1;
    roots[n] = try a.mul(
        try a.mul(columns.is_sh, high_half),
        try a.sub(columns.dst.next[3], columns.src.value[1]),
    );
    n += 1;

    for (0..4) |limb| {
        roots[n] = try a.add(
            try a.mul(columns.is_lw, try a.sub(columns.result[limb], columns.src.value[limb])),
            try a.mul(columns.is_sw, try a.sub(columns.dst.next[limb], columns.src.value[limb])),
        );
        n += 1;
    }
    const partial_store = try a.add(columns.is_sb, columns.is_sh);
    for (0..4) |limb| {
        roots[n] = try a.mul(
            try a.mul(partial_store, try a.sub(one, columns.markers[limb])),
            try a.sub(columns.dst.next[limb], columns.dst.previous[limb]),
        );
        n += 1;
    }

    roots[n] = try a.bit(columns.destination_nonzero);
    n += 1;
    roots[n] = try a.mul(columns.r2_idx, try a.sub(one, columns.destination_nonzero));
    n += 1;
    roots[n] = try a.sub(
        try a.mul(columns.r2_idx, columns.destination_inverse),
        columns.destination_nonzero,
    );
    n += 1;
    for (0..4) |limb| {
        roots[n] = try a.mul(
            is_load,
            try a.sub(
                columns.dst.next[limb],
                try a.mul(columns.destination_nonzero, columns.result[limb]),
            ),
        );
        n += 1;
    }
    for (columns.result) |limb| {
        roots[n] = try a.mul(try a.sub(one, is_load), limb);
        n += 1;
    }
    roots[n] = try a.mul(active, columns.rs1.value[3]);
    n += 1;
    roots[n] = try a.sub(active, is_active);
    n += 1;
    std.debug.assert(n == roots.len);

    var constraints: [DIRECT_CONSTRAINT_COUNT]types.ConstraintId = undefined;
    for (&constraints, roots, 0..) |*constraint, root, index|
        constraint.* = try a.assertDirect(index, root);

    return .{
        .active = active,
        .opcode_b = opcode_b,
        .opcode_h = opcode_h,
        .opcode_w = opcode_w,
        .is_signed = is_signed,
        .load_b = load_b,
        .load_h = load_h,
        .is_store = is_store,
        .is_load = is_load,
        .mem_addr = mem_addr,
        .marker_sum = marker_sum,
        .shift_id = shift_id,
        .signed_mask = signed_mask,
        .aligned_addr_quarter = aligned_addr_quarter,
        .opcode_id = opcode_id,
        .constraints = constraints,
        .roots = roots,
    };
}
