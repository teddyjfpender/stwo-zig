//! Degree-three AIR for one compact non-native modular linear-operation row.
//!
//! The row covers modular add, subtract, and one-step reduction. Values stay
//! in the guest-native radix-256 representation; a three-valued carry code
//! authenticates the byte recurrence without a wide integer column.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const affine = @import("secp256k1_affine.zig");
const field = @import("secp256k1_field.zig");

pub const Error = error{
    InvalidOperation,
    NonCanonicalOperand,
    InvalidResult,
    InvalidCarry,
};

pub const Layout = struct {
    pub const is_active: usize = 0;
    pub const selector_add: usize = is_active + 1;
    pub const selector_subtract: usize = selector_add + 1;
    pub const selector_reduce_once: usize = selector_subtract + 1;
    pub const quotient: usize = selector_reduce_once + 1;
    pub const lhs: usize = quotient + 1;
    pub const rhs: usize = lhs + field.limb_count;
    pub const result: usize = rhs + field.limb_count;
    pub const carry_code: usize = result + field.limb_count;
    pub const canonical_sum: usize = carry_code + field.limb_count + 1;
    pub const canonical_carry: usize = canonical_sum + field.limb_count;
    pub const main_columns: usize = canonical_carry + field.limb_count + 1;
};

pub const range_pair_count: usize = 2 * field.limb_count;
pub const constraint_count: usize = 1 + 3 + 1 + 1 +
    (field.limb_count + 1) + 2 +
    (field.limb_count + 1) + 2 +
    field.limb_count + field.limb_count + field.limb_count;
pub const maximum_constraint_degree: u8 = 3;

comptime {
    if (Layout.main_columns != 199)
        @compileError("secp linear row geometry drifted");
    if (range_pair_count != 64)
        @compileError("secp linear range geometry drifted");
    if (constraint_count != 172)
        @compileError("secp linear constraint inventory drifted");
}

pub fn rowFromRecord(
    record: *const affine.LinearRecord,
) Error![Layout.main_columns]M31 {
    const modulus = record.modulus.modulus();
    const modulus_value = modulus.integer();
    const lhs_value = integer(record.lhs);
    const rhs_value = integer(record.rhs);
    const result_value = integer(record.result);
    if (result_value >= modulus_value) return error.NonCanonicalOperand;

    var quotient: u1 = 0;
    switch (record.kind) {
        .add => {
            if (lhs_value >= modulus_value or rhs_value >= modulus_value)
                return error.NonCanonicalOperand;
            const wide = @as(u512, lhs_value) + @as(u512, rhs_value);
            quotient = @intFromBool(wide >= modulus_value);
            if (@as(u256, @intCast(wide - @as(u512, quotient) * modulus_value)) !=
                result_value)
            {
                return error.InvalidResult;
            }
        },
        .subtract => {
            if (lhs_value >= modulus_value or rhs_value >= modulus_value)
                return error.NonCanonicalOperand;
            quotient = @intFromBool(lhs_value < rhs_value);
            const expected = if (quotient == 1)
                modulus_value - (rhs_value - lhs_value)
            else
                lhs_value - rhs_value;
            if (expected != result_value) return error.InvalidResult;
        },
        .reduce_once => {
            if (!std.mem.eql(u8, &record.rhs, &modulus.bytes))
                return error.InvalidOperation;
            quotient = @intFromBool(lhs_value >= modulus_value);
            const expected = if (quotient == 1)
                lhs_value - modulus_value
            else
                lhs_value;
            if (expected != result_value) return error.InvalidResult;
        },
    }

    var row: [Layout.main_columns]M31 = @splat(M31.zero());
    row[Layout.is_active] = M31.one();
    row[selectorColumn(record.kind)] = M31.one();
    row[Layout.quotient] = M31.fromU64(quotient);
    writeBytes(&row, Layout.lhs, &record.lhs);
    writeBytes(&row, Layout.rhs, &record.rhs);
    writeBytes(&row, Layout.result, &record.result);

    var carry: i16 = 0;
    row[Layout.carry_code] = M31.one();
    for (0..field.limb_count) |index| {
        const coefficient = linearCoefficient(record, quotient, modulus, index) + carry;
        if (@mod(coefficient, field.radix) != 0) return error.InvalidCarry;
        const next = @divExact(coefficient, field.radix);
        if (next < -1 or next > 1) return error.InvalidCarry;
        row[Layout.carry_code + index + 1] = M31.fromU64(@intCast(next + 1));
        carry = @intCast(next);
    }
    if (carry != 0) return error.InvalidCarry;

    row[Layout.canonical_carry] = M31.zero();
    var canonical_carry: u16 = 0;
    for (0..field.limb_count) |index| {
        const sum = @as(u16, record.result[index]) +
            @as(u16, modulus.complement[index]) + canonical_carry;
        row[Layout.canonical_sum + index] = M31.fromU64(@as(u8, @truncate(sum)));
        canonical_carry = sum >> 8;
        row[Layout.canonical_carry + index + 1] = M31.fromU64(canonical_carry);
    }
    if (canonical_carry != 0) return error.NonCanonicalOperand;
    return row;
}

pub fn evaluateGeneric(
    comptime S: type,
    main: *const [Layout.main_columns]S,
    modulus: field.Modulus,
    sink: anytype,
) void {
    comptime requireSupportedField(S);
    const one = constant(S, 1);
    const two = constant(S, 2);
    const radix_value = constant(S, @intCast(field.radix));
    const active = main[Layout.is_active];
    const add = main[Layout.selector_add];
    const subtract = main[Layout.selector_subtract];
    const reduce_once = main[Layout.selector_reduce_once];
    const quotient = main[Layout.quotient];

    sink.add(active.mul(active.sub(one)), 2);
    sink.add(add.mul(add.sub(active)), 2);
    sink.add(subtract.mul(subtract.sub(active)), 2);
    sink.add(reduce_once.mul(reduce_once.sub(active)), 2);
    sink.add(add.add(subtract).add(reduce_once).sub(active), 1);
    sink.add(quotient.mul(quotient.sub(active)), 2);

    for (0..field.limb_count + 1) |index| {
        const code = main[Layout.carry_code + index];
        sink.add(code.mul(code.sub(active)).mul(code.sub(active.mul(two))), 3);
    }
    sink.add(main[Layout.carry_code].sub(active), 1);
    sink.add(main[Layout.carry_code + field.limb_count].sub(active), 1);

    for (0..field.limb_count + 1) |index| {
        const carry = main[Layout.canonical_carry + index];
        sink.add(carry.mul(carry.sub(active)), 2);
    }
    sink.add(main[Layout.canonical_carry], 1);
    sink.add(main[Layout.canonical_carry + field.limb_count], 1);

    const modulus_selector = subtract.sub(add).sub(reduce_once).mul(quotient);
    for (0..field.limb_count) |index| {
        const carry = main[Layout.carry_code + index].sub(active);
        const next_carry = main[Layout.carry_code + index + 1].sub(active);
        var equality = active.mul(main[Layout.lhs + index])
            .add(add.mul(main[Layout.rhs + index]))
            .sub(subtract.mul(main[Layout.rhs + index]))
            .sub(active.mul(main[Layout.result + index]))
            .add(modulus_selector.mul(constant(S, modulus.bytes[index])))
            .add(carry)
            .sub(next_carry.mul(radix_value));
        sink.add(equality, 2);

        equality = reduce_once.mul(
            main[Layout.rhs + index].sub(constant(S, modulus.bytes[index])),
        );
        sink.add(equality, 2);

        equality = active.mul(
            main[Layout.result + index].add(constant(S, modulus.complement[index])),
        ).add(main[Layout.canonical_carry + index])
            .sub(main[Layout.canonical_sum + index])
            .sub(main[Layout.canonical_carry + index + 1].mul(radix_value));
        sink.add(equality, 2);
    }
}

pub fn rangePairs(
    comptime S: type,
    main: *const [Layout.main_columns]S,
) [range_pair_count][2]S {
    comptime requireSupportedField(S);
    var result: [range_pair_count][2]S = undefined;
    for (0..3 * field.limb_count / 2) |index| {
        const offset = Layout.lhs + 2 * index;
        result[index] = .{ main[offset], main[offset + 1] };
    }
    for (0..field.limb_count / 2) |index| {
        const offset = Layout.canonical_sum + 2 * index;
        result[3 * field.limb_count / 2 + index] =
            .{ main[offset], main[offset + 1] };
    }
    return result;
}

fn linearCoefficient(
    record: *const affine.LinearRecord,
    quotient: u1,
    modulus: field.Modulus,
    index: usize,
) i16 {
    const lhs: i16 = record.lhs[index];
    const rhs: i16 = record.rhs[index];
    const result: i16 = record.result[index];
    const modulus_byte: i16 = modulus.bytes[index];
    return switch (record.kind) {
        .add => lhs + rhs - result - @as(i16, quotient) * modulus_byte,
        .subtract => lhs - rhs - result + @as(i16, quotient) * modulus_byte,
        .reduce_once => lhs - result - @as(i16, quotient) * modulus_byte,
    };
}

fn selectorColumn(kind: affine.LinearKind) usize {
    return switch (kind) {
        .add => Layout.selector_add,
        .subtract => Layout.selector_subtract,
        .reduce_once => Layout.selector_reduce_once,
    };
}

fn integer(value: affine.Value) u256 {
    return std.mem.readInt(u256, &value, .little);
}

fn writeBytes(
    row: *[Layout.main_columns]M31,
    offset: usize,
    bytes: []const u8,
) void {
    for (bytes, 0..) |byte, index| row[offset + index] = M31.fromU64(byte);
}

fn constant(comptime S: type, value: u64) S {
    if (S == M31) return M31.fromU64(value);
    if (S == QM31) return QM31.fromBase(M31.fromU64(value));
    unreachable;
}

fn requireSupportedField(comptime S: type) void {
    if (S != M31 and S != QM31)
        @compileError("secp linear AIR supports only M31 and QM31");
}
