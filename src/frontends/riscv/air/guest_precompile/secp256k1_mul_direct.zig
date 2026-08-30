//! Degree-three AIR for one compact non-native modular multiplication row.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const field = @import("secp256k1_field.zig");

pub const Layout = struct {
    pub const is_active: usize = 0;
    pub const lhs: usize = is_active + 1;
    pub const rhs: usize = lhs + field.limb_count;
    pub const result: usize = rhs + field.limb_count;
    pub const quotient: usize = result + field.limb_count;
    pub const carry_low: usize = quotient + field.limb_count;
    pub const carry_high: usize = carry_low + field.carry_count;
    pub const canonical_sum: usize = carry_high + field.carry_count;
    pub const canonical_carry: usize = canonical_sum + field.limb_count;
    pub const main_columns: usize = canonical_carry + field.limb_count + 1;

    pub const first_byte: usize = lhs;
    pub const byte_column_count: usize = canonical_sum + field.limb_count - lhs;
};

pub const range_pair_count: usize = Layout.byte_column_count / 2;
pub const constraint_count: usize = 1 + (field.limb_count + 1) + 2 +
    field.limb_count + 1;
pub const maximum_constraint_degree: u8 = 3;

comptime {
    if (Layout.byte_column_count % 2 != 0)
        @compileError("secp byte columns must pair exactly for range_check_8_8");
    if (range_pair_count != 142)
        @compileError("secp range-pair geometry drifted");
    if (Layout.main_columns != 318)
        @compileError("secp multiplication row geometry drifted");
    if (constraint_count != 69)
        @compileError("secp multiplication constraint inventory drifted");
}

pub fn rowFromWitness(witness: *const field.Witness) [Layout.main_columns]M31 {
    var row: [Layout.main_columns]M31 = @splat(M31.zero());
    row[Layout.is_active] = M31.one();
    writeBytes(&row, Layout.lhs, &witness.lhs);
    writeBytes(&row, Layout.rhs, &witness.rhs);
    writeBytes(&row, Layout.result, &witness.result);
    writeBytes(&row, Layout.quotient, &witness.quotient);
    writeBytes(&row, Layout.carry_low, &witness.carry_low);
    writeBytes(&row, Layout.carry_high, &witness.carry_high);
    writeBytes(&row, Layout.canonical_sum, &witness.canonical_sum);
    writeBytes(&row, Layout.canonical_carry, &witness.canonical_carry);
    return row;
}

pub fn evaluateGeneric(
    comptime S: type,
    main: *const [Layout.main_columns]S,
    modulus: field.Modulus,
    challenge: QM31,
    sink: anytype,
) void {
    comptime requireSupportedField(S);
    const one = constant(S, 1);
    const radix_value = constant(S, @intCast(field.radix));
    const active = main[Layout.is_active];

    sink.add(active.mul(active.sub(one)), 2);
    for (0..field.limb_count + 1) |index| {
        const carry = main[Layout.canonical_carry + index];
        sink.add(carry.mul(carry.sub(one)), 2);
    }
    sink.add(active.mul(main[Layout.canonical_carry]), 2);
    sink.add(active.mul(main[Layout.canonical_carry + field.limb_count]), 2);

    for (0..field.limb_count) |index| {
        var equality = main[Layout.result + index]
            .add(constant(S, modulus.complement[index]))
            .add(main[Layout.canonical_carry + index])
            .sub(main[Layout.canonical_sum + index]);
        equality = equality.sub(
            main[Layout.canonical_carry + index + 1].mul(radix_value),
        );
        sink.add(active.mul(equality), 2);
    }

    sink.add(lift(S, active).mul(polynomialResidual(S, main, modulus, challenge)), 3);
}

pub fn rangePairs(
    comptime S: type,
    main: *const [Layout.main_columns]S,
) [range_pair_count][2]S {
    comptime requireSupportedField(S);
    var result: [range_pair_count][2]S = undefined;
    for (&result, 0..) |*pair, index| {
        const offset = Layout.first_byte + 2 * index;
        pair.* = .{ main[offset], main[offset + 1] };
    }
    return result;
}

pub fn polynomialResidual(
    comptime S: type,
    main: *const [Layout.main_columns]S,
    modulus: field.Modulus,
    challenge: QM31,
) QM31 {
    comptime requireSupportedField(S);
    const lhs = evaluateTraceBytes(S, main, Layout.lhs, field.limb_count, challenge);
    const rhs = evaluateTraceBytes(S, main, Layout.rhs, field.limb_count, challenge);
    const result = evaluateTraceBytes(S, main, Layout.result, field.limb_count, challenge);
    const quotient = evaluateTraceBytes(
        S,
        main,
        Layout.quotient,
        field.limb_count,
        challenge,
    );
    const modulus_at = evaluateConstantBytes(modulus.bytes, challenge);
    const carries = evaluateTraceCarries(S, main, challenge);
    const radix_at = QM31.fromBase(M31.fromU64(@intCast(field.radix)));
    return lhs.mul(rhs)
        .sub(result)
        .sub(quotient.mul(modulus_at))
        .sub(challenge.sub(radix_at).mul(carries));
}

fn evaluateTraceBytes(
    comptime S: type,
    main: *const [Layout.main_columns]S,
    offset: usize,
    count: usize,
    challenge: QM31,
) QM31 {
    var result = QM31.zero();
    var index = count;
    while (index != 0) {
        index -= 1;
        result = result.mul(challenge).add(lift(S, main[offset + index]));
    }
    return result;
}

fn evaluateConstantBytes(bytes: [field.limb_count]u8, challenge: QM31) QM31 {
    var result = QM31.zero();
    var index = field.limb_count;
    while (index != 0) {
        index -= 1;
        result = result.mul(challenge).addM31(M31.fromU64(bytes[index]));
    }
    return result;
}

fn evaluateTraceCarries(
    comptime S: type,
    main: *const [Layout.main_columns]S,
    challenge: QM31,
) QM31 {
    var result = QM31.zero();
    const radix_at = QM31.fromBase(M31.fromU64(@intCast(field.radix)));
    const offset_at = QM31.fromBase(M31.fromU64(@intCast(field.carry_offset)));
    var index = field.carry_count;
    while (index != 0) {
        index -= 1;
        const encoded = lift(S, main[Layout.carry_low + index]).add(
            lift(S, main[Layout.carry_high + index]).mul(radix_at),
        );
        result = result.mul(challenge).add(encoded.sub(offset_at));
    }
    return result;
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

fn lift(comptime S: type, value: S) QM31 {
    if (S == M31) return QM31.fromBase(value);
    if (S == QM31) return value;
    unreachable;
}

fn requireSupportedField(comptime S: type) void {
    if (S != M31 and S != QM31)
        @compileError("secp multiplication AIR supports only M31 and QM31");
}
