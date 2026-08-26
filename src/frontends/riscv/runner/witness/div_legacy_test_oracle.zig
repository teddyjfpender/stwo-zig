//! Test-only oracle for the retired handwritten DIV/REM witness writer.
//!
//! This deliberately preserves the pre-cutover arithmetic independently of
//! the typed hint kernel, so exact row and proof differentials can detect drift.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const M31 = m31.M31;
const Opcode = @import("../decode.zig").Opcode;
const w = @import("writer.zig");

const DivWitness = struct {
    zero_divisor: bool,
    r_zero: bool,
    quotient: u32,
    remainder: u32,
    b_sign: bool,
    c_sign: bool,
    q_sign: bool,
    sign_xor: bool,
    c_sum_inv: M31,
    r_sum_inv: M31,
    r_abs: [4]u32,
    r_inv: [4]M31,
    lt_markers: [4]u32,
    lt_diff: u32,
};

fn inverseOrZero(value: u32) M31 {
    if (value == 0) return M31.zero();
    return M31.fromCanonical(value).invUncheckedNonZero();
}

fn negateLimbs(limbs: [4]u32) [4]u32 {
    var carry: u32 = 1;
    var result: [4]u32 = undefined;
    for (limbs, 0..) |limb, index| {
        const value = 256 + carry - 1 - limb;
        carry = value >> 8;
        result[index] = value & 0xff;
    }
    return result;
}

fn compute(lhs: u32, rhs: u32, signed: bool) DivWitness {
    const b = [_]u32{ lhs & 0xff, (lhs >> 8) & 0xff, (lhs >> 16) & 0xff, lhs >> 24 };
    const c = [_]u32{ rhs & 0xff, (rhs >> 8) & 0xff, (rhs >> 16) & 0xff, rhs >> 24 };
    const b_sign = signed and b[3] & 0x80 != 0;
    const c_sign = signed and c[3] & 0x80 != 0;
    const zero_divisor = rhs == 0;
    const overflow = signed and lhs == 0x8000_0000 and rhs == 0xffff_ffff;

    var quotient: u32 = undefined;
    var remainder: u32 = undefined;
    var q_sign = false;
    if (zero_divisor) {
        quotient = std.math.maxInt(u32);
        remainder = lhs;
        q_sign = signed;
    } else if (overflow) {
        quotient = lhs;
        remainder = 0;
    } else if (signed) {
        const signed_lhs: i32 = @bitCast(lhs);
        const signed_rhs: i32 = @bitCast(rhs);
        quotient = @bitCast(@divTrunc(signed_lhs, signed_rhs));
        remainder = @bitCast(@rem(signed_lhs, signed_rhs));
        q_sign = quotient >> 31 == 1;
    } else {
        quotient = lhs / rhs;
        remainder = lhs % rhs;
    }

    const sign_xor = b_sign != c_sign;
    const r_zero = remainder == 0 and !zero_divisor;
    const r = [_]u32{
        remainder & 0xff,
        (remainder >> 8) & 0xff,
        (remainder >> 16) & 0xff,
        remainder >> 24,
    };
    const r_abs = if (sign_xor) negateLimbs(r) else r;
    var r_inv: [4]M31 = undefined;
    for (&r_inv, r_abs) |*inverse, limb| {
        inverse.* = M31.fromCanonical(m31.Modulus - 256 + limb).invUncheckedNonZero();
    }

    var lt_markers = [_]u32{0} ** 4;
    var lt_diff: u32 = 0;
    if (!zero_divisor and !r_zero and !overflow) {
        var index: usize = 4;
        while (index > 0) {
            index -= 1;
            if (c[index] == r_abs[index]) continue;
            lt_markers[index] = 1;
            lt_diff = if (c_sign)
                r_abs[index] -% c[index]
            else
                c[index] -% r_abs[index];
            break;
        }
    }

    var c_sum: u32 = 0;
    var r_sum: u32 = 0;
    for (c) |limb| c_sum += limb;
    for (r) |limb| r_sum += limb;
    return .{
        .zero_divisor = zero_divisor,
        .r_zero = r_zero,
        .quotient = quotient,
        .remainder = remainder,
        .b_sign = b_sign,
        .c_sign = c_sign,
        .q_sign = q_sign,
        .sign_xor = sign_xor,
        .c_sum_inv = inverseOrZero(c_sum),
        .r_sum_inv = inverseOrZero(r_sum),
        .r_abs = r_abs,
        .r_inv = r_inv,
        .lt_markers = lt_markers,
        .lt_diff = lt_diff,
    };
}

pub fn writeRow(columns: anytype, index: usize, row: anytype) void {
    const signed = row.opcode == .DIV or row.opcode == .REM;
    const witness = compute(row.rs1_val, row.rs2_val, signed);
    w.common(columns, index, 0, row);
    w.rd(columns, index, 2, row);
    w.rs1(columns, index, 12, row);
    w.rs2(columns, index, 22, row);
    w.set(columns, index, 32, w.bit(witness.zero_divisor));
    w.set(columns, index, 33, w.bit(witness.r_zero));
    w.writeLimbs(columns, index, 34, witness.quotient);
    w.writeLimbs(columns, index, 38, witness.remainder);
    w.set(columns, index, 42, w.bit(witness.b_sign));
    w.set(columns, index, 43, w.bit(witness.c_sign));
    w.set(columns, index, 44, w.bit(witness.q_sign));
    w.set(columns, index, 45, w.bit(witness.sign_xor));
    w.set(columns, index, 46, witness.c_sum_inv);
    w.set(columns, index, 47, witness.r_sum_inv);
    for (witness.r_abs, 0..) |limb, limb_index| {
        w.set(columns, index, 48 + limb_index, w.u(limb));
    }
    for (witness.r_inv, 0..) |inverse, limb_index| {
        w.set(columns, index, 52 + limb_index, inverse);
    }
    for (witness.lt_markers, 0..) |marker, limb_index| {
        w.set(columns, index, 56 + limb_index, w.u(marker));
    }
    w.set(columns, index, 60, w.u(witness.lt_diff));
    w.set(columns, index, 61, w.bit(row.opcode == .DIV));
    w.set(columns, index, 62, w.bit(row.opcode == .DIVU));
    w.set(columns, index, 63, w.bit(row.opcode == .REM));
    w.set(columns, index, 64, w.bit(row.opcode == .REMU));
    w.destination(columns, index, 65, row.rd);
}
