//! Coordinate-wise QM31 operations used by recursion circuits.
//!
//! A circuit wire carries a QM31 `(x0 + x1·i) + (x2 + x3·i)·u` but several
//! gates treat it as four independent M31 lanes. These helpers are that lane
//! view, ported from `crates/circuits/src/ivalue.rs` (`impl IValue for QM31`)
//! of https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230. None of them is the field
//! multiplication or inverse of QM31; every result is canonical.

const std = @import("std");
const m31 = @import("m31.zig");
const qm31 = @import("qm31.zig");

const M31 = m31.M31;
const QM31 = qm31.QM31;

/// Builds a QM31 from four u32 coordinates, each fully reduced modulo P.
///
/// This is `qm31_from_u32s`, whose `u32 -> M31` conversion is `M31::reduce`:
/// `P` maps to 0 and `2^32 - 1` maps to 1. It is deliberately not
/// `QM31.fromU32Unchecked`, which keeps non-canonical words.
pub fn fromU32s(a: u32, b: u32, c: u32, d: u32) QM31 {
    return QM31.fromM31(M31.fromU64(a), M31.fromU64(b), M31.fromU64(c), M31.fromU64(d));
}

/// `(x0·y0) + (x1·y1)·i + (x2·y2)·u + (x3·y3)·iu`.
pub fn pointwiseMul(lhs: QM31, rhs: QM31) QM31 {
    const l = lhs.toM31Array();
    const r = rhs.toM31Array();
    return QM31.fromM31(l[0].mul(r[0]), l[1].mul(r[1]), l[2].mul(r[2]), l[3].mul(r[3]));
}

/// Each coordinate `x` becomes `1/x`, or 0 when `x == 0`.
pub fn pointwiseInvOrZero(value: QM31) QM31 {
    const v = value.toM31Array();
    return QM31.fromM31(invOrZero(v[0]), invOrZero(v[1]), invOrZero(v[2]), invOrZero(v[3]));
}

/// Each coordinate becomes its least significant bit (of the canonical value).
pub fn pointwiseLsb(value: QM31) QM31 {
    const v = value.toM31Array();
    return QM31.fromU32Unchecked(v[0].v & 1, v[1].v & 1, v[2].v & 1, v[3].v & 1);
}

fn invOrZero(value: M31) M31 {
    if (value.isZero()) return M31.zero();
    return value.invUncheckedNonZero();
}

test "qm31 pointwise: fromU32s fully reduces every coordinate" {
    const value = fromU32s(m31.Modulus, std.math.maxInt(u32), m31.Modulus - 1, 5);
    try std.testing.expect(value.eql(QM31.fromU32Unchecked(0, 1, m31.Modulus - 1, 5)));
}

test "qm31 pointwise: inv_or_zero matches upstream ivalue_test" {
    // `test_pointwise_inv_or_zero`, crates/circuits/src/ivalue_test.rs.
    const inverse = pointwiseInvOrZero(fromU32s(2, 0, 3, 4));
    const one = M31.one();
    const expected = QM31.fromM31(
        try one.div(M31.fromCanonical(2)),
        M31.zero(),
        try one.div(M31.fromCanonical(3)),
        try one.div(M31.fromCanonical(4)),
    );
    try std.testing.expect(inverse.eql(expected));
    try std.testing.expect(pointwiseInvOrZero(QM31.zero()).eql(QM31.zero()));
}

test "qm31 pointwise: mul is per coordinate, not the extension product" {
    const lhs = fromU32s(2, 3, 5, 7);
    const rhs = fromU32s(11, 13, m31.Modulus - 1, 0);
    const product = pointwiseMul(lhs, rhs);
    try std.testing.expect(product.eql(QM31.fromU32Unchecked(22, 39, m31.Modulus - 5, 0)));
    try std.testing.expect(!product.eql(lhs.mul(rhs)));

    // Every coordinate times its inverse-or-zero is its indicator.
    const mixed = fromU32s(0, 9, 0, m31.Modulus - 2);
    try std.testing.expect(pointwiseMul(mixed, pointwiseInvOrZero(mixed)).eql(fromU32s(0, 1, 0, 1)));
}

test "qm31 pointwise: lsb reads the canonical coordinate" {
    const value = fromU32s(0, 1, m31.Modulus - 1, m31.Modulus + 3);
    try std.testing.expect(pointwiseLsb(value).eql(fromU32s(0, 1, 0, 1)));
}
