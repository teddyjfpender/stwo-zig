const std = @import("std");
const fields = @import("fields/mod.zig");

const M31 = fields.m31.M31;
const CM31 = fields.cm31.CM31;
const QM31 = fields.qm31.QM31;

pub fn butterfly(comptime F: type, v0: *F, v1: *F, twid: M31) void {
    const tmp = mulByBase(F, v1.*, twid);
    v1.* = subF(F, v0.*, tmp);
    v0.* = addF(F, v0.*, tmp);
}

pub fn ibutterfly(comptime F: type, v0: *F, v1: *F, itwid: M31) void {
    const tmp = v0.*;
    v0.* = addF(F, tmp, v1.*);
    v1.* = mulByBase(F, subF(F, tmp, v1.*), itwid);
}

fn addF(comptime F: type, lhs: F, rhs: F) F {
    return lhs.add(rhs);
}

fn subF(comptime F: type, lhs: F, rhs: F) F {
    return lhs.sub(rhs);
}

fn mulByBase(comptime F: type, value: F, twid: M31) F {
    if (F == M31) return value.mul(twid);
    if (F == CM31) return value.mulM31(twid);
    if (F == QM31) return value.mulM31(twid);
    @compileError("unsupported field type for fft butterfly");
}

test "fft: butterfly formula for m31" {
    var v0 = M31.fromCanonical(10);
    var v1 = M31.fromCanonical(20);
    const twid = M31.fromCanonical(3);
    butterfly(M31, &v0, &v1, twid);

    try std.testing.expect(v0.eql(M31.fromCanonical(70)));
    try std.testing.expect(v1.eql(M31.fromCanonical(fields.m31.Modulus - 50)));
}

test "fft: ibutterfly after butterfly gives doubled inputs (m31)" {
    const a = M31.fromCanonical(1_234_567);
    const b = M31.fromCanonical(9_876_543);
    const twid = M31.fromCanonical(7);
    const itwid = try twid.inv();

    var v0 = a;
    var v1 = b;
    butterfly(M31, &v0, &v1, twid);
    ibutterfly(M31, &v0, &v1, itwid);

    try std.testing.expect(v0.eql(a.add(a)));
    try std.testing.expect(v1.eql(b.add(b)));
}

test "fft: butterfly supports qm31 values with m31 twiddle" {
    var v0 = QM31.fromU32Unchecked(1, 2, 3, 4);
    var v1 = QM31.fromU32Unchecked(5, 6, 7, 8);
    const twid = M31.fromCanonical(11);
    butterfly(QM31, &v0, &v1, twid);

    const expected_tmp = QM31.fromU32Unchecked(5, 6, 7, 8).mulM31(twid);
    try std.testing.expect(v0.eql(QM31.fromU32Unchecked(1, 2, 3, 4).add(expected_tmp)));
    try std.testing.expect(v1.eql(QM31.fromU32Unchecked(1, 2, 3, 4).sub(expected_tmp)));
}
