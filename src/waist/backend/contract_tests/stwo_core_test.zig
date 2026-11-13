//! Core field authority used by backend field-operation signatures.
const std = @import("std");
const core = @import("stwo_core");

test "cdc: backend field inversion preserves canonical values and rejects zero" {
    const F = core.fields.m31.M31;
    for ([_]u32{ 1, 2, 3, 0x7ffffffe }) |value| {
        const x = F.fromCanonical(value);
        const inverse = try x.inv();
        try std.testing.expect(x.mul(inverse).eql(F.one()));
        try std.testing.expect(inverse.v < core.fields.m31.Modulus);
    }
    try std.testing.expectError(error.DivisionByZero, F.zero().inv());
}
