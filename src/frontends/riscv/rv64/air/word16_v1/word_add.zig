//! One Word16 carry identity shared by ALU and effective-address arithmetic.
//! Callers separately authenticate U16 operands/result and Boolean carries.
//! Under those bounds the integer residual has absolute value below 2^17 < p.
const E = @import("../evaluation.zig");
pub inline fn limbResidualFor(comptime F: type, a: F, b: F, carry_in: F, sum: F, carry_out: F) F {
    return a.add(b).add(carry_in).sub(sum).sub(E.qFor(F, 65536).mul(carry_out));
}
