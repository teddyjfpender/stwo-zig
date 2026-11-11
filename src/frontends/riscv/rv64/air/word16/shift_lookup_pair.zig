//! Strict rational pair shared by the two concrete SHIFT representations.
const E = @import("../evaluation.zig");
pub fn forDenominators(comptime F: type, a: E.SecureFor(F), b: ?E.SecureFor(F), inverse: E.SecureFor(F)) struct { residual: E.SecureFor(F), contribution: E.SecureFor(F) } {
    const S = E.SecureFor(F);
    const product = if (b) |value| a.mul(value) else a;
    const numerator = if (b) |value| a.add(value) else S.one();
    return .{ .residual = product.mul(inverse).sub(S.one()), .contribution = numerator.mul(inverse) };
}

pub fn weightedForDenominators(comptime F: type, a: E.SecureFor(F), b: E.SecureFor(F), inverse: E.SecureFor(F), weight_a: F, weight_b: F) struct { residual: E.SecureFor(F), contribution: E.SecureFor(F) } {
    const pair = forDenominators(F, a, b, inverse);
    return .{ .residual = pair.residual, .contribution = E.mulBaseFor(F, b, weight_a).add(E.mulBaseFor(F, a, weight_b)).mul(inverse) };
}
