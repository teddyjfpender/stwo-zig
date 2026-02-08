const std = @import("std");
const canonic = @import("../../../core/poly/circle/canonic.zig");
const eval_mod = @import("evaluation.zig");
const poly = @import("poly.zig");
const secure_poly = @import("secure_poly.zig");

pub const PolyOpsError = poly.PolyError || eval_mod.EvaluationError || secure_poly.SecurePolyError;

pub fn evaluateOnCanonicDomain(
    allocator: std.mem.Allocator,
    coefficients: poly.CircleCoefficients,
    log_blowup_factor: u32,
) (std.mem.Allocator.Error || PolyOpsError)!eval_mod.CircleEvaluation {
    const domain = canonic.CanonicCoset.new(
        coefficients.logSize() + log_blowup_factor,
    ).circleDomain();
    return coefficients.evaluate(allocator, domain);
}

pub fn splitAtMid(
    allocator: std.mem.Allocator,
    coefficients: poly.CircleCoefficients,
) (std.mem.Allocator.Error || PolyOpsError)!poly.CircleCoefficients.SplitPair {
    return coefficients.splitAtMid(allocator);
}

pub fn splitSecureAtMid(
    allocator: std.mem.Allocator,
    coefficients: secure_poly.SecureCirclePoly,
) (std.mem.Allocator.Error || PolyOpsError)!secure_poly.SecureCirclePoly.SplitPair {
    return coefficients.splitAtMid(allocator);
}

test "prover poly circle ops: evaluate on canonic domain applies blowup" {
    const alloc = std.testing.allocator;
    const m31 = @import("../../../core/fields/m31.zig");

    const coeffs = [_]m31.M31{
        m31.M31.fromCanonical(9),
        m31.M31.fromCanonical(0),
    };
    const poly_coeffs = try poly.CircleCoefficients.initBorrowed(coeffs[0..]);
    const eval = try evaluateOnCanonicDomain(alloc, poly_coeffs, 2);
    defer alloc.free(@constCast(eval.values));

    try std.testing.expectEqual(@as(usize, 8), eval.values.len);
}
