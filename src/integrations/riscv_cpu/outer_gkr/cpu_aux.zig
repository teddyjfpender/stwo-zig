//! Extend public binding coefficients together with one twiddle tower and
//! the caller's existing proof pool. No retained cache or committed columns.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Aux = @import("../word16_global_execution/services/gkr_local/public_aux.zig");
const M = core.fields.m31.M31;
const Poly = engine.poly.circle.CircleCoefficients;
const Eval = engine.poly.circle.CircleEvaluation;

pub fn evaluate(a: std.mem.Allocator, coefficients: *const [Aux.COLUMNS]Poly, log: u32) ![Aux.COLUMNS]Eval {
    if (log < 1 or log > @import("profile.zig").MAX_VARIABLES) return error.InvalidHybridAuxGeometry;
    const rows = @as(usize, 1) << @intCast(log);
    for (coefficients) |poly| if (poly.log_size != log or poly.coeffs.len != rows) return error.InvalidHybridAuxGeometry;
    const domain = core.poly.circle.canonic.CanonicCoset.new(log + 1).circleDomain();
    var twiddles = try engine.poly.twiddles.precomputeM31(a, domain.half_coset);
    defer engine.poly.twiddles.deinitM31(a, &twiddles);
    var values: [Aux.COLUMNS][]M = undefined;
    var made: usize = 0;
    errdefer for (values[0..made]) |column| a.free(column);
    for (&values, coefficients) |*column, poly| {
        column.* = try a.alloc(M, rows * 2);
        made += 1;
        @memcpy(column.*[0..rows], poly.coeffs);
        // The fused 2x transform duplicates the lower half itself. It never
        // reads the uninitialized upper half before producing its values.
    }
    try engine.poly.circle.poly.evaluateExtensionBuffersWithTwiddlesWithPool(&values, domain, .{ .root_coset = twiddles.root_coset, .twiddles = twiddles.twiddles, .itwiddles = twiddles.itwiddles }, engine.work_pool.currentScopedPool());
    var result: [Aux.COLUMNS]Eval = undefined;
    for (&result, values) |*evaluation, column| evaluation.* = try Eval.init(domain, column);
    return result;
}
