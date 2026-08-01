//! Backend-scoped secure-composition dispatch for the Metal backend.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const base_polynomial = @import("base_polynomial_composition.zig");
const secure_composition = @import("secure_composition.zig");

pub fn computeCompositionEvaluation(
    allocator: std.mem.Allocator,
    components: []const prover.air.component_prover.ComponentProver,
    random_coeff: core.fields.qm31.QM31,
    trace: *const prover.air.component_prover.Trace,
    residency_handles: []const ?*anyopaque,
    composition_twiddles: ?prover.poly.twiddles.TwiddleTree([]const core.fields.m31.M31),
) !?prover.secure_column.SecureColumnByCoords {
    if (try base_polynomial.evaluate(
        allocator,
        components,
        random_coeff,
        trace,
        residency_handles,
    )) |evaluation| return evaluation;
    const twiddle_tree = composition_twiddles orelse return null;
    return secure_composition.evaluateLargeRecurrenceComposition(
        allocator,
        components,
        random_coeff,
        trace,
        residency_handles,
        twiddle_tree,
    );
}

pub fn interpolateSecureComposition(
    allocator: std.mem.Allocator,
    values: *prover.secure_column.SecureColumnByCoords,
    domain: core.poly.circle.domain.CircleDomain,
    twiddle_tree: prover.poly.twiddles.TwiddleTree([]const core.fields.m31.M31),
) !bool {
    return secure_composition.interpolateLargeSecureComposition(
        allocator,
        values,
        domain,
        twiddle_tree,
    );
}
