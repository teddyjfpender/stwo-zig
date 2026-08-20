//! Backend-scoped secure-composition dispatch for the Metal backend.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const work_profile = @import("stwo_prover_api").work_profile;
const base_polynomial = @import("base_polynomial_composition.zig");
const secure_composition = @import("secure_composition.zig");
const composition_work = prover.air.composition_work;

pub fn computeCompositionEvaluation(
    allocator: std.mem.Allocator,
    components: []const prover.air.component_prover.ComponentProver,
    random_coeff: core.fields.qm31.QM31,
    trace: *const prover.air.component_prover.Trace,
    residency_handles: []const ?*anyopaque,
    composition_twiddles: ?prover.poly.twiddles.TwiddleTree([]const core.fields.m31.M31),
) !?prover.secure_column.SecureColumnByCoords {
    return computeCompositionEvaluationWithWorkCapture(
        allocator,
        components,
        random_coeff,
        trace,
        residency_handles,
        composition_twiddles,
        null,
    );
}

/// Optional exact-work path. The legacy hook delegates here with no capture,
/// preserving the ordinary backend ABI and keeping profiling branches out of
/// every Metal kernel.
pub fn computeCompositionEvaluationWithWorkCapture(
    allocator: std.mem.Allocator,
    components: []const prover.air.component_prover.ComponentProver,
    random_coeff: core.fields.qm31.QM31,
    trace: *const prover.air.component_prover.Trace,
    residency_handles: []const ?*anyopaque,
    composition_twiddles: ?prover.poly.twiddles.TwiddleTree([]const core.fields.m31.M31),
    work_capture: ?*composition_work.Capture,
) !?prover.secure_column.SecureColumnByCoords {
    if (try base_polynomial.evaluateWithWorkCapture(
        allocator,
        components,
        random_coeff,
        trace,
        residency_handles,
        work_capture,
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
) !work_profile.M31InterpolationBackendResult {
    return secure_composition.interpolateLargeSecureComposition(
        allocator,
        values,
        domain,
        twiddle_tree,
    );
}
