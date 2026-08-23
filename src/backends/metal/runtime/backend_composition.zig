//! Backend-scoped secure-composition dispatch for the Metal backend.

const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const work_profile = @import("stwo_prover_api").work_profile;
const base_polynomial = @import("base_polynomial_composition.zig");
const secure_composition = @import("secure_composition.zig");
const composition_work = prover.air.composition_work;
const composition_execution = prover.air.composition_execution;

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

/// Execution-aware entry point used by profiled proofs. Resident work remains
/// on Metal; host-only components are scheduled by the backend as a bounded
/// task graph under the exact request authority.
pub fn computeCompositionEvaluationWithExecution(
    allocator: std.mem.Allocator,
    components: []const prover.air.component_prover.ComponentProver,
    random_coeff: core.fields.qm31.QM31,
    trace: *const prover.air.component_prover.Trace,
    residency_handles: []const ?*anyopaque,
    composition_twiddles: ?prover.poly.twiddles.TwiddleTree([]const core.fields.m31.M31),
    execution: composition_execution.Execution,
) !?prover.secure_column.SecureColumnByCoords {
    if (try base_polynomial.evaluateWithExecution(
        allocator,
        components,
        random_coeff,
        trace,
        residency_handles,
        execution,
    )) |evaluation| return evaluation;
    if (execution.task_recorder != null) {
        return error.ProfiledMetalCompositionDeclined;
    }
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

test "profiled Metal composition fails closed when the resident route declines" {
    const TreeVec = core.pcs.TreeVec;
    const Poly = prover.air.component_prover.Poly;
    var trace = prover.air.component_prover.Trace{
        .polys = TreeVec([]const Poly).initOwned(
            try std.testing.allocator.alloc([]const Poly, 0),
        ),
    };
    defer trace.polys.deinit(std.testing.allocator);
    var recorder = @import("stwo_prover_api").stage_profile.Recorder.init(
        std.testing.allocator,
        "Debug",
        "metal-profiled-decline",
    );
    defer recorder.deinit();
    try std.testing.expectError(
        error.ProfiledMetalCompositionDeclined,
        computeCompositionEvaluationWithExecution(
            std.testing.allocator,
            &.{},
            core.fields.qm31.QM31.zero(),
            &trace,
            &.{},
            null,
            .{
                .worker_budget = prover.work_pool.WorkerBudget.serial(),
                .pool = null,
                .host_byte_budget = std.math.maxInt(usize),
                .contention_policy = .strict,
                .explicit = true,
                .requested_worker_count = 1,
                .pool_capacity = 1,
                .task_recorder = &recorder,
            },
        ),
    );
    var profile = try recorder.taskSnapshot(std.testing.allocator);
    defer profile.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), profile.graphs.len);
}
