const std = @import("std");

const metal = @import("stwo_metal_backend").runtime;
const metal_telemetry = @import("stwo_metal_backend").telemetry;
const composition = @import("stwo_cairo_frontend").witness.composition_bundle;
const codegen = @import("eval_codegen.zig");
const composition_aot = @import("composition_aot.zig");

pub const Inputs = struct {
    allocator: std.mem.Allocator,
    runtime: *metal.Runtime,
    bundle: *const composition.Bundle,
    metallib_path: []const u8,
    /// Integrity admission for `metallib_path`. Defaults to the gating policy
    /// so that a caller that forgets to think about it gets the safe one.
    policy: composition_aot.Policy = .approved_manifest,
};

pub const Evidence = struct {
    expected_plan_count: u64,
    resolved_plan_count: u64,
    plan_preparation_ns: u64,
    cache_delta: metal_telemetry.PipelineCacheDelta,
    /// The measured identity of the library that was actually loaded.
    metallib_sha256: [32]u8,
    metallib_length: u64,
    metallib_label: ?[]const u8,
};

pub const AdmissionError = error{
    EmptyPlanSet,
    UnresolvedPlans,
    PipelineCacheHitCountMismatch,
    UnexpectedLibraryCacheMiss,
    UnexpectedBinaryArchiveHit,
    UnexpectedBinaryArchiveMiss,
    UnexpectedDirectCompile,
    UnexpectedArchivePopulation,
    UnexpectedArchiveSerialization,
};

/// Resolves every composition pipeline from an AOT library and persists any
/// binary-archive additions made by this pass. The evidence covers library
/// admission, all pipeline resolutions, and archive serialization.
pub fn prewarm(inputs: Inputs) !Evidence {
    const expected_plan_count = try expectedPlanCount(inputs.bundle);
    // Integrity before load. A failure here is terminal for this path: the
    // caller must not retry with a weaker policy.
    const admission = try composition_aot.authenticate(inputs.metallib_path, inputs.policy);
    const before = inputs.runtime.pipelineCacheStats();
    var library = try inputs.runtime.loadEvalLibrary(inputs.metallib_path);
    defer library.deinit();

    var timer = try std.time.Timer.start();
    var plan_preparation_ns: u64 = 0;
    var resolved_plan_count: u64 = 0;
    for (inputs.bundle.components) |component| for (component.parts) |part| {
        const name = try codegen.kernelName(inputs.allocator, part.semantic_hash);
        defer inputs.allocator.free(name);
        timer.reset();
        var plan = try inputs.runtime.prepareEvalFromLibrary(
            library,
            name,
            evalLayout(component, part),
        );
        plan_preparation_ns = std.math.add(
            u64,
            plan_preparation_ns,
            timer.read(),
        ) catch return error.PreparationTimeOverflow;
        plan.deinit();
        resolved_plan_count += 1;
    };
    try library.serialize();

    return .{
        .expected_plan_count = expected_plan_count,
        .resolved_plan_count = resolved_plan_count,
        .plan_preparation_ns = plan_preparation_ns,
        .cache_delta = metal_telemetry.PipelineCacheDelta.between(
            inputs.runtime.pipelineCacheStats(),
            before,
        ),
        .metallib_sha256 = admission.measurement.sha256,
        .metallib_length = admission.measurement.length,
        .metallib_label = admission.label,
    };
}

/// Accepts only a genuine warm-runtime second pass. Library-cache hits and
/// preparation timings are evidence, not rejection conditions.
pub fn validateSecondPass(evidence: Evidence) AdmissionError!void {
    if (evidence.expected_plan_count == 0) return AdmissionError.EmptyPlanSet;
    if (evidence.resolved_plan_count != evidence.expected_plan_count)
        return AdmissionError.UnresolvedPlans;
    if (evidence.cache_delta.pipeline_cache_hits != evidence.expected_plan_count)
        return AdmissionError.PipelineCacheHitCountMismatch;
    if (evidence.cache_delta.library_cache_misses != 0)
        return AdmissionError.UnexpectedLibraryCacheMiss;
    if (evidence.cache_delta.binary_archive_hits != 0)
        return AdmissionError.UnexpectedBinaryArchiveHit;
    if (evidence.cache_delta.binary_archive_misses != 0)
        return AdmissionError.UnexpectedBinaryArchiveMiss;
    if (evidence.cache_delta.direct_compiles != 0)
        return AdmissionError.UnexpectedDirectCompile;
    if (evidence.cache_delta.archive_populations != 0)
        return AdmissionError.UnexpectedArchivePopulation;
    if (evidence.cache_delta.archive_serializations != 0)
        return AdmissionError.UnexpectedArchiveSerialization;
}

fn expectedPlanCount(bundle: *const composition.Bundle) !u64 {
    var count: u64 = 0;
    for (bundle.components) |component| {
        count = std.math.add(u64, count, component.parts.len) catch
            return error.PlanCountOverflow;
    }
    return count;
}

fn evalLayout(
    component: composition.Component,
    part: composition.Part,
) metal.EvalLayout {
    return .{
        .trace_offsets = 0,
        .interaction_offsets = 0,
        .base_params = 0,
        .ext_params = 0,
        .random_coeffs = 0,
        .denom_inv = 0,
        .coordinates = .{ 0, 0, 0, 0 },
        .row_count = @as(u32, 1) << @intCast(component.evaluation_log_size),
        .trace_log_size = component.trace_log_size,
        .domain_log_size = part.program.header.domain_log_size,
        .rc_base = part.rc_base,
    };
}

fn warmEvidence() Evidence {
    return .{
        .expected_plan_count = 3,
        .resolved_plan_count = 3,
        .plan_preparation_ns = 17,
        .cache_delta = .{
            .library_cache_hits = 1,
            .pipeline_cache_hits = 3,
            .pipeline_preparation_seconds = 0.25,
            .library_preparation_seconds = 0.125,
        },
    };
}

test "composition prewarm accepts an exact cache-only second pass" {
    try validateSecondPass(warmEvidence());
}

test "composition prewarm rejects incomplete second-pass evidence" {
    var evidence = warmEvidence();
    evidence.expected_plan_count = 0;
    evidence.resolved_plan_count = 0;
    evidence.cache_delta.pipeline_cache_hits = 0;
    try std.testing.expectError(AdmissionError.EmptyPlanSet, validateSecondPass(evidence));

    evidence = warmEvidence();
    evidence.resolved_plan_count -= 1;
    try std.testing.expectError(AdmissionError.UnresolvedPlans, validateSecondPass(evidence));

    evidence = warmEvidence();
    evidence.cache_delta.pipeline_cache_hits -= 1;
    try std.testing.expectError(AdmissionError.PipelineCacheHitCountMismatch, validateSecondPass(evidence));
}

test "composition prewarm rejects work outside the runtime caches" {
    var evidence = warmEvidence();
    evidence.cache_delta.library_cache_misses = 1;
    try std.testing.expectError(AdmissionError.UnexpectedLibraryCacheMiss, validateSecondPass(evidence));

    evidence = warmEvidence();
    evidence.cache_delta.binary_archive_hits = 1;
    try std.testing.expectError(AdmissionError.UnexpectedBinaryArchiveHit, validateSecondPass(evidence));

    evidence = warmEvidence();
    evidence.cache_delta.binary_archive_misses = 1;
    try std.testing.expectError(AdmissionError.UnexpectedBinaryArchiveMiss, validateSecondPass(evidence));

    evidence = warmEvidence();
    evidence.cache_delta.direct_compiles = 1;
    try std.testing.expectError(AdmissionError.UnexpectedDirectCompile, validateSecondPass(evidence));

    evidence = warmEvidence();
    evidence.cache_delta.archive_populations = 1;
    try std.testing.expectError(AdmissionError.UnexpectedArchivePopulation, validateSecondPass(evidence));

    evidence = warmEvidence();
    evidence.cache_delta.archive_serializations = 1;
    try std.testing.expectError(AdmissionError.UnexpectedArchiveSerialization, validateSecondPass(evidence));
}
