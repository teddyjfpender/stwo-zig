//! Metal request telemetry normalization and headline-validity gates.

const std = @import("std");
const config = @import("../config.zig");
const report = @import("../report.zig");

pub const Totals = struct {
    metal_dispatches: u64 = 0,
    cpu_fallbacks: u64 = 0,
};

pub const WarmupSnapshot = struct {
    pipeline_cache: report.PipelineCacheDelta,
    archive_store: report.ArchiveStoreDelta,
};

pub fn postWarmup(snapshot: anytype) WarmupSnapshot {
    return .{
        .pipeline_cache = pipelineCache(snapshot.pipeline_cache),
        .archive_store = archiveStore(snapshot.archive_store),
    };
}

pub fn request(delta: anytype) report.BackendTelemetryDelta {
    const counters = delta.counters;
    return .{
        .classification = @tagName(delta.classification()),
        .metal_dispatches = counters.metalDispatchTotal(),
        .cpu_fallbacks = counters.cpuFallbackTotal(),
        .counters = .{
            .host_merkle_commits = counters.host_merkle_commits,
            .resident_merkle_commits = counters.resident_merkle_commits,
            .metal_quotient_dispatches = counters.metal_quotient_dispatches,
            .metal_sampled_value_dispatches = counters.metal_sampled_value_dispatches,
            .metal_circle_transform_dispatches = counters.metal_circle_transform_dispatches,
            .metal_circle_lde_dispatches = counters.metal_circle_lde_dispatches,
            .metal_fri_circle_fold_dispatches = counters.metal_fri_circle_fold_dispatches,
            .metal_fri_line_fold_dispatches = counters.metal_fri_line_fold_dispatches,
            .metal_fri_fold_commit_epochs = counters.metal_fri_fold_commit_epochs,
            .metal_qm31_coordinate_dispatches = counters.metal_qm31_coordinate_dispatches,
            .metal_relation_epochs = counters.metal_relation_epochs,
            .metal_trace_generation_dispatches = counters.metal_trace_generation_dispatches,
            .metal_trace_generation_synchronizations = counters.metal_trace_generation_synchronizations,
            .metal_trace_generation_copybacks = counters.metal_trace_generation_copybacks,
            .metal_composition_eval_dispatches = counters.metal_composition_eval_dispatches,
            .riscv_base_polynomial_eligible_components = counters.riscv_base_polynomial_eligible_components,
            .riscv_lookup_polynomial_eligible_components = counters.riscv_lookup_polynomial_eligible_components,
            .metal_riscv_base_polynomial_batch_dispatches = counters.metal_riscv_base_polynomial_batch_dispatches,
            .metal_riscv_lookup_polynomial_batch_dispatches = counters.metal_riscv_lookup_polynomial_batch_dispatches,
            .cpu_small_merkle_commits = counters.cpu_small_merkle_commits,
            .cpu_streaming_merkle_commits = counters.cpu_streaming_merkle_commits,
            .cpu_sampled_value_evaluations = counters.cpu_sampled_value_evaluations,
            .cpu_small_circle_interpolations = counters.cpu_small_circle_interpolations,
            .cpu_small_circle_evaluations = counters.cpu_small_circle_evaluations,
            .cpu_small_circle_ldes = counters.cpu_small_circle_ldes,
            .cpu_composition_evaluations = counters.cpu_composition_evaluations,
            .cpu_riscv_polynomial_composition_declines = counters.cpu_riscv_polynomial_composition_declines,
            .metal_commit_source_arena_aliases = counters.metal_commit_source_arena_aliases,
            .metal_commit_source_arena_memcpys = counters.metal_commit_source_arena_memcpys,
            .metal_commit_source_uploads = counters.metal_commit_source_uploads,
        },
        .pipeline_cache = pipelineCache(delta.pipeline_cache),
        .archive_store = archiveStore(delta.archive_store),
    };
}

pub fn archiveStore(stats: anytype) report.ArchiveStoreDelta {
    return .{
        .archive_disk_hits = stats.archive_disk_hits,
        .archive_disk_misses = stats.archive_disk_misses,
        .archive_disk_evictions = stats.archive_disk_evictions,
        .archive_disk_rebuilds = stats.archive_disk_rebuilds,
        .archive_disk_rejections = stats.archive_disk_rejections,
        .archive_disk_quarantines = stats.archive_disk_quarantines,
        .archive_lock_acquisitions = stats.archive_lock_acquisitions,
        .archive_lock_contentions = stats.archive_lock_contentions,
        .archive_lock_timeouts = stats.archive_lock_timeouts,
        .archive_publication_successes = stats.archive_publication_successes,
        .archive_publication_failures = stats.archive_publication_failures,
        .archive_bytes_published = stats.archive_bytes_published,
        .archive_bytes_evicted = stats.archive_bytes_evicted,
        .archive_persistence_bypasses = stats.archive_persistence_bypasses,
        .archive_lock_wait_seconds = stats.archive_lock_wait_seconds,
        .archive_disk_entries = stats.archive_disk_entries,
        .archive_disk_bytes = stats.archive_disk_bytes,
        .archive_disk_entry_limit = stats.archive_disk_entry_limit,
        .archive_disk_byte_limit = stats.archive_disk_byte_limit,
        .archive_per_entry_byte_limit = stats.archive_per_entry_byte_limit,
        .archive_quarantine_entries = stats.archive_quarantine_entries,
        .archive_quarantine_bytes = stats.archive_quarantine_bytes,
        .archive_quarantine_entry_limit = stats.archive_quarantine_entry_limit,
        .archive_quarantine_byte_limit = stats.archive_quarantine_byte_limit,
    };
}

pub fn pipelineCache(stats: anytype) report.PipelineCacheDelta {
    return .{
        .library_cache_hits = stats.library_cache_hits,
        .library_cache_misses = stats.library_cache_misses,
        .pipeline_cache_hits = stats.pipeline_cache_hits,
        .binary_archive_hits = stats.binary_archive_hits,
        .binary_archive_misses = stats.binary_archive_misses,
        .direct_compiles = stats.direct_compiles,
        .archive_populations = stats.archive_populations,
        .archive_serializations = stats.archive_serializations,
        .pipeline_preparation_seconds = stats.pipeline_preparation_seconds,
        .library_preparation_seconds = stats.library_preparation_seconds,
        .library_cache_entries = stats.library_cache_entries,
        .library_cache_bytes = stats.library_cache_bytes,
        .library_cache_peak_entries = stats.library_cache_peak_entries,
        .library_cache_peak_bytes = stats.library_cache_peak_bytes,
        .library_cache_evictions = stats.library_cache_evictions,
        .library_cache_rejections = stats.library_cache_rejections,
        .pipeline_cache_entries = stats.pipeline_cache_entries,
        .pipeline_cache_bytes = stats.pipeline_cache_bytes,
        .pipeline_cache_peak_entries = stats.pipeline_cache_peak_entries,
        .pipeline_cache_peak_bytes = stats.pipeline_cache_peak_bytes,
        .pipeline_cache_evictions = stats.pipeline_cache_evictions,
        .pipeline_cache_invalidations = stats.pipeline_cache_invalidations,
        .pipeline_cache_rejections = stats.pipeline_cache_rejections,
        .library_cache_entry_limit = stats.library_cache_entry_limit,
        .library_cache_byte_limit = stats.library_cache_byte_limit,
        .pipeline_cache_entry_limit = stats.pipeline_cache_entry_limit,
        .pipeline_cache_byte_limit = stats.pipeline_cache_byte_limit,
    };
}

pub fn valid(
    comptime backend: config.Backend,
    warmups: []const report.BackendTelemetryDelta,
    samples: []const report.BackendTelemetryDelta,
) bool {
    if (comptime backend == .cpu_native) return warmups.len == 0 and samples.len == 0;
    for (warmups) |delta| {
        if (delta.metal_dispatches == 0 or delta.cpu_fallbacks != 0) return false;
    }
    for (samples) |delta| {
        if (delta.metal_dispatches == 0 or
            delta.cpu_fallbacks != 0 or
            pipelinePreparationOccurred(delta.pipeline_cache) or
            archivePreparationOccurred(delta.archive_store))
            return false;
    }
    return true;
}

fn archivePreparationOccurred(store: report.ArchiveStoreDelta) bool {
    return store.archive_disk_hits > 0 or
        store.archive_disk_misses > 0 or
        store.archive_disk_evictions > 0 or
        store.archive_disk_rebuilds > 0 or
        store.archive_disk_rejections > 0 or
        store.archive_disk_quarantines > 0 or
        store.archive_lock_acquisitions > 0 or
        store.archive_lock_contentions > 0 or
        store.archive_lock_timeouts > 0 or
        store.archive_publication_successes > 0 or
        store.archive_publication_failures > 0 or
        store.archive_bytes_published > 0 or
        store.archive_bytes_evicted > 0 or
        store.archive_persistence_bypasses > 0 or
        store.archive_lock_wait_seconds > 0;
}

pub fn sum(
    warmups: []const report.BackendTelemetryDelta,
    samples: []const report.BackendTelemetryDelta,
) Totals {
    var result: Totals = .{};
    for (warmups) |delta| {
        result.metal_dispatches +|= delta.metal_dispatches;
        result.cpu_fallbacks +|= delta.cpu_fallbacks;
    }
    for (samples) |delta| {
        result.metal_dispatches +|= delta.metal_dispatches;
        result.cpu_fallbacks +|= delta.cpu_fallbacks;
    }
    return result;
}

fn pipelinePreparationOccurred(cache: report.PipelineCacheDelta) bool {
    // Cache-hit lookup time is still accumulated; counters identify samples
    // that actually create or load library or pipeline state after warmup.
    return cache.library_cache_misses > 0 or
        cache.binary_archive_hits > 0 or
        cache.binary_archive_misses > 0 or
        cache.direct_compiles > 0 or
        cache.archive_populations > 0 or
        cache.archive_serializations > 0;
}

test "every Metal request needs a dispatch" {
    const accelerated = report.BackendTelemetryDelta{
        .classification = "accelerated_without_fallbacks",
        .metal_dispatches = 1,
        .cpu_fallbacks = 0,
        .counters = .{},
        .pipeline_cache = .{},
        .archive_store = .{},
    };
    var host_only = accelerated;
    host_only.metal_dispatches = 0;
    try std.testing.expect(valid(.metal_hybrid, &.{accelerated}, &.{accelerated}));
    try std.testing.expect(!valid(.metal_hybrid, &.{accelerated}, &.{host_only}));
    var fallback = accelerated;
    fallback.classification = "accelerated_with_fallbacks";
    fallback.cpu_fallbacks = 1;
    try std.testing.expect(!valid(.metal_hybrid, &.{fallback}, &.{accelerated}));
    try std.testing.expect(!valid(.metal_hybrid, &.{accelerated}, &.{fallback}));
    var cold = accelerated;
    cold.pipeline_cache.direct_compiles = 1;
    try std.testing.expect(!valid(.metal_hybrid, &.{accelerated}, &.{cold}));
    cold = accelerated;
    cold.archive_store.archive_disk_hits = 1;
    try std.testing.expect(!valid(.metal_hybrid, &.{accelerated}, &.{cold}));
    try std.testing.expect(valid(.cpu_native, &.{}, &.{}));
}

test "library misses are cold but hit timing is warm" {
    var cache = report.PipelineCacheDelta{};
    cache.library_cache_misses = 1;
    try std.testing.expect(pipelinePreparationOccurred(cache));

    cache = .{};
    cache.library_cache_hits = 1;
    cache.pipeline_preparation_seconds = 0.125;
    cache.library_preparation_seconds = 0.25;
    try std.testing.expect(!pipelinePreparationOccurred(cache));
}
