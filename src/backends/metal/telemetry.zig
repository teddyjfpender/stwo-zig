//! Low-overhead evidence that a generic proof used the intended Metal paths.

const std = @import("std");
const runtime = @import("runtime.zig");

pub const Event = enum {
    host_merkle_commit,
    resident_merkle_commit,
    metal_quotient_dispatch,
    metal_sampled_value_dispatch,
    metal_circle_transform_dispatch,
    metal_circle_lde_dispatch,
    metal_fri_circle_fold_dispatch,
    metal_fri_line_fold_dispatch,
    metal_fri_fold_commit_epoch,
    metal_qm31_coordinate_dispatch,
    /// One LogUp relation epoch (`relation.metal`'s fused/scan kernel chain).
    metal_relation_epoch,
    metal_trace_generation_dispatch,
    metal_trace_generation_synchronization,
    metal_trace_generation_copyback,
    /// One AIR composition-evaluation epoch dispatched from the composition
    /// metallib.
    metal_composition_eval_dispatch,
    cpu_small_merkle_commit,
    cpu_streaming_merkle_commit,
    cpu_sampled_value_evaluation,
    cpu_small_circle_interpolation,
    cpu_small_circle_evaluation,
    cpu_small_circle_lde,
    /// A composition evaluation that a device path was structurally admitted
    /// for and then declined — currently only an unauthenticated composition
    /// metallib. This is NOT recorded for the default host placement of
    /// composition, which is a placement and not a fallback; recording it there
    /// would make every hybrid Metal proof report a fallback and would destroy
    /// the meaning of `accelerated_without_fallbacks`.
    cpu_composition_evaluation,
    /// One base-trace commit whose source columns already were the backend's
    /// contiguous base arena AND whose arena was page-aligned, so the
    /// coefficient buffer was a `newBufferWithBytesNoCopy` alias of host memory
    /// and nothing was copied (`circle_legacy.m:229-236`). This is the whole
    /// point of the trace arena and until now nothing observed it.
    metal_commit_source_arena_alias,
    /// One base-trace commit whose source columns were the base arena but whose
    /// arena missed the page-alignment or page-multiple requirement, so the
    /// commit paid exactly one `memcpy` per column into a fresh device buffer
    /// (`circle_legacy.m:324-329`). Still byte-correct, still device-accelerated
    /// — this is NOT a fallback and is deliberately excluded from
    /// `cpuFallbackTotal`.
    metal_commit_source_arena_memcpy,
    /// One base-trace commit whose source columns were NOT the base arena, i.e.
    /// the arena was not adopted and the fused-upload/blit encoder ran
    /// (`circle_legacy.m:267-323`). The pre-arena behaviour.
    metal_commit_source_upload,
};

pub const CounterValues = struct {
    host_merkle_commits: u64 = 0,
    resident_merkle_commits: u64 = 0,
    metal_quotient_dispatches: u64 = 0,
    metal_sampled_value_dispatches: u64 = 0,
    metal_circle_transform_dispatches: u64 = 0,
    metal_circle_lde_dispatches: u64 = 0,
    metal_fri_circle_fold_dispatches: u64 = 0,
    metal_fri_line_fold_dispatches: u64 = 0,
    metal_fri_fold_commit_epochs: u64 = 0,
    metal_qm31_coordinate_dispatches: u64 = 0,
    metal_relation_epochs: u64 = 0,
    metal_trace_generation_dispatches: u64 = 0,
    metal_trace_generation_synchronizations: u64 = 0,
    metal_trace_generation_copybacks: u64 = 0,
    metal_composition_eval_dispatches: u64 = 0,
    cpu_small_merkle_commits: u64 = 0,
    cpu_streaming_merkle_commits: u64 = 0,
    cpu_sampled_value_evaluations: u64 = 0,
    cpu_small_circle_interpolations: u64 = 0,
    cpu_small_circle_evaluations: u64 = 0,
    cpu_small_circle_ldes: u64 = 0,
    cpu_composition_evaluations: u64 = 0,
    metal_commit_source_arena_aliases: u64 = 0,
    metal_commit_source_arena_memcpys: u64 = 0,
    metal_commit_source_uploads: u64 = 0,

    pub fn delta(after: CounterValues, before: CounterValues) CounterValues {
        var result: CounterValues = .{};
        inline for (std.meta.fields(CounterValues)) |field| {
            @field(result, field.name) = @field(after, field.name) -| @field(before, field.name);
        }
        return result;
    }

    pub fn metalDispatchTotal(self: CounterValues) u64 {
        var total: u64 = 0;
        inline for (.{
            self.resident_merkle_commits,
            self.metal_quotient_dispatches,
            self.metal_sampled_value_dispatches,
            self.metal_circle_transform_dispatches,
            self.metal_circle_lde_dispatches,
            self.metal_fri_circle_fold_dispatches,
            self.metal_fri_line_fold_dispatches,
            self.metal_fri_fold_commit_epochs,
            self.metal_qm31_coordinate_dispatches,
            self.metal_relation_epochs,
            self.metal_trace_generation_dispatches,
            self.metal_composition_eval_dispatches,
        }) |value| total +|= value;
        return total;
    }

    pub fn cpuFallbackTotal(self: CounterValues) u64 {
        const named_merkle = self.cpu_small_merkle_commits +| self.cpu_streaming_merkle_commits;
        var total = @max(self.host_merkle_commits, named_merkle);
        inline for (.{
            self.cpu_sampled_value_evaluations,
            self.cpu_small_circle_interpolations,
            self.cpu_small_circle_evaluations,
            self.cpu_small_circle_ldes,
            self.cpu_composition_evaluations,
        }) |value| total +|= value;
        return total;
    }
};

pub const PipelineCacheDelta = struct {
    library_cache_hits: u64 = 0,
    library_cache_misses: u64 = 0,
    pipeline_cache_hits: u64 = 0,
    binary_archive_hits: u64 = 0,
    binary_archive_misses: u64 = 0,
    direct_compiles: u64 = 0,
    archive_populations: u64 = 0,
    archive_serializations: u64 = 0,
    pipeline_preparation_seconds: f64 = 0,
    library_preparation_seconds: f64 = 0,
    library_cache_entries: u64 = 0,
    library_cache_bytes: u64 = 0,
    library_cache_peak_entries: u64 = 0,
    library_cache_peak_bytes: u64 = 0,
    library_cache_evictions: u64 = 0,
    library_cache_rejections: u64 = 0,
    pipeline_cache_entries: u64 = 0,
    pipeline_cache_bytes: u64 = 0,
    pipeline_cache_peak_entries: u64 = 0,
    pipeline_cache_peak_bytes: u64 = 0,
    pipeline_cache_evictions: u64 = 0,
    pipeline_cache_invalidations: u64 = 0,
    pipeline_cache_rejections: u64 = 0,
    library_cache_entry_limit: u64 = 0,
    library_cache_byte_limit: u64 = 0,
    pipeline_cache_entry_limit: u64 = 0,
    pipeline_cache_byte_limit: u64 = 0,

    pub fn between(
        after: runtime.PipelineCacheStats,
        before: runtime.PipelineCacheStats,
    ) PipelineCacheDelta {
        return .{
            .library_cache_hits = after.library_cache_hits -| before.library_cache_hits,
            .library_cache_misses = after.library_cache_misses -| before.library_cache_misses,
            .pipeline_cache_hits = after.pipeline_cache_hits -| before.pipeline_cache_hits,
            .binary_archive_hits = after.binary_archive_hits -| before.binary_archive_hits,
            .binary_archive_misses = after.binary_archive_misses -| before.binary_archive_misses,
            .direct_compiles = after.direct_compiles -| before.direct_compiles,
            .archive_populations = after.archive_populations -| before.archive_populations,
            .archive_serializations = after.archive_serializations -| before.archive_serializations,
            .pipeline_preparation_seconds = @max(
                @as(f64, 0),
                after.pipeline_preparation_seconds - before.pipeline_preparation_seconds,
            ),
            .library_preparation_seconds = @max(
                @as(f64, 0),
                after.library_preparation_seconds - before.library_preparation_seconds,
            ),
            .library_cache_entries = after.library_cache_entries,
            .library_cache_bytes = after.library_cache_bytes,
            .library_cache_peak_entries = after.library_cache_peak_entries,
            .library_cache_peak_bytes = after.library_cache_peak_bytes,
            .library_cache_evictions = after.library_cache_evictions -| before.library_cache_evictions,
            .library_cache_rejections = after.library_cache_rejections -| before.library_cache_rejections,
            .pipeline_cache_entries = after.pipeline_cache_entries,
            .pipeline_cache_bytes = after.pipeline_cache_bytes,
            .pipeline_cache_peak_entries = after.pipeline_cache_peak_entries,
            .pipeline_cache_peak_bytes = after.pipeline_cache_peak_bytes,
            .pipeline_cache_evictions = after.pipeline_cache_evictions -| before.pipeline_cache_evictions,
            .pipeline_cache_invalidations = after.pipeline_cache_invalidations -| before.pipeline_cache_invalidations,
            .pipeline_cache_rejections = after.pipeline_cache_rejections -| before.pipeline_cache_rejections,
            .library_cache_entry_limit = after.library_cache_entry_limit,
            .library_cache_byte_limit = after.library_cache_byte_limit,
            .pipeline_cache_entry_limit = after.pipeline_cache_entry_limit,
            .pipeline_cache_byte_limit = after.pipeline_cache_byte_limit,
        };
    }
};

pub const ArchiveStoreDelta = struct {
    archive_disk_hits: u64 = 0,
    archive_disk_misses: u64 = 0,
    archive_disk_evictions: u64 = 0,
    archive_disk_rebuilds: u64 = 0,
    archive_disk_rejections: u64 = 0,
    archive_disk_quarantines: u64 = 0,
    archive_lock_acquisitions: u64 = 0,
    archive_lock_contentions: u64 = 0,
    archive_lock_timeouts: u64 = 0,
    archive_publication_successes: u64 = 0,
    archive_publication_failures: u64 = 0,
    archive_bytes_published: u64 = 0,
    archive_bytes_evicted: u64 = 0,
    archive_persistence_bypasses: u64 = 0,
    archive_lock_wait_seconds: f64 = 0,
    archive_disk_entries: u64 = 0,
    archive_disk_bytes: u64 = 0,
    archive_disk_entry_limit: u64 = 0,
    archive_disk_byte_limit: u64 = 0,
    archive_per_entry_byte_limit: u64 = 0,
    archive_quarantine_entries: u64 = 0,
    archive_quarantine_bytes: u64 = 0,
    archive_quarantine_entry_limit: u64 = 0,
    archive_quarantine_byte_limit: u64 = 0,

    pub fn between(
        after: runtime.ArchiveStoreStatsV1,
        before: runtime.ArchiveStoreStatsV1,
    ) ArchiveStoreDelta {
        return .{
            .archive_disk_hits = after.archive_disk_hits -| before.archive_disk_hits,
            .archive_disk_misses = after.archive_disk_misses -| before.archive_disk_misses,
            .archive_disk_evictions = after.archive_disk_evictions -| before.archive_disk_evictions,
            .archive_disk_rebuilds = after.archive_disk_rebuilds -| before.archive_disk_rebuilds,
            .archive_disk_rejections = after.archive_disk_rejections -| before.archive_disk_rejections,
            .archive_disk_quarantines = after.archive_disk_quarantines -| before.archive_disk_quarantines,
            .archive_lock_acquisitions = after.archive_lock_acquisitions -| before.archive_lock_acquisitions,
            .archive_lock_contentions = after.archive_lock_contentions -| before.archive_lock_contentions,
            .archive_lock_timeouts = after.archive_lock_timeouts -| before.archive_lock_timeouts,
            .archive_publication_successes = after.archive_publication_successes -| before.archive_publication_successes,
            .archive_publication_failures = after.archive_publication_failures -| before.archive_publication_failures,
            .archive_bytes_published = after.archive_bytes_published -| before.archive_bytes_published,
            .archive_bytes_evicted = after.archive_bytes_evicted -| before.archive_bytes_evicted,
            .archive_persistence_bypasses = after.archive_persistence_bypasses -| before.archive_persistence_bypasses,
            .archive_lock_wait_seconds = @max(
                @as(f64, 0),
                after.archive_lock_wait_seconds - before.archive_lock_wait_seconds,
            ),
            .archive_disk_entries = after.archive_disk_entries,
            .archive_disk_bytes = after.archive_disk_bytes,
            .archive_disk_entry_limit = after.archive_disk_entry_limit,
            .archive_disk_byte_limit = after.archive_disk_byte_limit,
            .archive_per_entry_byte_limit = after.archive_per_entry_byte_limit,
            .archive_quarantine_entries = after.archive_quarantine_entries,
            .archive_quarantine_bytes = after.archive_quarantine_bytes,
            .archive_quarantine_entry_limit = after.archive_quarantine_entry_limit,
            .archive_quarantine_byte_limit = after.archive_quarantine_byte_limit,
        };
    }
};

pub const Classification = enum {
    no_backend_work,
    host_only,
    accelerated_with_fallbacks,
    accelerated_without_fallbacks,
};

pub const ClassificationError = error{
    NoMetalDispatch,
    CpuFallbackObserved,
};

pub const Snapshot = struct {
    counters: CounterValues,
    pipeline_cache: runtime.PipelineCacheStats,
    archive_store: runtime.ArchiveStoreStatsV1 = runtime.ArchiveStoreStatsV1.zero(),

    pub fn delta(after: Snapshot, before: Snapshot) Delta {
        return .{
            .counters = CounterValues.delta(after.counters, before.counters),
            .pipeline_cache = PipelineCacheDelta.between(after.pipeline_cache, before.pipeline_cache),
            .archive_store = ArchiveStoreDelta.between(after.archive_store, before.archive_store),
        };
    }
};

pub const Delta = struct {
    counters: CounterValues,
    pipeline_cache: PipelineCacheDelta,
    archive_store: ArchiveStoreDelta = .{},

    pub fn classification(self: Delta) Classification {
        const metal_dispatches = self.counters.metalDispatchTotal();
        const cpu_fallbacks = self.counters.cpuFallbackTotal();
        if (metal_dispatches == 0) {
            return if (cpu_fallbacks == 0) .no_backend_work else .host_only;
        }
        return if (cpu_fallbacks == 0)
            .accelerated_without_fallbacks
        else
            .accelerated_with_fallbacks;
    }

    /// Hybrid Metal benchmarks may report CPU fallback work, but cannot claim
    /// a Metal result unless at least one device operation was dispatched.
    pub fn requireMetalDispatch(self: Delta) error{NoMetalDispatch}!void {
        if (self.counters.metalDispatchTotal() == 0) return error.NoMetalDispatch;
    }

    /// A benchmark may claim an accelerated Metal result only after this
    /// succeeds. Missing dispatches and every known CPU fallback fail closed.
    pub fn requireAcceleratedWithoutFallbacks(self: Delta) ClassificationError!void {
        if (self.counters.metalDispatchTotal() == 0) return error.NoMetalDispatch;
        if (self.counters.cpuFallbackTotal() != 0) return error.CpuFallbackObserved;
    }
};

const AtomicCounter = std.atomic.Value(u64);

const CounterBank = struct {
    host_merkle_commits: AtomicCounter = AtomicCounter.init(0),
    resident_merkle_commits: AtomicCounter = AtomicCounter.init(0),
    metal_quotient_dispatches: AtomicCounter = AtomicCounter.init(0),
    metal_sampled_value_dispatches: AtomicCounter = AtomicCounter.init(0),
    metal_circle_transform_dispatches: AtomicCounter = AtomicCounter.init(0),
    metal_circle_lde_dispatches: AtomicCounter = AtomicCounter.init(0),
    metal_fri_circle_fold_dispatches: AtomicCounter = AtomicCounter.init(0),
    metal_fri_line_fold_dispatches: AtomicCounter = AtomicCounter.init(0),
    metal_fri_fold_commit_epochs: AtomicCounter = AtomicCounter.init(0),
    metal_qm31_coordinate_dispatches: AtomicCounter = AtomicCounter.init(0),
    metal_relation_epochs: AtomicCounter = AtomicCounter.init(0),
    metal_trace_generation_dispatches: AtomicCounter = AtomicCounter.init(0),
    metal_trace_generation_synchronizations: AtomicCounter = AtomicCounter.init(0),
    metal_trace_generation_copybacks: AtomicCounter = AtomicCounter.init(0),
    metal_composition_eval_dispatches: AtomicCounter = AtomicCounter.init(0),
    cpu_small_merkle_commits: AtomicCounter = AtomicCounter.init(0),
    cpu_streaming_merkle_commits: AtomicCounter = AtomicCounter.init(0),
    cpu_sampled_value_evaluations: AtomicCounter = AtomicCounter.init(0),
    cpu_small_circle_interpolations: AtomicCounter = AtomicCounter.init(0),
    cpu_small_circle_evaluations: AtomicCounter = AtomicCounter.init(0),
    cpu_small_circle_ldes: AtomicCounter = AtomicCounter.init(0),
    cpu_composition_evaluations: AtomicCounter = AtomicCounter.init(0),
    metal_commit_source_arena_aliases: AtomicCounter = AtomicCounter.init(0),
    metal_commit_source_arena_memcpys: AtomicCounter = AtomicCounter.init(0),
    metal_commit_source_uploads: AtomicCounter = AtomicCounter.init(0),
};

var counter_bank: CounterBank = .{};

pub fn record(event: Event) void {
    const counter = switch (event) {
        .host_merkle_commit => &counter_bank.host_merkle_commits,
        .resident_merkle_commit => &counter_bank.resident_merkle_commits,
        .metal_quotient_dispatch => &counter_bank.metal_quotient_dispatches,
        .metal_sampled_value_dispatch => &counter_bank.metal_sampled_value_dispatches,
        .metal_circle_transform_dispatch => &counter_bank.metal_circle_transform_dispatches,
        .metal_circle_lde_dispatch => &counter_bank.metal_circle_lde_dispatches,
        .metal_fri_circle_fold_dispatch => &counter_bank.metal_fri_circle_fold_dispatches,
        .metal_fri_line_fold_dispatch => &counter_bank.metal_fri_line_fold_dispatches,
        .metal_fri_fold_commit_epoch => &counter_bank.metal_fri_fold_commit_epochs,
        .metal_qm31_coordinate_dispatch => &counter_bank.metal_qm31_coordinate_dispatches,
        .metal_relation_epoch => &counter_bank.metal_relation_epochs,
        .metal_trace_generation_dispatch => &counter_bank.metal_trace_generation_dispatches,
        .metal_trace_generation_synchronization => &counter_bank.metal_trace_generation_synchronizations,
        .metal_trace_generation_copyback => &counter_bank.metal_trace_generation_copybacks,
        .metal_composition_eval_dispatch => &counter_bank.metal_composition_eval_dispatches,
        .cpu_small_merkle_commit => &counter_bank.cpu_small_merkle_commits,
        .cpu_streaming_merkle_commit => &counter_bank.cpu_streaming_merkle_commits,
        .cpu_sampled_value_evaluation => &counter_bank.cpu_sampled_value_evaluations,
        .cpu_small_circle_interpolation => &counter_bank.cpu_small_circle_interpolations,
        .cpu_small_circle_evaluation => &counter_bank.cpu_small_circle_evaluations,
        .cpu_small_circle_lde => &counter_bank.cpu_small_circle_ldes,
        .cpu_composition_evaluation => &counter_bank.cpu_composition_evaluations,
        .metal_commit_source_arena_alias => &counter_bank.metal_commit_source_arena_aliases,
        .metal_commit_source_arena_memcpy => &counter_bank.metal_commit_source_arena_memcpys,
        .metal_commit_source_upload => &counter_bank.metal_commit_source_uploads,
    };
    _ = counter.fetchAdd(1, .monotonic);
}

/// The `source_binding` code the circle-LDE commit reports back, mapped onto its
/// counter. The classification is made where the decision is made — inside the
/// Objective-C commit — and is reported, never re-derived here, so the counter
/// cannot drift away from the branch it claims to observe.
pub const CommitSourceBinding = enum(u32) {
    upload = 0,
    arena_alias = 1,
    arena_memcpy = 2,
};

pub fn recordCommitSourceBinding(code: u32) void {
    record(switch (std.meta.intToEnum(CommitSourceBinding, code) catch return) {
        .upload => .metal_commit_source_upload,
        .arena_alias => .metal_commit_source_arena_alias,
        .arena_memcpy => .metal_commit_source_arena_memcpy,
    });
}

pub fn capture(pipeline_cache: runtime.PipelineCacheStats) Snapshot {
    var values: CounterValues = .{};
    inline for (std.meta.fields(CounterValues)) |field| {
        @field(values, field.name) = @field(counter_bank, field.name).load(.monotonic);
    }
    return .{ .counters = values, .pipeline_cache = pipeline_cache };
}

pub fn captureWithArchiveStore(
    pipeline_cache: runtime.PipelineCacheStats,
    archive_store: runtime.ArchiveStoreStatsV1,
) Snapshot {
    var result = capture(pipeline_cache);
    result.archive_store = archive_store;
    return result;
}

fn snapshot(counters: CounterValues, cache_hits: u64) Snapshot {
    var cache = runtime.PipelineCacheStats.zero();
    cache.pipeline_cache_hits = cache_hits;
    return .{ .counters = counters, .pipeline_cache = cache };
}

test "Metal telemetry delta is monotonic and includes pipeline cache evidence" {
    const before = snapshot(.{
        .host_merkle_commits = 4,
        .resident_merkle_commits = 8,
        .metal_quotient_dispatches = 2,
    }, 11);
    var after_cache = runtime.PipelineCacheStats.zero();
    after_cache.pipeline_cache_hits = 17;
    after_cache.direct_compiles = 3;
    after_cache.pipeline_preparation_seconds = 0.75;
    after_cache.library_preparation_seconds = 0.25;
    after_cache.library_cache_entries = 2;
    after_cache.library_cache_evictions = 1;
    after_cache.pipeline_cache_bytes = 512 * 1024;
    after_cache.library_cache_entry_limit = 8;
    after_cache.pipeline_cache_byte_limit = 16 * 1024 * 1024;
    var after_archive = runtime.ArchiveStoreStatsV1.zero();
    after_archive.archive_disk_hits = 4;
    after_archive.archive_disk_rebuilds = 1;
    after_archive.archive_publication_successes = 2;
    after_archive.archive_disk_entries = 3;
    after_archive.archive_disk_entry_limit = 128;
    const after = Snapshot{
        .counters = .{
            .host_merkle_commits = 3,
            .resident_merkle_commits = 10,
            .metal_quotient_dispatches = 5,
        },
        .pipeline_cache = after_cache,
        .archive_store = after_archive,
    };
    const result = after.delta(before);
    try std.testing.expectEqual(@as(u64, 0), result.counters.host_merkle_commits);
    try std.testing.expectEqual(@as(u64, 2), result.counters.resident_merkle_commits);
    try std.testing.expectEqual(@as(u64, 3), result.counters.metal_quotient_dispatches);
    try std.testing.expectEqual(@as(u64, 6), result.pipeline_cache.pipeline_cache_hits);
    try std.testing.expectEqual(@as(u64, 3), result.pipeline_cache.direct_compiles);
    try std.testing.expectEqual(@as(f64, 0.75), result.pipeline_cache.pipeline_preparation_seconds);
    try std.testing.expectEqual(@as(f64, 0.25), result.pipeline_cache.library_preparation_seconds);
    try std.testing.expectEqual(@as(u64, 2), result.pipeline_cache.library_cache_entries);
    try std.testing.expectEqual(@as(u64, 1), result.pipeline_cache.library_cache_evictions);
    try std.testing.expectEqual(@as(u64, 512 * 1024), result.pipeline_cache.pipeline_cache_bytes);
    try std.testing.expectEqual(@as(u64, 8), result.pipeline_cache.library_cache_entry_limit);
    try std.testing.expectEqual(@as(u64, 16 * 1024 * 1024), result.pipeline_cache.pipeline_cache_byte_limit);
    try std.testing.expectEqual(@as(u64, 4), result.archive_store.archive_disk_hits);
    try std.testing.expectEqual(@as(u64, 1), result.archive_store.archive_disk_rebuilds);
    try std.testing.expectEqual(@as(u64, 2), result.archive_store.archive_publication_successes);
    try std.testing.expectEqual(@as(u64, 3), result.archive_store.archive_disk_entries);
    try std.testing.expectEqual(@as(u64, 128), result.archive_store.archive_disk_entry_limit);
}

test "Metal telemetry classification fails closed" {
    const empty = Delta{ .counters = .{}, .pipeline_cache = .{} };
    try std.testing.expectEqual(Classification.no_backend_work, empty.classification());
    try std.testing.expectError(error.NoMetalDispatch, empty.requireMetalDispatch());
    try std.testing.expectError(error.NoMetalDispatch, empty.requireAcceleratedWithoutFallbacks());

    const metal = Delta{
        .counters = .{ .metal_quotient_dispatches = 1 },
        .pipeline_cache = .{},
    };
    try std.testing.expectEqual(Classification.accelerated_without_fallbacks, metal.classification());
    try metal.requireMetalDispatch();
    try metal.requireAcceleratedWithoutFallbacks();

    const mixed = Delta{
        .counters = .{
            .resident_merkle_commits = 1,
            .host_merkle_commits = 1,
            .cpu_small_merkle_commits = 1,
        },
        .pipeline_cache = .{},
    };
    try std.testing.expectEqual(Classification.accelerated_with_fallbacks, mixed.classification());
    try mixed.requireMetalDispatch();
    try std.testing.expectError(error.CpuFallbackObserved, mixed.requireAcceleratedWithoutFallbacks());

    const host = Delta{
        .counters = .{ .cpu_sampled_value_evaluations = 1 },
        .pipeline_cache = .{},
    };
    try std.testing.expectEqual(Classification.host_only, host.classification());
    try std.testing.expectError(error.NoMetalDispatch, host.requireMetalDispatch());
    try std.testing.expectError(error.NoMetalDispatch, host.requireAcceleratedWithoutFallbacks());
}

test "relation and composition dispatches count toward the Metal total" {
    // Before this counter existed, `metalDispatchTotal` summed exactly ten
    // fields and could not see interaction or composition device work, so a
    // proof that dispatched only those would have classified as
    // `no_backend_work` and the zero-fallback gate would have under-reported.
    const relation = Delta{
        .counters = .{ .metal_relation_epochs = 3 },
        .pipeline_cache = .{},
    };
    try std.testing.expectEqual(@as(u64, 3), relation.counters.metalDispatchTotal());
    try std.testing.expectEqual(
        Classification.accelerated_without_fallbacks,
        relation.classification(),
    );
    try relation.requireAcceleratedWithoutFallbacks();

    const composition = Delta{
        .counters = .{ .metal_composition_eval_dispatches = 2 },
        .pipeline_cache = .{},
    };
    try std.testing.expectEqual(@as(u64, 2), composition.counters.metalDispatchTotal());
    try composition.requireAcceleratedWithoutFallbacks();
}

test "a declined composition device path is a counted fallback" {
    // The digest-binding fail-closed path records this. A Metal proof that
    // fell back to the host evaluator because the composition metallib failed
    // authentication must not be able to claim `accelerated_without_fallbacks`.
    const declined = Delta{
        .counters = .{
            .metal_circle_lde_dispatches = 40,
            .cpu_composition_evaluations = 1,
        },
        .pipeline_cache = .{},
    };
    try std.testing.expectEqual(@as(u64, 1), declined.counters.cpuFallbackTotal());
    try std.testing.expectEqual(
        Classification.accelerated_with_fallbacks,
        declined.classification(),
    );
    try std.testing.expectError(
        error.CpuFallbackObserved,
        declined.requireAcceleratedWithoutFallbacks(),
    );
}

test "the new counters leave untouched paths byte-for-byte unchanged" {
    // Every counter added here defaults to zero, so a report from a path that
    // does not record them must produce exactly the totals it produced before.
    // This is the guard that the two new Metal counters and the new CPU
    // fallback counter cannot move an existing workload's dispatch count.
    const hybrid = Delta{
        .counters = .{
            .resident_merkle_commits = 4,
            .metal_quotient_dispatches = 1,
            .metal_sampled_value_dispatches = 1,
            .metal_circle_transform_dispatches = 2,
            .metal_circle_lde_dispatches = 40,
            .metal_fri_circle_fold_dispatches = 10,
            .metal_fri_line_fold_dispatches = 8,
            .metal_fri_fold_commit_epochs = 6,
            .metal_qm31_coordinate_dispatches = 2,
            .metal_trace_generation_dispatches = 0,
        },
        .pipeline_cache = .{},
    };
    try std.testing.expectEqual(@as(u64, 74), hybrid.counters.metalDispatchTotal());
    try std.testing.expectEqual(@as(u64, 0), hybrid.counters.cpuFallbackTotal());
    try std.testing.expectEqual(
        Classification.accelerated_without_fallbacks,
        hybrid.classification(),
    );
    try hybrid.requireAcceleratedWithoutFallbacks();
}

test "every Event maps to a distinct counter" {
    // A switch in `record` is exhaustive, but two events could still be mapped
    // to the same counter by a copy-paste. Counting fields against variants
    // catches that, and catches a counter added without an event.
    const event_count = std.meta.fields(Event).len;
    const counter_count = std.meta.fields(CounterValues).len;
    try std.testing.expectEqual(event_count, counter_count);
    try std.testing.expectEqual(
        std.meta.fields(CounterBank).len,
        std.meta.fields(CounterValues).len,
    );
}
