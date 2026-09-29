//! Lifecycle binding for the Cairo Metal product.

const std = @import("std");
const package = @import("stwo_cairo_metal");
const application = @import("cairo_product").application;
const capability_surface = @import("capabilities.zig");
const witness_cpu_aot = @import("cairo_witness_cpu_aot");
const metal_aot_config = @import("metal_aot_config");
const product_identity = @import("identity.zig");

const backend_transaction =
    package.integrations.cairo_metal.transaction;

pub const Product = struct {
    pub const name = "stwo-cairo-metal";
    pub const backend_name = "metal";
    pub const backend_description =
        "Apple Metal PCS, bounded AIR evaluation, and native witness execution.";
    pub const stwo = package;
    pub const transaction = backend_transaction;
    pub const capabilities = capability_surface;
    pub const identity = product_identity;
    /// Retain one committed-column representation. The shared PCS backend opens
    /// these with its exact resident/streamed barycentric evaluator.
    pub const sampled_evaluation = package.frontends.cairo.proving.transaction.SampledEvaluationStorage.committed_columns;

    /// Experimental coefficient retention; ordinary storage remains the default.
    pub fn sampledEvaluationStorage() package.frontends.cairo.proving.transaction.SampledEvaluationStorage {
        const value = std.posix.getenv("STWO_CAIRO_COMPACT_POLYNOMIALS") orelse return sampled_evaluation;
        if (std.mem.eql(u8, value, "preprocessed")) return .compact_preprocessed;
        return if (std.mem.eql(u8, value, "1")) .compact_polynomials else sampled_evaluation;
    }

    pub fn witnessExecutor() ?package.frontends.cairo.witness.generated_executor.Executor {
        return witness_cpu_aot.executor();
    }

    pub fn interactionExecutor(
        _: *ProofContext,
    ) ?package.frontends.cairo.witness.interaction_executor.Executor {
        const enabled = std.posix.getenv(
            "STWO_CAIRO_METAL_RESIDENT_LOGUP",
        ) orelse std.posix.getenv(
            "STWO_CAIRO_METAL_HOST_BRIDGED_LOGUP",
        ) orelse return null;
        if (!std.mem.eql(u8, enabled, "1")) return null;
        return package.integrations.cairo_metal.interaction_executor.executor();
    }

    /// Authenticated native and bounded tiled device composition. Admission (metallib digest, arena
    /// plan, kernel resolution) happens inside `open`; a refusal keeps the
    /// unchanged host composition stage.
    pub fn compositionDevice(
        asset_path: []const u8,
    ) ?package.frontends.cairo.proving.air.device_stage.Device {
        return package.integrations.cairo_metal.composition_stage.productDevice(asset_path);
    }

    pub const ProofContext = struct {
        before: backend_transaction.TelemetrySnapshot,
        lifecycle_before: backend_transaction.RuntimeLifecycleSnapshot,
    };

    pub fn beginProof(
        allocator: std.mem.Allocator,
    ) !ProofContext {
        const lifecycle_before =
            backend_transaction.runtimeLifecycleSnapshot();
        const bundle_path = try resolveBundlePath(allocator);
        defer allocator.free(bundle_path);
        try backend_transaction.initializeRuntime(allocator, .{
            .authenticated_aot = .{
                .bundle_path = bundle_path,
                .manifest_sha256 = metal_aot_config.manifest_sha256,
            },
        });
        return .{
            .before = try backend_transaction.telemetrySnapshot(),
            .lifecycle_before = lifecycle_before,
        };
    }

    pub fn finishProof(
        context: *ProofContext,
    ) !application.BackendEvidence {
        const after = try backend_transaction.telemetrySnapshot();
        const delta = after.delta(context.before);
        try delta.requireAcceleratedWithoutFallbacks();
        const lifecycle = backend_transaction.runtimeLifecycleSnapshot();
        return .{
            .execution = "metal-pcs",
            .pipeline_cache = .{
                .library_hits = delta.pipeline_cache.library_cache_hits,
                .library_misses = delta.pipeline_cache.library_cache_misses,
                .pipeline_hits = delta.pipeline_cache.pipeline_cache_hits,
                .binary_archive_hits = delta.pipeline_cache.binary_archive_hits,
                .binary_archive_misses = delta.pipeline_cache.binary_archive_misses,
                .direct_compiles = delta.pipeline_cache.direct_compiles,
                .archive_populations = delta.pipeline_cache.archive_populations,
                .archive_serializations = delta.pipeline_cache.archive_serializations,
                .pipeline_preparation_seconds = delta.pipeline_cache.pipeline_preparation_seconds,
                .library_preparation_seconds = delta.pipeline_cache.library_preparation_seconds,
            },
            .archive_store = .{
                .disk_hits = delta.archive_store.archive_disk_hits,
                .disk_misses = delta.archive_store.archive_disk_misses,
                .bytes_published = delta.archive_store.archive_bytes_published,
                .publication_failures = delta.archive_store.archive_publication_failures,
                .persistence_bypasses = delta.archive_store.archive_persistence_bypasses,
                .disk_bytes = delta.archive_store.archive_disk_bytes,
            },
            .classification = @tagName(delta.classification()),
            .metal_dispatches = delta.counters.metalDispatchTotal(),
            .cpu_fallbacks = delta.counters.cpuFallbackTotal(),
            .runtime_initializations = lifecycle.initialization_count -
                context.lifecycle_before.initialization_count,
            .runtime_shutdowns = lifecycle.shutdown_count -
                context.lifecycle_before.shutdown_count,
            .commit_source_arena_aliases = delta.counters.metal_commit_source_arena_aliases,
            .commit_source_arena_memcpys = delta.counters.metal_commit_source_arena_memcpys,
            .commit_source_uploads = delta.counters.metal_commit_source_uploads,
            .cached_merkle_artifact_adoptions = delta.counters.cached_merkle_artifact_adoptions,
            .compacted_merkle_layer_adoptions = delta.counters.compacted_merkle_layer_adoptions,
        };
    }

    pub fn endProof(
        context: *ProofContext,
        evidence: application.BackendEvidence,
    ) !application.BackendEvidence {
        try backend_transaction.shutdown();
        const lifecycle = backend_transaction.runtimeLifecycleSnapshot();
        var completed = evidence;
        completed.runtime_shutdowns = lifecycle.shutdown_count -
            context.lifecycle_before.shutdown_count;
        return completed;
    }

    pub fn abortProof(_: *ProofContext) void {
        backend_transaction.shutdown() catch {};
    }
};

fn resolveBundlePath(allocator: std.mem.Allocator) ![]u8 {
    const configured = std.process.getEnvVarOwned(
        allocator,
        "STWO_CAIRO_METAL_AOT_BUNDLE",
    ) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => return err,
    };
    if (configured) |path| {
        errdefer allocator.free(path);
        if (path.len == 0 or !std.fs.path.isAbsolute(path))
            return error.InvalidMetalAotBundlePath;
        return path;
    }
    const executable = try std.fs.selfExePathAlloc(allocator);
    defer allocator.free(executable);
    const bin_dir = std.fs.path.dirname(executable) orelse
        return error.InvalidExecutablePath;
    return std.fs.path.resolve(
        allocator,
        &.{ bin_dir, "..", metal_aot_config.install_subdir },
    );
}

pub fn main() !void {
    return application.run(Product);
}

test "Cairo Metal application requires no-fallback telemetry" {
    try std.testing.expectEqualStrings("metal", Product.backend_name);
    _ = &backend_transaction.TelemetryDelta.requireAcceleratedWithoutFallbacks;
    try std.testing.expect(!std.mem.eql(
        u8,
        &metal_aot_config.manifest_sha256,
        &([_]u8{0} ** 32),
    ));
    _ = &package.integrations.cairo_metal.composition_stage.productDevice;
}

test "composition decline cannot claim fallback-free product evidence" {
    const delta: backend_transaction.TelemetryDelta = .{
        .counters = .{
            .resident_merkle_commits = 1,
            .cpu_composition_evaluations = 1,
        },
        .pipeline_cache = .{},
    };
    try std.testing.expectEqual(
        package.backends.metal.telemetry.Classification.accelerated_with_fallbacks,
        delta.classification(),
    );
    try std.testing.expectError(
        error.CpuFallbackObserved,
        delta.requireAcceleratedWithoutFallbacks(),
    );
}

test "Cairo Metal host writers cover every authenticated program" {
    var bundle = try package.frontends.cairo.witness.bundle.Bundle.readFile(
        std.testing.allocator,
        "vectors/cairo/official/witness_programs_v1.bin",
    );
    defer bundle.deinit();
    try std.testing.expectEqual(
        bundle.entries.len,
        witness_cpu_aot.generated_program_count,
    );
    const executor = Product.witnessExecutor().?;
    for (bundle.entries) |entry| {
        try std.testing.expect(executor.resolve(entry.program) != null);
    }
}

test "authenticated runtime ownership supports repeated sessions" {
    const allocator = std.testing.allocator;
    const bundle_path = try resolveBundlePath(allocator);
    defer allocator.free(bundle_path);
    const before = backend_transaction.runtimeLifecycleSnapshot();
    try std.testing.expect(!before.initialized);
    for (0..2) |_| {
        try backend_transaction.initializeRuntime(allocator, .{
            .authenticated_aot = .{
                .bundle_path = bundle_path,
                .manifest_sha256 = metal_aot_config.manifest_sha256,
            },
        });
        const active = backend_transaction.runtimeLifecycleSnapshot();
        try std.testing.expect(active.initialized);
        try std.testing.expectEqualStrings(
            "authenticated_core_aot",
            @tagName(active.identity.?.origin),
        );
        try backend_transaction.shutdown();
        try std.testing.expect(
            !backend_transaction.runtimeLifecycleSnapshot().initialized,
        );
    }
    const after = backend_transaction.runtimeLifecycleSnapshot();
    try std.testing.expectEqual(
        before.initialization_count + 2,
        after.initialization_count,
    );
    try std.testing.expectEqual(
        before.shutdown_count + 2,
        after.shutdown_count,
    );
}
