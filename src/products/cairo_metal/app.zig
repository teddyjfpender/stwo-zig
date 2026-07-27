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
        "Apple Metal PCS with explicit host witness and AIR evaluation.";
    pub const stwo = package;
    pub const transaction = backend_transaction;
    pub const capabilities = capability_surface;
    pub const identity = product_identity;

    pub fn witnessExecutor() ?package.frontends.cairo.witness.generated_executor.Executor {
        return witness_cpu_aot.executor();
    }

    pub fn interactionExecutor(
        _: *ProofContext,
    ) ?package.frontends.cairo.witness.interaction_executor.Executor {
        const enabled = std.posix.getenv(
            "STWO_CAIRO_METAL_HOST_BRIDGED_LOGUP",
        ) orelse return null;
        if (!std.mem.eql(u8, enabled, "1")) return null;
        return package.integrations.cairo_metal.interaction_executor.executor();
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
            .classification = @tagName(delta.classification()),
            .metal_dispatches = delta.counters.metalDispatchTotal(),
            .cpu_fallbacks = delta.counters.cpuFallbackTotal(),
            .runtime_initializations = lifecycle.initialization_count -
                context.lifecycle_before.initialization_count,
            .runtime_shutdowns = lifecycle.shutdown_count -
                context.lifecycle_before.shutdown_count,
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
