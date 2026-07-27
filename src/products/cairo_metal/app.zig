//! Lifecycle binding for the Cairo Metal product.

const std = @import("std");
const package = @import("stwo_cairo_metal");
const application = @import("cairo_product").application;
const capability_surface = @import("capabilities.zig");
const product_identity = @import("identity.zig");

const backend_transaction =
    package.integrations.cairo_metal.transaction;

const Product = struct {
    pub const name = "stwo-cairo-metal";
    pub const backend_name = "metal";
    pub const backend_description =
        "Apple Metal PCS with explicit host witness and AIR evaluation.";
    pub const stwo = package;
    pub const transaction = backend_transaction;
    pub const capabilities = capability_surface;
    pub const identity = product_identity;

    pub const ProofContext = struct {
        before: backend_transaction.TelemetrySnapshot,
        lifecycle_before: backend_transaction.RuntimeLifecycleSnapshot,
    };

    pub fn beginProof(
        allocator: std.mem.Allocator,
    ) !ProofContext {
        const lifecycle_before =
            backend_transaction.runtimeLifecycleSnapshot();
        try backend_transaction.initializeRuntime(allocator, .source_jit);
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

pub fn main() !void {
    return application.run(Product);
}

test "Cairo Metal application requires no-fallback telemetry" {
    try std.testing.expectEqualStrings("metal", Product.backend_name);
    _ = &backend_transaction.TelemetryDelta.requireAcceleratedWithoutFallbacks;
}
