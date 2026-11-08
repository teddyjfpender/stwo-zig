//! Product-level ownership and failure contracts for authenticated Metal.

const std = @import("std");
const package = @import("stwo_cairo_metal");
const app = @import("app.zig");
const metal_aot_config = @import("metal_aot_config");

const Backend = package.backends.metal.MetalCommitBackend;
const Runtime = package.backends.metal.Runtime;
const transaction = app.Product.transaction;

fn bundlePath(allocator: std.mem.Allocator) ![]u8 {
    const path = try std.process.getEnvVarOwned(
        allocator,
        "STWO_CAIRO_METAL_AOT_BUNDLE",
    );
    errdefer allocator.free(path);
    if (path.len == 0 or !std.fs.path.isAbsolute(path))
        return error.InvalidMetalAotBundlePath;
    return path;
}

test "Cairo Metal rejects an explicitly missing device" {
    const placeholder_metallib = [_]u8{0};
    try std.testing.expectError(
        error.RuntimeInitializationFailed,
        Runtime.initFromMetallibDataOnDevice(
            null,
            &placeholder_metallib,
        ),
    );
    try std.testing.expect(!transaction.runtimeLifecycleSnapshot().initialized);
}

test "Cairo Metal admission allocation failure leaves no runtime state" {
    const allocator = std.testing.allocator;
    const bundle_path = try bundlePath(allocator);
    defer allocator.free(bundle_path);
    const before = transaction.runtimeLifecycleSnapshot();
    try std.testing.expect(!before.initialized);

    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        transaction.initializeRuntime(failing.allocator(), .{
            .authenticated_aot = .{
                .bundle_path = bundle_path,
                .manifest_sha256 = metal_aot_config.manifest_sha256,
            },
        }),
    );
    try std.testing.expect(failing.has_induced_failure);

    const rejected = transaction.runtimeLifecycleSnapshot();
    try std.testing.expect(!rejected.initialized);
    try std.testing.expectEqual(
        before.initialization_count,
        rejected.initialization_count,
    );
    try std.testing.expectEqual(
        before.shutdown_count,
        rejected.shutdown_count,
    );
    try std.testing.expectEqual(@as(u64, 0), rejected.active_call_leases);
    try std.testing.expectEqual(@as(u64, 0), rejected.live_resident_resources);

    try transaction.initializeRuntime(allocator, .{
        .authenticated_aot = .{
            .bundle_path = bundle_path,
            .manifest_sha256 = metal_aot_config.manifest_sha256,
        },
    });
    try transaction.shutdown();
}

test "Cairo Metal resident buffers block teardown and release exactly once" {
    const allocator = std.testing.allocator;
    var context = try app.Product.beginProof(allocator);
    var runtime_owned = true;
    defer if (runtime_owned) app.Product.abortProof(&context);

    const active = transaction.runtimeLifecycleSnapshot();
    try std.testing.expect(active.initialized);

    var column = try Backend.allocateSecureColumn(8);
    var column_owned = true;
    defer if (column_owned) column.deinit(allocator);
    try std.testing.expectEqual(
        active.live_resident_resources + 1,
        transaction.runtimeLifecycleSnapshot().live_resident_resources,
    );
    try std.testing.expectError(
        error.ResidentResourcesLive,
        transaction.shutdown(),
    );

    column.deinit(allocator);
    column_owned = false;
    try std.testing.expectEqual(
        active.live_resident_resources,
        transaction.runtimeLifecycleSnapshot().live_resident_resources,
    );
    try transaction.shutdown();
    runtime_owned = false;
    try std.testing.expect(!transaction.runtimeLifecycleSnapshot().initialized);
}
