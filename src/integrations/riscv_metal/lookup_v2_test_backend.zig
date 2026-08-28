const std = @import("std");
const integration = @import("stwo_riscv_metal_integration");
const metal_aot_config = @import("metal_aot_config");

pub const Engine = integration.MetalProverEngine;

pub fn initialize(allocator: std.mem.Allocator) !void {
    const bundle_path = try std.process.getEnvVarOwned(
        allocator,
        "STWO_RISCV_METAL_AOT_BUNDLE",
    );
    defer allocator.free(bundle_path);
    try Engine.initializeRuntime(allocator, .{
        .authenticated_aot = .{
            .bundle_path = bundle_path,
            .manifest_sha256 = metal_aot_config.manifest_sha256,
        },
    });
}

pub fn shutdown() void {
    Engine.Backend.shutdown() catch unreachable;
}
