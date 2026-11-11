//! Product-owned lifecycle for the manifest-bound Metal runtime.
//!
//! Both the unchanged base adapter and the opt-in guest profile enter through
//! this guard. It rejects an already initialized process, authenticates the AOT
//! bundle without touching a device, initializes exactly once, and requires a
//! clean shutdown before a product transaction may publish an artifact.

const std = @import("std");
const metal_aot_config = @import("metal_aot_config");
const stwo = @import("stwo_riscv_metal");

const profile = stwo.integrations.riscv_metal.guest_precompile;

pub fn Guard(comptime Engine: type) type {
    return struct {
        active: bool = false,

        const Self = @This();

        pub fn init(allocator: std.mem.Allocator) !Self {
            if (Engine.runtimeLifecycleSnapshot().initialized)
                return error.RuntimeAlreadyInitialized;

            const bundle_path = try resolveBundlePath(allocator);
            defer allocator.free(bundle_path);
            try profile.aot_bundle_admission.validate(
                allocator,
                bundle_path,
                metal_aot_config.manifest_sha256,
            );
            try Engine.initializeRuntime(allocator, .{
                .authenticated_aot = .{
                    .bundle_path = bundle_path,
                    .manifest_sha256 = metal_aot_config.manifest_sha256,
                },
            });
            errdefer Engine.Backend.shutdown() catch {};
            try profile.validateRuntimeLifecycle(Engine.runtimeLifecycleSnapshot());
            return .{ .active = true };
        }

        pub fn finish(self: *Self) !void {
            if (!self.active) return;
            try Engine.Backend.shutdown();
            self.active = false;
        }

        pub fn deinit(self: *Self) void {
            if (!self.active) return;
            Engine.Backend.shutdown() catch {};
            self.active = false;
        }
    };
}

fn resolveBundlePath(allocator: std.mem.Allocator) ![]u8 {
    const configured = std.process.getEnvVarOwned(
        allocator,
        "STWO_RISCV_METAL_AOT_BUNDLE",
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
