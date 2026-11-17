//! Test-only (excluded from jobs/lint.zig by its _test.zig name): open the job
//! runtime's libraries for the opt-in real-GPU native-job tests.
//! STWO_RV64_GPU_LIBRARY=<libstwo-rv64-native.so>, STWO_RV64_M8_JOBS_LIBRARY=<libstwo-rv64-jobs.so>.
//! STWO_RV64_M8_REQUIRE_GPU=1 (pod receipts): a missing library is a test
//! FAILURE (error.GpuTestsRequired), not a skip, so a GPU receipt cannot pass
//! with its GPU tests silently skipped. Each GPU test that runs prints one
//! `GPU_M8_TEST_RAN <name>` line (count them in the receipt).
const std = @import("std");
const O = @import("ops.zig");

pub fn required() bool {
    const v = std.posix.getenv("STWO_RV64_M8_REQUIRE_GPU") orelse return false;
    return std.mem.eql(u8, v, "1");
}

/// Missing libraries may skip only the optional host-only qualification arm.
pub fn librariesAvailable(base: ?[]const u8, addon: ?[]const u8, force: bool) !bool {
    if (base != null and addon != null) return true;
    if (force) return error.GpuTestsRequired;
    return false;
}

test "required GPU libraries cannot silently select the host-only arm" {
    for ([_]bool{ false, true }) |base_present| {
        for ([_]bool{ false, true }) |addon_present| {
            for ([_]bool{ false, true }) |force| {
                const base: ?[]const u8 = if (base_present) "" else null;
                const addon: ?[]const u8 = if (addon_present) "" else null;
                if (force and !(base_present and addon_present)) {
                    try std.testing.expectError(error.GpuTestsRequired, librariesAvailable(base, addon, force));
                } else {
                    try std.testing.expectEqual(base_present and addon_present, try librariesAvailable(base, addon, force));
                }
            }
        }
    }
}

pub const Gpu = struct {
    libs: O.Libraries,
    pub fn open() !?Gpu {
        return openNamed("unnamed");
    }
    /// As `open`; `name` is printed when the GPU test runs.
    pub fn openNamed(name: []const u8) !?Gpu {
        const base_path = std.posix.getenv("STWO_RV64_GPU_LIBRARY");
        const addon_path = std.posix.getenv("STWO_RV64_M8_JOBS_LIBRARY");
        if (!try librariesAvailable(base_path, addon_path, required())) return null;
        const gpu = Gpu{ .libs = try O.Libraries.open(base_path.?, addon_path.?) };
        std.debug.print("GPU_M8_TEST_RAN {s}\n", .{name});
        return gpu;
    }
    pub fn close(self: *Gpu) void {
        self.libs.close();
    }
};
