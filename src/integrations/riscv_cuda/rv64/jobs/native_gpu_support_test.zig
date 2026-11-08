//! Test-only (excluded from jobs/lint.zig by its _test.zig name): open the job
//! runtime's libraries for the opt-in real-GPU native-job tests.
//! STWO_RV64_M8_GPU_BASE=<libstwo-rv64-native.so>, STWO_RV64_M8_JOBS_LIBRARY=<libstwo-rv64-jobs.so>.
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

pub const Gpu = struct {
    libs: O.Libraries,
    pub fn open() !?Gpu {
        return openNamed("unnamed");
    }
    /// As `open`; `name` is printed when the GPU test runs.
    pub fn openNamed(name: []const u8) !?Gpu {
        const base_path = std.posix.getenv("STWO_RV64_M8_GPU_BASE") orelse return missing();
        const addon_path = std.posix.getenv("STWO_RV64_M8_JOBS_LIBRARY") orelse return missing();
        const gpu = Gpu{ .libs = try O.Libraries.open(base_path, addon_path) };
        std.debug.print("GPU_M8_TEST_RAN {s}\n", .{name});
        return gpu;
    }
    fn missing() !?Gpu {
        if (required()) return error.GpuTestsRequired;
        return null;
    }
    pub fn close(self: *Gpu) void {
        self.libs.close();
    }
};
