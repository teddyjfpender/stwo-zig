//! Test-only (excluded from jobs/lint.zig by its _test.zig name): open the job
//! runtime's libraries for the opt-in real-GPU native-job tests.
//! STWO_RV64_M8_GPU_BASE=<libstwo-rv64-native.so>, STWO_RV64_M8_JOBS_LIBRARY=<libstwo-rv64-jobs.so>.
const std = @import("std");
const O = @import("ops.zig");

pub const Gpu = struct {
    libs: O.Libraries,
    pub fn open() !?Gpu {
        const base_path = std.posix.getenv("STWO_RV64_M8_GPU_BASE") orelse return null;
        const addon_path = std.posix.getenv("STWO_RV64_M8_JOBS_LIBRARY") orelse return null;
        return .{ .libs = try O.Libraries.open(base_path, addon_path) };
    }
    pub fn close(self: *Gpu) void {
        self.libs.close();
    }
};
