//! Explicit CUDA toolchain options for developer-only build products.

const std = @import("std");
const cuda = @import("cuda.zig");

pub const Options = struct {
    nvcc: ?[]const u8,
    host_cxx: ?[]const u8,
    host_runtime: ?[]const u8,
    host_unwind_runtime: ?[]const u8,
    archiver: ?[]const u8,
    cuda_home: ?[]const u8,
    library_dir: ?[]const u8,
    architectures: ?[]const u8,
    jobs: u16,

    pub fn read(b: *std.Build) Options {
        return .{
            .nvcc = b.option([]const u8, "cuda-nvcc", "Explicit nvcc executable"),
            .host_cxx = b.option([]const u8, "cuda-host-cxx", "Explicit nvcc host C++ compiler"),
            .host_runtime = b.option([]const u8, "cuda-host-runtime", "Absolute GNU C++ runtime shared-library path"),
            .host_unwind_runtime = b.option([]const u8, "cuda-host-unwind-runtime", "Absolute GNU C++ unwind runtime shared-library path"),
            .archiver = b.option([]const u8, "cuda-ar", "Explicit static archiver"),
            .cuda_home = b.option([]const u8, "cuda-home", "Explicit CUDA toolkit root"),
            .library_dir = b.option([]const u8, "cuda-library-dir", "Explicit CUDA library directory"),
            .architectures = b.option([]const u8, "cuda-arch", "Comma-separated numeric CUDA SM targets"),
            .jobs = b.option(u16, "cuda-build-jobs", "Maximum parallel nvcc processes") orelse 8,
        };
    }

    pub fn complete(self: Options) bool {
        return self.nvcc != null and
            self.host_cxx != null and
            self.archiver != null and
            self.cuda_home != null and
            self.library_dir != null and
            self.architectures != null;
    }

    pub fn runtimeComplete(self: Options) bool {
        return self.complete() and
            self.host_runtime != null and
            self.host_unwind_runtime != null;
    }

    pub fn toolchain(self: Options) cuda.Toolchain {
        if (!self.complete()) @panic(
            "cuda-native-archive requires -Dcuda-nvcc, -Dcuda-host-cxx, " ++
                "-Dcuda-ar, -Dcuda-home, -Dcuda-library-dir, and -Dcuda-arch",
        );
        return .{
            .nvcc = self.nvcc.?,
            .host_cxx = self.host_cxx.?,
            .host_runtime = self.host_runtime orelse "",
            .host_unwind_runtime = self.host_unwind_runtime orelse "",
            .archiver = self.archiver.?,
            .cuda_home = self.cuda_home.?,
            .library_dir = self.library_dir.?,
            .architectures = self.architectures.?,
            .jobs = self.jobs,
        };
    }

    pub fn planningToolchain(self: Options) cuda.Toolchain {
        return .{
            .nvcc = self.nvcc orelse "/opt/cuda/bin/nvcc",
            .host_cxx = self.host_cxx orelse "/usr/bin/c++",
            .host_runtime = self.host_runtime orelse "/usr/lib/libstdc++.so.6",
            .host_unwind_runtime = self.host_unwind_runtime orelse "/usr/lib/libgcc_s.so.1",
            .archiver = self.archiver orelse "/usr/bin/ar",
            .cuda_home = self.cuda_home orelse "/opt/cuda",
            .library_dir = self.library_dir orelse "/opt/cuda/lib64",
            .architectures = self.architectures orelse "sm_90",
            .jobs = self.jobs,
        };
    }
};

test "CUDA archive options are all-or-nothing" {
    const absent = Options{
        .nvcc = null,
        .host_cxx = null,
        .host_runtime = null,
        .host_unwind_runtime = null,
        .archiver = null,
        .cuda_home = null,
        .library_dir = null,
        .architectures = null,
        .jobs = 8,
    };
    try std.testing.expect(!absent.complete());
    var complete = absent;
    complete.nvcc = "nvcc";
    complete.host_cxx = "c++";
    complete.archiver = "ar";
    complete.cuda_home = "/cuda";
    complete.library_dir = "/cuda/lib64";
    complete.architectures = "sm_90";
    try std.testing.expect(complete.complete());
    try std.testing.expect(!complete.runtimeComplete());
    complete.host_runtime = "/usr/lib/libstdc++.so.6";
    try std.testing.expect(!complete.runtimeComplete());
    complete.host_unwind_runtime = "/usr/lib/libgcc_s.so.1";
    try std.testing.expect(complete.runtimeComplete());
}
