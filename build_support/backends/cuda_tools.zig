//! Host-independent source/build-plan gates and explicit CUDA archive build.

const std = @import("std");
const cuda = @import("cuda.zig");
const construction_observer = @import("../graph/construction_observer.zig");

pub const Options = struct {
    nvcc: ?[]const u8,
    host_cxx: ?[]const u8,
    archiver: ?[]const u8,
    cuda_home: ?[]const u8,
    library_dir: ?[]const u8,
    architectures: ?[]const u8,
    jobs: u16,

    pub fn read(b: *std.Build) Options {
        return .{
            .nvcc = b.option([]const u8, "cuda-nvcc", "Explicit nvcc executable"),
            .host_cxx = b.option([]const u8, "cuda-host-cxx", "Explicit nvcc host C++ compiler"),
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

    pub fn toolchain(self: Options) cuda.Toolchain {
        if (!self.complete()) @panic(
            "cuda-native-archive requires -Dcuda-nvcc, -Dcuda-host-cxx, " ++
                "-Dcuda-ar, -Dcuda-home, -Dcuda-library-dir, and -Dcuda-arch",
        );
        return .{
            .nvcc = self.nvcc.?,
            .host_cxx = self.host_cxx.?,
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
            .archiver = self.archiver orelse "/usr/bin/ar",
            .cuda_home = self.cuda_home orelse "/opt/cuda",
            .library_dir = self.library_dir orelse "/opt/cuda/lib64",
            .architectures = self.architectures orelse "sm_90",
            .jobs = self.jobs,
        };
    }
};

pub fn addProducts(
    b: *std.Build,
    target: std.Build.ResolvedTarget,
    optimize: std.builtin.OptimizeMode,
) void {
    const options = Options.read(b);
    const source = cuda.addSourceClosureGate(b);
    b.step(
        "cuda-source-closure",
        "Verify the exact pinned CUDA/C++ source authority",
    ).dependOn(&source.step);

    const plan = cuda.addPlan(b, options.planningToolchain());
    b.step(
        "cuda-build-plan",
        "Validate and print the isolated native CUDA archive build plan",
    ).dependOn(&plan.step);

    const tests = b.addSystemCommand(&.{
        "python3",
        "-m",
        "unittest",
        "scripts.tests.test_cuda_build",
    });
    tests.step.dependOn(&source.step);
    b.step(
        "test-cuda-build-plan",
        "Test CUDA source, AOT, toolchain, and build-plan contracts without a GPU",
    ).dependOn(&tests.step);

    const runtime_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/backends/cuda/mod.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.step(
        "test-cuda-runtime-contract",
        "Test proof-owned CUDA context, residency, and strict-AOT contracts",
    ).dependOn(&b.addRunArtifact(runtime_tests).step);

    if (options.complete()) {
        const archive = cuda.addArchive(b, options.toolchain());
        b.step(
            "cuda-native-archive",
            "Build the exact static CUDA runtime and copied AOT pack",
        ).dependOn(&archive.build.step);
    } else {
        const unavailable = b.addFail(
            "cuda-native-archive requires explicit compiler, toolkit, library, " ++
                "archiver, and SM options; run `zig build cuda-build-plan` for " ++
                "the host-independent contract",
        );
        b.step(
            "cuda-native-archive",
            "Build the exact static CUDA runtime and copied AOT pack",
        ).dependOn(&unavailable.step);
    }
    construction_observer.recordConstructor(b, "backends/cuda_tools.addProducts");
}

test "CUDA archive options are all-or-nothing" {
    const absent = Options{
        .nvcc = null,
        .host_cxx = null,
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
}
