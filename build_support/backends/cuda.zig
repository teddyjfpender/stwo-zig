//! Explicit, isolated build and link ownership for the native CUDA archive.

const std = @import("std");

pub const source_root = "src/backends/cuda/vendor/upstream";
pub const source_manifest = "src/backends/cuda/source_manifest.json";
pub const archive_name = "stwo_cuda_kernels";

pub const Toolchain = struct {
    nvcc: []const u8 = "",
    host_cxx: []const u8 = "",
    archiver: []const u8 = "",
    cuda_home: []const u8 = "",
    library_dir: []const u8 = "",
    architectures: []const u8 = "",
    jobs: u16 = 1,

    pub fn validate(self: Toolchain) !void {
        if (self.nvcc.len == 0) return error.MissingCudaCompiler;
        if (self.host_cxx.len == 0) return error.MissingCudaHostCompiler;
        if (self.archiver.len == 0) return error.MissingCudaArchiver;
        if (self.cuda_home.len == 0) return error.MissingCudaToolkitDirectory;
        if (self.library_dir.len == 0) return error.MissingCudaLibraryDirectory;
        if (self.architectures.len == 0) return error.MissingCudaArchitecture;
        if (self.jobs == 0) return error.InvalidCudaBuildJobs;
    }
};

pub const Archive = struct {
    directory: std.Build.LazyPath,
    build: *std.Build.Step.Run,
};

pub fn addArchive(b: *std.Build, toolchain: Toolchain) Archive {
    require(toolchain);
    const command = buildCommand(b, toolchain, false);
    return .{
        .directory = command.addOutputDirectoryArg("stwo-native-cuda-runtime"),
        .build = command,
    };
}

pub fn addPlan(b: *std.Build, toolchain: Toolchain) *std.Build.Step.Run {
    require(toolchain);
    const command = buildCommand(b, toolchain, true);
    _ = command.addOutputDirectoryArg("stwo-native-cuda-plan");
    return command;
}

pub fn addSourceClosureGate(b: *std.Build) *std.Build.Step.Run {
    return b.addSystemCommand(&.{ "python3", "scripts/cuda_source_closure.py" });
}

pub fn linkRuntime(
    artifact: *std.Build.Step.Compile,
    toolchain: Toolchain,
    archive: Archive,
) void {
    require(toolchain);
    artifact.step.dependOn(&archive.build.step);
    artifact.addLibraryPath(archive.directory);
    artifact.addLibraryPath(.{ .cwd_relative = toolchain.library_dir });
    artifact.linkSystemLibrary(archive_name);
    artifact.linkSystemLibrary("cudart");
    artifact.linkSystemLibrary("nvrtc");
    artifact.linkSystemLibrary("cuda");
    artifact.linkSystemLibrary("stdc++");
    artifact.linkLibC();
}

fn buildCommand(
    b: *std.Build,
    toolchain: Toolchain,
    plan_only: bool,
) *std.Build.Step.Run {
    const command = b.addSystemCommand(&.{ "python3", "scripts/cuda_build.py" });
    command.addArg("--source-root");
    command.addDirectoryArg(b.path(source_root));
    command.addArg("--source-manifest");
    command.addFileArg(b.path(source_manifest));
    command.addArgs(&.{ "--nvcc", toolchain.nvcc });
    command.addArgs(&.{ "--host-cxx", toolchain.host_cxx });
    command.addArgs(&.{ "--ar", toolchain.archiver });
    command.addArgs(&.{ "--cuda-home", toolchain.cuda_home });
    command.addArgs(&.{ "--cuda-library-dir", toolchain.library_dir });
    command.addArgs(&.{ "--arch", toolchain.architectures });
    command.addArgs(&.{ "--jobs", b.fmt("{d}", .{toolchain.jobs}) });
    if (plan_only) command.addArg("--plan-only");
    command.addArg("--out-dir");
    return command;
}

fn require(toolchain: Toolchain) void {
    toolchain.validate() catch |err| std.debug.panic(
        "invalid explicit CUDA toolchain: {s}",
        .{@errorName(err)},
    );
}

test "CUDA toolchain has no implicit compiler, path, or architecture" {
    try std.testing.expectError(error.MissingCudaCompiler, (Toolchain{}).validate());
    try std.testing.expectError(error.MissingCudaHostCompiler, (Toolchain{
        .nvcc = "/cuda/bin/nvcc",
    }).validate());
    try std.testing.expectError(error.MissingCudaArchiver, (Toolchain{
        .nvcc = "/cuda/bin/nvcc",
        .host_cxx = "/usr/bin/c++",
    }).validate());
    try std.testing.expectError(error.MissingCudaToolkitDirectory, (Toolchain{
        .nvcc = "/cuda/bin/nvcc",
        .host_cxx = "/usr/bin/c++",
        .archiver = "/usr/bin/ar",
    }).validate());
    try std.testing.expectError(error.MissingCudaLibraryDirectory, (Toolchain{
        .nvcc = "/cuda/bin/nvcc",
        .host_cxx = "/usr/bin/c++",
        .archiver = "/usr/bin/ar",
        .cuda_home = "/cuda",
    }).validate());
    try std.testing.expectError(error.MissingCudaArchitecture, (Toolchain{
        .nvcc = "/cuda/bin/nvcc",
        .host_cxx = "/usr/bin/c++",
        .archiver = "/usr/bin/ar",
        .cuda_home = "/cuda",
        .library_dir = "/cuda/lib64",
    }).validate());
    try (Toolchain{
        .nvcc = "/cuda/bin/nvcc",
        .host_cxx = "/usr/bin/c++",
        .archiver = "/usr/bin/ar",
        .cuda_home = "/cuda",
        .library_dir = "/cuda/lib64",
        .architectures = "sm_86,sm_90",
        .jobs = 8,
    }).validate();
}
