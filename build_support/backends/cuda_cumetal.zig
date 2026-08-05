//! Explicit CuMetal provider build for the resident CUDA architecture.

const std = @import("std");

pub const archive_name = "stwo_cuda_kernels";
const build_script = "scripts/cuda_cumetal_build.py";

pub const Toolchain = struct {
    clang: []const u8,
    compiler: []const u8,
    root: []const u8,
    library: []const u8,
    air_inspect: []const u8,
    air_validate: []const u8,
    archiver: []const u8 = "/usr/bin/ar",
    jobs: u16 = 8,

    pub fn validate(self: Toolchain) !void {
        inline for (.{
            self.clang,
            self.compiler,
            self.root,
            self.library,
            self.air_inspect,
            self.air_validate,
            self.archiver,
        }) |value| if (value.len == 0) return error.MissingCuMetalToolchain;
        if (self.jobs == 0) return error.InvalidCuMetalBuildJobs;
    }
};

pub const Archive = struct {
    directory: std.Build.LazyPath,
    build: *std.Build.Step.Run,
};

pub fn addNativeArchive(
    b: *std.Build,
    toolchain: Toolchain,
) Archive {
    toolchain.validate() catch |err| std.debug.panic(
        "invalid explicit CuMetal toolchain: {s}",
        .{@errorName(err)},
    );
    const command = b.addSystemCommand(&.{"python3"});
    command.addFileArg(b.path(build_script));
    addDirectoryInputs(b, command, "scripts/cuda_build_lib");
    addDirectoryInputs(b, command, "src/backends/cuda/authority/active");
    addDirectoryInputs(b, command, "src/backends/cuda/native");
    addDirectoryInputs(b, command, "src/backends/cuda/aot/native");
    addDirectoryInputs(b, command, "src/backends/cuda/cumetal");
    command.addArgs(&.{ "--frontend", "native" });
    command.addArgs(&.{ "--cumetal-root", toolchain.root });
    command.addArgs(&.{ "--clang", toolchain.clang });
    command.addArgs(&.{ "--cumetalc", toolchain.compiler });
    command.addArgs(&.{ "--cumetal-library", toolchain.library });
    command.addArgs(&.{ "--air-inspect", toolchain.air_inspect });
    command.addArgs(&.{ "--air-validate", toolchain.air_validate });
    command.addArgs(&.{ "--ar", toolchain.archiver });
    command.addArgs(&.{ "--jobs", b.fmt("{d}", .{toolchain.jobs}) });
    command.addArg("--out-dir");
    return .{
        .directory = command.addOutputDirectoryArg("stwo-native-cumetal"),
        .build = command,
    };
}

pub fn linkRuntime(
    artifact: *std.Build.Step.Compile,
    toolchain: Toolchain,
    archive: Archive,
) void {
    artifact.step.dependOn(&archive.build.step);
    artifact.addLibraryPath(archive.directory);
    artifact.addLibraryPath(.{
        .cwd_relative = std.fs.path.dirname(toolchain.library) orelse ".",
    });
    artifact.linkSystemLibrary(archive_name);
    artifact.linkSystemLibrary("cumetal");
    artifact.linkLibCpp();
    artifact.linkLibC();
    artifact.addRPath(.{
        .cwd_relative = std.fs.path.dirname(toolchain.library) orelse ".",
    });
}

fn addDirectoryInputs(
    b: *std.Build,
    command: *std.Build.Step.Run,
    relative_root: []const u8,
) void {
    var directory = b.build_root.handle.openDir(
        relative_root,
        .{ .iterate = true },
    ) catch |err| std.debug.panic(
        "cannot open CuMetal build input {s}: {s}",
        .{ relative_root, @errorName(err) },
    );
    defer directory.close();
    var walker = directory.walk(b.allocator) catch @panic("OOM");
    defer walker.deinit();
    while (walker.next() catch @panic("cannot enumerate CuMetal inputs")) |entry| {
        if (entry.kind != .file) continue;
        command.addFileInput(b.path(b.pathJoin(&.{ relative_root, entry.path })));
    }
}

test "CuMetal toolchain remains explicit" {
    try std.testing.expectError(
        error.MissingCuMetalToolchain,
        (Toolchain{
            .clang = "",
            .compiler = "cumetalc",
            .root = "/cuda-metal",
            .library = "/cuda-metal/libcumetal.dylib",
            .air_inspect = "air_inspect",
            .air_validate = "air_validate",
        }).validate(),
    );
}
