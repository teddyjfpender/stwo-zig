//! External CUDA authority materialization and adapter build commands.

const std = @import("std");

pub const Authority = struct {
    directory: std.Build.LazyPath,
    run: *std.Build.Step.Run,
};

pub fn addAuthority(b: *std.Build) Authority {
    const command = b.addSystemCommand(&.{"python3"});
    command.addFileArg(b.path("scripts/cuda_external_authority.py"));
    command.addArg("materialize");
    command.addArg("--output");
    const directory = command.addOutputDirectoryArg("cuda-host-authority");
    command.addFileInput(b.path("src/backends/cuda/source_manifest.json"));
    command.addFileInput(b.path(
        "src/backends/cuda/host_source_manifest.json",
    ));
    return .{ .directory = directory, .run = command };
}

pub fn addAdapter(
    b: *std.Build,
    subcommand: []const u8,
    authority: std.Build.LazyPath,
) *std.Build.Step.Run {
    const command = b.addSystemCommand(&.{"python3"});
    command.addFileArg(b.path("scripts/cuda_adapter_external.py"));
    command.addFileInput(b.path("scripts/cuda_external_authority.py"));
    command.addArg(subcommand);
    command.addArg("--authority-root");
    command.addDirectoryArg(authority);
    command.addArg("--adapter-root");
    command.addDirectoryArg(b.path("tools/stwo-cuda-adapter-rs"));
    command.addArg("--output");
    _ = command.addOutputDirectoryArg(b.fmt(
        "cuda-adapter-{s}",
        .{subcommand},
    ));
    return command;
}
