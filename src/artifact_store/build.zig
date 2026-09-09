const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const artifact_store = b.addModule("stwo_artifact_store", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    const tests = b.addTest(.{ .root_module = artifact_store });
    b.step(
        "test",
        "Run persistent typed artifact-store tests",
    ).dependOn(&b.addRunArtifact(tests).step);
}
