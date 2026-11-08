const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const artifact_store = b.dependency("stwo_artifact_store", .{
        .target = target,
        .optimize = optimize,
    }).module("stwo_artifact_store");
    const metal_session = b.addModule("stwo_metal_session", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    metal_session.addImport("stwo_artifact_store", artifact_store);
    const tests = b.addTest(.{ .root_module = metal_session });
    b.step(
        "test",
        "Run the stwo_metal_session package tests",
    ).dependOn(&b.addRunArtifact(tests).step);
}
