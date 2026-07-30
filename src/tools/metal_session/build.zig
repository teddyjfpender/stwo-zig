const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const metal_session = b.addModule("stwo_metal_session", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    const tests = b.addTest(.{ .root_module = metal_session });
    b.step(
        "test",
        "Run the stwo_metal_session package tests",
    ).dependOn(&b.addRunArtifact(tests).step);
}
