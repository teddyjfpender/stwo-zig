const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const dependency_options = .{ .target = target, .optimize = optimize };

    const core = b.dependency("stwo_core", dependency_options).module("stwo_core");
    const api = b.addModule("stwo_prover_api", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    api.addImport("stwo_core", core);

    const tests = b.addRunArtifact(b.addTest(.{ .root_module = api }));
    b.step(
        "test",
        "Compile and test the stable stwo_prover_api package",
    ).dependOn(&tests.step);
}
