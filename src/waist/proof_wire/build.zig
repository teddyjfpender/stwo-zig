const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const dependency_options = .{ .target = target, .optimize = optimize };
    const core = b.dependency("stwo_core", dependency_options).module("stwo_core");
    const proof_wire = b.addModule("stwo_proof_wire", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    proof_wire.addImport("stwo_core", core);
    const tests = b.addTest(.{ .root_module = proof_wire });
    b.step(
        "test",
        "Run the stwo_proof_wire package tests",
    ).dependOn(&b.addRunArtifact(tests).step);
}
