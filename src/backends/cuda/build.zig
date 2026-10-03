const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const dependency_options = .{ .target = target, .optimize = optimize };

    const backend_contracts = b.dependency(
        "stwo_backend_contracts",
        dependency_options,
    ).module("stwo_backend_contracts");
    const backend = b.addModule("stwo_cuda_backend", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    backend.addImport("stwo_backend_contracts", backend_contracts);

    const filters: []const []const u8 = if (b.option([]const u8, "test-filter", "Run CUDA backend tests whose names contain this text")) |filter| &.{filter} else &.{};
    // Test-only C stubs must not mutate the exported production module. The
    // circuit CUDA product imports this dependency and links the real archive.
    const test_root = b.createModule(.{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    test_root.addImport("stwo_backend_contracts", backend_contracts);
    const tests = b.addTest(.{ .root_module = test_root, .filters = filters });
    tests.addCSourceFile(.{
        .file = b.path("runtime/stages/test_stubs.c"),
        .flags = &.{ "-std=c11", "-Wno-strict-prototypes" },
    });
    tests.linkLibC();

    const test_step = b.step(
        "test",
        "Run the host-independent stwo_cuda_backend package tests",
    );
    test_step.dependOn(&b.addRunArtifact(tests).step);
}
