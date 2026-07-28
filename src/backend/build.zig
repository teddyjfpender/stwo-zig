const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const dependency_options = .{ .target = target, .optimize = optimize };

    const core = b.dependency("stwo_core", dependency_options).module("stwo_core");
    const backend_contracts = b.addModule("stwo_backend_contracts", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    backend_contracts.addImport("stwo_core", core);

    const tests = b.addTest(.{ .root_module = backend_contracts });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step(
        "test",
        "Compile and test the stwo_backend_contracts package",
    );
    test_step.dependOn(&run_tests.step);
}
