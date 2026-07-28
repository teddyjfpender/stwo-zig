const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const dependency_options = .{ .target = target, .optimize = optimize };

    const core = b.dependency("stwo_core", dependency_options).module("stwo_core");
    const backend_contracts = b.dependency(
        "stwo_backend_contracts",
        dependency_options,
    ).module("stwo_backend_contracts");
    const prover = b.addModule("stwo_prover_impl", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    prover.addImport("stwo_core", core);
    prover.addImport("stwo_backend_contracts", backend_contracts);

    const tests = b.addTest(.{ .root_module = prover });
    const run_tests = b.addRunArtifact(tests);
    const deep_tests = b.createModule(.{
        .root_source_file = b.path("testing.zig"),
        .target = target,
        .optimize = optimize,
    });
    deep_tests.addImport("stwo_core", core);
    deep_tests.addImport("stwo_prover_impl", prover);
    const run_deep_tests = b.addRunArtifact(b.addTest(.{
        .root_module = deep_tests,
    }));
    const test_step = b.step("test", "Compile and test the stwo_prover_impl package");
    test_step.dependOn(&run_tests.step);
    test_step.dependOn(&run_deep_tests.step);
}
