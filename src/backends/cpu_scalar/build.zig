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
    const prover = b.dependency(
        "stwo_prover_impl",
        dependency_options,
    ).module("stwo_prover_impl");
    const backend = b.addModule("stwo_cpu_backend", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    backend.addImport("stwo_core", core);
    backend.addImport("stwo_backend_contracts", backend_contracts);
    backend.addImport("stwo_prover_impl", prover);

    const tests = b.addRunArtifact(b.addTest(.{ .root_module = backend }));
    const test_step = b.step(
        "test",
        "Compile and test the stwo_cpu_backend package",
    );
    test_step.dependOn(&tests.step);
}
