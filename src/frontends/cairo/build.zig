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
    const frontend = b.addModule("stwo_cairo_frontend", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    frontend.addImport("stwo_core", core);
    frontend.addImport("stwo_backend_contracts", backend_contracts);
    frontend.addImport("stwo_prover_impl", prover);

    const repository_root: std.Build.LazyPath = .{
        .cwd_relative = b.pathFromRoot("../../.."),
    };
    const tests = b.addRunArtifact(b.addTest(.{ .root_module = frontend }));
    // The package owns the tests, while the monorepo owns the authenticated
    // Cairo conformance vectors they consume. Make that test-only boundary
    // independent of the directory from which `zig build` was invoked.
    tests.setCwd(repository_root);
    const deep_root = b.createModule(.{
        .root_source_file = b.path("testing.zig"),
        .target = target,
        .optimize = optimize,
    });
    deep_root.addImport("cairo_frontend", frontend);
    deep_root.addImport("stwo_core", core);
    deep_root.addImport("stwo_backend_contracts", backend_contracts);
    deep_root.addImport("stwo_prover_impl", prover);
    const deep_tests = b.addRunArtifact(b.addTest(.{ .root_module = deep_root }));
    deep_tests.setCwd(repository_root);

    const test_step = b.step(
        "test",
        "Compile and test the stwo_cairo_frontend package",
    );
    test_step.dependOn(&tests.step);
    test_step.dependOn(&deep_tests.step);
}
