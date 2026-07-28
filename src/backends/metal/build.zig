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
        "stwo_prover_engine",
        dependency_options,
    ).module("stwo_prover_engine");
    const prover_api = b.dependency(
        "stwo_prover_api",
        dependency_options,
    ).module("stwo_prover_api");
    const cpu_backend = b.dependency(
        "stwo_cpu_backend",
        dependency_options,
    ).module("stwo_cpu_backend");
    const backend = b.addModule("stwo_metal_backend", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    addImports(backend, core, backend_contracts, prover_api, prover, cpu_backend);

    const test_step = b.step(
        "test",
        "Compile the stwo_metal_backend package tests",
    );
    if (target.result.os.tag != .macos) {
        test_step.dependOn(&b.addFail(
            "stwo_metal_backend tests require a macOS target and the Apple Metal SDK",
        ).step);
        return;
    }
    const tests = b.addTest(.{ .root_module = backend });
    linkRuntime(b, tests);
    const deep_root = b.createModule(.{
        .root_source_file = b.path("testing.zig"),
        .target = target,
        .optimize = optimize,
    });
    addImports(deep_root, core, backend_contracts, prover_api, prover, cpu_backend);
    const deep_tests = b.addTest(.{ .root_module = deep_root });
    linkRuntime(b, deep_tests);

    test_step.dependOn(&tests.step);
    test_step.dependOn(&deep_tests.step);
}

fn addImports(
    module: *std.Build.Module,
    core: *std.Build.Module,
    backend_contracts: *std.Build.Module,
    prover_api: *std.Build.Module,
    prover: *std.Build.Module,
    cpu_backend: *std.Build.Module,
) void {
    module.addImport("stwo_core", core);
    module.addImport("stwo_backend_contracts", backend_contracts);
    module.addImport("stwo_prover_api", prover_api);
    module.addImport("stwo_prover_engine", prover);
    module.addImport("stwo_cpu_backend", cpu_backend);
}

fn linkRuntime(b: *std.Build, artifact: *std.Build.Step.Compile) void {
    artifact.addCSourceFile(.{
        .file = b.path("runtime.m"),
        .flags = &.{ "-fobjc-arc", "-fblocks" },
    });
    artifact.linkLibC();
    artifact.linkFramework("Foundation");
    artifact.linkFramework("Metal");
    artifact.linkSystemLibrary("objc");
}
