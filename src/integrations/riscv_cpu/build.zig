const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const dependency_options = .{ .target = target, .optimize = optimize };

    const core = b.dependency("stwo_core", dependency_options).module("stwo_core");
    const prover = b.dependency(
        "stwo_prover_impl",
        dependency_options,
    ).module("stwo_prover_impl");
    const cpu_backend = b.dependency(
        "stwo_cpu_backend",
        dependency_options,
    ).module("stwo_cpu_backend");
    const frontend = b.dependency(
        "stwo_riscv_frontend",
        dependency_options,
    ).module("stwo_riscv_frontend");
    const integration = b.addModule("stwo_riscv_cpu_integration", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    addImports(integration, core, prover, cpu_backend, frontend);

    const tests = b.addRunArtifact(b.addTest(.{ .root_module = integration }));
    const test_step = b.step(
        "test",
        "Compile and test the stwo_riscv_cpu_integration package",
    );
    test_step.dependOn(&tests.step);
}

fn addImports(
    module: *std.Build.Module,
    core: *std.Build.Module,
    prover: *std.Build.Module,
    cpu_backend: *std.Build.Module,
    frontend: *std.Build.Module,
) void {
    module.addImport("stwo_core", core);
    module.addImport("stwo_prover_impl", prover);
    module.addImport("stwo_cpu_backend", cpu_backend);
    module.addImport("stwo_riscv_frontend", frontend);
}
