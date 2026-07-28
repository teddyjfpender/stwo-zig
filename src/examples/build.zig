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
    const proof_wire = b.dependency(
        "stwo_proof_wire",
        dependency_options,
    ).module("stwo_proof_wire");

    const examples = b.addModule("stwo_native_examples", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    addImports(examples, core, prover, cpu_backend, proof_wire);

    const test_root = b.createModule(.{
        .root_source_file = b.path("test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    addImports(test_root, core, prover, cpu_backend, proof_wire);
    const tests = b.addTest(.{ .root_module = test_root });
    b.step(
        "test",
        "Run Native example AIR and reusable-session tests",
    ).dependOn(&b.addRunArtifact(tests).step);
}

fn addImports(
    module: *std.Build.Module,
    core: *std.Build.Module,
    prover: *std.Build.Module,
    cpu_backend: *std.Build.Module,
    proof_wire: *std.Build.Module,
) void {
    module.addImport("stwo_core", core);
    module.addImport("stwo_prover_impl", prover);
    module.addImport("stwo_cpu_backend", cpu_backend);
    module.addImport("stwo_proof_wire", proof_wire);
}
