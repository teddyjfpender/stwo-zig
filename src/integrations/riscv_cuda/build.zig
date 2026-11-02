const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const options = .{ .target = target, .optimize = optimize };
    const contracts = b.dependency(
        "stwo_backend_contracts",
        options,
    ).module("stwo_backend_contracts");
    const backend = b.dependency(
        "stwo_cuda_backend",
        options,
    ).module("stwo_cuda_backend");
    const frontend = b.dependency(
        "stwo_riscv_frontend",
        options,
    ).module("stwo_riscv_frontend");
    const integration = b.addModule("stwo_riscv_cuda_integration", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    integration.addImport("stwo_backend_contracts", contracts);
    integration.addImport("stwo_cuda_backend", backend);
    integration.addImport("stwo_riscv_frontend", frontend);
    integration.addImport("stwo_core", b.dependency("stwo_core", options).module("stwo_core"));
    integration.addImport("stwo_prover_engine", b.dependency("stwo_prover_engine", options).module("stwo_prover_engine"));
    const tests = b.addRunArtifact(b.addTest(.{ .root_module = integration }));
    const test_step = b.step(
        "test",
        "Run host-independent RISC-V CUDA integration contract tests",
    );
    test_step.dependOn(&tests.step);
    const numerical_root = b.createModule(.{
        .root_source_file = b.path("rv64_numerical_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    numerical_root.addImport("stwo_core", b.dependency("stwo_core", options).module("stwo_core"));
    numerical_root.addImport("stwo_prover_engine", b.dependency("stwo_prover_engine", options).module("stwo_prover_engine"));
    const numerical = b.addTest(.{ .root_module = numerical_root });
    numerical.addCSourceFile(.{ .file = b.path("../../../tests/cuda/rv64/numerical_bridge.cpp"), .flags = &.{"-std=c++17"} });
    numerical.addIncludePath(b.path("../../../tests/cuda/rv64/host_include"));
    numerical.addIncludePath(b.path("../../backends/cuda/native"));
    numerical.linkLibCpp();
    const numerical_step = b.step("test-rv64-numerical", "Check CUDA host arithmetic against native OM31 and GKR");
    const run_numerical = b.addRunArtifact(numerical);
    numerical_step.dependOn(&run_numerical.step);
    test_step.dependOn(&run_numerical.step);
    const binding_root = b.createModule(.{
        .root_source_file = b.path("rv64_binding_check_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    binding_root.addImport("stwo_cuda_backend", backend);
    const binding_object = b.addObject(.{ .name = "rv64-cuda-binding-check", .root_module = binding_root });
    binding_object.linkLibC();
    const binding_step = b.step("check-rv64-native-bindings", "Compile real-context RV64 CUDA FFI without requiring a GPU");
    binding_step.dependOn(&binding_object.step);
    test_step.dependOn(&binding_object.step);
}
