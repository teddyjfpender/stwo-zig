const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const dependency_options = .{ .target = target, .optimize = optimize };
    const backend_contracts = b.dependency(
        "stwo_backend_contracts",
        dependency_options,
    ).module("stwo_backend_contracts");
    const core = b.dependency("stwo_core", dependency_options).module("stwo_core");
    const prover = b.dependency(
        "stwo_prover_engine",
        dependency_options,
    ).module("stwo_prover_engine");
    const cuda_backend = b.dependency(
        "stwo_cuda_backend",
        dependency_options,
    ).module("stwo_cuda_backend");
    const native_examples = b.dependency(
        "stwo_native_examples",
        dependency_options,
    ).module("stwo_native_examples");
    const proof_wire = b.dependency(
        "stwo_proof_wire",
        dependency_options,
    ).module("stwo_proof_wire");

    const integration = b.addModule("stwo_native_cuda_integration", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    integration.addImport("stwo_backend_contracts", backend_contracts);
    integration.addImport("stwo_core", core);
    integration.addImport("stwo_prover_engine", prover);
    integration.addImport("stwo_cuda_backend", cuda_backend);
    integration.addImport("stwo_native_examples", native_examples);
    integration.addImport("stwo_proof_wire", proof_wire);

    const filters: []const []const u8 = if (b.option(
        []const u8,
        "test-filter",
        "Run Native CUDA integration tests whose names contain this text",
    )) |filter|
        b.allocator.dupe([]const u8, &.{filter}) catch @panic("out of memory")
    else
        &.{};
    const tests = b.addRunArtifact(b.addTest(.{
        .root_module = integration,
        .filters = filters,
    }));
    b.step(
        "test",
        "Run the host-independent Native CUDA integration package tests",
    ).dependOn(&tests.step);
}
