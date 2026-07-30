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
    const cuda_dependency = b.dependency(
        "stwo_cuda_backend",
        dependency_options,
    );
    const cuda_backend = cuda_dependency.module("stwo_cuda_backend");
    const cairo_frontend = b.dependency(
        "stwo_cairo_frontend",
        dependency_options,
    ).module("stwo_cairo_frontend");
    const native_cuda = b.dependency(
        "stwo_native_cuda_integration",
        dependency_options,
    ).module("stwo_native_cuda_integration");

    const integration = b.addModule("stwo_cairo_cuda_integration", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    integration.addImport("stwo_backend_contracts", backend_contracts);
    integration.addImport("stwo_core", core);
    integration.addImport("stwo_prover_engine", prover);
    integration.addImport("stwo_cuda_backend", cuda_backend);
    integration.addImport("stwo_cairo_frontend", cairo_frontend);
    integration.addImport("stwo_native_cuda_integration", native_cuda);

    const filters: []const []const u8 = if (b.option(
        []const u8,
        "test-filter",
        "Run Cairo CUDA integration tests whose names contain this text",
    )) |filter|
        b.allocator.dupe([]const u8, &.{filter}) catch @panic("out of memory")
    else
        &.{};
    const tests = b.addTest(.{
        .root_module = integration,
        .filters = filters,
    });
    tests.addCSourceFile(.{
        .file = b.path("test_stubs.c"),
        .flags = &.{ "-std=c11", "-Wno-strict-prototypes" },
    });
    tests.linkLibC();
    const run_tests = b.addRunArtifact(tests);
    b.step(
        "test",
        "Run host-independent Cairo CUDA integration package tests",
    ).dependOn(&run_tests.step);
}
