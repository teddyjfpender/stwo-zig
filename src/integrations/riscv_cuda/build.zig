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
    const tests = b.addRunArtifact(b.addTest(.{ .root_module = integration }));
    b.step(
        "test",
        "Run host-independent RISC-V CUDA integration contract tests",
    ).dependOn(&tests.step);
}
