const std = @import("std");
const proof_steps = @import("build_proof_steps.zig");
const segment_steps = @import("build_segment_steps.zig");
const binary_steps = @import("build_binary_steps.zig");
const artifact_steps = @import("build_artifact_steps.zig");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const dependency_options = .{ .target = target, .optimize = optimize };

    const core = b.dependency("stwo_core", dependency_options).module("stwo_core");
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
    const frontend_dependency = b.dependency(
        "stwo_riscv_frontend",
        dependency_options,
    );
    const frontend = frontend_dependency.module("stwo_riscv_frontend");
    const secp256k1_proof_harness =
        frontend_dependency.module("secp256k1_proof_harness");
    const postcard = frontend.import_table.get("interop_postcard") orelse
        @panic("canonical RISC-V frontend is missing interop_postcard");
    const integration = b.addModule("stwo_riscv_cpu_integration", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    integration.addImport("stwo_core", core);
    integration.addImport("stwo_prover_api", prover_api);
    integration.addImport("stwo_prover_engine", prover);
    integration.addImport("stwo_cpu_backend", cpu_backend);
    integration.addImport("stwo_riscv_frontend", frontend);
    integration.addImport("interop_postcard", postcard);

    const test_step = b.step(
        "test",
        "Compile and test the stwo_riscv_cpu_integration package",
    );
    const context = .{
        .b = b,
        .target = target,
        .optimize = optimize,
        .core = core,
        .prover = prover,
        .prover_api = prover_api,
        .cpu_backend = cpu_backend,
        .frontend = frontend,
        .secp256k1_proof_harness = secp256k1_proof_harness,
        .postcard = postcard,
        .integration = integration,
        .test_step = test_step,
    };
    proof_steps.add(context);
    segment_steps.add(context);
    binary_steps.add(context);
    artifact_steps.add(context);
}
