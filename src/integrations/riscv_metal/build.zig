const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const options = .{ .target = target, .optimize = optimize };

    const core = b.dependency("stwo_core", options).module("stwo_core");
    const prover_api = b.dependency("stwo_prover_api", options).module("stwo_prover_api");
    const prover = b.dependency("stwo_prover_engine", options).module("stwo_prover_engine");
    const metal = b.dependency("stwo_metal_backend", options).module("stwo_metal_backend");
    const frontend = b.dependency("stwo_riscv_frontend", options).module("stwo_riscv_frontend");
    const secp256k1_proof_harness = b.dependency("stwo_riscv_frontend", options).module("secp256k1_proof_harness");
    const cpu = b.dependency("stwo_riscv_cpu_integration", options);

    const integration = b.addModule("stwo_riscv_metal_integration", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    integration.addImport("stwo_core", core);
    integration.addImport("stwo_prover_api", prover_api);
    integration.addImport("stwo_prover_engine", prover);
    integration.addImport("stwo_metal_backend", metal);
    integration.addImport("stwo_riscv_frontend", frontend);

    const test_step = b.step("test", "Run device-free RISC-V Metal integration tests");
    if (target.result.os.tag != .macos) {
        test_step.dependOn(&b.addFail("RISC-V Metal integration requires macOS and the Metal SDK").step);
    } else {
        const tests = b.addTest(.{ .root_module = integration });
        linkMetalFrameworks(tests);
        test_step.dependOn(&b.addRunArtifact(tests).step);
    }

    const blake3_runtime = b.createModule(.{
        .root_source_file = b.path("blake3_runtime.zig"),
        .target = target,
        .optimize = optimize,
    });
    const csp_root = b.createModule(.{
        .root_source_file = b.path("blake3_csp_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    csp_root.addImport("blake3_runtime", blake3_runtime);
    csp_root.addImport("stwo_core", core);
    csp_root.addImport("stwo_prover_engine", prover);
    csp_root.addImport("stwo_metal_backend", metal);
    csp_root.addImport("secp256k1_proof_harness", secp256k1_proof_harness);
    const csp_tests = b.addTest(.{
        .root_module = csp_root,
        .filters = &.{"Metal BLAKE3 canonical CSP ECDSA proves and independently verifies"},
    });
    linkMetalFrameworks(csp_tests);
    const csp_jit = b.addRunArtifact(csp_tests);
    csp_jit.setEnvironmentVariable("STWO_BLAKE3_CSP_RUNTIME", "source_jit");
    b.step("test-blake3-csp-ecdsa-jit", "Prove and independently verify canonical CSP ECDSA on Metal source-JIT")
        .dependOn(&csp_jit.step);
    const aot_step = b.step("test-blake3-csp-ecdsa-aot", "Prove and independently verify canonical CSP ECDSA on authenticated AOT Metal");
    if (b.option([]const u8, "metal-core-aot-bundle", "Absolute authenticated core AOT bundle for real-device acceptance")) |bundle| {
        const csp_aot = b.addRunArtifact(csp_tests);
        csp_aot.setEnvironmentVariable("STWO_BLAKE3_CSP_RUNTIME", "authenticated_aot");
        csp_aot.setEnvironmentVariable("STWO_RISCV_METAL_AOT_BUNDLE", bundle);
        aot_step.dependOn(&csp_aot.step);
    } else {
        aot_step.dependOn(&b.addFail("test-blake3-csp-ecdsa-aot requires -Dmetal-core-aot-bundle=<absolute-path>").step);
    }

    // The shared SegmentV2 detached protocol has one producer implementation;
    // Metal supplies only its authenticated backend/runtime boundary.
    const leaf_root = b.createModule(.{
        .root_source_file = b.path("recursive_segment_v2_detached_leaf_runner.zig"),
        .target = target,
        .optimize = optimize,
    });
    leaf_root.addImport("stwo_metal_backend", metal);
    leaf_root.addImport("stwo_riscv_detached_leaf_runner", cpu.module("stwo_riscv_detached_leaf_runner"));
    const leaf = b.addExecutable(.{
        .name = "recursive-segment-v2-detached-leaf-prove-metal",
        .root_module = leaf_root,
    });
    linkMetalFrameworks(leaf);
    b.step("build-recursive-segment-v2-detached-leaf-producer", "Build the authenticated Metal SegmentV2 leaf producer")
        .dependOn(&b.addInstallArtifact(leaf, .{}).step);

    const parent_root = b.createModule(.{
        .root_source_file = b.path("recursive_segment_v2_detached_parent_producer_runner.zig"),
        .target = target,
        .optimize = optimize,
    });
    parent_root.addImport("stwo_metal_backend", metal);
    parent_root.addImport("stwo_riscv_frontend", frontend);
    parent_root.addImport("stwo_riscv_detached_parent_producer", cpu.module("stwo_riscv_detached_parent_producer"));
    const parent = b.addExecutable(.{
        .name = "recursive-segment-v2-detached-parent-prove-metal",
        .root_module = parent_root,
    });
    linkMetalFrameworks(parent);
    b.step("build-recursive-segment-v2-detached-parent-producer", "Build the authenticated Metal SegmentV2 parent producer")
        .dependOn(&b.addInstallArtifact(parent, .{}).step);
}

fn linkMetalFrameworks(artifact: *std.Build.Step.Compile) void {
    artifact.linkLibC();
    artifact.linkFramework("Foundation");
    artifact.linkFramework("Metal");
    artifact.linkSystemLibrary("objc");
}
