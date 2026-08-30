const std = @import("std");

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
    const metal_backend = b.dependency(
        "stwo_metal_backend",
        dependency_options,
    ).module("stwo_metal_backend");
    const frontend_dependency = b.dependency(
        "stwo_riscv_frontend",
        dependency_options,
    );
    const frontend = frontend_dependency.module("stwo_riscv_frontend");
    const secp256k1_proof_harness =
        frontend_dependency.module("secp256k1_proof_harness");
    const keccakf_proof_harness =
        frontend_dependency.module("keccakf_proof_harness");
    const integration = b.addModule("stwo_riscv_metal_integration", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    integration.addImport("stwo_core", core);
    integration.addImport("stwo_prover_api", prover_api);
    integration.addImport("stwo_prover_engine", prover);
    integration.addImport("stwo_metal_backend", metal_backend);
    integration.addImport("stwo_riscv_frontend", frontend);

    const test_step = b.step(
        "test",
        "Run device-free stwo_riscv_metal_integration contract tests",
    );
    const authenticated_aot_step = b.step(
        "test-authenticated-aot",
        "Run the guest Poseidon2 proof on a real device with authenticated AOT",
    );
    const secp256k1_proof_step = b.step(
        "test-secp256k1-precompile-proof",
        "Prove compact typed secp256k1 ECDSA on Metal and verify independently",
    );
    const keccakf_proof_step = b.step(
        "test-keccakf-precompile-proof",
        "Prove compact typed Keccak-f on Metal and verify independently",
    );
    if (target.result.os.tag != .macos) {
        const unsupported = b.addFail(
            "stwo_riscv_metal_integration tests require macOS and the Apple Metal SDK",
        );
        test_step.dependOn(&unsupported.step);
        authenticated_aot_step.dependOn(&unsupported.step);
        secp256k1_proof_step.dependOn(&unsupported.step);
        keccakf_proof_step.dependOn(&unsupported.step);
        return;
    }
    const tests = b.addTest(.{ .root_module = integration });
    linkMetalFrameworks(tests);
    test_step.dependOn(&b.addRunArtifact(tests).step);

    const configured_bundle = b.option(
        []const u8,
        "metal-core-aot-bundle",
        "Absolute authenticated core AOT bundle for real-device acceptance",
    ) orelse {
        const missing_bundle = b.addFail(
            "test-authenticated-aot requires -Dmetal-core-aot-bundle=<absolute-path>",
        );
        authenticated_aot_step.dependOn(&missing_bundle.step);
        secp256k1_proof_step.dependOn(&missing_bundle.step);
        keccakf_proof_step.dependOn(&missing_bundle.step);
        return;
    };
    if (!std.fs.path.isAbsolute(configured_bundle)) {
        const invalid_bundle = b.addFail(
            "test-authenticated-aot requires an absolute AOT bundle path",
        );
        authenticated_aot_step.dependOn(&invalid_bundle.step);
        secp256k1_proof_step.dependOn(&invalid_bundle.step);
        keccakf_proof_step.dependOn(&invalid_bundle.step);
        return;
    }
    const real_tests = b.addTest(.{
        .root_module = integration,
        .filters = &.{
            "guest Metal profile proves and independently verifies when an AOT bundle is supplied",
        },
    });
    linkMetalFrameworks(real_tests);
    const run_real = b.addRunArtifact(real_tests);
    run_real.setEnvironmentVariable(
        "STWO_RISCV_METAL_AOT_BUNDLE",
        configured_bundle,
    );
    run_real.setEnvironmentVariable("STWO_ZIG_WORKERS", "1");
    run_real.setEnvironmentVariable("STWO_ZIG_MERKLE_WORKERS", "1");
    authenticated_aot_step.dependOn(&run_real.step);

    const secp256k1_root = b.createModule(.{
        .root_source_file = b.path("secp256k1_precompile_proof_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    secp256k1_root.addImport("stwo_core", core);
    secp256k1_root.addImport("stwo_metal_backend", metal_backend);
    secp256k1_root.addImport("stwo_prover_engine", prover);
    secp256k1_root.addImport("stwo_riscv_frontend", frontend);
    secp256k1_root.addImport("secp256k1_proof_harness", secp256k1_proof_harness);
    const secp256k1_tests = b.addTest(.{
        .root_module = secp256k1_root,
        .filters = &.{"secp256k1 typed ECDSA bundle proves on Metal"},
    });
    linkMetalFrameworks(secp256k1_tests);
    const run_secp256k1 = b.addRunArtifact(secp256k1_tests);
    run_secp256k1.has_side_effects = true;
    run_secp256k1.setEnvironmentVariable(
        "STWO_RISCV_METAL_AOT_BUNDLE",
        configured_bundle,
    );
    secp256k1_proof_step.dependOn(&run_secp256k1.step);

    const keccakf_root = b.createModule(.{
        .root_source_file = b.path("keccakf_precompile_proof_test.zig"),
        .target = target,
        .optimize = optimize,
    });
    keccakf_root.addImport("stwo_core", core);
    keccakf_root.addImport("stwo_metal_backend", metal_backend);
    keccakf_root.addImport("stwo_prover_engine", prover);
    keccakf_root.addImport("stwo_riscv_frontend", frontend);
    keccakf_root.addImport("keccakf_proof_harness", keccakf_proof_harness);
    const keccakf_tests = b.addTest(.{
        .root_module = keccakf_root,
        .filters = &.{"Keccak-f typed shard proves on Metal"},
    });
    linkMetalFrameworks(keccakf_tests);
    const run_keccakf = b.addRunArtifact(keccakf_tests);
    run_keccakf.has_side_effects = true;
    run_keccakf.setEnvironmentVariable(
        "STWO_RISCV_METAL_AOT_BUNDLE",
        configured_bundle,
    );
    keccakf_proof_step.dependOn(&run_keccakf.step);
}

fn linkMetalFrameworks(artifact: *std.Build.Step.Compile) void {
    artifact.linkLibC();
    artifact.linkFramework("Foundation");
    artifact.linkFramework("Metal");
    artifact.linkSystemLibrary("objc");
}
