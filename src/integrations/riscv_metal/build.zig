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
    const frontend = b.dependency(
        "stwo_riscv_frontend",
        dependency_options,
    ).module("stwo_riscv_frontend");
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
    if (target.result.os.tag != .macos) {
        const unsupported = b.addFail(
            "stwo_riscv_metal_integration tests require macOS and the Apple Metal SDK",
        );
        test_step.dependOn(&unsupported.step);
        authenticated_aot_step.dependOn(&unsupported.step);
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
        authenticated_aot_step.dependOn(&b.addFail(
            "test-authenticated-aot requires -Dmetal-core-aot-bundle=<absolute-path>",
        ).step);
        return;
    };
    if (!std.fs.path.isAbsolute(configured_bundle)) {
        authenticated_aot_step.dependOn(&b.addFail(
            "test-authenticated-aot requires an absolute AOT bundle path",
        ).step);
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
}

fn linkMetalFrameworks(artifact: *std.Build.Step.Compile) void {
    artifact.linkLibC();
    artifact.linkFramework("Foundation");
    artifact.linkFramework("Metal");
    artifact.linkSystemLibrary("objc");
}
