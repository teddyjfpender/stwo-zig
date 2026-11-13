const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const check_only = b.option(bool, "check-only", "Compile focused source contracts without running") orelse false;
    const options = .{ .target = target, .optimize = optimize };

    const core = b.dependency("stwo_core", options).module("stwo_core");
    const prover_api = b.dependency("stwo_prover_api", options).module("stwo_prover_api");
    const prover = b.dependency("stwo_prover_engine", options).module("stwo_prover_engine");
    const metal = b.dependency("stwo_metal_backend", options).module("stwo_metal_backend");
    const frontend = b.dependency("stwo_riscv_frontend", options).module("stwo_riscv_frontend");
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
    const export_root = b.createModule(.{ .root_source_file = b.path("native_polynomial_aot_export.zig"), .target = target, .optimize = optimize });
    export_root.addImport("stwo_metal_backend", metal);
    export_root.addImport("stwo_riscv_frontend", frontend);
    const exporter = b.addExecutable(.{ .name = "riscv-native-polynomial-aot-export", .root_module = export_root });
    const aot_root = b.createModule(.{ .root_source_file = b.path("native_polynomial_aot_test_root.zig"), .target = target, .optimize = optimize });
    aot_root.addImport("stwo_core", core);
    aot_root.addImport("stwo_metal_backend", metal);
    aot_root.addImport("stwo_riscv_frontend", frontend);
    const aot_tests = b.addTest(.{ .root_module = aot_root });
    if (target.result.os.tag == .macos) {
        linkMetalFrameworks(exporter);
        linkMetalFrameworks(aot_tests);
    }
    const native_aot_step = b.step("test-native-polynomial-aot", "Check native polynomial source authority and compile its offline exporter");
    native_aot_step.dependOn(&exporter.step);
    native_aot_step.dependOn(if (check_only) &aot_tests.step else &b.addRunArtifact(aot_tests).step);
    test_step.dependOn(native_aot_step);
    b.step("build-native-polynomial-aot-export", "Install the offline native AIR catalog exporter")
        .dependOn(&b.addInstallArtifact(exporter, .{}).step);
    if (target.result.os.tag != .macos) {
        test_step.dependOn(&b.addFail("RISC-V Metal integration requires macOS and the Metal SDK").step);
    } else {
        const tests = b.addTest(.{ .root_module = integration });
        linkMetalFrameworks(tests);
        test_step.dependOn(&b.addRunArtifact(tests).step);
    }

    // The shared SegmentV2 detached protocol has one producer implementation;
    // Metal supplies only its authenticated backend/runtime boundary.
    const leaf_root = b.createModule(.{
        .root_source_file = b.path("recursive_segment_detached_leaf_runner.zig"),
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
        .root_source_file = b.path("recursive_segment_detached_parent_producer_runner.zig"),
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
