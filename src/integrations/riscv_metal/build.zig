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
    const metal_package = b.dependency("stwo_metal_backend", dependency_options);
    const metal_backend = metal_package.module("stwo_metal_backend");
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
        "Compile the stwo_riscv_metal_integration package tests",
    );
    if (target.result.os.tag != .macos) {
        test_step.dependOn(&b.addFail(
            "stwo_riscv_metal_integration tests require macOS and the Apple Metal SDK",
        ).step);
        return;
    }
    const tests = b.addTest(.{ .root_module = integration });
    tests.addCSourceFile(.{
        .file = metal_package.path("runtime.m"),
        .flags = &.{ "-fobjc-arc", "-fblocks" },
    });
    tests.linkLibC();
    tests.linkFramework("Foundation");
    tests.linkFramework("Metal");
    tests.linkSystemLibrary("objc");
    test_step.dependOn(&tests.step);
}
