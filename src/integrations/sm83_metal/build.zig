const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const options = .{ .target = target, .optimize = optimize };

    const core = b.dependency("stwo_core", options).module("stwo_core");
    const cpu = b.dependency("stwo_cpu_backend", options).module("stwo_cpu_backend");
    const metal = b.dependency("stwo_metal_backend", options).module("stwo_metal_backend");
    const frontend = b.dependency("stwo_sm83_frontend", options).module("stwo_sm83_frontend");

    const integration = b.addModule("stwo_sm83_metal_integration", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    integration.addImport("stwo_core", core);
    integration.addImport("stwo_cpu_backend", cpu);
    integration.addImport("stwo_metal_backend", metal);
    integration.addImport("stwo_sm83_frontend", frontend);

    const test_step = b.step("test", "Test the SM83 Metal proof integration");
    const machine_environment_step = b.step(
        "test-machine-environment",
        "Test the complete SM83 machine environment through Metal",
    );
    const pokemon_checkpoint_step = b.step(
        "test-pokemon-checkpoint",
        "Prove the pinned Pokemon checkpoint slice on Metal",
    );
    if (target.result.os.tag != .macos) {
        const unsupported = b.addFail(
            "stwo_sm83_metal_integration tests require macOS and the Apple Metal SDK",
        );
        test_step.dependOn(&unsupported.step);
        machine_environment_step.dependOn(&unsupported.step);
        pokemon_checkpoint_step.dependOn(&unsupported.step);
        return;
    }
    // The complete machine-environment proof has its own focused step below.
    // These inclusive filters keep it out of the broad suite even though the
    // public adapter must import its implementation.
    const tests = b.addTest(.{
        .root_module = integration,
        .filters = &.{
            "SM83",
            "cartridge Metal proof",
            "environment Metal proof binds",
            "environment adapter selects only Metal",
        },
    });
    tests.linkLibC();
    tests.linkFramework("Foundation");
    tests.linkFramework("Metal");
    tests.linkSystemLibrary("objc");
    test_step.dependOn(&b.addRunArtifact(tests).step);

    const machine_environment_tests = b.createModule(.{
        .root_source_file = b.path("machine_environment_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    machine_environment_tests.addImport("stwo_core", core);
    machine_environment_tests.addImport("stwo_metal_backend", metal);
    machine_environment_tests.addImport("stwo_sm83_frontend", frontend);
    const focused_tests = b.addTest(.{
        .root_module = machine_environment_tests,
    });
    focused_tests.linkLibC();
    focused_tests.linkFramework("Foundation");
    focused_tests.linkFramework("Metal");
    focused_tests.linkSystemLibrary("objc");
    machine_environment_step.dependOn(
        &b.addRunArtifact(focused_tests).step,
    );

    const pokemon_gate = b.createModule(.{
        .root_source_file = b.path("pokemon_checkpoint_proof.zig"),
        .target = target,
        .optimize = optimize,
    });
    pokemon_gate.addImport("stwo_core", core);
    pokemon_gate.addImport("stwo_cpu_backend", cpu);
    pokemon_gate.addImport("stwo_metal_backend", metal);
    pokemon_gate.addImport("stwo_sm83_frontend", frontend);
    const pokemon_executable = b.addExecutable(.{
        .name = "sm83-pokemon-metal-proof",
        .root_module = pokemon_gate,
    });
    pokemon_executable.linkLibC();
    pokemon_executable.linkFramework("Foundation");
    pokemon_executable.linkFramework("Metal");
    pokemon_executable.linkSystemLibrary("objc");
    const run_pokemon_gate = b.addRunArtifact(pokemon_executable);
    if (b.args) |args| run_pokemon_gate.addArgs(args);
    pokemon_checkpoint_step.dependOn(&run_pokemon_gate.step);
}
