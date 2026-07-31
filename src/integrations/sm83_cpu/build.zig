const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const options = .{ .target = target, .optimize = optimize };

    const core = b.dependency("stwo_core", options).module("stwo_core");
    const prover = b.dependency("stwo_prover_engine", options).module("stwo_prover_engine");
    const cpu = b.dependency("stwo_cpu_backend", options).module("stwo_cpu_backend");
    const frontend = b.dependency("stwo_sm83_frontend", options).module("stwo_sm83_frontend");

    const integration = b.addModule("stwo_sm83_cpu_integration", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    integration.addImport("stwo_core", core);
    integration.addImport("stwo_prover_engine", prover);
    integration.addImport("stwo_cpu_backend", cpu);
    integration.addImport("stwo_sm83_frontend", frontend);
    const default_machine_environment_options = b.addOptions();
    default_machine_environment_options.addOption(u8, "log_size", 4);
    integration.addOptions(
        "machine_environment_test_options",
        default_machine_environment_options,
    );

    // The complete machine-environment proof has its own focused step below.
    // Keep its source reachable for the package contract without executing the
    // expensive proof twice in the broad package suite.
    const tests = b.addRunArtifact(b.addTest(.{
        .root_module = integration,
        .filters = &.{
            "SM83",
            "cartridge CPU proof",
            "environment CPU proof binds",
        },
    }));
    b.step("test", "Compile and test the SM83 CPU proof integration").dependOn(&tests.step);

    const machine_environment_tests = b.createModule(.{
        .root_source_file = b.path("machine_environment_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    const machine_environment_log = b.option(
        u8,
        "machine-environment-log",
        "Focused SM83 machine-environment trace log size (4...16)",
    ) orelse 4;
    if (machine_environment_log < 4 or machine_environment_log > 16) {
        std.debug.panic(
            "-Dmachine-environment-log must be between 4 and 16, got {d}",
            .{machine_environment_log},
        );
    }
    const machine_environment_options = b.addOptions();
    machine_environment_options.addOption(
        u8,
        "log_size",
        machine_environment_log,
    );
    machine_environment_tests.addOptions(
        "machine_environment_test_options",
        machine_environment_options,
    );
    machine_environment_tests.addImport("stwo_core", core);
    machine_environment_tests.addImport("stwo_prover_engine", prover);
    machine_environment_tests.addImport("stwo_cpu_backend", cpu);
    machine_environment_tests.addImport("stwo_sm83_frontend", frontend);
    const run_machine_environment = b.addRunArtifact(b.addTest(.{
        .root_module = machine_environment_tests,
    }));
    b.step(
        "test-machine-environment",
        "Run the complete SM83 machine-environment CPU proof gate",
    ).dependOn(&run_machine_environment.step);

    const pokemon_gate = b.createModule(.{
        .root_source_file = b.path("pokemon_checkpoint_proof.zig"),
        .target = target,
        .optimize = optimize,
    });
    pokemon_gate.addImport("stwo_core", core);
    pokemon_gate.addImport("stwo_cpu_backend", cpu);
    pokemon_gate.addImport("stwo_sm83_frontend", frontend);
    const run_pokemon_gate = b.addRunArtifact(b.addExecutable(.{
        .name = "sm83-pokemon-cpu-proof",
        .root_module = pokemon_gate,
    }));
    if (b.args) |args| run_pokemon_gate.addArgs(args);
    b.step(
        "test-pokemon-checkpoint",
        "Prove the pinned Pokemon checkpoint slice on CPU/SIMD",
    ).dependOn(&run_pokemon_gate.step);

    const battle_chain = b.createModule(.{
        .root_source_file = b.path("pokemon_battle_chain_proof.zig"),
        .target = target,
        .optimize = optimize,
    });
    battle_chain.addImport("stwo_core", core);
    battle_chain.addImport("stwo_cpu_backend", cpu);
    battle_chain.addImport("stwo_sm83_frontend", frontend);
    const run_battle_chain = b.addRunArtifact(b.addExecutable(.{
        .name = "sm83-pokemon-cpu-battle-chain",
        .root_module = battle_chain,
    }));
    if (b.args) |args| run_battle_chain.addArgs(args);
    b.step(
        "test-pokemon-battle-chain",
        "Prove and verify the streamed Pokemon battle prefix",
    ).dependOn(&run_battle_chain.step);
}
