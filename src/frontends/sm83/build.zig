const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});
    const core = b.dependency("stwo_core", .{
        .target = target,
        .optimize = optimize,
    }).module("stwo_core");
    const prover = b.dependency("stwo_prover_engine", .{
        .target = target,
        .optimize = optimize,
    }).module("stwo_prover_engine");
    const prover_api = b.dependency("stwo_prover_api", .{
        .target = target,
        .optimize = optimize,
    }).module("stwo_prover_api");
    const frontend = b.addModule("stwo_sm83_frontend", .{
        .root_source_file = b.path("mod.zig"),
        .target = target,
        .optimize = optimize,
    });
    frontend.addImport("stwo_core", core);
    frontend.addImport("stwo_prover_api", prover_api);
    frontend.addImport("stwo_prover_engine", prover);
    const tests = b.addRunArtifact(b.addTest(.{ .root_module = frontend }));
    const test_step = b.step("test", "Compile and test the stwo_sm83_frontend package");
    test_step.dependOn(&tests.step);

    const isa_tests = b.addRunArtifact(b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("isa/mod.zig"),
            .target = target,
            .optimize = optimize,
        }),
    }));
    b.step("test-isa", "Run only SM83 opcode-table and decoder tests")
        .dependOn(&isa_tests.step);

    const runner_tests = b.addRunArtifact(b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("runner_test_root.zig"),
            .target = target,
            .optimize = optimize,
        }),
    }));
    b.step("test-runner", "Run only SM83 instruction-runner tests")
        .dependOn(&runner_tests.step);

    const checkpoint_tests = b.addRunArtifact(b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("sameboy_checkpoint_test_root.zig"),
            .target = target,
            .optimize = optimize,
        }),
    }));
    const checkpoint_gate_module = b.createModule(.{
        .root_source_file = b.path("sameboy_checkpoint_gate.zig"),
        .target = target,
        .optimize = optimize,
    });
    const checkpoint_gate = b.addExecutable(.{
        .name = "sm83-sameboy-checkpoint-gate",
        .root_module = checkpoint_gate_module,
    });
    const run_checkpoint_gate = b.addRunArtifact(checkpoint_gate);
    if (b.args) |args| run_checkpoint_gate.addArgs(args);
    const checkpoint_gate_tests = b.addRunArtifact(b.addTest(.{
        .root_module = checkpoint_gate_module,
    }));
    const checkpoint_step = b.step(
        "test-sameboy-checkpoint",
        "Import one pinned SameBoy native-v15 plus BESS checkpoint",
    );
    checkpoint_step.dependOn(&checkpoint_tests.step);
    checkpoint_step.dependOn(&run_checkpoint_gate.step);
    checkpoint_step.dependOn(&checkpoint_gate_tests.step);

    const replay_gate_module = b.createModule(.{
        .root_source_file = b.path("sameboy_replay_gate.zig"),
        .target = target,
        .optimize = optimize,
    });
    const replay_gate = b.addExecutable(.{
        .name = "sm83-sameboy-replay-gate",
        .root_module = replay_gate_module,
    });
    const run_replay_gate = b.addRunArtifact(replay_gate);
    if (b.args) |args| run_replay_gate.addArgs(args);
    const replay_gate_tests = b.addRunArtifact(b.addTest(.{
        .root_module = replay_gate_module,
    }));
    const replay_step = b.step(
        "test-sameboy-replay",
        "Replay one pinned Pokemon checkpoint prefix against SameBoy",
    );
    replay_step.dependOn(&run_replay_gate.step);
    replay_step.dependOn(&replay_gate_tests.step);

    const pokemon_fixture_module = b.createModule(.{
        .root_source_file = b.path("pokemon_checkpoint_fixture.zig"),
        .target = target,
        .optimize = optimize,
    });
    pokemon_fixture_module.addImport("stwo_core", core);
    pokemon_fixture_module.addImport("stwo_prover_api", prover_api);
    pokemon_fixture_module.addImport("stwo_prover_engine", prover);
    const pokemon_fixture = b.addExecutable(.{
        .name = "sm83-pokemon-checkpoint-fixture",
        .root_module = pokemon_fixture_module,
    });
    const run_pokemon_fixture = b.addRunArtifact(pokemon_fixture);
    if (b.args) |args| run_pokemon_fixture.addArgs(args);
    const run_pokemon_fixture_tests = b.addRunArtifact(b.addTest(.{
        .root_module = pokemon_fixture_module,
    }));
    const pokemon_fixture_step = b.step(
        "test-pokemon-fixture",
        "Prepare the pinned Pokemon machine-environment proof input",
    );
    pokemon_fixture_step.dependOn(&run_pokemon_fixture.step);
    pokemon_fixture_step.dependOn(&run_pokemon_fixture_tests.step);
    b.step(
        "benchmark-pokemon-prepare",
        "Prepare one pinned Pokemon benchmark fixture without package tests",
    ).dependOn(&run_pokemon_fixture.step);

    const pokemon_hardware_surface_step = b.step(
        "test-pokemon-hardware-surface",
        "Audit the exact hardware surface of the pinned Pokemon replay",
    );
    const pokemon_corpus = b.option(
        []const u8,
        "pokemon-corpus",
        "Path to the pinned PE-AGI v1 Pokemon corpus",
    );
    if (pokemon_corpus) |corpus_root| {
        const pokemon_hardware_surface_module = b.createModule(.{
            .root_source_file = b.path("pokemon_hardware_surface_test.zig"),
            .target = target,
            .optimize = optimize,
        });
        pokemon_hardware_surface_module.addImport("stwo_core", core);
        pokemon_hardware_surface_module.addImport("stwo_prover_api", prover_api);
        pokemon_hardware_surface_module.addImport("stwo_prover_engine", prover);
        const pokemon_hardware_surface_tests = b.addTest(.{
            .root_module = pokemon_hardware_surface_module,
            .filters = &.{
                "SM83 Pokemon hardware surface",
                "SM83 Pokemon benchmark hardware surface",
            },
        });
        const run_pokemon_hardware_surface_tests =
            b.addRunArtifact(pokemon_hardware_surface_tests);
        run_pokemon_hardware_surface_tests.setEnvironmentVariable(
            "SM83_POKEMON_CORPUS",
            corpus_root,
        );
        pokemon_hardware_surface_step.dependOn(
            &run_pokemon_hardware_surface_tests.step,
        );
    } else {
        pokemon_hardware_surface_step.dependOn(&b.addFail(
            "test-pokemon-hardware-surface requires -Dpokemon-corpus=<pinned PE-AGI v1 directory>",
        ).step);
    }

    const joypad_tests = b.createModule(.{
        .root_source_file = b.path("joypad_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    joypad_tests.addImport("stwo_core", core);
    joypad_tests.addImport("stwo_prover_engine", prover);
    const run_joypad_tests = b.addRunArtifact(b.addTest(.{
        .root_module = joypad_tests,
    }));
    b.step("test-joypad", "Run the focused SM83 joypad runner and AIR tests")
        .dependOn(&run_joypad_tests.step);

    const apu_binding_tests = b.createModule(.{
        .root_source_file = b.path("apu_binding_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    apu_binding_tests.addImport("stwo_core", core);
    apu_binding_tests.addImport("stwo_prover_engine", prover);
    const run_apu_binding_tests = b.addRunArtifact(b.addTest(.{
        .root_module = apu_binding_tests,
    }));
    b.step(
        "test-apu-binding",
        "Run the focused SM83 CPU-visible APU binding tests",
    ).dependOn(&run_apu_binding_tests.step);

    const environment_tests = b.createModule(.{
        .root_source_file = b.path("environment_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    environment_tests.addImport("stwo_core", core);
    environment_tests.addImport("stwo_prover_engine", prover);
    const run_environment_tests = b.addRunArtifact(b.addTest(.{
        .root_module = environment_tests,
    }));
    b.step(
        "test-environment",
        "Run the focused SM83 environment statement and replay tests",
    ).dependOn(&run_environment_tests.step);

    const intermediate_ram_observation_tests = b.createModule(.{
        .root_source_file = b.path(
            "intermediate_ram_observation_lookup_test_root.zig",
        ),
        .target = target,
        .optimize = optimize,
    });
    intermediate_ram_observation_tests.addImport("stwo_core", core);
    intermediate_ram_observation_tests.addImport("stwo_prover_engine", prover);
    const run_intermediate_ram_observation_tests = b.addRunArtifact(b.addTest(.{
        .root_module = intermediate_ram_observation_tests,
    }));
    b.step(
        "test-intermediate-ram-observation",
        "Run the focused SM83 intermediate RAM observation lookup tests",
    ).dependOn(&run_intermediate_ram_observation_tests.step);

    const scheduler_tests = b.createModule(.{
        .root_source_file = b.path("scheduler_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    scheduler_tests.addImport("stwo_core", core);
    scheduler_tests.addImport("stwo_prover_engine", prover);
    const run_scheduler_tests = b.addRunArtifact(b.addTest(.{
        .root_module = scheduler_tests,
    }));
    b.step("test-scheduler", "Run the focused SM83 scheduler AIR tests")
        .dependOn(&run_scheduler_tests.step);

    const dma_tests = b.createModule(.{
        .root_source_file = b.path("dma_binding_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    dma_tests.addImport("stwo_core", core);
    dma_tests.addImport("stwo_prover_engine", prover);
    const run_dma_tests = b.addRunArtifact(b.addTest(.{
        .root_module = dma_tests,
    }));
    b.step("test-dma", "Run the focused SM83 DMA binding and lookup tests")
        .dependOn(&run_dma_tests.step);

    const ppu_tests = b.createModule(.{
        .root_source_file = b.path("ppu_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    ppu_tests.addImport("stwo_core", core);
    ppu_tests.addImport("stwo_prover_engine", prover);
    const run_ppu_tests = b.addRunArtifact(b.addTest(.{
        .root_module = ppu_tests,
    }));
    b.step(
        "test-ppu",
        "Run the focused SM83 PPU timing, MMIO, AIR, and component tests",
    ).dependOn(&run_ppu_tests.step);

    const timer_tests = b.createModule(.{
        .root_source_file = b.path("timer_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    timer_tests.addImport("stwo_core", core);
    timer_tests.addImport("stwo_prover_engine", prover);
    const run_timer_tests = b.addRunArtifact(b.addTest(.{
        .root_module = timer_tests,
    }));
    b.step(
        "test-timer",
        "Run the focused SM83 timer AIR and component tests",
    ).dependOn(&run_timer_tests.step);

    const cartridge_tests = b.createModule(.{
        .root_source_file = b.path("cartridge_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    cartridge_tests.addImport("stwo_core", core);
    cartridge_tests.addImport("stwo_prover_engine", prover);
    const run_cartridge_tests = b.addRunArtifact(b.addTest(.{
        .root_module = cartridge_tests,
    }));
    b.step("test-cartridge", "Run the focused SM83 cartridge runner and AIR tests")
        .dependOn(&run_cartridge_tests.step);

    const cartridge_proof_tests = b.createModule(.{
        .root_source_file = b.path("cartridge_proof_test_root.zig"),
        .target = target,
        .optimize = optimize,
    });
    cartridge_proof_tests.addImport("stwo_core", core);
    cartridge_proof_tests.addImport("stwo_prover_engine", prover);
    const run_cartridge_proof_tests = b.addRunArtifact(b.addTest(.{
        .root_module = cartridge_proof_tests,
    }));
    b.step(
        "test-cartridge-proof",
        "Run the focused SM83 cartridge statement and component geometry tests",
    ).dependOn(&run_cartridge_proof_tests.step);

    const corpus_module = b.createModule(.{
        .root_source_file = b.path("corpus_gate.zig"),
        .target = target,
        .optimize = optimize,
    });
    corpus_module.addImport("stwo_core", core);
    corpus_module.addImport("stwo_prover_api", prover_api);
    corpus_module.addImport("stwo_prover_engine", prover);
    const corpus_gate = b.addExecutable(.{
        .name = "sm83-corpus-gate",
        .root_module = corpus_module,
    });
    const run_corpus = b.addRunArtifact(corpus_gate);
    if (b.args) |args| run_corpus.addArgs(args);
    b.step("test-corpus", "Run the pinned 500000-case SM83 differential corpus")
        .dependOn(&run_corpus.step);

    const blargg_gate = b.addExecutable(.{
        .name = "sm83-blargg-flat-gate",
        .root_module = b.createModule(.{
            .root_source_file = b.path("blargg_gate.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_blargg = b.addRunArtifact(blargg_gate);
    if (b.args) |args| run_blargg.addArgs(args);
    b.step(
        "test-blargg-flat",
        "Run all 11 Blargg cpu_instrs ROMs on the flat SM83 machine",
    ).dependOn(&run_blargg.step);

    const mooneye_gate = b.addExecutable(.{
        .name = "sm83-mooneye-focused-gate",
        .root_module = b.createModule(.{
            .root_source_file = b.path("mooneye_gate.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    const run_mooneye = b.addRunArtifact(mooneye_gate);
    if (b.args) |args| run_mooneye.addArgs(args);
    const mooneye_unit_module = b.createModule(.{
        .root_source_file = b.path("mooneye_gate.zig"),
        .target = target,
        .optimize = optimize,
    });
    const run_mooneye_unit_tests = b.addRunArtifact(b.addTest(.{
        .root_module = mooneye_unit_module,
    }));
    const mooneye_step = b.step(
        "test-mooneye-focused",
        "Run unit tests and 25 pinned PPU-independent Mooneye machine ROMs",
    );
    mooneye_step.dependOn(&run_mooneye.step);
    mooneye_step.dependOn(&run_mooneye_unit_tests.step);

    const mooneye_ppu_module = b.createModule(.{
        .root_source_file = b.path("mooneye_ppu_gate.zig"),
        .target = target,
        .optimize = optimize,
    });
    const mooneye_ppu_gate = b.addExecutable(.{
        .name = "sm83-mooneye-live-ppu-gate",
        .root_module = mooneye_ppu_module,
    });
    const run_mooneye_ppu = b.addRunArtifact(mooneye_ppu_gate);
    if (b.args) |args| run_mooneye_ppu.addArgs(args);
    const run_mooneye_ppu_unit_tests = b.addRunArtifact(b.addTest(.{
        .root_module = mooneye_ppu_module,
    }));
    const mooneye_ppu_step = b.step(
        "test-mooneye-ppu-live",
        "Run the pinned live-PPU Mooneye ROM and detached-device control",
    );
    mooneye_ppu_step.dependOn(&run_mooneye_ppu.step);
    mooneye_ppu_step.dependOn(&run_mooneye_ppu_unit_tests.step);

    const mooneye_dma_module = b.createModule(.{
        .root_source_file = b.path("mooneye_dma_gate.zig"),
        .target = target,
        .optimize = optimize,
    });
    const mooneye_dma_gate = b.addExecutable(.{
        .name = "sm83-mooneye-live-dma-gate",
        .root_module = mooneye_dma_module,
    });
    const run_mooneye_dma = b.addRunArtifact(mooneye_dma_gate);
    if (b.args) |args| run_mooneye_dma.addArgs(args);
    const run_mooneye_dma_unit_tests = b.addRunArtifact(b.addTest(.{
        .root_module = mooneye_dma_module,
    }));
    const mooneye_dma_step = b.step(
        "test-mooneye-dma-live",
        "Run the pinned live-DMA Mooneye ROM and negative controls",
    );
    mooneye_dma_step.dependOn(&run_mooneye_dma.step);
    mooneye_dma_step.dependOn(&run_mooneye_dma_unit_tests.step);
}
