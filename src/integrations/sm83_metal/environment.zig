//! Metal adapter for the shared SM83 environment proof transaction.

const std = @import("std");
const pcs_core = @import("stwo_core").pcs;
const frontend = @import("stwo_sm83_frontend");
const metal = @import("stwo_metal_backend");
const prover = frontend.environment_prover;

pub const ProverEngine =
    prover.ProverEngineForBackend(metal.MetalCommitBackend);
pub const ExecutionStatement = prover.ExecutionStatement;
pub const ProveOutput = prover.ProveOutput;

comptime {
    prover.assertProverEngine(ProverEngine);
}

pub fn proveExecution(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    rom: frontend.cartridge.Cartridge,
    initial_images: frontend.air.cartridge_memory_lookup.Images,
    final_images: frontend.air.cartridge_memory_lookup.Images,
    initial_mcycle: u32,
    initial_joypad: frontend.runner.joypad.State,
    initial_timer: frontend.runner.timer.Timer,
    actions: []const frontend.action_schedule.Action,
    observations: []const frontend.ram_observation.Region,
    intermediate_observations: []const frontend.air.intermediate_ram_observation_lookup.Sample,
    steps: []const frontend.CartridgeStepTrace,
) !ProveOutput {
    return prover.proveExecutionWithEngine(
        ProverEngine,
        allocator,
        pcs_config,
        rom,
        initial_images,
        final_images,
        initial_mcycle,
        initial_joypad,
        initial_timer,
        actions,
        observations,
        intermediate_observations,
        steps,
    );
}

pub fn verifyExecution(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    rom: frontend.cartridge.Cartridge,
    initial_images: frontend.air.cartridge_memory_lookup.Images,
    final_images: frontend.air.cartridge_memory_lookup.Images,
    actions: []const frontend.action_schedule.Action,
    observations: []const frontend.ram_observation.Region,
    intermediate_observations: []const frontend.air.intermediate_ram_observation_lookup.Sample,
    statement: ExecutionStatement,
    proof: prover.Proof,
) !void {
    return prover.verifyExecutionWithEngine(
        ProverEngine,
        allocator,
        pcs_config,
        rom,
        initial_images,
        final_images,
        actions,
        observations,
        intermediate_observations,
        statement,
        proof,
    );
}

test "environment adapter selects only Metal" {
    try std.testing.expect(
        ProverEngine.Backend == metal.MetalCommitBackend,
    );
}
