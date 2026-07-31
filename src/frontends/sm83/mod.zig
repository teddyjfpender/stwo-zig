//! Sharp SM83 proof-system frontend.
//!
//! The architectural claim is ROM-agnostic: under committed ROM and initial
//! state, committed actions produce the committed final state.

pub const action_schedule = @import("action_schedule.zig");
pub const pokemon_battle_actions = @import("pokemon_battle_actions.zig");
pub const isa = @import("isa/mod.zig");
pub const runner = @import("runner/mod.zig");
pub const machine = @import("runner/machine.zig");
pub const cartridge = @import("cartridge/mod.zig");
pub const checkpoint = @import("checkpoint/mod.zig");
pub const cartridge_prover = @import("cartridge_prover.zig");
pub const cartridge_proof_statement =
    @import("cartridge_proof_statement.zig");
pub const environment_statement = @import("environment_statement.zig");
pub const environment_prover = @import("environment_prover.zig");
pub const machine_environment_chain =
    @import("machine_environment_chain.zig");
pub const machine_environment_memory_replay =
    @import("machine_environment_memory_replay.zig");
pub const machine_environment_prover =
    @import("machine_environment_prover.zig");
pub const machine_environment_statement =
    @import("machine_environment_statement.zig");
pub const machine_environment_verifier =
    @import("machine_environment_verifier.zig");
pub const pokemon_checkpoint_fixture =
    @import("pokemon_checkpoint_fixture.zig");
pub const pokemon_checkpoint_replay =
    @import("pokemon_checkpoint_replay.zig");
pub const pokemon_battle_chain = @import("pokemon_battle_chain.zig");
pub const air = @import("air/mod.zig");
pub const joypad_trace = @import("joypad_trace.zig");
pub const machine_memory_replay = @import("machine_memory_replay.zig");
pub const prover = @import("prover.zig");
pub const ram_observation = @import("ram_observation.zig");
pub const rom = @import("rom.zig");
pub const sameboy_instruction_trace = @import("sameboy_instruction_trace.zig");
pub const memory = @import("memory.zig");

pub const DecodedOpcode = isa.DecodedOpcode;
pub const Instruction = isa.Instruction;
pub const decode = isa.decode;
pub const Cpu = runner.Cpu;
pub const Memory = runner.Memory;
pub const StepTrace = runner.StepTrace;
pub const CartridgeMemory = runner.cartridge_memory.Memory;
pub const CartridgeStepTrace = runner.CartridgeStepTrace;
pub const CartridgeMachine = machine.CartridgeMachine;
pub const CartridgeMachineStepResult = machine.CartridgeStepResult;
pub const Machine = machine.Machine;
pub const MachineStepResult = machine.StepResult;
pub const Rom = rom.Rom;
pub const MemoryImage = memory.Image;
pub const step = runner.step;
pub const stepCartridge = runner.stepCartridge;
pub const proveExecutionWithEngine = prover.proveExecutionWithEngine;
pub const proveMachineExecutionWithEngine = prover.proveMachineExecutionWithEngine;
pub const verifyExecutionWithEngine = prover.verifyExecutionWithEngine;

test "api signature: SM83 facade preserves decoder and runner boundaries" {
    comptime {
        if (DecodedOpcode != isa.DecodedOpcode) @compileError("DecodedOpcode facade alias drifted");
        if (Cpu != runner.Cpu) @compileError("Cpu facade alias drifted");
        if (Machine != machine.Machine) @compileError("Machine facade alias drifted");
        if (CartridgeMachine != machine.CartridgeMachine)
            @compileError("CartridgeMachine facade alias drifted");
        if (CartridgeMachineStepResult != machine.CartridgeStepResult)
            @compileError("CartridgeMachineStepResult facade alias drifted");
        if (Rom != rom.Rom) @compileError("Rom facade alias drifted");
        if (MemoryImage != memory.Image) @compileError("MemoryImage facade alias drifted");
        switch (@typeInfo(@TypeOf(decode))) {
            .@"fn" => {},
            else => @compileError("decode must remain a function"),
        }
        switch (@typeInfo(@TypeOf(step))) {
            .@"fn" => {},
            else => @compileError("step must remain a function"),
        }
        switch (@typeInfo(@TypeOf(stepCartridge))) {
            .@"fn" => {},
            else => @compileError("stepCartridge must remain a function"),
        }
        switch (@typeInfo(@TypeOf(proveExecutionWithEngine))) {
            .@"fn" => {},
            else => @compileError("proveExecutionWithEngine must remain a function"),
        }
        switch (@typeInfo(@TypeOf(proveMachineExecutionWithEngine))) {
            .@"fn" => {},
            else => @compileError("proveMachineExecutionWithEngine must remain a function"),
        }
        switch (@typeInfo(@TypeOf(verifyExecutionWithEngine))) {
            .@"fn" => {},
            else => @compileError("verifyExecutionWithEngine must remain a function"),
        }
    }
}

test {
    _ = action_schedule;
    _ = @import("action_schedule_test.zig");
    _ = pokemon_battle_actions;
    _ = isa;
    _ = runner;
    _ = machine;
    _ = cartridge;
    _ = checkpoint;
    _ = @import("cartridge_machine_test_root.zig");
    _ = cartridge_prover;
    _ = cartridge_proof_statement;
    _ = @import("cartridge_proof_components.zig");
    _ = environment_statement;
    _ = @import("environment_statement_test.zig");
    _ = @import("environment_memory_replay_test.zig");
    _ = @import("environment_memory_observation_replay_test.zig");
    _ = environment_prover;
    _ = machine_environment_chain;
    _ = machine_environment_memory_replay;
    _ = @import("machine_environment_memory_replay_test.zig");
    _ = machine_environment_prover;
    _ = @import("machine_environment_prover_test.zig");
    _ = machine_environment_statement;
    _ = @import("machine_environment_statement_test.zig");
    _ = @import("machine_environment_geometry.zig");
    _ = @import("machine_environment_trace.zig");
    _ = @import("machine_environment_trace_test.zig");
    _ = @import("machine_environment_proof_components.zig");
    _ = @import("machine_environment_proof_components_test.zig");
    _ = @import("machine_environment_proof_interaction.zig");
    _ = @import("machine_environment_proof_interaction_test.zig");
    _ = @import("machine_environment_verifier.zig");
    _ = @import("machine_environment_verifier_test.zig");
    _ = pokemon_checkpoint_fixture;
    _ = pokemon_checkpoint_replay;
    _ = @import("pokemon_checkpoint_replay_test.zig");
    _ = pokemon_battle_chain;
    _ = @import("pokemon_hardware_surface_test.zig");
    _ = @import("environment_proof_components.zig");
    _ = @import("environment_proof_components_test.zig");
    _ = air;
    _ = @import("air/cartridge_access_test.zig");
    _ = @import("air/joypad_component_test.zig");
    _ = @import("air/joypad_test.zig");
    _ = @import("air/scheduler_test.zig");
    _ = @import("runner/cartridge_memory_apu_test.zig");
    _ = @import("runner/cartridge_memory_core_test.zig");
    _ = @import("runner/cartridge_memory_ppu_test.zig");
    _ = @import("runner/machine_restore_test.zig");
    _ = @import("runner/rom_only_hardware_test.zig");
    _ = joypad_trace;
    _ = @import("joypad_trace_test.zig");
    _ = machine_memory_replay;
    _ = @import("machine_memory_replay_test.zig");
    _ = prover;
    _ = ram_observation;
    _ = @import("ram_observation_test.zig");
    _ = rom;
    _ = sameboy_instruction_trace;
    _ = memory;
    _ = @import("corpus_scope.zig");
}
