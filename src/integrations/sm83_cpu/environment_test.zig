//! CPU-backend environment proof with committed joypad input.

const std = @import("std");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_sm83_frontend");
const cartridge_fixture = @import("cartridge_test.zig");

const environment_prover = frontend.environment_prover;
const Engine = environment_prover.ProverEngineForBackend(CpuBackend);
const actions = [_]frontend.action_schedule.Action{.{
    .mcycle = 0,
    .pressed = frontend.runner.joypad.Key.right.mask(),
}};
const observations = [_]frontend.ram_observation.Region{.{
    .space = .system,
    .start = 0xc000,
    .length = 1,
}};
const intermediate_observations =
    [_]frontend.air.intermediate_ram_observation_lookup.Sample{.{
        .mcycle = 0,
        .key = 0xc001,
        .expected = 0,
    }};

test "environment CPU proof binds actions devices and observations" {
    cartridge_fixture.proof_run_mutex.lock();
    defer cartridge_fixture.proof_run_mutex.unlock();
    comptime environment_prover.assertProverEngine(Engine);

    var fixture = try cartridge_fixture.Fixture.init(
        std.testing.allocator,
    );
    defer fixture.deinit();
    const initial_joypad = frontend.runner.joypad.State{};
    var final_joypad = initial_joypad;
    _ = final_joypad.setPressed(actions[0].pressed);
    fixture.initial_system[frontend.runner.joypad.P1_ADDRESS] =
        initial_joypad.readP1();
    fixture.final_system[frontend.runner.joypad.P1_ADDRESS] =
        final_joypad.readP1();
    fixture.final_system[
        frontend.runner.cartridge_memory.INTERRUPT_FLAGS
    ] |= frontend.runner.joypad.JOYPAD_INTERRUPT;
    const initial_timer = frontend.runner.timer.Timer{};
    var final_timer = initial_timer;
    for (fixture.steps) |step|
        _ = final_timer.tickMcycles(step.instruction.cycle_count);
    setTimerRegisters(fixture.initial_system, initial_timer);
    setTimerRegisters(fixture.final_system, final_timer);

    const config = try cartridge_fixture.testConfig();
    const rom = try fixture.rom();
    const initial = try fixture.initialImages();
    const final = try fixture.finalImages();
    const honest = environment_prover.proveExecutionWithEngine(
        Engine,
        std.testing.allocator,
        config,
        rom,
        initial,
        final,
        0,
        initial_joypad,
        initial_timer,
        &actions,
        &observations,
        &intermediate_observations,
        &fixture.steps,
    ) catch |err| {
        std.debug.print("environment CPU prove failed: {s}\n", .{
            @errorName(err),
        });
        return err;
    };
    environment_prover.verifyExecutionWithEngine(
        Engine,
        std.testing.allocator,
        config,
        rom,
        initial,
        final,
        &actions,
        &observations,
        &intermediate_observations,
        honest.statement,
        honest.proof,
    ) catch |err| {
        std.debug.print("environment CPU verify failed: {s}\n", .{
            @errorName(err),
        });
        return err;
    };

    inline for ([_]environment_prover.testing.ForgedWitness{
        .joypad,
        .timer,
        .intermediate_observation,
    }) |forged|
        try cartridge_fixture.expectConstraintFailure(
            environment_prover.testing.proveForgedWitnessWithEngine(
                Engine,
                std.testing.allocator,
                config,
                rom,
                initial,
                final,
                0,
                initial_joypad,
                initial_timer,
                &actions,
                &observations,
                &intermediate_observations,
                &fixture.steps,
                forged,
            ),
        );
}

fn setTimerRegisters(
    bytes: []u8,
    state: frontend.runner.timer.Timer,
) void {
    bytes[0xff04] = state.readDiv();
    bytes[0xff05] = state.readTima();
    bytes[0xff06] = state.readTma();
    bytes[0xff07] = state.readTac();
}
