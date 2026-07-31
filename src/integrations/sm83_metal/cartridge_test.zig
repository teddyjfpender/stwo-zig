//! Metal-backend parity gate for RTC-free MBC3 cartridge proofs.

const std = @import("std");
const pcs_core = @import("stwo_core").pcs;
const frontend = @import("stwo_sm83_frontend");
const MetalProverEngine =
    @import("stwo_metal_backend").MetalProverEngine;

const cartridge = frontend.cartridge;
const cartridge_prover = frontend.cartridge_prover;
const environment_prover = frontend.environment_prover;
const memory = frontend.memory;
const memory_lookup = frontend.air.cartridge_memory_lookup;
const runner = frontend.runner;
const EnvironmentEngine =
    environment_prover.ProverEngineForBackend(
        @import("stwo_metal_backend").MetalCommitBackend,
    );

const Fixture = struct {
    rom_bytes: *[cartridge.header.ROM_SIZE]u8,
    initial_system: *[memory_lookup.SYSTEM_SIZE]u8,
    final_system: *[memory_lookup.SYSTEM_SIZE]u8,
    initial_sram: *[memory_lookup.SRAM_SIZE]u8,
    final_sram: *[memory_lookup.SRAM_SIZE]u8,
    steps: [16]runner.CartridgeStepTrace,
    final_mapper: cartridge.State,
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator) !Fixture {
        const rom_bytes =
            try allocator.create([cartridge.header.ROM_SIZE]u8);
        errdefer allocator.destroy(rom_bytes);
        const initial_system =
            try allocator.create([memory_lookup.SYSTEM_SIZE]u8);
        errdefer allocator.destroy(initial_system);
        const final_system =
            try allocator.create([memory_lookup.SYSTEM_SIZE]u8);
        errdefer allocator.destroy(final_system);
        const initial_sram =
            try allocator.create([memory_lookup.SRAM_SIZE]u8);
        errdefer allocator.destroy(initial_sram);
        const final_sram =
            try allocator.create([memory_lookup.SRAM_SIZE]u8);
        errdefer allocator.destroy(final_sram);
        @memset(rom_bytes, 0);
        @memset(initial_system, 0);
        @memset(final_system, 0);
        @memset(initial_sram, 0);
        @memset(final_sram, 0);

        // Select bank 2, authenticate a switched-bank byte, mirror it through
        // WRAM/echo, then enable, write, and read SRAM.
        const program = [_]u8{
            0x3e, 0x02, // LD A,$02
            0xea, 0x00, 0x20, // LD ($2000),A
            0xfa, 0x00, 0x40, // LD A,($4000)
            0xea, 0x00, 0xc0, // LD ($c000),A
            0xfa, 0x00, 0xe0, // LD A,($e000)
            0x3e, 0x0a, // LD A,$0a
            0xea, 0x00, 0x00, // LD ($0000),A
            0x3e, 0x55, // LD A,$55
            0xea, 0x00, 0xa0, // LD ($a000),A
            0xfa, 0x00, 0xa0, // LD A,($a000)
            0x00, 0x00, 0x00,
            0x00, 0x00, 0x00,
        };
        @memcpy(rom_bytes[0..program.len], &program);
        rom_bytes[2 * cartridge.header.ROM_BANK_SIZE] = 0x99;
        rom_bytes[cartridge.header.CARTRIDGE_TYPE_OFFSET] =
            cartridge.header.CARTRIDGE_TYPE_MBC3_RAM_BATTERY;
        rom_bytes[cartridge.header.ROM_SIZE_CODE_OFFSET] =
            cartridge.header.ROM_SIZE_CODE_1_MIB;
        rom_bytes[cartridge.header.RAM_SIZE_CODE_OFFSET] =
            cartridge.header.RAM_SIZE_CODE_32_KIB;
        rom_bytes[cartridge.header.HEADER_CHECKSUM_OFFSET] =
            cartridge.header.headerChecksum(rom_bytes);
        std.mem.writeInt(
            u16,
            rom_bytes[cartridge.header.GLOBAL_CHECKSUM_OFFSET..cartridge.header.HEADER_END][0..2],
            cartridge.header.globalChecksum(rom_bytes),
            .big,
        );

        const loaded_cartridge =
            try cartridge.Cartridge.init(rom_bytes);
        var address_space = frontend.CartridgeMemory.init(
            loaded_cartridge,
            final_sram,
            final_system,
            .{},
            0,
        );
        var cpu = runner.Cpu{};
        var steps: [16]runner.CartridgeStepTrace = undefined;
        for (&steps) |*step_value|
            step_value.* = try runner.stepCartridge(
                &cpu,
                &address_space,
            );
        return .{
            .rom_bytes = rom_bytes,
            .initial_system = initial_system,
            .final_system = final_system,
            .initial_sram = initial_sram,
            .final_sram = final_sram,
            .steps = steps,
            .final_mapper = address_space.mapper,
            .allocator = allocator,
        };
    }

    fn rom(self: *const Fixture) !cartridge.Cartridge {
        return cartridge.Cartridge.init(self.rom_bytes);
    }

    fn initialImages(self: *const Fixture) !memory_lookup.Images {
        return .{
            .system = try memory.Image.init(self.initial_system),
            .sram = try memory_lookup.SramImage.init(self.initial_sram),
        };
    }

    fn finalImages(self: *const Fixture) !memory_lookup.Images {
        return .{
            .system = try memory.Image.init(self.final_system),
            .sram = try memory_lookup.SramImage.init(self.final_sram),
        };
    }

    fn deinit(self: *Fixture) void {
        self.allocator.destroy(self.final_sram);
        self.allocator.destroy(self.initial_sram);
        self.allocator.destroy(self.final_system);
        self.allocator.destroy(self.initial_system);
        self.allocator.destroy(self.rom_bytes);
        self.* = undefined;
    }
};

test "cartridge Metal proof roundtrip and soundness controls" {
    comptime cartridge_prover.assertProverEngine(MetalProverEngine);
    const allocator = std.testing.allocator;
    const config = try testConfig();
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();
    const rom = try fixture.rom();
    const initial = try fixture.initialImages();
    const final = try fixture.finalImages();

    try std.testing.expectEqual(
        @as(u8, 0x99),
        fixture.final_system[0xc000],
    );
    try std.testing.expectEqual(
        @as(u8, 0x55),
        fixture.final_sram[0],
    );
    try std.testing.expectEqual(
        @as(u7, 2),
        fixture.final_mapper.rom_bank_register,
    );
    try std.testing.expect(fixture.final_mapper.ram_enabled);

    const honest = try cartridge_prover.proveExecutionWithEngine(
        MetalProverEngine,
        allocator,
        config,
        rom,
        initial,
        final,
        &fixture.steps,
    );
    try cartridge_prover.verifyExecutionWithEngine(
        MetalProverEngine,
        allocator,
        config,
        rom,
        initial,
        final,
        honest.statement,
        honest.proof,
    );

    try expectConstraintFailure(
        cartridge_prover.testing.proveForgedPackedAccessWithEngine(
            MetalProverEngine,
            allocator,
            config,
            rom,
            initial,
            final,
            &fixture.steps,
            .value,
        ),
    );
    try expectConstraintFailure(
        cartridge_prover.testing.proveInactiveExecutionWithEngine(
            MetalProverEngine,
            allocator,
            config,
            rom,
            initial,
            final,
            &fixture.steps,
        ),
    );
}

test "environment Metal proof binds actions devices and observations" {
    comptime environment_prover.assertProverEngine(EnvironmentEngine);
    const allocator = std.testing.allocator;
    const config = try testConfig();
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();
    const initial_joypad = runner.joypad.State{};
    var final_joypad = initial_joypad;
    const actions = [_]frontend.action_schedule.Action{.{
        .mcycle = 0,
        .pressed = runner.joypad.Key.right.mask(),
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
    _ = final_joypad.setPressed(actions[0].pressed);
    fixture.initial_system[runner.joypad.P1_ADDRESS] =
        initial_joypad.readP1();
    fixture.final_system[runner.joypad.P1_ADDRESS] =
        final_joypad.readP1();
    fixture.final_system[
        runner.cartridge_memory.INTERRUPT_FLAGS
    ] |= runner.joypad.JOYPAD_INTERRUPT;
    const initial_timer = runner.timer.Timer{};
    var final_timer = initial_timer;
    for (fixture.steps) |step|
        _ = final_timer.tickMcycles(step.instruction.cycle_count);
    setTimerRegisters(fixture.initial_system, initial_timer);
    setTimerRegisters(fixture.final_system, final_timer);
    const rom = try fixture.rom();
    const initial = try fixture.initialImages();
    const final = try fixture.finalImages();

    const honest = try environment_prover.proveExecutionWithEngine(
        EnvironmentEngine,
        allocator,
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
    );
    try environment_prover.verifyExecutionWithEngine(
        EnvironmentEngine,
        allocator,
        config,
        rom,
        initial,
        final,
        &actions,
        &observations,
        &intermediate_observations,
        honest.statement,
        honest.proof,
    );
    inline for ([_]environment_prover.testing.ForgedWitness{
        .joypad,
        .timer,
        .intermediate_observation,
    }) |forged|
        try expectConstraintFailure(
            environment_prover.testing.proveForgedWitnessWithEngine(
                EnvironmentEngine,
                allocator,
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
    state: runner.timer.Timer,
) void {
    bytes[0xff04] = state.readDiv();
    bytes[0xff05] = state.readTima();
    bytes[0xff06] = state.readTma();
    bytes[0xff07] = state.readTac();
}

fn expectConstraintFailure(result: anytype) !void {
    try std.testing.expectError(
        error.ConstraintsNotSatisfied,
        result,
    );
}

fn testConfig() !pcs_core.PcsConfig {
    return .{
        .pow_bits = 0,
        .fri_config = try @import("stwo_core").fri.FriConfig.init(
            0,
            1,
            3,
        ),
    };
}
