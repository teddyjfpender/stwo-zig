//! Metal-only adapter and proof gate for the complete v7 SM83 environment.

const std = @import("std");
const pcs_core = @import("stwo_core").pcs;
const frontend = @import("stwo_sm83_frontend");
const metal = @import("stwo_metal_backend");

const prover = frontend.machine_environment_prover;
const verifier = frontend.machine_environment_verifier;
const memory_lookup = frontend.air.cartridge_memory_lookup;
const observation =
    frontend.air.intermediate_ram_observation_lookup;
const ppu_binding = frontend.air.ppu_binding;
const timer_binding = frontend.air.timer_binding;
const runner = frontend.runner;

pub const ProverEngine = metal.MetalProverEngine;
pub const Input = prover.Input;
pub const ExecutionStatement = prover.ExecutionStatement;
pub const ProveOutput = prover.ProveOutput;

comptime {
    prover.assertProverEngine(ProverEngine);
    verifier.assertProverEngine(ProverEngine);
}

/// Proves through Metal or propagates the Metal/backend error without fallback.
pub fn proveExecution(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    input: Input,
) !ProveOutput {
    return prover.proveExecutionWithEngine(
        ProverEngine,
        allocator,
        pcs_config,
        input,
        .{},
    );
}

/// Consumes `proof` through the frontend-owned v7 verifier.
pub fn verifyExecution(
    allocator: std.mem.Allocator,
    pcs_config: pcs_core.PcsConfig,
    rom: frontend.cartridge.Cartridge,
    initial_images: memory_lookup.Images,
    final_images: memory_lookup.Images,
    actions: []const frontend.action_schedule.Action,
    observation_regions: []const frontend.ram_observation.Region,
    intermediate_observations: []const observation.Sample,
    statement: ExecutionStatement,
    proof: verifier.Proof,
) !void {
    return verifier.verifyExecutionWithEngine(
        ProverEngine,
        allocator,
        pcs_config,
        rom,
        initial_images,
        final_images,
        actions,
        observation_regions,
        intermediate_observations,
        statement,
        proof,
    );
}

const TRACE_SIZE: usize = 16;
const PROGRAM_START: u16 = 0xff80;
const INITIAL_MCYCLE: u32 = 7;
const DMA_PAGE: u8 = 0xc0;
const DMA_SOURCE_START: u16 = @as(u16, DMA_PAGE) << 8;
const committed_actions = [_]frontend.action_schedule.Action{.{
    .mcycle = INITIAL_MCYCLE,
    .pressed = runner.joypad.Key.a.mask(),
}};

test "machine environment Metal proves verifies and rejects mutations" {
    try std.testing.expect(
        ProverEngine.Backend == metal.MetalCommitBackend,
    );
    const allocator = std.testing.allocator;
    const config = try testConfig();
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();
    var machine = try frontend.CartridgeMachine.init(
        &fixture.memory,
        .{ .pc = PROGRAM_START },
    );
    const initial_timer = machine.timer;
    var initial = try Snapshot.capture(allocator, fixture);
    defer initial.deinit(allocator);
    var results: [TRACE_SIZE]frontend.CartridgeMachineStepResult =
        undefined;
    for (&results) |*result| result.* = try machine.step();
    const dma_transfer_count = totalMcycles(&results);
    const dma_source_bytes =
        fixture.system[DMA_SOURCE_START..][0..dma_transfer_count];
    var final = try Snapshot.capture(allocator, fixture);
    defer final.deinit(allocator);
    @memcpy(
        final.system[runner.dma.OAM_START..][0..dma_transfer_count],
        dma_source_bytes,
    );
    const initial_joypad = try runner.joypad.State.init(
        0xff,
        0,
        3,
        0,
    );
    var final_joypad = initial_joypad;
    try std.testing.expect(
        !final_joypad.setPressed(committed_actions[0].pressed),
    );
    setEndpoints(
        &initial,
        &final,
        initial_timer,
        results[TRACE_SIZE - 1].after,
        initial_joypad,
        final_joypad,
    );

    const regions = [_]frontend.ram_observation.Region{.{
        .space = .system,
        .start = 0xc100,
        .length = 1,
    }};
    const samples = [_]observation.Sample{.{
        .mcycle = INITIAL_MCYCLE + 3,
        .key = 0xc100,
        .expected = 0x42,
    }};
    const input = Input{
        .rom = fixture.memory.cartridge,
        .initial_images = try initial.images(),
        .final_images = try final.images(),
        .initial_mcycle = INITIAL_MCYCLE,
        .initial_joypad = initial_joypad,
        .initial_timer = initial_timer,
        .initial_ppu = .{},
        .initial_apu = .{},
        .initial_dma = .{
            .clock = INITIAL_MCYCLE,
            .page = DMA_PAGE,
            .phase = .transfer,
        },
        .actions = &committed_actions,
        .observation_regions = &regions,
        .intermediate_observations = &samples,
        .results = &results,
        .dma_source_bytes = dma_source_bytes,
    };

    const honest = try proveExecution(allocator, config, input);
    try verifyExecution(
        allocator,
        config,
        input.rom,
        input.initial_images,
        input.final_images,
        input.actions,
        input.observation_regions,
        input.intermediate_observations,
        honest.statement,
        honest.proof,
    );
    try std.testing.expectEqual(
        @as(u32, committed_actions.len),
        honest.statement.base.action_count,
    );
    try std.testing.expectEqualDeep(
        final_joypad,
        honest.statement.base.final_joypad,
    );
    try std.testing.expectEqual(
        @as(u8, @intCast(dma_transfer_count)),
        honest.statement.final_dma.copied,
    );
    try std.testing.expectEqual(
        runner.dma.Phase.transfer,
        honest.statement.final_dma.phase,
    );
    try std.testing.expectEqualSlices(
        u8,
        dma_source_bytes,
        final.system[runner.dma.OAM_START..][0..dma_transfer_count],
    );

    var action_mutation = committed_actions;
    action_mutation[0].pressed = runner.joypad.Key.b.mask();
    try std.testing.expectError(
        error.ActionDigestMismatch,
        verifier.testing.validatePublicAndShape(
            honest.statement,
            input.rom,
            input.initial_images,
            input.final_images,
            &action_mutation,
            input.observation_regions,
            input.intermediate_observations,
            4,
        ),
    );

    var dma_source_mutation =
        try allocator.dupe(u8, dma_source_bytes);
    defer allocator.free(dma_source_mutation);
    dma_source_mutation[0] ^= 1;
    var dma_forged = input;
    dma_forged.dma_source_bytes = dma_source_mutation;
    try std.testing.expectError(
        error.InvalidDmaSourceValue,
        proveExecution(allocator, config, dma_forged),
    );

    var semantic_mutation = results;
    semantic_mutation[TRACE_SIZE - 1].after.cpu.a ^= 1;
    var forged = input;
    forged.results = &semantic_mutation;
    try std.testing.expectError(
        error.InvalidSchedulerStep,
        proveExecution(allocator, config, forged),
    );

    forged = input;
    forged.results = &.{};
    try std.testing.expectError(
        error.InvalidTraceLength,
        proveExecution(allocator, config, forged),
    );
}

const Fixture = struct {
    rom: *[frontend.cartridge.header.ROM_SIZE]u8,
    sram: *[frontend.cartridge.header.RAM_SIZE]u8,
    system: *[runner.cartridge_memory.SYSTEM_SIZE]u8,
    memory: runner.cartridge_memory.Memory,
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator) !Fixture {
        const rom = try allocator.create(
            [frontend.cartridge.header.ROM_SIZE]u8,
        );
        errdefer allocator.destroy(rom);
        const sram = try allocator.create(
            [frontend.cartridge.header.RAM_SIZE]u8,
        );
        errdefer allocator.destroy(sram);
        const system = try allocator.create(
            [runner.cartridge_memory.SYSTEM_SIZE]u8,
        );
        errdefer allocator.destroy(system);
        @memset(rom, 0);
        @memset(sram, 0);
        @memset(system, 0);
        system[0xc100] = 0x42;
        system[runner.dma.DMA_ADDRESS] = DMA_PAGE;
        for (
            system[DMA_SOURCE_START .. DMA_SOURCE_START +
                runner.dma.OAM_LENGTH],
            0..,
        ) |*byte, index| byte.* = @truncate(index + 1);
        system[PROGRAM_START] = 0x00;
        rom[frontend.cartridge.header.CARTRIDGE_TYPE_OFFSET] =
            frontend.cartridge.header.CARTRIDGE_TYPE_MBC3_RAM_BATTERY;
        rom[frontend.cartridge.header.ROM_SIZE_CODE_OFFSET] =
            frontend.cartridge.header.ROM_SIZE_CODE_1_MIB;
        rom[frontend.cartridge.header.RAM_SIZE_CODE_OFFSET] =
            frontend.cartridge.header.RAM_SIZE_CODE_32_KIB;
        rom[frontend.cartridge.header.HEADER_CHECKSUM_OFFSET] =
            frontend.cartridge.header.headerChecksum(rom);
        std.mem.writeInt(
            u16,
            rom[frontend.cartridge.header.GLOBAL_CHECKSUM_OFFSET..frontend.cartridge.header.HEADER_END][0..2],
            frontend.cartridge.header.globalChecksum(rom),
            .big,
        );
        const cartridge =
            try frontend.cartridge.Cartridge.init(rom);
        return .{
            .rom = rom,
            .sram = sram,
            .system = system,
            .memory = runner.cartridge_memory.Memory.init(
                cartridge,
                sram,
                system,
                .{},
                0xff,
            ),
            .allocator = allocator,
        };
    }

    fn deinit(self: *Fixture) void {
        self.allocator.destroy(self.system);
        self.allocator.destroy(self.sram);
        self.allocator.destroy(self.rom);
        self.* = undefined;
    }
};

const Snapshot = struct {
    system: []u8,
    sram: []u8,

    fn capture(
        allocator: std.mem.Allocator,
        fixture: Fixture,
    ) !Snapshot {
        const system = try allocator.dupe(u8, fixture.system);
        errdefer allocator.free(system);
        return .{
            .system = system,
            .sram = try allocator.dupe(u8, fixture.sram),
        };
    }

    fn deinit(self: *Snapshot, allocator: std.mem.Allocator) void {
        allocator.free(self.sram);
        allocator.free(self.system);
        self.* = undefined;
    }

    fn images(self: Snapshot) !memory_lookup.Images {
        return .{
            .system = try frontend.memory.Image.init(self.system),
            .sram = try memory_lookup.SramImage.init(self.sram),
        };
    }
};

fn setEndpoints(
    initial: *Snapshot,
    final: *Snapshot,
    initial_timer: runner.timer.Timer,
    final_machine: frontend.machine.MachineState,
    initial_joypad: runner.joypad.State,
    final_joypad: runner.joypad.State,
) void {
    initial.system[runner.joypad.P1_ADDRESS] =
        initial_joypad.readP1();
    final.system[runner.joypad.P1_ADDRESS] =
        final_joypad.readP1();
    setTimer(initial.system, initial_timer);
    setTimer(final.system, .{
        .div_counter = final_machine.div_counter,
        .tima = final_machine.tima,
        .tma = final_machine.tma,
        .tac = @truncate(final_machine.tac),
        .reload_state = final_machine.timer_reload,
    });
    setPpu(initial.system, .{});
    setPpu(final.system, .{});
    initial.system[runner.dma.DMA_ADDRESS] = DMA_PAGE;
    final.system[runner.dma.DMA_ADDRESS] = DMA_PAGE;
}

fn totalMcycles(
    results: []const frontend.CartridgeMachineStepResult,
) usize {
    var count: usize = 0;
    for (results) |result| count += result.m_cycles;
    return count;
}

fn setTimer(system: []u8, state: runner.timer.Timer) void {
    system[timer_binding.FIRST_ADDRESS] = state.readDiv();
    system[timer_binding.FIRST_ADDRESS + 1] = state.readTima();
    system[timer_binding.FIRST_ADDRESS + 2] = state.readTma();
    system[timer_binding.FIRST_ADDRESS + 3] = state.readTac();
}

fn setPpu(system: []u8, state: ppu_binding.State) void {
    system[runner.ppu_mmio.LCDC_ADDRESS] = state.read(.lcdc);
    system[runner.ppu_mmio.STAT_ADDRESS] = state.read(.stat);
    system[runner.ppu_mmio.LY_ADDRESS] = state.read(.ly);
    system[runner.ppu_mmio.LYC_ADDRESS] = state.read(.lyc);
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
