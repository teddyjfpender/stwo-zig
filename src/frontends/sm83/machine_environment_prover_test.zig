const std = @import("std");
const subject = @import("machine_environment_prover.zig");
const cartridge = @import("cartridge/mod.zig");
const memory_image = @import("memory.zig");
const runner = @import("runner/mod.zig");
const machine = @import("runner/machine.zig");
const memory_lookup = @import("air/cartridge_memory_lookup.zig");
const ppu_binding = @import("air/ppu_binding.zig");
const timer_binding = @import("air/timer_binding.zig");
const observation =
    @import("air/intermediate_ram_observation_lookup.zig");
const ram_observation = @import("ram_observation.zig");
const base_statement = @import("cartridge_proof_statement.zig");
const geometry = @import("machine_environment_geometry.zig");

const TRACE_SIZE: usize = 16;
const PROGRAM_START: u16 = 0x0200;
const INITIAL_MCYCLE: u32 = 7;

test "v7 preparation owns canonical geometry without copying replay columns" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var scheduler = try machine.CartridgeMachine.init(
        &fixture.memory,
        .{ .pc = PROGRAM_START },
    );
    const initial_timer = scheduler.timer;
    var initial = try Snapshot.capture(fixture);
    defer initial.deinit();
    var results: [TRACE_SIZE]machine.CartridgeStepResult = undefined;
    for (&results) |*result| result.* = try scheduler.step();
    var final = try Snapshot.capture(fixture);
    defer final.deinit();
    setEndpoints(
        &initial,
        &final,
        initial_timer,
        results[TRACE_SIZE - 1].after,
    );
    const regions = [_]ram_observation.Region{.{
        .space = .system,
        .start = 0xc000,
        .length = 1,
    }};
    const observations = [_]observation.Sample{.{
        .mcycle = INITIAL_MCYCLE + 3,
        .key = 0xc000,
        .expected = 0x42,
    }};
    const input = subject.Input{
        .rom = fixture.memory.cartridge,
        .initial_images = try initial.images(),
        .final_images = try final.images(),
        .initial_mcycle = INITIAL_MCYCLE,
        .initial_joypad = .{},
        .initial_timer = initial_timer,
        .initial_ppu = .{},
        .initial_apu = .{},
        .initial_dma = .{ .clock = INITIAL_MCYCLE },
        .actions = &.{},
        .observation_regions = &regions,
        .intermediate_observations = &observations,
        .results = &results,
        .dma_source_bytes = &.{},
    };
    var prepared = try subject.prepare(std.testing.allocator, input);
    defer prepared.deinit(std.testing.allocator);
    try prepared.validateGeometry();
    try std.testing.expectEqual(@as(u32, 4), prepared.logs.execution);
    try std.testing.expectEqual(@as(u32, 0), prepared.request.expected_service_count);
    try std.testing.expectEqual(
        @as(usize, geometry.N_MAIN_COLUMNS),
        prepared.trace.main.columns.?.len,
    );
    try std.testing.expectEqual(
        @intFromPtr(prepared.replay.memory.main[0].ptr),
        @intFromPtr(
            prepared.trace.main.columns.?[
                base_statement.MUTABLE_WITNESS_MAIN_OFFSET
            ].values.ptr,
        ),
    );

    prepared.trace.main.columns.?[
        geometry.PPU_BINDING_MAIN_OFFSET
    ].log_size += 1;
    try std.testing.expectError(
        error.DetachedColumnLog,
        prepared.validateGeometry(),
    );
    prepared.trace.main.columns.?[
        geometry.PPU_BINDING_MAIN_OFFSET
    ].log_size -= 1;
    prepared.boundary_final_clocks[0].v ^= 1;
    try std.testing.expectError(
        error.BoundaryClockMismatch,
        prepared.validateGeometry(),
    );
    prepared.boundary_final_clocks[0].v ^= 1;
    prepared.replay.scheduler_predecessors[0]
        .interrupt_flags.value ^= 1;
    try std.testing.expectError(
        error.SchedulerPredecessorMismatch,
        prepared.replay.validate(
            std.testing.allocator,
            &results,
            try initial.images(),
            try final.images(),
            INITIAL_MCYCLE,
            prepared.joypad.rows,
            prepared.timer.rows,
            prepared.ppu.rows,
            prepared.dma.rows,
            &observations,
        ),
    );
    prepared.replay.scheduler_predecessors[0]
        .interrupt_flags.value ^= 1;

    try std.testing.expect(
        prepared.interaction_sources_state == .retained,
    );
    prepared.releaseInteractionSources(std.testing.allocator);
    try std.testing.expect(
        prepared.interaction_sources_state == .released,
    );
    try std.testing.expectError(
        error.InteractionSourcesReleased,
        prepared.validateGeometry(),
    );
    prepared.releaseInteractionSources(std.testing.allocator);
}

test "v7 preparation rejects DMA final-memory and open-bus mutations" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    var scheduler = try machine.CartridgeMachine.init(
        &fixture.memory,
        .{ .pc = PROGRAM_START },
    );
    const initial_timer = scheduler.timer;
    var initial = try Snapshot.capture(fixture);
    defer initial.deinit();
    var results: [TRACE_SIZE]machine.CartridgeStepResult = undefined;
    for (&results) |*result| result.* = try scheduler.step();
    var final = try Snapshot.capture(fixture);
    defer final.deinit();
    setEndpoints(
        &initial,
        &final,
        initial_timer,
        results[TRACE_SIZE - 1].after,
    );
    const regions = [_]ram_observation.Region{.{
        .space = .system,
        .start = 0xc000,
        .length = 1,
    }};
    const observations = [_]observation.Sample{.{
        .mcycle = INITIAL_MCYCLE,
        .key = 0xc000,
        .expected = 0x42,
    }};
    var input = subject.Input{
        .rom = fixture.memory.cartridge,
        .initial_images = try initial.images(),
        .final_images = try final.images(),
        .initial_mcycle = INITIAL_MCYCLE,
        .initial_joypad = .{},
        .initial_timer = initial_timer,
        .initial_ppu = .{},
        .initial_apu = .{},
        .initial_dma = .{ .clock = INITIAL_MCYCLE + 1 },
        .actions = &.{},
        .observation_regions = &regions,
        .intermediate_observations = &observations,
        .results = &results,
        .dma_source_bytes = &.{},
    };
    try std.testing.expectError(
        error.InitialDmaClockMismatch,
        subject.prepare(std.testing.allocator, input),
    );
    input.initial_dma.clock = INITIAL_MCYCLE;
    final.system[0xc001] ^= 1;
    input.final_images = try final.images();
    try std.testing.expectError(
        error.FinalMemoryMismatch,
        subject.prepare(std.testing.allocator, input),
    );

    var open_bus_fixture = try Fixture.init();
    defer open_bus_fixture.deinit();
    open_bus_fixture.rom[PROGRAM_START] = 0x0a; // LD A,(BC).
    var open_bus_scheduler = try machine.CartridgeMachine.init(
        &open_bus_fixture.memory,
        .{
            .b = 0xa0,
            .c = 0x00,
            .pc = PROGRAM_START,
        },
    );
    const open_bus_initial_timer = open_bus_scheduler.timer;
    var open_bus_initial = try Snapshot.capture(open_bus_fixture);
    defer open_bus_initial.deinit();
    var open_bus_results: [TRACE_SIZE]machine.CartridgeStepResult = undefined;
    for (&open_bus_results) |*result|
        result.* = try open_bus_scheduler.step();
    var open_bus_final = try Snapshot.capture(open_bus_fixture);
    defer open_bus_final.deinit();

    const open_bus_access =
        &open_bus_results[0].instruction.?.accesses[1].?;
    try std.testing.expectEqual(
        runner.cartridge_memory.Region.cartridge_open_bus,
        open_bus_access.region,
    );
    const forged_value: u8 = 0x66;
    open_bus_access.value = forged_value;
    open_bus_results[0].instruction.?.instruction.cycles[1].value =
        forged_value;
    open_bus_results[0].instruction.?.instruction.after.a = forged_value;
    open_bus_results[0].after.cpu.a = forged_value;
    for (open_bus_results[1..]) |*result| {
        result.before.cpu.a = forged_value;
        result.after.cpu.a = forged_value;
        result.instruction.?.instruction.before.a = forged_value;
        result.instruction.?.instruction.after.a = forged_value;
    }
    try std.testing.expect(open_bus_results[0].hasCanonicalShape());
    setEndpoints(
        &open_bus_initial,
        &open_bus_final,
        open_bus_initial_timer,
        open_bus_results[TRACE_SIZE - 1].after,
    );
    input = .{
        .rom = open_bus_fixture.memory.cartridge,
        .initial_images = try open_bus_initial.images(),
        .final_images = try open_bus_final.images(),
        .initial_mcycle = INITIAL_MCYCLE,
        .initial_joypad = .{},
        .initial_timer = open_bus_initial_timer,
        .initial_ppu = .{},
        .initial_apu = .{},
        .initial_dma = .{ .clock = INITIAL_MCYCLE },
        .actions = &.{},
        .observation_regions = &regions,
        .intermediate_observations = &observations,
        .results = &open_bus_results,
        .dma_source_bytes = &.{},
    };
    try std.testing.expectError(
        error.UnsupportedOpenBus,
        subject.prepare(std.testing.allocator, input),
    );
}

test "v7 composition sizing includes PPU and APU constraints" {
    try std.testing.expectEqual(
        @as(u32, 21),
        try subject.requiredCompositionLog(4, 5, 6, 7, 8, 9, 10),
    );
    try std.testing.expectEqual(
        @as(u32, 21),
        try subject.requiredCompositionLog(4, 4, 4, 4, 4, 20, 4),
    );
    try std.testing.expectEqual(
        @as(u32, 22),
        try subject.requiredCompositionLog(4, 4, 4, 4, 20, 4, 4),
    );
}

const Fixture = struct {
    rom: *[cartridge.header.ROM_SIZE]u8,
    sram: *[cartridge.header.RAM_SIZE]u8,
    system: *[runner.cartridge_memory.SYSTEM_SIZE]u8,
    memory: runner.cartridge_memory.Memory,

    fn init() !Fixture {
        const allocator = std.testing.allocator;
        const rom = try allocator.create([cartridge.header.ROM_SIZE]u8);
        errdefer allocator.destroy(rom);
        const sram = try allocator.create([cartridge.header.RAM_SIZE]u8);
        errdefer allocator.destroy(sram);
        const system = try allocator.create(
            [runner.cartridge_memory.SYSTEM_SIZE]u8,
        );
        errdefer allocator.destroy(system);
        @memset(rom, 0);
        @memset(sram, 0);
        @memset(system, 0);
        system[0xc000] = 0x42;
        system[runner.dma.DMA_ADDRESS] = 0xff;
        rom[PROGRAM_START] = 0x00;
        rom[cartridge.header.CARTRIDGE_TYPE_OFFSET] =
            cartridge.header.CARTRIDGE_TYPE_MBC3_RAM_BATTERY;
        rom[cartridge.header.ROM_SIZE_CODE_OFFSET] =
            cartridge.header.ROM_SIZE_CODE_1_MIB;
        rom[cartridge.header.RAM_SIZE_CODE_OFFSET] =
            cartridge.header.RAM_SIZE_CODE_32_KIB;
        rom[cartridge.header.HEADER_CHECKSUM_OFFSET] =
            cartridge.header.headerChecksum(rom);
        std.mem.writeInt(
            u16,
            rom[cartridge.header.GLOBAL_CHECKSUM_OFFSET..cartridge.header.HEADER_END][0..2],
            cartridge.header.globalChecksum(rom),
            .big,
        );
        return .{
            .rom = rom,
            .sram = sram,
            .system = system,
            .memory = runner.cartridge_memory.Memory.init(
                try cartridge.Cartridge.init(rom),
                sram,
                system,
                .{},
                0xff,
            ),
        };
    }

    fn deinit(self: *Fixture) void {
        std.testing.allocator.destroy(self.system);
        std.testing.allocator.destroy(self.sram);
        std.testing.allocator.destroy(self.rom);
        self.* = undefined;
    }
};

const Snapshot = struct {
    system: []u8,
    sram: []u8,

    fn capture(fixture: Fixture) !Snapshot {
        const allocator = std.testing.allocator;
        const system = try allocator.dupe(u8, fixture.system);
        errdefer allocator.free(system);
        return .{
            .system = system,
            .sram = try allocator.dupe(u8, fixture.sram),
        };
    }

    fn deinit(self: *Snapshot) void {
        std.testing.allocator.free(self.sram);
        std.testing.allocator.free(self.system);
        self.* = undefined;
    }

    fn images(self: Snapshot) !memory_lookup.Images {
        return .{
            .system = try memory_image.Image.init(self.system),
            .sram = try memory_lookup.SramImage.init(self.sram),
        };
    }
};

fn setEndpoints(
    initial: *Snapshot,
    final: *Snapshot,
    initial_timer: runner.timer.Timer,
    final_machine: machine.MachineState,
) void {
    initial.system[runner.joypad.P1_ADDRESS] =
        (runner.joypad.State{}).readP1();
    final.system[runner.joypad.P1_ADDRESS] =
        (runner.joypad.State{}).readP1();
    setTimer(initial.system, initial_timer);
    setTimer(
        final.system,
        .{
            .div_counter = final_machine.div_counter,
            .tima = final_machine.tima,
            .tma = final_machine.tma,
            .tac = @truncate(final_machine.tac),
            .reload_state = final_machine.timer_reload,
        },
    );
    setPpu(initial.system, .{});
    setPpu(final.system, .{});
    initial.system[runner.dma.DMA_ADDRESS] = 0xff;
    final.system[runner.dma.DMA_ADDRESS] = 0xff;
}

fn setTimer(system: []u8, timer: runner.timer.Timer) void {
    system[timer_binding.FIRST_ADDRESS] = timer.readDiv();
    system[timer_binding.FIRST_ADDRESS + 1] = timer.readTima();
    system[timer_binding.FIRST_ADDRESS + 2] = timer.readTma();
    system[timer_binding.FIRST_ADDRESS + 3] = timer.readTac();
}

fn setPpu(system: []u8, ppu: ppu_binding.State) void {
    system[runner.ppu_mmio.LCDC_ADDRESS] = ppu.read(.lcdc);
    system[runner.ppu_mmio.STAT_ADDRESS] = ppu.read(.stat);
    system[runner.ppu_mmio.SCY_ADDRESS] = ppu.read(.scy);
    system[runner.ppu_mmio.SCX_ADDRESS] = ppu.read(.scx);
    system[runner.ppu_mmio.LY_ADDRESS] = ppu.read(.ly);
    system[runner.ppu_mmio.LYC_ADDRESS] = ppu.read(.lyc);
    system[runner.ppu_mmio.WY_ADDRESS] = ppu.read(.wy);
}
