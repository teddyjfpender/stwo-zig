const std = @import("std");
const channel_blake2s = @import("stwo_core").channel.blake2s;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const action_schedule = @import("action_schedule.zig");
const base_statement = @import("cartridge_proof_statement.zig");
const cartridge = @import("cartridge/mod.zig");
const environment = @import("environment_statement.zig");
const geometry = @import("machine_environment_geometry.zig");
const memory_image = @import("memory.zig");
const replay_mod = @import("machine_environment_memory_replay.zig");
const ram_observation = @import("ram_observation.zig");
const statement = @import("machine_environment_statement.zig");
const subject = @import("machine_environment_proof_interaction.zig");
const joypad_trace = @import("joypad_trace.zig");
const machine = @import("runner/machine.zig");
const runner = @import("runner/mod.zig");
const action_lookup = @import("air/joypad_action_lookup.zig");
const dma_binding = @import("air/dma_binding.zig");
const dma_execution = @import("air/dma_execution_lookup.zig");
const intermediate_observation =
    @import("air/intermediate_ram_observation_lookup.zig");
const memory_lookup = @import("air/cartridge_memory_lookup.zig");
const joypad_mmio = @import("air/joypad_mmio_lookup.zig");
const ppu_binding = @import("air/ppu_binding.zig");
const ppu_mmio = @import("air/ppu_mmio_lookup.zig");
const rom_lookup = @import("air/cartridge_rom_lookup.zig");
const timer_binding = @import("air/timer_binding.zig");
const timer_mmio = @import("air/timer_mmio_lookup.zig");
const apu_execution = @import("air/apu_execution_lookup.zig");

const Channel = channel_blake2s.Blake2sChannel;
const TRACE_SIZE = 16;
const PROGRAM_START: u16 = 0x0200;
const INITIAL_MCYCLE: u32 = 7;
const regions = [_]ram_observation.Region{
    .{ .space = .system, .start = 0xc000, .length = 1 },
};

test "v7 machine interaction is ordered honest and mutation sensitive" {
    var fixture = try Fixture.init();
    defer fixture.deinit();
    fixture.system[0xffff] = 1;
    fixture.system[runner.cartridge_memory.INTERRUPT_FLAGS] = 1;
    fixture.system[runner.dma.DMA_ADDRESS] = 0xff;

    var scheduler = try machine.CartridgeMachine.init(
        &fixture.memory,
        .{ .pc = PROGRAM_START, .sp = 0xc102, .ime = true },
    );
    const initial_timer = scheduler.timer;
    var initial = try Snapshot.capture(fixture);
    defer initial.deinit();
    var results: [TRACE_SIZE]machine.CartridgeStepResult = undefined;
    for (&results) |*result| result.* = try scheduler.step();
    try std.testing.expectEqual(
        machine.SchedulerEvent.interrupt_service,
        results[0].event,
    );
    const final_mcycle = INITIAL_MCYCLE + machineCycles(&results);

    var joypad = try joypad_trace.generateFromMachineExecution(
        std.testing.allocator,
        INITIAL_MCYCLE,
        final_mcycle,
        .{},
        &.{},
        &results,
    );
    defer joypad.deinit(std.testing.allocator);
    var timer = try timer_binding.generateFromMachineExecution(
        std.testing.allocator,
        INITIAL_MCYCLE,
        final_mcycle,
        initial_timer,
        &results,
    );
    defer timer.deinit(std.testing.allocator);
    var ppu = try ppu_binding.generateFromMachineExecution(
        std.testing.allocator,
        INITIAL_MCYCLE,
        final_mcycle,
        .{},
        &results,
    );
    defer ppu.deinit(std.testing.allocator);
    var dma = try dma_binding.generateFromMachineExecution(
        std.testing.allocator,
        INITIAL_MCYCLE,
        final_mcycle,
        .{ .clock = INITIAL_MCYCLE },
        &results,
        &.{},
    );
    defer dma.deinit(std.testing.allocator);
    var apu = try apu_execution.generateFromMachineExecution(
        std.testing.allocator,
        INITIAL_MCYCLE,
        .{},
        &results,
    );
    defer apu.deinit(std.testing.allocator);

    var final = try Snapshot.capture(fixture);
    defer final.deinit();
    setDeviceEndpoints(
        &initial,
        &final,
        joypad.rows,
        timer.rows,
        ppu.rows,
        dma.rows,
    );
    const observations = [_]intermediate_observation.Sample{.{
        .mcycle = INITIAL_MCYCLE + 3,
        .key = 0xc000,
        .expected = 0,
    }};
    const initial_images = try initial.images();
    const final_images = try final.images();
    var replay = try replay_mod.generate(
        std.testing.allocator,
        &results,
        initial_images,
        final_images,
        INITIAL_MCYCLE,
        joypad.rows,
        timer.rows,
        ppu.rows,
        dma.rows,
        &observations,
    );
    defer replay.deinit();

    const request = try makeStatement(
        fixture,
        &results,
        initial_images,
        final_images,
        joypad.rows,
        timer.rows,
        ppu.rows,
        dma.rows,
        &observations,
    );
    var channel = Channel{};
    var prepared = try subject.generate(
        std.testing.allocator,
        &channel,
        .{
            .request = request,
            .results = &results,
            .rom = try cartridge.Cartridge.init(fixture.rom),
            .initial_images = initial_images,
            .final_images = final_images,
            .actions = &.{},
            .observation_regions = &regions,
            .intermediate_observations = &observations,
            .joypad_events = joypad.rows,
            .timer_events = timer.rows,
            .ppu_events = ppu.rows,
            .dma_events = dma.rows,
            .apu_trace = apu,
            .replay = &replay,
            .boundary_final_clocks = replay.memory.final_clocks,
        },
    );
    defer prepared.deinit(std.testing.allocator);

    try std.testing.expectEqual(
        geometry.N_INTERACTION_COLUMNS,
        prepared.columns.columns.?.len,
    );
    const expected_logs = geometry.interactionLogSizes(
        request.base.base.log_size,
        request.base.joypad_log_size,
        request.base.timer_log_size,
        request.base.intermediate_observation_log_size,
        request.ppu_log_size,
        request.dma_log_size,
        request.apu_log_size,
    );
    for (prepared.columns.columns.?, expected_logs) |column, log_size|
        try std.testing.expectEqual(log_size, column.log_size);
    try std.testing.expectEqual(
        @as(u32, 1),
        prepared.claims.service_memory.service_count,
    );
    try std.testing.expectEqual(
        @as(usize, final_mcycle - INITIAL_MCYCLE),
        prepared.claims.dma_execution.dma_count,
    );
    try subject.verifyCancellation(request, prepared.claims);

    var claimed = request;
    prepared.claims.applyTo(&claimed);
    try statement.verifyLookupCancellation(claimed);

    var prefix = Channel{};
    try std.testing.expect(std.meta.eql(
        prepared.rom_relation,
        try rom_lookup.Relation.draw(std.testing.allocator, &prefix),
    ));
    try std.testing.expect(std.meta.eql(
        prepared.memory_relation,
        try memory_lookup.Relation.draw(std.testing.allocator, &prefix),
    ));
    try std.testing.expect(std.meta.eql(
        prepared.action_relation,
        try action_lookup.Relation.draw(std.testing.allocator, &prefix),
    ));
    try std.testing.expect(std.meta.eql(
        prepared.joypad_mmio_relations,
        try joypad_mmio.Relations.draw(std.testing.allocator, &prefix),
    ));
    try std.testing.expect(std.meta.eql(
        prepared.timer_mmio_relations,
        try timer_mmio.Relations.draw(std.testing.allocator, &prefix),
    ));
    try std.testing.expect(std.meta.eql(
        prepared.ppu_mmio_relations,
        try ppu_mmio.Relations.draw(std.testing.allocator, &prefix),
    ));
    try std.testing.expect(std.meta.eql(
        prepared.dma_execution_relations,
        try dma_execution.Relations.draw(std.testing.allocator, &prefix),
    ));
    try std.testing.expect(std.meta.eql(
        prepared.apu_execution_relation,
        try apu_execution.Relation.draw(std.testing.allocator, &prefix),
    ));
    try std.testing.expectEqualSlices(
        u8,
        &channel.digestBytes(),
        &prefix.digestBytes(),
    );

    var forged = prepared.claims;
    forged.ppu_if = forged.ppu_if.add(QM31.one());
    try std.testing.expectError(
        error.CartridgeMemoryLookupSumNonZero,
        subject.verifyCancellation(request, forged),
    );
    forged = prepared.claims;
    forged.ppu_policy.dma = forged.ppu_policy.dma.add(QM31.one());
    try std.testing.expectError(
        error.PpuExecutionPolicyLookupSumNonZero,
        subject.verifyCancellation(request, forged),
    );
    try std.testing.expect(!subject.memoryBoundaryEnabled(
        runner.ppu_mmio.LCDC_ADDRESS,
    ));
    try std.testing.expect(subject.memoryBoundaryEnabled(
        runner.dma.DMA_ADDRESS,
    ));
}

fn makeStatement(
    fixture: Fixture,
    results: []const machine.CartridgeStepResult,
    initial_images: memory_lookup.Images,
    final_images: memory_lookup.Images,
    joypad: []const joypad_trace.EventRow,
    timer: []const timer_binding.EventRow,
    ppu: []const ppu_binding.EventRow,
    dma: []const dma_binding.EventRow,
    observations: []const intermediate_observation.Sample,
) !statement.ExecutionStatement {
    const final_mcycle = INITIAL_MCYCLE + machineCycles(results);
    const rom = try cartridge.Cartridge.init(fixture.rom);
    const base = base_statement.init(
        4,
        .{ .cpu = results[0].before.cpu, .mcycle = INITIAL_MCYCLE },
        .{
            .cpu = results[results.len - 1].after.cpu,
            .mcycle = final_mcycle,
        },
        results[0].mapper_before,
        results[results.len - 1].mapper_after,
        rom,
        initial_images,
        final_images,
    );
    const environment_request = try environment.init(
        base,
        rom,
        initial_images,
        final_images,
        &.{},
        joypad[0].transition.before,
        joypad[joypad.len - 1].transition.after,
        paddedLog(joypad.len),
        timer[0].transition.before,
        timer[timer.len - 1].transition.after,
        paddedLog(timer.len),
        &regions,
        observations,
        paddedLog(observations.len),
    );
    const ppu_last = ppu[ppu.len - 1];
    return statement.init(
        environment_request,
        results[0].before,
        results[results.len - 1].after,
        .{
            .timing = ppu[0].transition.before,
            .lcdc = ppu[0].lcdc_before,
        },
        .{
            .timing = ppu_last.transition.after,
            .lcdc = ppu_last.lcdc_after,
        },
        .{},
        .{},
        dma[0].transition.before,
        dma[dma.len - 1].transition.after,
        1,
        paddedLog(ppu.len),
        4,
        paddedLog(dma.len),
        initial_images,
        final_images,
    );
}

fn paddedLog(count: usize) u32 {
    const size = std.math.ceilPowerOfTwo(
        usize,
        @max(count, 16),
    ) catch unreachable;
    return @intCast(std.math.log2_int(usize, size));
}

fn machineCycles(results: []const machine.CartridgeStepResult) u32 {
    var count: u32 = 0;
    for (results) |result| count += result.m_cycles;
    return count;
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
        const allocator = std.testing.allocator;
        allocator.destroy(self.system);
        allocator.destroy(self.sram);
        allocator.destroy(self.rom);
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

fn setDeviceEndpoints(
    initial: *Snapshot,
    final: *Snapshot,
    joypad: []const joypad_trace.EventRow,
    timer: []const timer_binding.EventRow,
    ppu: []const ppu_binding.EventRow,
    dma: []const dma_binding.EventRow,
) void {
    initial.system[runner.joypad.P1_ADDRESS] =
        joypad[0].transition.before.readP1();
    final.system[runner.joypad.P1_ADDRESS] =
        joypad[joypad.len - 1].transition.after.readP1();
    setTimer(initial.system, timer[0].transition.before);
    setTimer(final.system, timer[timer.len - 1].transition.after);
    setPpu(initial.system, .{
        .timing = ppu[0].transition.before,
        .lcdc = ppu[0].lcdc_before,
    });
    const ppu_last = ppu[ppu.len - 1];
    setPpu(final.system, .{
        .timing = ppu_last.transition.after,
        .lcdc = ppu_last.lcdc_after,
    });
    initial.system[runner.dma.DMA_ADDRESS] =
        dma[0].transition.before.page;
    final.system[runner.dma.DMA_ADDRESS] =
        dma[dma.len - 1].transition.after.page;
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
    system[runner.ppu_mmio.LY_ADDRESS] = ppu.read(.ly);
    system[runner.ppu_mmio.LYC_ADDRESS] = ppu.read(.lyc);
}
