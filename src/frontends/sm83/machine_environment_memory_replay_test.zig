const std = @import("std");
const replay = @import("machine_environment_memory_replay.zig");
const action_schedule = @import("action_schedule.zig");
const cartridge = @import("cartridge/mod.zig");
const memory_image = @import("memory.zig");
const machine = @import("runner/machine.zig");
const runner = @import("runner/mod.zig");
const memory_lookup = @import("air/cartridge_memory_lookup.zig");
const joypad_trace = @import("joypad_trace.zig");
const timer_binding = @import("air/timer_binding.zig");
const ppu_binding = @import("air/ppu_binding.zig");
const dma_binding = @import("air/dma_binding.zig");
const observation =
    @import("air/intermediate_ram_observation_lookup.zig");

const TRACE_SIZE: usize = 16;
const PROGRAM_START: u16 = 0x0200;
const IF: u16 = runner.cartridge_memory.INTERRUPT_FLAGS;
const IE: u16 = 0xffff;

test "machine boundary excludes only device-owned registers" {
    try std.testing.expect(!replay.memoryBoundaryEnabled(
        runner.joypad.P1_ADDRESS,
    ));
    try std.testing.expect(!replay.memoryBoundaryEnabled(
        timer_binding.FIRST_ADDRESS,
    ));
    try std.testing.expect(!replay.memoryBoundaryEnabled(
        runner.ppu_mmio.LCDC_ADDRESS,
    ));
    try std.testing.expect(!replay.memoryBoundaryEnabled(
        runner.ppu_mmio.SCY_ADDRESS,
    ));
    try std.testing.expect(!replay.memoryBoundaryEnabled(
        runner.ppu_mmio.SCX_ADDRESS,
    ));
    try std.testing.expect(!replay.memoryBoundaryEnabled(
        runner.ppu_mmio.WY_ADDRESS,
    ));
    for (runner.apu_mmio.FIRST_ADDRESS..runner.apu_mmio.LAST_ADDRESS + 1) |address|
        try std.testing.expect(!replay.memoryBoundaryEnabled(address));
    try std.testing.expect(replay.memoryBoundaryEnabled(
        runner.apu_mmio.FIRST_ADDRESS - 1,
    ));
    try std.testing.expect(replay.memoryBoundaryEnabled(
        runner.apu_mmio.LAST_ADDRESS + 8,
    ));
    try std.testing.expect(replay.memoryBoundaryEnabled(
        runner.dma.DMA_ADDRESS,
    ));
    try std.testing.expect(replay.memoryBoundaryEnabled(IF));
}

test "machine environment replay rejects an empty execution before devices" {
    const allocator = std.testing.allocator;
    const system = try allocator.alloc(u8, memory_lookup.SYSTEM_SIZE);
    defer allocator.free(system);
    @memset(system, 0);
    const sram = try allocator.alloc(u8, memory_lookup.SRAM_SIZE);
    defer allocator.free(sram);
    @memset(sram, 0);
    const images = memory_lookup.Images{
        .system = .{ .bytes = system },
        .sram = .{ .bytes = sram },
    };
    try std.testing.expectError(
        error.InvalidTraceLength,
        replay.generate(
            allocator,
            &.{},
            images,
            images,
            0,
            &.{},
            &.{},
            &.{},
            &.{},
            &.{},
        ),
    );
}

test "machine environment replay owns every phase and rejects drift" {
    var fixture = try Fixture.init(&.{0x00});
    defer fixture.deinit();
    fixture.system[runner.dma.DMA_ADDRESS] = 0x80;
    fixture.system[0xc000] = 0x42;
    var dma_sources: [TRACE_SIZE]u8 = undefined;
    for (&dma_sources, 0..) |*value, index| {
        value.* = @intCast(index + 1);
        fixture.system[0x8000 + index] = value.*;
    }
    var scheduler_machine = try machine.CartridgeMachine.init(
        &fixture.memory,
        .{ .pc = PROGRAM_START },
    );
    scheduler_machine.timer.reload_state = .reloading;
    const initial_timer = scheduler_machine.timer;
    var initial = try Snapshot.capture(fixture);
    defer initial.deinit();
    var results: [TRACE_SIZE]machine.CartridgeStepResult = undefined;
    for (&results) |*result|
        result.* = try scheduler_machine.step();
    const initial_mcycle: u32 = 7;
    const final_mcycle = initial_mcycle + TRACE_SIZE;

    var joypad = try joypad_trace.generateFromMachineExecution(
        std.testing.allocator,
        initial_mcycle,
        final_mcycle,
        .{},
        &.{},
        &results,
    );
    defer joypad.deinit(std.testing.allocator);
    var timer = try timer_binding.generateFromMachineExecution(
        std.testing.allocator,
        initial_mcycle,
        final_mcycle,
        initial_timer,
        &results,
    );
    defer timer.deinit(std.testing.allocator);
    var ppu = try ppu_binding.generateFromMachineExecution(
        std.testing.allocator,
        initial_mcycle,
        final_mcycle,
        .{},
        &results,
    );
    defer ppu.deinit(std.testing.allocator);
    var dma = try dma_binding.generateFromMachineExecution(
        std.testing.allocator,
        initial_mcycle,
        final_mcycle,
        .{
            .clock = initial_mcycle,
            .page = 0x80,
            .phase = .transfer,
        },
        &results,
        &dma_sources,
    );
    defer dma.deinit(std.testing.allocator);
    var final = try Snapshot.capture(fixture);
    defer final.deinit();
    @memcpy(
        final.system[runner.dma.OAM_START .. runner.dma.OAM_START + TRACE_SIZE],
        &dma_sources,
    );
    setDeviceEndpoints(
        &initial,
        &final,
        joypad.rows,
        timer.rows,
        ppu.rows,
        dma.rows,
    );
    const observations = [_]observation.Sample{.{
        .mcycle = initial_mcycle + 3,
        .key = 0xc000,
        .expected = 0x42,
    }};
    var result = try replay.generate(
        std.testing.allocator,
        &results,
        try initial.images(),
        try final.images(),
        initial_mcycle,
        joypad.rows,
        timer.rows,
        ppu.rows,
        dma.rows,
        &observations,
    );
    defer result.deinit();
    try std.testing.expectEqual(final_mcycle, result.final_mcycle);
    try std.testing.expectEqual(
        @as(u8, 1),
        result.dma_predecessors[0].source.value,
    );
    try std.testing.expect(
        timer.rows[0].transition.interrupt_requested,
    );
    try std.testing.expectEqual(
        @as(u8, 0),
        result.timer_predecessors[0].value,
    );
    try std.testing.expectEqual(
        try memory_lookup.memory_clock.phaseClock(
            initial_mcycle,
            memory_lookup.memory_clock.SCHEDULER_PHASE,
        ),
        result.timer_predecessors[0].clock,
    );
    try result.validate(
        std.testing.allocator,
        &results,
        try initial.images(),
        try final.images(),
        initial_mcycle,
        joypad.rows,
        timer.rows,
        ppu.rows,
        dma.rows,
        &observations,
    );
    result.observation_predecessors[0].clock += 1;
    try std.testing.expectError(
        error.ObservationPredecessorMismatch,
        result.validate(
            std.testing.allocator,
            &results,
            try initial.images(),
            try final.images(),
            initial_mcycle,
            joypad.rows,
            timer.rows,
            ppu.rows,
            dma.rows,
            &observations,
        ),
    );
    result.observation_predecessors[0].clock -= 1;
    result.scheduler_predecessors[0]
        .post_interrupt_flags.value ^= 1;
    try std.testing.expectError(
        error.SchedulerPredecessorMismatch,
        result.validate(
            std.testing.allocator,
            &results,
            try initial.images(),
            try final.images(),
            initial_mcycle,
            joypad.rows,
            timer.rows,
            ppu.rows,
            dma.rows,
            &observations,
        ),
    );
    result.scheduler_predecessors[0]
        .post_interrupt_flags.value ^= 1;
    result.dma_predecessors[0].destination.value ^= 1;
    try std.testing.expectError(
        error.DmaPredecessorMismatch,
        result.validate(
            std.testing.allocator,
            &results,
            try initial.images(),
            try final.images(),
            initial_mcycle,
            joypad.rows,
            timer.rows,
            ppu.rows,
            dma.rows,
            &observations,
        ),
    );
    result.dma_predecessors[0].destination.value ^= 1;
    const altered = try std.testing.allocator.dupe(
        joypad_trace.EventRow,
        joypad.rows,
    );
    defer std.testing.allocator.free(altered);
    altered[0].provenance = .{ .action_index = 0 };
    try std.testing.expectError(
        error.InvalidJoypadEvent,
        replay.generate(
            std.testing.allocator,
            &results,
            try initial.images(),
            try final.images(),
            initial_mcycle,
            altered,
            timer.rows,
            ppu.rows,
            dma.rows,
            &observations,
        ),
    );
    try std.testing.expectError(
        error.MissingDmaEvent,
        replay.generate(
            std.testing.allocator,
            &results,
            try initial.images(),
            try final.images(),
            initial_mcycle,
            joypad.rows,
            timer.rows,
            ppu.rows,
            dma.rows[0 .. dma.rows.len - 1],
            &observations,
        ),
    );
}

test "machine environment replay covers service and HALT scheduler rows" {
    try runSchedulerCase(
        .{ .pc = 0x2345, .sp = 0xc102, .ime = true },
        1,
        1,
        .interrupt_service,
    );
    try runSchedulerCase(
        .{ .pc = PROGRAM_START, .halted = true },
        0,
        0,
        .halt_idle,
    );
}

test "joypad action phase feeds the same-cycle scheduler sample" {
    var fixture = try Fixture.init(&.{0x00});
    defer fixture.deinit();
    fixture.system[IF] = runner.joypad.JOYPAD_INTERRUPT;
    fixture.system[runner.dma.DMA_ADDRESS] = 0xff;
    var scheduler_machine = try machine.CartridgeMachine.init(
        &fixture.memory,
        .{ .pc = PROGRAM_START },
    );
    const initial_timer = scheduler_machine.timer;
    var initial = try Snapshot.capture(fixture);
    defer initial.deinit();
    initial.system[IF] = 0;
    var results: [TRACE_SIZE]machine.CartridgeStepResult = undefined;
    for (&results) |*result|
        result.* = try scheduler_machine.step();
    const initial_mcycle: u32 = 21;
    const final_mcycle = initial_mcycle + machineCycles(&results);
    const actions = [_]action_schedule.Action{.{
        .mcycle = initial_mcycle,
        .pressed = runner.joypad.Key.right.mask(),
    }};
    var joypad = try joypad_trace.generateFromMachineExecution(
        std.testing.allocator,
        initial_mcycle,
        final_mcycle,
        .{},
        &actions,
        &results,
    );
    defer joypad.deinit(std.testing.allocator);
    try std.testing.expect(
        joypad.rows[0].transition.interrupt_requested,
    );
    var timer = try timer_binding.generateFromMachineExecution(
        std.testing.allocator,
        initial_mcycle,
        final_mcycle,
        initial_timer,
        &results,
    );
    defer timer.deinit(std.testing.allocator);
    var ppu = try ppu_binding.generateFromMachineExecution(
        std.testing.allocator,
        initial_mcycle,
        final_mcycle,
        .{},
        &results,
    );
    defer ppu.deinit(std.testing.allocator);
    var dma = try dma_binding.generateFromMachineExecution(
        std.testing.allocator,
        initial_mcycle,
        final_mcycle,
        .{ .clock = initial_mcycle },
        &results,
        &.{},
    );
    defer dma.deinit(std.testing.allocator);
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
    var result = try replay.generate(
        std.testing.allocator,
        &results,
        try initial.images(),
        try final.images(),
        initial_mcycle,
        joypad.rows,
        timer.rows,
        ppu.rows,
        dma.rows,
        &.{},
    );
    defer result.deinit();
    try std.testing.expectEqual(
        @as(u8, runner.joypad.JOYPAD_INTERRUPT),
        result.scheduler_predecessors[0].interrupt_flags.value,
    );
    try std.testing.expectEqual(
        try memory_lookup.memory_clock.phaseClock(
            initial_mcycle,
            memory_lookup.memory_clock.ACTION_PHASE,
        ),
        result.scheduler_predecessors[0].interrupt_flags.clock,
    );
}

fn runSchedulerCase(
    cpu: runner.Cpu,
    interrupt_enable: u8,
    interrupt_flags: u8,
    expected_first: machine.SchedulerEvent,
) !void {
    var fixture = try Fixture.init(&.{0x00});
    defer fixture.deinit();
    fixture.system[IE] = interrupt_enable;
    fixture.system[IF] = interrupt_flags;
    fixture.system[runner.dma.DMA_ADDRESS] = 0xff;
    var scheduler_machine = try machine.CartridgeMachine.init(
        &fixture.memory,
        cpu,
    );
    const initial_timer = scheduler_machine.timer;
    var initial = try Snapshot.capture(fixture);
    defer initial.deinit();
    var results: [TRACE_SIZE]machine.CartridgeStepResult = undefined;
    for (&results) |*result|
        result.* = try scheduler_machine.step();
    try std.testing.expectEqual(expected_first, results[0].event);
    const initial_mcycle: u32 = 13;
    const final_mcycle = initial_mcycle + machineCycles(&results);
    var joypad = try joypad_trace.generateFromMachineExecution(
        std.testing.allocator,
        initial_mcycle,
        final_mcycle,
        .{},
        &.{},
        &results,
    );
    defer joypad.deinit(std.testing.allocator);
    var timer = try timer_binding.generateFromMachineExecution(
        std.testing.allocator,
        initial_mcycle,
        final_mcycle,
        initial_timer,
        &results,
    );
    defer timer.deinit(std.testing.allocator);
    var ppu = try ppu_binding.generateFromMachineExecution(
        std.testing.allocator,
        initial_mcycle,
        final_mcycle,
        .{},
        &results,
    );
    defer ppu.deinit(std.testing.allocator);
    var dma = try dma_binding.generateFromMachineExecution(
        std.testing.allocator,
        initial_mcycle,
        final_mcycle,
        .{ .clock = initial_mcycle },
        &results,
        &.{},
    );
    defer dma.deinit(std.testing.allocator);
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
    var result = try replay.generate(
        std.testing.allocator,
        &results,
        try initial.images(),
        try final.images(),
        initial_mcycle,
        joypad.rows,
        timer.rows,
        ppu.rows,
        dma.rows,
        &.{},
    );
    defer result.deinit();
    try std.testing.expectEqual(final_mcycle, result.final_mcycle);
    if (expected_first == .interrupt_service)
        try std.testing.expect(
            result.service_predecessors[0].acknowledgement != null,
        );
}

fn machineCycles(
    results: []const machine.CartridgeStepResult,
) u32 {
    var count: u32 = 0;
    for (results) |result| count += result.m_cycles;
    return count;
}

const Fixture = struct {
    rom: *[cartridge.header.ROM_SIZE]u8,
    sram: *[cartridge.header.RAM_SIZE]u8,
    system: *[runner.cartridge_memory.SYSTEM_SIZE]u8,
    memory: runner.cartridge_memory.Memory,

    fn init(program: []const u8) !Fixture {
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
        @memcpy(
            rom[PROGRAM_START .. PROGRAM_START + program.len],
            program,
        );
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
    setPpu(
        initial.system,
        .{
            .timing = ppu[0].transition.before,
            .lcdc = ppu[0].lcdc_before,
            .scy = ppu[0].latches_before[0],
            .scx = ppu[0].latches_before[1],
            .wy = ppu[0].latches_before[2],
        },
    );
    const ppu_last = ppu[ppu.len - 1];
    setPpu(
        final.system,
        .{
            .timing = ppu_last.transition.after,
            .lcdc = ppu_last.lcdc_after,
            .scy = ppu_last.latches_after[0],
            .scx = ppu_last.latches_after[1],
            .wy = ppu_last.latches_after[2],
        },
    );
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
    system[runner.ppu_mmio.SCY_ADDRESS] = ppu.read(.scy);
    system[runner.ppu_mmio.SCX_ADDRESS] = ppu.read(.scx);
    system[runner.ppu_mmio.LY_ADDRESS] = ppu.read(.ly);
    system[runner.ppu_mmio.LYC_ADDRESS] = ppu.read(.lyc);
    system[runner.ppu_mmio.WY_ADDRESS] = ppu.read(.wy);
}
