const std = @import("std");
const core_air_utils = @import("stwo_core").air.utils;
const M31 = @import("stwo_core").fields.m31.M31;
const cartridge = @import("../cartridge/mod.zig");
const memory_image = @import("../memory.zig");
const machine_memory_replay = @import("../machine_memory_replay.zig");
const machine = @import("../runner/machine.zig");
const runner = @import("../runner/mod.zig");
const execution = @import("execution.zig");
const family_trace = @import("family_trace.zig");
const interrupt_service = @import("interrupt_service.zig");
const lookup = @import("cartridge_memory_lookup.zig");
const scheduler_binding = @import("scheduler_binding.zig");
const scheduler_memory = @import("scheduler_memory_lookup.zig");
const subject = @import("machine_scheduler_trace.zig");

const PROGRAM_START: u16 = 0x0200;
const IF: u16 = runner.cartridge_memory.INTERRUPT_FLAGS;
const IE: u16 = 0xffff;
const TRACE_SIZE: usize = 16;

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

    fn images(self: Snapshot) !lookup.Images {
        return .{
            .system = try memory_image.Image.init(self.system),
            .sram = try lookup.SramImage.init(self.sram),
        };
    }

    fn deinit(self: *Snapshot) void {
        const allocator = std.testing.allocator;
        allocator.free(self.sram);
        allocator.free(self.system);
        self.* = undefined;
    }
};

const Scenario = struct {
    fixture: Fixture,
    initial: Snapshot,
    final: Snapshot,
    results: [TRACE_SIZE]machine.CartridgeStepResult,
    replay: machine_memory_replay.Replay,

    fn init(
        cpu: runner.Cpu,
        interrupt_enable: u8,
        interrupt_flags: u8,
        initial_mcycle: u32,
    ) !Scenario {
        var fixture = try Fixture.init();
        errdefer fixture.deinit();
        fixture.system[IE] = interrupt_enable;
        fixture.system[IF] = interrupt_flags;
        var cartridge_machine = try machine.CartridgeMachine.init(
            &fixture.memory,
            cpu,
        );
        var initial = try Snapshot.capture(fixture);
        errdefer initial.deinit();
        var results: [TRACE_SIZE]machine.CartridgeStepResult = undefined;
        for (&results) |*result|
            result.* = try cartridge_machine.step();
        var final = try Snapshot.capture(fixture);
        errdefer final.deinit();
        const replay = try machine_memory_replay.generate(
            std.testing.allocator,
            &results,
            try initial.images(),
            try final.images(),
            initial_mcycle,
        );
        return .{
            .fixture = fixture,
            .initial = initial,
            .final = final,
            .results = results,
            .replay = replay,
        };
    }

    fn deinit(self: *Scenario) void {
        self.replay.deinit();
        self.final.deinit();
        self.initial.deinit();
        self.fixture.deinit();
        self.* = undefined;
    }
};

test "machine scheduler trace aligns instruction HALT wake and SameBoy service rows" {
    try expectScenario(
        .{ .pc = PROGRAM_START },
        0,
        0,
        .instruction,
        7,
    );
    try expectScenario(
        .{ .pc = PROGRAM_START, .halted = true },
        0,
        0,
        .halt_idle,
        9,
    );
    try expectScenario(
        .{ .pc = PROGRAM_START, .halted = true },
        1,
        1,
        .halt_wake,
        11,
    );
    try expectScenario(
        .{ .pc = 0x2345, .sp = 0xc102, .ime = true },
        1,
        1,
        .interrupt_service,
        13,
    );
    try expectScenario(
        .{
            .pc = 0x2345,
            .sp = 0xc102,
            .ime = true,
            .halted = true,
        },
        1,
        1,
        .interrupt_service,
        17,
    );
}

test "machine family activity is exact and scheduler provenance is not forgeable" {
    var instruction = try Scenario.init(
        .{ .pc = PROGRAM_START },
        0,
        0,
        0,
    );
    defer instruction.deinit();
    var instruction_trace = try subject.generate(
        std.testing.allocator,
        &instruction.results,
        &instruction.replay,
    );
    defer instruction_trace.deinit();
    try expectFamilyActivity(
        instruction_trace,
        &instruction.results,
    );

    var idle = try Scenario.init(
        .{ .pc = PROGRAM_START, .halted = true },
        0,
        0,
        0,
    );
    defer idle.deinit();
    var idle_trace = try subject.generate(
        std.testing.allocator,
        &idle.results,
        &idle.replay,
    );
    defer idle_trace.deinit();
    try expectFamilyActivity(idle_trace, &idle.results);

    var service = try Scenario.init(
        .{ .pc = 0x2345, .sp = 0xc102, .ime = true },
        1,
        1,
        0,
    );
    defer service.deinit();
    var service_trace = try subject.generate(
        std.testing.allocator,
        &service.results,
        &service.replay,
    );
    defer service_trace.deinit();
    try expectFamilyActivity(service_trace, &service.results);

    const storage = try core_air_utils.circleBitReversedIndex(4, 0);
    const provenance = scheduler_binding.EVENT_OFFSET +
        @intFromEnum(machine.SchedulerEvent.interrupt_service);
    service_trace.provenance_main[provenance][storage] = M31.zero();
    try std.testing.expectError(
        error.DetachedMachineSchedulerTrace,
        service_trace.validate(&service.results, &service.replay),
    );
    service_trace.provenance_main[provenance][storage] = M31.one();
    try service_trace.validate(&service.results, &service.replay);
}

test "machine scheduler trace rejects predecessor service vacuity and detachment mutations" {
    var scenario = try Scenario.init(
        .{ .pc = 0x2345, .sp = 0xc102, .ime = true },
        1,
        1,
        23,
    );
    defer scenario.deinit();
    var trace = try subject.generate(
        std.testing.allocator,
        &scenario.results,
        &scenario.replay,
    );
    defer trace.deinit();
    try trace.validate(&scenario.results, &scenario.replay);
    const storage0 = try core_air_utils.circleBitReversedIndex(4, 0);

    @memset(trace.scheduler_main[0], M31.zero());
    try expectDetached(trace, scenario);
    @memset(trace.scheduler_main[0], M31.one());

    trace.families.main[
        family_trace.INTERRUPT_SERVICE_SELECTOR
    ][storage0] = M31.zero();
    try expectDetached(trace, scenario);
    trace.families.main[
        family_trace.INTERRUPT_SERVICE_SELECTOR
    ][storage0] = M31.one();

    const service_leaf =
        family_trace.INTERRUPT_SERVICE_OFFSET;
    trace.families.main[service_leaf][storage0] =
        flip(trace.families.main[service_leaf][storage0]);
    try expectDetached(trace, scenario);
    trace.families.main[service_leaf][storage0] =
        flip(trace.families.main[service_leaf][storage0]);

    const ie_previous = @intFromEnum(
        scheduler_memory.SampleIndex.interrupt_enable,
    ) * scheduler_memory.N_SAMPLE_COLUMNS +
        scheduler_memory.PREVIOUS_CLOCK_OFFSET;
    trace.scheduler_memory.main[ie_previous][storage0] =
        trace.scheduler_memory.main[ie_previous][storage0].add(M31.one());
    try expectDetached(trace, scenario);
    trace.scheduler_memory.main[ie_previous][storage0] =
        trace.scheduler_memory.main[ie_previous][storage0].sub(M31.one());

    trace.scheduler_memory.samples[0][0].value ^= 1;
    try expectDetached(trace, scenario);
    trace.scheduler_memory.samples[0][0].value ^= 1;

    const storage1 = try core_air_utils.circleBitReversedIndex(4, 1);
    const pc = @intFromEnum(execution.StateIndex.pc);
    std.mem.swap(
        M31,
        &trace.execution.main[pc][storage0],
        &trace.execution.main[pc][storage1],
    );
    try expectDetached(trace, scenario);
    std.mem.swap(
        M31,
        &trace.execution.main[pc][storage0],
        &trace.execution.main[pc][storage1],
    );
    try trace.validate(&scenario.results, &scenario.replay);

    scenario.replay.scheduler_predecessors[0]
        .interrupt_enable.value ^= 1;
    try std.testing.expectError(
        error.InvalidSchedulerMemoryPredecessor,
        subject.generate(
            std.testing.allocator,
            &scenario.results,
            &scenario.replay,
        ),
    );
    scenario.replay.scheduler_predecessors[0]
        .interrupt_enable.value ^= 1;

    const original_if_clock = scenario.replay.scheduler_predecessors[0]
        .interrupt_flags.clock;
    scenario.replay.scheduler_predecessors[0]
        .interrupt_flags.clock = try lookup.memory_clock.phaseClock(
        scenario.replay.initial_mcycle,
        scheduler_memory.SCHEDULER_PHASE,
    );
    try std.testing.expectError(
        error.InvalidSchedulerMemoryPredecessor,
        subject.generate(
            std.testing.allocator,
            &scenario.results,
            &scenario.replay,
        ),
    );
    scenario.replay.scheduler_predecessors[0]
        .interrupt_flags.clock = original_if_clock;

    var forged_service = scenario.results;
    forged_service[0].service.cycles[0].kind = .no_access;
    try std.testing.expectError(
        error.InvalidMachineSchedulerStep,
        subject.generate(
            std.testing.allocator,
            &forged_service,
            &scenario.replay,
        ),
    );

    var disconnected_cpu = scenario.results;
    disconnected_cpu[1].before.cpu.a ^= 1;
    try std.testing.expectError(
        error.DisconnectedMachineCpu,
        subject.generate(
            std.testing.allocator,
            &disconnected_cpu,
            &scenario.replay,
        ),
    );

    var disconnected_mapper = scenario.results;
    disconnected_mapper[1].mapper_before.rom_bank_register = 2;
    try std.testing.expectError(
        error.DisconnectedMachineMapper,
        subject.generate(
            std.testing.allocator,
            &disconnected_mapper,
            &scenario.replay,
        ),
    );

    scenario.replay.final_mcycle += 1;
    try std.testing.expectError(
        error.DetachedMachineMemoryReplay,
        subject.generate(
            std.testing.allocator,
            &scenario.results,
            &scenario.replay,
        ),
    );
    scenario.replay.final_mcycle -= 1;
}

fn expectScenario(
    cpu: runner.Cpu,
    interrupt_enable: u8,
    interrupt_flags: u8,
    expected_first: machine.SchedulerEvent,
    initial_mcycle: u32,
) !void {
    var scenario = try Scenario.init(
        cpu,
        interrupt_enable,
        interrupt_flags,
        initial_mcycle,
    );
    defer scenario.deinit();
    try std.testing.expectEqual(expected_first, scenario.results[0].event);
    var trace = try subject.generate(
        std.testing.allocator,
        &scenario.results,
        &scenario.replay,
    );
    defer trace.deinit();
    try trace.validate(&scenario.results, &scenario.replay);
    try expectFamilyActivity(trace, &scenario.results);
    try std.testing.expectEqual(
        scenario.replay.initial_mcycle,
        trace.execution.initial.mcycle,
    );
    try std.testing.expectEqual(
        scenario.replay.final_mcycle,
        trace.execution.final.mcycle,
    );
    if (expected_first == .interrupt_service) {
        const storage = try core_air_utils.circleBitReversedIndex(4, 0);
        const exact = interrupt_service.columns(
            try interrupt_service.ValidatedStep.init(scenario.results[0]),
        );
        for (
            trace.families.main[family_trace.INTERRUPT_SERVICE_OFFSET..][0..interrupt_service.N_MAIN_COLUMNS],
            exact,
        ) |column, value|
            try std.testing.expectEqual(value, column[storage]);
    }
}

fn expectFamilyActivity(
    trace: subject.Trace,
    results: []const machine.CartridgeStepResult,
) !void {
    for (results, 0..) |result, row| {
        const storage = try core_air_utils.circleBitReversedIndex(
            trace.log_size,
            row,
        );
        var activity = M31.zero();
        for (trace.families.main[0..execution.N_FAMILY_SELECTORS]) |column|
            activity = activity.add(column[storage]);
        const expected = result.event == .instruction or
            result.event == .interrupt_service;
        try std.testing.expectEqual(
            M31.fromCanonical(@intFromBool(expected)),
            activity,
        );
    }
}

fn expectDetached(
    trace: subject.Trace,
    scenario: Scenario,
) !void {
    try std.testing.expectError(
        error.DetachedMachineSchedulerTrace,
        trace.validate(&scenario.results, &scenario.replay),
    );
}

fn flip(value: M31) M31 {
    return if (value.isZero()) M31.one() else M31.zero();
}
