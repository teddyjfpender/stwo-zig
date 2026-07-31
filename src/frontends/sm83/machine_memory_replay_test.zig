const std = @import("std");
const core_air_utils = @import("stwo_core").air.utils;
const M31 = @import("stwo_core").fields.m31.M31;
const cartridge = @import("cartridge/mod.zig");
const memory_image = @import("memory.zig");
const machine = @import("runner/machine.zig");
const runner = @import("runner/mod.zig");
const cartridge_access = @import("air/cartridge_access.zig");
const machine_access = @import("air/cartridge_machine_access.zig");
const execution = @import("air/execution.zig");
const execution_input = @import("air/execution_input.zig");
const lookup = @import("air/cartridge_memory_lookup.zig");
const subject = @import("machine_memory_replay.zig");

const PROGRAM_START: u16 = 0x0200;
const IF: u16 = runner.cartridge_memory.INTERRUPT_FLAGS;
const IE: u16 = 0xffff;
const TRACE_SIZE: usize = 16;

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
        const allocator = std.testing.allocator;
        allocator.free(self.sram);
        allocator.free(self.system);
        self.* = undefined;
    }

    fn images(self: Snapshot) !lookup.Images {
        return .{
            .system = try memory_image.Image.init(self.system),
            .sram = try lookup.SramImage.init(self.sram),
        };
    }
};

test "machine replay authenticates instruction reads and exact endpoints" {
    var fixture = try Fixture.init(&.{0x7e}); // LD A,(HL)
    defer fixture.deinit();
    fixture.system[0xc000] = 0x42;
    var scheduler = try machine.CartridgeMachine.init(
        &fixture.memory,
        .{ .pc = PROGRAM_START, .h = 0xc0 },
    );
    var initial = try Snapshot.capture(fixture);
    defer initial.deinit();
    var results: [TRACE_SIZE]machine.CartridgeStepResult = undefined;
    try collect(&scheduler, &results);
    var final = try Snapshot.capture(fixture);
    defer final.deinit();

    var replay = try subject.generate(
        std.testing.allocator,
        &results,
        try initial.images(),
        try final.images(),
        7,
    );
    defer replay.deinit();
    try std.testing.expectEqual(@as(u32, 24), replay.final_mcycle);
    const read = replay.memory.accesses[1];
    try std.testing.expect(read.enabled);
    try std.testing.expectEqual(@as(u17, 0xc000), read.address);
    try std.testing.expectEqual(@as(u8, 0x42), read.previous_value);
    try std.testing.expectEqual(
        try lookup.memory_clock.phaseClock(
            7,
            lookup.memory_clock.CPU_PHASE,
        ) + lookup.memory_clock.PHASES,
        read.clock,
    );
    try replay.validate(
        std.testing.allocator,
        &results,
        try initial.images(),
        try final.images(),
        7,
    );
    try expectMemoryRowsValid(replay, &results, 7);

    replay.scheduler_predecessors[0].interrupt_enable.clock += 1;
    try std.testing.expectError(
        error.SchedulerPredecessorMismatch,
        replay.validate(
            std.testing.allocator,
            &results,
            try initial.images(),
            try final.images(),
            7,
        ),
    );
    replay.scheduler_predecessors[0].interrupt_enable.clock -= 1;
    replay.scheduler_predecessors[0]
        .post_interrupt_flags.clock += 1;
    try std.testing.expectError(
        error.SchedulerPredecessorMismatch,
        replay.validate(
            std.testing.allocator,
            &results,
            try initial.images(),
            try final.images(),
            7,
        ),
    );
    replay.scheduler_predecessors[0]
        .post_interrupt_flags.clock -= 1;
    replay.memory.accesses[1].clock += 1;
    try std.testing.expectError(
        error.ReplayMemoryMismatch,
        replay.validate(
            std.testing.allocator,
            &results,
            try initial.images(),
            try final.images(),
            7,
        ),
    );
}

test "machine replay rejects read image final tail state mapper and clock drift" {
    var fixture = try Fixture.init(&.{0x7e});
    defer fixture.deinit();
    fixture.system[0xc000] = 0x42;
    var scheduler = try machine.CartridgeMachine.init(
        &fixture.memory,
        .{ .pc = PROGRAM_START, .h = 0xc0 },
    );
    var initial = try Snapshot.capture(fixture);
    defer initial.deinit();
    var results: [TRACE_SIZE]machine.CartridgeStepResult = undefined;
    try collect(&scheduler, &results);
    var final = try Snapshot.capture(fixture);
    defer final.deinit();

    initial.system[0xc000] ^= 1;
    try expectGenerateError(
        error.MemoryReadMismatch,
        &results,
        initial,
        final,
        0,
    );
    initial.system[0xc000] ^= 1;
    final.system[0xc000] ^= 1;
    try expectGenerateError(
        error.FinalMemoryMismatch,
        &results,
        initial,
        final,
        0,
    );
    final.system[0xc000] ^= 1;

    var tail = results;
    tail[0].instruction.?.accesses[5] =
        tail[0].instruction.?.accesses[1];
    try expectGenerateError(
        error.InvalidMachineStep,
        &tail,
        initial,
        final,
        0,
    );

    var second_fixture = try Fixture.init(&.{0x00});
    defer second_fixture.deinit();
    var second_scheduler = try machine.CartridgeMachine.init(
        &second_fixture.memory,
        .{ .pc = PROGRAM_START, .a = 1 },
    );
    var disconnected = results;
    disconnected[1] = try second_scheduler.step();
    try expectGenerateError(
        error.DisconnectedMachineState,
        &disconnected,
        initial,
        final,
        0,
    );

    var mapper = results;
    mapper[1].mapper_before.rom_bank_register = 2;
    mapper[1].mapper_after.rom_bank_register = 2;
    for (mapper[1].instruction.?.accesses[0..mapper[1].m_cycles]) |*access|
        if (access.*) |*item| {
            item.mapper_before.rom_bank_register = 2;
            item.mapper_after.rom_bank_register = 2;
        };
    try std.testing.expect(mapper[1].hasCanonicalShape());
    try expectGenerateError(
        error.DisconnectedMapperState,
        &mapper,
        initial,
        final,
        0,
    );
    try expectGenerateError(
        error.NonCanonicalMemoryClock,
        &results,
        initial,
        final,
        lookup.memory_clock.MAX_FINAL_MCYCLE + 1,
    );
    try std.testing.expectError(
        error.InvalidTraceLength,
        subject.generate(
            std.testing.allocator,
            results[0..0],
            try initial.images(),
            try final.images(),
            0,
        ),
    );
}

test "machine replay covers HALT idle and wake without vacuous bus rows" {
    var idle_fixture = try Fixture.init(&.{0x00});
    defer idle_fixture.deinit();
    var idle_scheduler = try machine.CartridgeMachine.init(
        &idle_fixture.memory,
        .{ .pc = PROGRAM_START, .halted = true },
    );
    var idle_initial = try Snapshot.capture(idle_fixture);
    defer idle_initial.deinit();
    var idle: [TRACE_SIZE]machine.CartridgeStepResult = undefined;
    try collect(&idle_scheduler, &idle);
    var idle_final = try Snapshot.capture(idle_fixture);
    defer idle_final.deinit();
    for (idle) |result|
        try std.testing.expectEqual(
            machine.SchedulerEvent.halt_idle,
            result.event,
        );
    var idle_replay = try subject.generate(
        std.testing.allocator,
        &idle,
        try idle_initial.images(),
        try idle_final.images(),
        0,
    );
    defer idle_replay.deinit();
    for (idle_replay.memory.accesses) |access|
        try std.testing.expect(!access.enabled);

    var wake_fixture = try Fixture.init(&.{0x00});
    defer wake_fixture.deinit();
    wake_fixture.system[IE] = 1;
    wake_fixture.system[IF] = 1;
    var wake_scheduler = try machine.CartridgeMachine.init(
        &wake_fixture.memory,
        .{ .pc = PROGRAM_START, .halted = true },
    );
    var wake_initial = try Snapshot.capture(wake_fixture);
    defer wake_initial.deinit();
    var wake: [TRACE_SIZE]machine.CartridgeStepResult = undefined;
    try collect(&wake_scheduler, &wake);
    var wake_final = try Snapshot.capture(wake_fixture);
    defer wake_final.deinit();
    try std.testing.expectEqual(
        machine.SchedulerEvent.halt_wake,
        wake[0].event,
    );
    var wake_replay = try subject.generate(
        std.testing.allocator,
        &wake,
        try wake_initial.images(),
        try wake_final.images(),
        0,
    );
    defer wake_replay.deinit();
}

test "machine replay orders pinned service bus resamples and acknowledgement" {
    var fixture = try Fixture.init(&.{0x00});
    defer fixture.deinit();
    fixture.system[IE] = 1;
    fixture.system[IF] = 1;
    var scheduler = try machine.CartridgeMachine.init(
        &fixture.memory,
        .{ .pc = 0x2345, .sp = 0xc102, .ime = true },
    );
    var initial = try Snapshot.capture(fixture);
    defer initial.deinit();
    var results: [TRACE_SIZE]machine.CartridgeStepResult = undefined;
    try collect(&scheduler, &results);
    var final = try Snapshot.capture(fixture);
    defer final.deinit();
    const service = results[0].service;
    try std.testing.expectEqual(
        machine.SchedulerEvent.interrupt_service,
        results[0].event,
    );
    try std.testing.expect(service.cycles[0].access != null);
    try std.testing.expect(service.cycles[1].access == null);
    try std.testing.expect(service.cycles[2].access == null);
    try std.testing.expect(service.cycles[3].access != null);
    try std.testing.expect(service.cycles[4].access != null);

    var replay = try subject.generate(
        std.testing.allocator,
        &results,
        try initial.images(),
        try final.images(),
        7,
    );
    defer replay.deinit();
    const predecessors = replay.service_predecessors[0];
    try std.testing.expectEqual(
        try lookup.memory_clock.phaseClock(
            7,
            lookup.memory_clock.SCHEDULER_PHASE,
        ),
        predecessors.ie_resample.?.clock,
    );
    try std.testing.expectEqual(
        try lookup.memory_clock.phaseClock(
            11,
            lookup.memory_clock.SERVICE_RESAMPLE_PHASE,
        ),
        predecessors.acknowledgement.?.clock,
    );
    try std.testing.expectEqual(
        try lookup.memory_clock.phaseClock(
            replay.final_mcycle - 1,
            lookup.memory_clock.OBSERVATION_PHASE,
        ),
        try finalClock(replay.memory, IF),
    );
    try expectMemoryRowsValid(replay, &results, 7);
    replay.service_predecessors[0].acknowledgement.?.clock += 1;
    try std.testing.expectError(
        error.ServicePredecessorMismatch,
        replay.validate(
            std.testing.allocator,
            &results,
            try initial.images(),
            try final.images(),
            7,
        ),
    );
}

test "machine replay preserves service cancellation reprioritization and IF alias" {
    try expectServiceCase(0, 0, 1, 1, null);
    try expectServiceCase(0x0200, 0, 1, 3, 1);

    var fixture = try Fixture.init(&.{0x00});
    defer fixture.deinit();
    fixture.system[IE] = 1;
    fixture.system[IF] = 1;
    var scheduler = try machine.CartridgeMachine.init(
        &fixture.memory,
        .{ .pc = 2, .sp = IF + 2, .ime = true },
    );
    var initial = try Snapshot.capture(fixture);
    defer initial.deinit();
    var results: [TRACE_SIZE]machine.CartridgeStepResult = undefined;
    try collect(&scheduler, &results);
    var final = try Snapshot.capture(fixture);
    defer final.deinit();
    var replay = try subject.generate(
        std.testing.allocator,
        &results,
        try initial.images(),
        try final.images(),
        0,
    );
    defer replay.deinit();
    const predecessors = replay.service_predecessors[0];
    try std.testing.expectEqual(@as(u8, 1), predecessors.if_logical_source.?.value);
    try std.testing.expectEqual(@as(u8, 2), predecessors.if_resample.?.value);
    try std.testing.expectEqual(
        try lookup.memory_clock.phaseClock(
            4,
            lookup.memory_clock.CPU_PHASE,
        ),
        predecessors.if_resample.?.clock,
    );
    try std.testing.expectEqual(@as(u8, 2), final.system[IF]);
}

test "detached machine replay rejects attached device MMIO" {
    var fixture = try Fixture.init(&.{ 0xf0, 0x04 }); // LDH A,(DIV)
    defer fixture.deinit();
    var scheduler = try machine.CartridgeMachine.init(
        &fixture.memory,
        .{ .pc = PROGRAM_START },
    );
    var initial = try Snapshot.capture(fixture);
    defer initial.deinit();
    var results: [TRACE_SIZE]machine.CartridgeStepResult = undefined;
    try collect(&scheduler, &results);
    var final = try Snapshot.capture(fixture);
    defer final.deinit();
    try expectGenerateError(
        error.AttachedDeviceMmio,
        &results,
        initial,
        final,
        0,
    );
}

fn expectServiceCase(
    pc: u16,
    sp: u16,
    ie: u8,
    flags: u8,
    index: ?u3,
) !void {
    var fixture = try Fixture.init(&.{0x00});
    defer fixture.deinit();
    fixture.system[IE] = ie;
    fixture.system[IF] = flags;
    var scheduler = try machine.CartridgeMachine.init(
        &fixture.memory,
        .{ .pc = pc, .sp = sp, .ime = true },
    );
    var initial = try Snapshot.capture(fixture);
    defer initial.deinit();
    var results: [TRACE_SIZE]machine.CartridgeStepResult = undefined;
    try collect(&scheduler, &results);
    var final = try Snapshot.capture(fixture);
    defer final.deinit();
    try std.testing.expectEqual(index, results[0].interrupt_index);
    var replay = try subject.generate(
        std.testing.allocator,
        &results,
        try initial.images(),
        try final.images(),
        0,
    );
    defer replay.deinit();
    try std.testing.expectEqual(
        index != null,
        replay.service_predecessors[0].acknowledgement != null,
    );
}

fn collect(
    scheduler: *machine.CartridgeMachine,
    results: *[TRACE_SIZE]machine.CartridgeStepResult,
) !void {
    for (results) |*result| result.* = try scheduler.step();
}

fn expectGenerateError(
    expected: anyerror,
    results: []const machine.CartridgeStepResult,
    initial: Snapshot,
    final: Snapshot,
    initial_mcycle: u32,
) !void {
    try std.testing.expectError(
        expected,
        subject.generate(
            std.testing.allocator,
            results,
            try initial.images(),
            try final.images(),
            initial_mcycle,
        ),
    );
}

fn finalClock(witness: lookup.Witness, key: usize) !u32 {
    const storage = try core_air_utils.circleBitReversedIndex(
        lookup.BOUNDARY_LOG_SIZE,
        key,
    );
    return witness.final_clocks[storage].toU32();
}

fn expectMemoryRowsValid(
    replay: subject.Replay,
    results: []const machine.CartridgeStepResult,
    initial_mcycle: u32,
) !void {
    const log_size: u32 =
        @intCast(std.math.log2_int(usize, results.len));
    var mcycle = initial_mcycle;
    for (results, 0..) |result, row| {
        const input = try execution_input.fromCartridgeMachine(result);
        const machine_values =
            try execution_input.cartridgeExecutionColumns(input, mcycle);
        const validated = try machine_access.ValidatedStep.init(result);
        var sources =
            [_][cartridge_access.N_MAIN_COLUMNS]M31{
                cartridge_access.inactiveColumns(),
            } ** execution.N_BUS_CYCLES;
        for (0..validated.count) |cycle|
            sources[cycle] =
                machine_access.columnsForCycle(validated, cycle);
        const storage = try core_air_utils.circleBitReversedIndex(
            log_size,
            row,
        );
        var main: [lookup.N_MAIN_COLUMNS]M31 = undefined;
        for (&main, replay.memory.main) |*value, column|
            value.* = column[storage];
        try std.testing.expect(
            (try lookup.evaluate(
                machine_values,
                sources,
                main,
            )).allZero(),
        );
        mcycle += result.m_cycles;
    }
}
