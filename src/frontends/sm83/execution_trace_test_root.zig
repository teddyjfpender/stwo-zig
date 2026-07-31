const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const cartridge = @import("cartridge/mod.zig");
const execution = @import("air/execution.zig");
const execution_input = @import("air/execution_input.zig");
const execution_trace = @import("air/execution_trace.zig");
const machine = @import("runner/machine.zig");
const runner = @import("runner/mod.zig");

const PROGRAM_START: u16 = 0x0200;
const IF: u16 = 0xff0f;
const IE: u16 = 0xffff;
const TAC: u16 = 0xff07;

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
        const loaded = try cartridge.Cartridge.init(rom);
        return .{
            .rom = rom,
            .sram = sram,
            .system = system,
            .memory = runner.cartridge_memory.Memory.init(
                loaded,
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

test "typed cartridge input admits timer-authenticated ordinary rows" {
    var fixture = try Fixture.init(&.{0x00});
    defer fixture.deinit();
    fixture.system[TAC] = 0x05;
    var scheduler = try machine.CartridgeMachine.init(
        &fixture.memory,
        .{ .pc = PROGRAM_START },
    );
    const result = try scheduler.step();
    const input = try execution_input.fromCartridgeMachine(result);
    try std.testing.expectEqual(machine.SchedulerEvent.instruction, result.event);
    try std.testing.expect(input.result.hasCanonicalShape());
    try std.testing.expectEqualDeep(
        execution.columns(result.instruction.?.instruction, 9),
        try execution_input.cartridgeExecutionColumns(input, 9),
    );
    try std.testing.expectError(
        error.TimerEnabled,
        execution_input.fromMachine(result.schedulerResult()),
    );
}

test "HALT idle and wake produce one honest active idle execution cycle" {
    var fixture = try Fixture.init(&.{0x00});
    defer fixture.deinit();
    fixture.system[IE] = 1;
    var scheduler = try machine.CartridgeMachine.init(
        &fixture.memory,
        .{ .pc = PROGRAM_START, .halted = true },
    );
    const idle = try scheduler.step();
    try expectHaltRow(idle, 20);
    fixture.system[IF] = 1;
    const wake = try scheduler.step();
    try expectHaltRow(wake, 21);

    const input = try execution_input.fromCartridgeMachine(idle);
    const honest = try execution_input.cartridgeExecutionColumns(input, 20);
    var forged = honest;
    forged[@intFromEnum(execution.StateIndex.a)] = M31.one();
    try expectRejected(forged, honest, idle, 20);
    forged = honest;
    forged[2 * execution.N_STATE_COLUMNS + 2] = M31.zero();
    try expectRejected(forged, honest, idle, 20);
    forged = honest;
    forged[2 * execution.N_STATE_COLUMNS + execution.N_BUS_COLUMNS] =
        M31.one();
    try expectRejected(forged, honest, idle, 20);
    forged = honest;
    const clock = 2 * execution.N_STATE_COLUMNS +
        execution.N_BUS_CYCLES * execution.N_BUS_COLUMNS;
    forged[clock + 1] = M31.fromCanonical(22);
    try expectRejected(forged, honest, idle, 20);
    try std.testing.expectError(
        error.ExecutionClockOverflow,
        execution_input.cartridgeExecutionColumns(input, std.math.maxInt(u32)),
    );
}

test "HALT bug boundary survives typed ingestion and trace ownership" {
    var fixture = try Fixture.init(&.{
        0x76, // HALT
        0x06, // LD B,d8, whose opcode byte is duplicated by the bug.
        0x99,
    });
    defer fixture.deinit();
    fixture.system[IE] = 1;
    fixture.system[IF] = 1;
    var scheduler = try machine.CartridgeMachine.init(
        &fixture.memory,
        .{ .pc = PROGRAM_START },
    );
    var results: [16]machine.CartridgeStepResult = undefined;
    for (&results) |*result| result.* = try scheduler.step();
    const halt = try execution_input.fromCartridgeMachine(results[0]);
    const duplicated = try execution_input.fromCartridgeMachine(results[1]);
    try std.testing.expect(execution_input.haltBugBoundary(halt).after);
    try std.testing.expect(execution_input.haltBugBoundary(duplicated).before);
    try std.testing.expect(!execution_input.haltBugBoundary(duplicated).after);

    var trace = try execution_trace.generateAt(
        std.testing.allocator,
        &results,
        100,
    );
    defer trace.deinit();
    const retained = trace.cartridgeResults() orelse
        return error.TestExpectedEqual;
    try std.testing.expectEqual(@as(usize, 16), retained.len);
    try std.testing.expect(retained[0].after.halt_bug);
    try std.testing.expect(retained[1].before.halt_bug);
    try std.testing.expectEqualDeep(
        results[1].mapper_before,
        retained[1].mapper_before,
    );
    try std.testing.expectEqual(@as(u32, 100), trace.initial.mcycle);
    var total: u32 = 100;
    for (results) |result| total += result.m_cycles;
    try std.testing.expectEqual(total, trace.final.mcycle);
}

test "cartridge service execution keeps exact SameBoy cycles and logical events" {
    var fixture = try Fixture.init(&.{0x00});
    defer fixture.deinit();
    fixture.system[IE] = 1;
    fixture.system[IF] = 1;
    var scheduler = try machine.CartridgeMachine.init(
        &fixture.memory,
        .{ .pc = 0x2345, .sp = 0xc102, .ime = true },
    );
    const result = try scheduler.step();
    const input = try execution_input.fromCartridgeMachine(result);
    try std.testing.expectEqual(
        machine.SchedulerEvent.interrupt_service,
        execution_input.cartridgeSchedulerResult(input).event,
    );
    try std.testing.expectEqual(@as(u3, 5), input.result.service.count);
    try expectServiceRow(result, 0);
    var service_rows: [16]machine.CartridgeStepResult = undefined;
    service_rows[0] = result;
    for (service_rows[1..]) |*row| row.* = try scheduler.step();
    var trace = try execution_trace.generate(
        std.testing.allocator,
        &service_rows,
    );
    defer trace.deinit();
    try std.testing.expectEqual(@as(u32, 20), trace.final.mcycle);

    try std.testing.expectError(
        error.FlatServiceTraceUnavailable,
        execution_input.fromMachine(result.schedulerResult()),
    );
    var forged = result;
    forged.mapper_after.rom_bank_register +%= 1;
    try std.testing.expectError(
        error.NonCanonicalMachineResult,
        execution_input.fromCartridgeMachine(forged),
    );

    var cancelled_fixture = try Fixture.init(&.{0x00});
    defer cancelled_fixture.deinit();
    cancelled_fixture.system[IE] = 1;
    cancelled_fixture.system[IF] = 1;
    var cancelled_scheduler = try machine.CartridgeMachine.init(
        &cancelled_fixture.memory,
        .{ .pc = 0, .sp = 0, .ime = true },
    );
    const cancelled_result = try cancelled_scheduler.step();
    const cancelled = try execution_input.fromCartridgeMachine(
        cancelled_result,
    );
    try std.testing.expectEqual(@as(?u3, null), cancelled.result.interrupt_index);
    try std.testing.expectEqual(@as(u3, 5), cancelled.result.service.count);
    try expectServiceRow(cancelled_result, 20);
    try std.testing.expectError(
        error.FlatServiceTraceUnavailable,
        execution_input.fromMachine(cancelled_result.schedulerResult()),
    );

    var reprioritized_fixture = try Fixture.init(&.{0x00});
    defer reprioritized_fixture.deinit();
    reprioritized_fixture.system[IE] = 1;
    reprioritized_fixture.system[IF] = 3;
    var reprioritized_scheduler = try machine.CartridgeMachine.init(
        &reprioritized_fixture.memory,
        .{ .pc = 0x0200, .sp = 0, .ime = true },
    );
    const reprioritized = try reprioritized_scheduler.step();
    try std.testing.expectEqual(@as(?u3, 1), reprioritized.interrupt_index);
    try expectServiceRow(reprioritized, 30);

    var halted_fixture = try Fixture.init(&.{0x00});
    defer halted_fixture.deinit();
    halted_fixture.system[IE] = 1;
    halted_fixture.system[IF] = 1;
    var halted_scheduler = try machine.CartridgeMachine.init(
        &halted_fixture.memory,
        .{ .pc = 0x2345, .sp = 0xc102, .ime = true, .halted = true },
    );
    const halted = try halted_scheduler.step();
    try std.testing.expectEqual(@as(u3, 6), halted.service.count);
    try expectServiceRow(halted, 40);
}

test "typed trace rejects state clock shape and mapper vacuity mutations" {
    var fixture = try Fixture.init(&.{0x00});
    defer fixture.deinit();
    var scheduler = try machine.CartridgeMachine.init(
        &fixture.memory,
        .{ .pc = PROGRAM_START },
    );
    var results: [16]machine.CartridgeStepResult = undefined;
    for (&results) |*result| result.* = try scheduler.step();
    var disconnected = results;
    disconnected[1].before.cpu.a +%= 1;
    try std.testing.expectError(
        error.DisconnectedExecution,
        execution_trace.generate(std.testing.allocator, &disconnected),
    );
    var bad_shape = results;
    bad_shape[0].m_cycles = 2;
    try std.testing.expectError(
        error.NonCanonicalMachineResult,
        execution_trace.generate(std.testing.allocator, &bad_shape),
    );
    var bad_mapper = results;
    bad_mapper[0].mapper_after.rom_bank_register +%= 1;
    try std.testing.expectError(
        error.NonCanonicalMachineResult,
        execution_trace.generate(std.testing.allocator, &bad_mapper),
    );
    var disconnected_mapper = results;
    disconnected_mapper[1].mapper_before.rom_bank_register +%= 1;
    disconnected_mapper[1].mapper_after.rom_bank_register +%= 1;
    disconnected_mapper[1].instruction.?.accesses[0].?.mapper_before
        .rom_bank_register +%= 1;
    disconnected_mapper[1].instruction.?.accesses[0].?.mapper_after
        .rom_bank_register +%= 1;
    try std.testing.expect(disconnected_mapper[1].hasCanonicalShape());
    try std.testing.expectError(
        error.DisconnectedMapperState,
        execution_trace.generate(std.testing.allocator, &disconnected_mapper),
    );
    try std.testing.expectError(
        error.NonCanonicalExecutionClock,
        execution_trace.generateAt(
            std.testing.allocator,
            &results,
            @import("stwo_core").fields.m31.Modulus - 16,
        ),
    );
}

fn expectHaltRow(
    result: machine.CartridgeStepResult,
    mcycle: u32,
) !void {
    try std.testing.expect(
        result.event == .halt_idle or result.event == .halt_wake,
    );
    const input = try execution_input.fromCartridgeMachine(result);
    const columns = try execution_input.cartridgeExecutionColumns(input, mcycle);
    const bus = 2 * execution.N_STATE_COLUMNS;
    try std.testing.expectEqual(M31.zero(), columns[bus]);
    try std.testing.expectEqual(M31.zero(), columns[bus + 1]);
    try std.testing.expectEqual(M31.one(), columns[bus + 2]);
    try std.testing.expectEqual(M31.zero(), columns[bus + 3]);
    try std.testing.expectEqual(M31.zero(), columns[bus + 4]);
    try std.testing.expectEqual(M31.zero(), columns[bus + 5]);
    const boundary = execution.Boundary{
        .cpu = result.before.cpu,
        .mcycle = mcycle,
    };
    const final = execution.Boundary{
        .cpu = result.after.cpu,
        .mcycle = mcycle + 1,
    };
    try std.testing.expect(
        (try execution.evaluate(
            columns,
            columns,
            true,
            true,
            boundary,
            final,
        )).allZero(),
    );
}

fn expectServiceRow(
    result: machine.CartridgeStepResult,
    mcycle: u32,
) !void {
    const input = try execution_input.fromCartridgeMachine(result);
    const columns = try execution_input.cartridgeExecutionColumns(
        input,
        mcycle,
    );
    const bus = 2 * execution.N_STATE_COLUMNS;
    const offset: usize = if (result.before.cpu.halted) 1 else 0;
    try std.testing.expectEqual(M31.one(), columns[bus + 2]);
    try std.testing.expectEqual(
        M31.one(),
        columns[bus + offset * execution.N_BUS_COLUMNS + 3],
    );
    for ([_]usize{ offset + 1, offset + 2 }) |cycle| {
        const at = bus + cycle * execution.N_BUS_COLUMNS;
        try std.testing.expectEqual(M31.one(), columns[at + 2]);
        try std.testing.expectEqual(M31.zero(), columns[at + 3]);
        try std.testing.expectEqual(M31.zero(), columns[at + 4]);
    }
    for ([_]usize{ offset + 3, offset + 4 }) |cycle| {
        const at = bus + cycle * execution.N_BUS_COLUMNS;
        try std.testing.expectEqual(M31.one(), columns[at + 4]);
    }
    try std.testing.expect(
        (try execution.evaluate(
            columns,
            columns,
            true,
            true,
            .{ .cpu = result.before.cpu, .mcycle = mcycle },
            .{
                .cpu = result.after.cpu,
                .mcycle = mcycle + result.m_cycles,
            },
        )).allZero(),
    );
}

fn expectRejected(
    forged: [execution.N_MAIN_COLUMNS]M31,
    honest: [execution.N_MAIN_COLUMNS]M31,
    result: machine.CartridgeStepResult,
    mcycle: u32,
) !void {
    try std.testing.expect(
        !(try execution.evaluate(
            forged,
            honest,
            true,
            true,
            .{ .cpu = result.before.cpu, .mcycle = mcycle },
            .{ .cpu = result.after.cpu, .mcycle = mcycle + 1 },
        )).allZero(),
    );
}

test {
    _ = @import("air/execution.zig");
    _ = @import("air/execution_input.zig");
    _ = @import("air/execution_trace.zig");
}
