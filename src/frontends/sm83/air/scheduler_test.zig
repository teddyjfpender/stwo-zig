//! Degree, semantic, and adversarial controls for the scheduler.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const cartridge = @import("../cartridge/mod.zig");
const runner = @import("../runner/mod.zig");
const machine = @import("../runner/machine.zig");
const subject = @import("scheduler.zig");

const EVENT_OFFSET: usize = 0;
const INTERRUPT_OFFSET: usize = EVENT_OFFSET + 4;
const IE_OFFSET: usize = INTERRUPT_OFFSET + 5;
const IF_OFFSET: usize = IE_OFFSET + 5;
const QUEUE_OFFSET: usize = IF_OFFSET + 5;
const QUEUE_NONZERO_OFFSET: usize = QUEUE_OFFSET + 5;
const QUEUE_INVERSE_OFFSET: usize = QUEUE_NONZERO_OFFSET + 1;
const POST_IF_OFFSET: usize = QUEUE_INVERSE_OFFSET + 1;
const POST_QUEUE_OFFSET: usize = POST_IF_OFFSET + 5;
const POST_QUEUE_NONZERO_OFFSET: usize = POST_QUEUE_OFFSET + 5;
const POST_QUEUE_INVERSE_OFFSET: usize = POST_QUEUE_NONZERO_OFFSET + 1;
const EFFECTIVE_IME_OFFSET: usize = POST_QUEUE_INVERSE_OFFSET + 1;
const BEFORE_IME_OFFSET: usize = EFFECTIVE_IME_OFFSET + 1;
const BEFORE_PENDING_OFFSET: usize = BEFORE_IME_OFFSET + 1;
const BEFORE_HALTED_OFFSET: usize = BEFORE_PENDING_OFFSET + 1;
const BEFORE_HALT_BUG_OFFSET: usize = BEFORE_HALTED_OFFSET + 1;
const AFTER_IME_OFFSET: usize = BEFORE_HALT_BUG_OFFSET + 1;
const AFTER_PENDING_OFFSET: usize = AFTER_IME_OFFSET + 1;
const AFTER_HALTED_OFFSET: usize = AFTER_PENDING_OFFSET + 1;
const AFTER_HALT_BUG_OFFSET: usize = AFTER_HALTED_OFFSET + 1;
const MCYCLE_OFFSET: usize = AFTER_HALT_BUG_OFFSET + 1;
const MCYCLE_LOW_ZERO_OFFSET: usize = MCYCLE_OFFSET + 3;
const MCYCLE_LOW_ONE_OFFSET: usize = MCYCLE_LOW_ZERO_OFFSET + 1;

test "scheduler geometry is cubic and L plus one ready" {
    try std.testing.expectEqual(@as(usize, 52), subject.N_MAIN_COLUMNS);
    try std.testing.expectEqual(@as(usize, 149), subject.N_CONSTRAINTS);
    const variables =
        [_]Degree{Degree.variable()} ** subject.N_MAIN_COLUMNS;
    const semantics = subject.Semantics(Degree);
    const row = try semantics.Row.fromColumns(&variables);
    const evaluation = semantics.evaluate(row, Degree.variable());
    var maximum: u32 = 0;
    for (evaluation.values) |value| maximum = @max(maximum, value.value);
    try std.testing.expectEqual(@as(u32, 3), maximum);
}

test "scheduler accepts every event timer state and HALT bug shape" {
    const results = [_]machine.StepResult{
        try schedulerResult(.{}, 0, 0),
        try schedulerResult(
            .{ .halted = true, .ime_enable_pending = true },
            0,
            0,
        ),
        try schedulerResult(
            .{ .halted = true, .ime_enable_pending = true },
            1,
            1,
        ),
        try schedulerResult(
            .{ .ime = true, .sp = 0xc000, .pc = 0x1234 },
            1,
            1,
        ),
        try schedulerResult(
            .{ .halted = true, .ime = true, .sp = 0xc000, .pc = 0x1234 },
            1,
            1,
        ),
    };
    const expected = [_]machine.SchedulerEvent{
        .instruction,
        .halt_idle,
        .halt_wake,
        .interrupt_service,
        .interrupt_service,
    };
    for (results, expected) |result, event_kind| {
        try std.testing.expectEqual(event_kind, result.event);
        try expectHonest(result);
    }
    try std.testing.expectEqual(@as(u3, 5), results[3].m_cycles);
    try std.testing.expectEqual(@as(u3, 6), results[4].m_cycles);

    const timed = [_]machine.StepResult{
        try timerSchedulerResult(.{}, 0, 0),
        try timerSchedulerResult(.{ .halted = true }, 0, 0),
        try timerSchedulerResult(.{ .halted = true }, 1, 1),
        try timerSchedulerResult(
            .{ .ime = true, .sp = 0xc000 },
            1,
            1,
        ),
        try timerSchedulerResult(
            .{ .halted = true, .ime = true, .sp = 0xc000 },
            1,
            1,
        ),
    };
    for (timed) |result| {
        try std.testing.expect(result.before.tac & 0x04 != 0);
        try expectHonest(result);
    }

    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.write(0, 0x76);
    memory.write(1, 0);
    memory.write(0xffff, 1);
    memory.write(0xff0f, 1);
    var scheduler_machine = machine.Machine.init(&memory, .{});
    const trigger = try scheduler_machine.step();
    try std.testing.expect(trigger.after.halt_bug);
    try expectHonest(trigger);
    const consume = try scheduler_machine.step();
    try std.testing.expect(consume.before.halt_bug);
    try std.testing.expect(!consume.after.halt_bug);
    try expectHonest(consume);
}

test "new clock products and queue inverse reject both witness branches" {
    const one_cycle = subject.columns(try subject.ValidatedStep.init(
        try schedulerResult(.{}, 0, 0),
    ));
    const three_cycle = subject.columns(try subject.ValidatedStep.init(
        try programResult(.{}, 0, 0, &.{ 0x01, 0, 0 }),
    ));
    const four_cycle = subject.columns(try subject.ValidatedStep.init(
        try programResult(.{}, 0, 0, &.{ 0xc3, 0, 0 }),
    ));
    try std.testing.expectEqual(@as(u3, 3), try mcycles(three_cycle));
    try std.testing.expectEqual(@as(u3, 4), try mcycles(four_cycle));
    try expectMutation(one_cycle, MCYCLE_LOW_ZERO_OFFSET);
    try expectMutation(four_cycle, MCYCLE_LOW_ZERO_OFFSET);
    try expectMutation(one_cycle, MCYCLE_LOW_ONE_OFFSET);
    try expectMutation(three_cycle, MCYCLE_LOW_ONE_OFFSET);
    try expectMutation(one_cycle, QUEUE_INVERSE_OFFSET);
    try expectMutation(one_cycle, POST_QUEUE_INVERSE_OFFSET);

    const queued = subject.columns(try subject.ValidatedStep.init(
        try schedulerResult(.{ .ime = true, .sp = 0xc000 }, 1, 1),
    ));
    try expectMutation(queued, QUEUE_INVERSE_OFFSET);
    try expectMutation(queued, POST_QUEUE_INVERSE_OFFSET);
}

test "every inactive scheduler column is forced to zero" {
    const inactive = [_]M31{M31.zero()} ** subject.N_MAIN_COLUMNS;
    try std.testing.expect((try subject.evaluate(inactive, false)).allZero());
    for (0..subject.N_MAIN_COLUMNS) |column| {
        var forged = inactive;
        forged[column] = M31.one();
        try std.testing.expect(!(try subject.evaluate(forged, false)).allZero());
    }
}

test "scheduler rejects event queue priority and state mutations" {
    const wake = subject.columns(try subject.ValidatedStep.init(
        try schedulerResult(.{ .halted = true }, 1, 1),
    ));
    for ([_]usize{
        IE_OFFSET,
        IF_OFFSET,
        QUEUE_OFFSET,
        QUEUE_NONZERO_OFFSET,
        POST_IF_OFFSET,
        POST_QUEUE_OFFSET,
        POST_QUEUE_NONZERO_OFFSET,
        EFFECTIVE_IME_OFFSET,
        BEFORE_HALTED_OFFSET,
    }) |column| try expectMutation(wake, column);

    var forged = wake;
    forged[EVENT_OFFSET + @intFromEnum(machine.SchedulerEvent.halt_wake)] =
        M31.zero();
    forged[EVENT_OFFSET + @intFromEnum(machine.SchedulerEvent.halt_idle)] =
        M31.one();
    try expectRejected(forged);
    forged = wake;
    @memset(forged[EVENT_OFFSET..INTERRUPT_OFFSET], M31.zero());
    try expectRejected(forged);

    const service = subject.columns(try subject.ValidatedStep.init(
        try schedulerResult(.{ .ime = true, .sp = 0xc000 }, 3, 3),
    ));
    forged = service;
    forged[INTERRUPT_OFFSET] = M31.zero();
    forged[INTERRUPT_OFFSET + 1] = M31.one();
    try expectRejected(forged);

    const idle = subject.columns(try subject.ValidatedStep.init(
        try schedulerResult(
            .{ .halted = true, .ime_enable_pending = true },
            0,
            0,
        ),
    ));
    for ([_]usize{
        BEFORE_IME_OFFSET,
        BEFORE_PENDING_OFFSET,
        BEFORE_HALT_BUG_OFFSET,
        AFTER_IME_OFFSET,
        AFTER_PENDING_OFFSET,
        AFTER_HALTED_OFFSET,
        AFTER_HALT_BUG_OFFSET,
    }) |column| try expectMutation(idle, column);
}

test "scheduler accepts an authenticated interrupt raised during HALT" {
    var wake = try schedulerResult(.{ .halted = true, .ime = true }, 1, 0);
    wake.event = .halt_wake;
    wake.after.cpu.halted = false;
    wake.after.interrupt_flags = 1;
    try std.testing.expect(wake.hasCanonicalShape());
    try expectHonest(wake);

    const honest = subject.columns(try subject.ValidatedStep.init(wake));
    try expectMutation(honest, POST_IF_OFFSET);
    try expectMutation(honest, POST_QUEUE_OFFSET);
    try expectMutation(honest, POST_QUEUE_INVERSE_OFFSET);

    var stale = wake;
    stale.after.interrupt_flags = 0;
    try expectValidationRejection(stale);
}

test "scheduler rejects forbidden and event-specific cycle counts" {
    var instruction = subject.columns(try subject.ValidatedStep.init(
        try schedulerResult(.{}, 0, 0),
    ));
    setMcycles(&instruction, 0);
    try expectRejected(instruction);
    setMcycles(&instruction, 7);
    try expectRejected(instruction);

    var service = subject.columns(try subject.ValidatedStep.init(
        try schedulerResult(
            .{ .halted = true, .ime = true, .sp = 0xc000 },
            1,
            1,
        ),
    ));
    setMcycles(&service, 5);
    try expectRejected(service);
}

test "scheduler validation rejects non-scheduler boundaries" {
    var cancelled =
        try schedulerResult(.{ .ime = true, .sp = 0xc000 }, 1, 1);
    cancelled.interrupt_index = null;
    cancelled.after.cpu.pc = 0;
    try std.testing.expect(cancelled.hasCanonicalShape());
    try expectHonest(cancelled);

    var stopped = try schedulerResult(.{}, 0, 0);
    stopped.before.cpu.stopped = true;
    try expectValidationRejection(stopped);

    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.write(0, 0x76);
    memory.write(0xffff, 1);
    memory.write(0xff0f, 1);
    var scheduler = machine.Machine.init(
        &memory,
        .{ .ime_enable_pending = true },
    );
    try expectHonest(try scheduler.step());
}

test "scheduler separates initial dispatch from resampled cartridge service" {
    const cancelled = try cartridgeServiceResult(0);
    try std.testing.expectEqual(
        machine.SchedulerEvent.interrupt_service,
        cancelled.event,
    );
    try std.testing.expectEqual(@as(?u3, null), cancelled.interrupt_index);
    try expectHonest(cancelled);

    const reprioritized = try cartridgeServiceResult(0x0200);
    try std.testing.expectEqual(@as(?u3, 1), reprioritized.interrupt_index);
    const witness = subject.columns(
        try subject.ValidatedStep.init(reprioritized),
    );
    try std.testing.expectEqual(M31.one(), witness[INTERRUPT_OFFSET]);
    try std.testing.expect(witness[INTERRUPT_OFFSET + 1].isZero());
    try std.testing.expect((try subject.evaluate(witness, true)).allZero());

    var forged = reprioritized;
    forged.service.ie_resample.?.value ^= 1;
    try std.testing.expectError(
        error.NotSchedulerStep,
        subject.ValidatedStep.init(forged),
    );
}

fn schedulerResult(
    cpu: runner.Cpu,
    ie: u8,
    interrupt_flags: u8,
) !machine.StepResult {
    return programResult(cpu, ie, interrupt_flags, &.{0x00});
}

fn programResult(
    cpu: runner.Cpu,
    ie: u8,
    interrupt_flags: u8,
    program: []const u8,
) !machine.StepResult {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    for (program, 0..) |byte, address| memory.write(@intCast(address), byte);
    memory.write(0xffff, ie);
    memory.write(0xff0f, interrupt_flags);
    var scheduler = machine.Machine.init(&memory, cpu);
    return scheduler.step();
}

fn timerSchedulerResult(
    cpu: runner.Cpu,
    ie: u8,
    interrupt_flags: u8,
) !machine.StepResult {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.write(0, 0);
    memory.write(0xffff, ie);
    memory.write(0xff0f, interrupt_flags);
    memory.write(0xff07, 0x05);
    var scheduler_machine = machine.Machine.init(&memory, cpu);
    scheduler_machine.timer.div_counter = 8;
    return scheduler_machine.step();
}

fn expectHonest(result: anytype) !void {
    const witness = subject.columns(try subject.ValidatedStep.init(result));
    try std.testing.expect((try subject.evaluate(witness, true)).allZero());
}

fn cartridgeServiceResult(pc: u16) !machine.CartridgeStepResult {
    const allocator = std.testing.allocator;
    const rom = try allocator.create([cartridge.header.ROM_SIZE]u8);
    defer allocator.destroy(rom);
    const sram = try allocator.create([cartridge.header.RAM_SIZE]u8);
    defer allocator.destroy(sram);
    const system = try allocator.create(
        [runner.cartridge_memory.SYSTEM_SIZE]u8,
    );
    defer allocator.destroy(system);
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
    var memory = runner.cartridge_memory.Memory.init(
        try cartridge.Cartridge.init(rom),
        sram,
        system,
        .{},
        0xff,
    );
    system[0xffff] = 3;
    system[0xff0f] = 3;
    var scheduler_machine = try machine.CartridgeMachine.init(
        &memory,
        .{ .ime = true, .sp = 0, .pc = pc },
    );
    return scheduler_machine.step();
}

fn expectMutation(
    honest: [subject.N_MAIN_COLUMNS]M31,
    column: usize,
) !void {
    var forged = honest;
    forged[column] = flip(forged[column]);
    try expectRejected(forged);
}

fn expectRejected(values: [subject.N_MAIN_COLUMNS]M31) !void {
    try std.testing.expect(!(try subject.evaluate(values, true)).allZero());
}

fn expectValidationRejection(result: machine.StepResult) !void {
    try std.testing.expectError(
        error.NotSchedulerStep,
        subject.ValidatedStep.init(result),
    );
}

fn setMcycles(values: *[subject.N_MAIN_COLUMNS]M31, value: u3) void {
    for (values[MCYCLE_OFFSET..MCYCLE_LOW_ZERO_OFFSET], 0..) |*bit, index|
        bit.* = M31.fromCanonical(value >> @intCast(index) & 1);
    const low = value & 0x3;
    values[MCYCLE_LOW_ZERO_OFFSET] =
        M31.fromCanonical(@intFromBool(low == 0));
    values[MCYCLE_LOW_ONE_OFFSET] =
        M31.fromCanonical(@intFromBool(low == 3));
}

fn mcycles(values: [subject.N_MAIN_COLUMNS]M31) !u3 {
    var result: u3 = 0;
    for (values[MCYCLE_OFFSET..MCYCLE_LOW_ZERO_OFFSET], 0..) |bit, index|
        result |= @as(u3, @intCast(bit.toU32())) << @intCast(index);
    return result;
}

fn flip(value: M31) M31 {
    return if (value.isZero()) M31.one() else M31.zero();
}

const Degree = struct {
    value: u32,

    fn variable() Degree {
        return .{ .value = 1 };
    }

    pub fn zero() Degree {
        return .{ .value = 0 };
    }

    pub fn one() Degree {
        return .{ .value = 0 };
    }

    pub fn fromBase(_: M31) Degree {
        return .{ .value = 0 };
    }

    pub fn add(left: Degree, right: Degree) Degree {
        return .{ .value = @max(left.value, right.value) };
    }

    pub fn sub(left: Degree, right: Degree) Degree {
        return add(left, right);
    }

    pub fn mul(left: Degree, right: Degree) Degree {
        return .{ .value = left.value + right.value };
    }

    pub fn isZero(_: Degree) bool {
        return false;
    }
};
