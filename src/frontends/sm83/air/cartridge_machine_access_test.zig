const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const machine = @import("../runner/machine.zig");
const runner = @import("../runner/mod.zig");
const subject = @import("cartridge_machine_access.zig");
const cartridge_access = @import("cartridge_access.zig");
const rom_lookup = @import("cartridge_rom_lookup.zig");

test "machine access projects canonical HALT idle and wake cycles" {
    const idle = haltResult(.halt_idle, false);
    const wake = haltResult(.halt_wake, true);
    for ([_]machine.CartridgeStepResult{ idle, wake }) |result| {
        const step = try subject.ValidatedStep.init(result);
        try std.testing.expectEqual(@as(u3, 1), step.count);
        try std.testing.expectEqual(runner.BusAction.idle, step.cycles[0].bus.action);
        try std.testing.expect(step.cycles[0].access == null);
        const columns = subject.columnsForCycle(step, 0);
        try std.testing.expect(
            (try cartridge_access.evaluate(&columns, M31.one())).allZero(),
        );
        const packed_columns = subject.columns(step);
        const tail =
            packed_columns[cartridge_access.N_MAIN_COLUMNS..];
        for (tail) |value| try std.testing.expect(value.isZero());
    }
}

test "machine access preserves instruction bus and mapper endpoints" {
    const result = instructionResult();
    const step = try subject.ValidatedStep.init(result);
    try std.testing.expectEqual(@as(u3, 1), step.count);
    try std.testing.expectEqual(
        runner.BusAction.read,
        step.cycles[0].bus.action,
    );
    try std.testing.expectEqual(@as(u16, 0xc000), step.cycles[0].bus.address);
    try std.testing.expectEqualDeep(
        result.mapper_before,
        step.cycles[0].mapper_before,
    );
    try std.testing.expectEqualDeep(
        result.mapper_after,
        step.cycles[0].mapper_after,
    );
    const columns = subject.columnsForCycle(step, 0);
    try std.testing.expect(
        (try cartridge_access.evaluate(&columns, M31.one())).allZero(),
    );

    var forged = result;
    forged.instruction.?.accesses[0].?.logical_address = 0xc001;
    try std.testing.expectError(
        error.InvalidSchedulerStep,
        subject.ValidatedStep.init(forged),
    );
}

test "machine access projects pinned SameBoy service bus order" {
    const result = serviceResult();
    try std.testing.expect(result.hasCanonicalShape());
    const step = try subject.ValidatedStep.init(result);
    try std.testing.expectEqual(@as(u3, 5), step.count);
    const actions = [_]runner.BusAction{
        .read,
        .idle,
        .idle,
        .write,
        .write,
    };
    for (step.activeCycles(), actions, 0..) |cycle, action, index| {
        try std.testing.expectEqual(action, cycle.bus.action);
        const columns = subject.columnsForCycle(step, index);
        try std.testing.expect(
            (try cartridge_access.evaluate(&columns, M31.one())).allZero(),
        );
    }
    try std.testing.expectEqual(
        result.before.cpu.pc,
        step.cycles[0].bus.address,
    );
    try std.testing.expectEqual(
        result.before.cpu.sp -% 1,
        step.cycles[3].bus.address,
    );
    try std.testing.expectEqual(
        result.before.cpu.sp -% 2,
        step.cycles[4].bus.address,
    );
    var forged = result;
    forged.service.cycles[0].access.?.mapper_after.rom_bank_register = 2;
    try std.testing.expectError(
        error.InvalidSchedulerStep,
        subject.ValidatedStep.init(forged),
    );
}

test "machine access rejects relabelled scheduler events" {
    var forged = haltResult(.halt_idle, false);
    forged.event = .halt_wake;
    try std.testing.expectError(
        error.InvalidSchedulerStep,
        subject.ValidatedStep.init(forged),
    );
}

test "ROM lookup consumes the canonical machine access projection" {
    var result = instructionResult();
    result.instruction.?.instruction.cycles[0] = .{
        .address = 0x1234,
        .value = 0xab,
        .action = .read,
    };
    result.instruction.?.accesses[0] = .{
        .logical_address = 0x1234,
        .action = .read,
        .region = .cartridge_rom,
        .physical_offset = 0x1234,
        .mapper_before = result.mapper_before,
        .mapper_after = result.mapper_after,
        .value = 0xab,
    };
    const columns = try rom_lookup.columnsFromStep(result);
    const row = try rom_lookup.Row(M31).fromColumns(&columns);
    try std.testing.expectEqual(
        @as(u32, 0x1234),
        row.accesses[0].offset().toU32(),
    );
    try std.testing.expectEqual(
        @as(u32, 0xab),
        row.accesses[0].value().toU32(),
    );
    try std.testing.expect(!row.accesses[0].active.isZero());
    for (row.accesses[1..]) |item|
        try std.testing.expect(item.active.isZero());
}

fn instructionResult() machine.CartridgeStepResult {
    const mapper = @import("../cartridge/mbc3.zig").State{};
    var trace = std.mem.zeroes(runner.CartridgeStepTrace);
    trace.instruction.cycle_count = 1;
    trace.instruction.cycles[0] = .{
        .address = 0xc000,
        .value = 0,
        .action = .read,
    };
    trace.accesses[0] = .{
        .logical_address = 0xc000,
        .action = .read,
        .region = .system,
        .physical_offset = null,
        .mapper_before = mapper,
        .mapper_after = mapper,
        .value = 0,
    };
    return .{
        .before = state(trace.instruction.before, 0),
        .after = state(trace.instruction.after, 0),
        .event = .instruction,
        .m_cycles = 1,
        .instruction = trace,
        .mapper_before = mapper,
        .mapper_after = mapper,
    };
}

fn serviceResult() machine.CartridgeStepResult {
    const mapper = @import("../cartridge/mbc3.zig").State{};
    const before = state(
        .{ .pc = 0xc000, .sp = 0xc100, .ime = true },
        1,
    );
    var after = state(.{ .pc = 0x40, .sp = 0xc0fe }, 0);
    after.interrupt_enable = 1;
    return .{
        .before = before,
        .after = after,
        .event = .interrupt_service,
        .m_cycles = 5,
        .interrupt_index = 0,
        .service = .{
            .cycles = .{
                .{ .kind = .dummy_read, .access = access(
                    before.cpu.pc,
                    .read,
                    0,
                    mapper,
                ) },
                .{ .kind = .oam_bug },
                .{ .kind = .no_access },
                .{ .kind = .stack_high, .access = access(
                    before.cpu.sp -% 1,
                    .write,
                    @truncate(before.cpu.pc >> 8),
                    mapper,
                ) },
                .{ .kind = .stack_low, .access = access(
                    before.cpu.sp -% 2,
                    .write,
                    @truncate(before.cpu.pc),
                    mapper,
                ) },
                .{},
            },
            .count = 5,
            .ie_resample = .{ .after_cycle = 3, .value = 1 },
            .if_resample = .{ .after_cycle = 4, .value = 1 },
            .acknowledgement = .{
                .during_cycle = 4,
                .index = 0,
                .before = 1,
                .after = 0,
            },
        },
        .mapper_before = mapper,
        .mapper_after = mapper,
    };
}

fn access(
    address: u16,
    action: runner.cartridge_memory.Action,
    value: u8,
    mapper: @import("../cartridge/mbc3.zig").State,
) runner.cartridge_memory.Access {
    return .{
        .logical_address = address,
        .action = action,
        .region = .system,
        .physical_offset = null,
        .mapper_before = mapper,
        .mapper_after = mapper,
        .value = value,
    };
}

fn haltResult(
    event: machine.SchedulerEvent,
    wake: bool,
) machine.CartridgeStepResult {
    var after_cpu = runner.Cpu{ .halted = true };
    after_cpu.halted = !wake;
    return .{
        .before = state(.{ .halted = true }, if (wake) 1 else 0),
        .after = state(after_cpu, if (wake) 1 else 0),
        .event = event,
        .m_cycles = 1,
    };
}

fn state(cpu: runner.Cpu, interrupt: u8) machine.MachineState {
    return .{
        .cpu = cpu,
        .halt_bug = false,
        .div_counter = 0,
        .tima = 0,
        .tma = 0,
        .tac = 0,
        .timer_reload = .running,
        .interrupt_flags = interrupt,
        .interrupt_enable = interrupt,
    };
}
