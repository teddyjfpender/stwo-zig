const std = @import("std");
const action_schedule = @import("action_schedule.zig");
const trace_builder = @import("joypad_trace.zig");
const runner = @import("runner/mod.zig");
const machine = @import("runner/machine.zig");

const joypad = runner.joypad;
const memory = runner.cartridge_memory;

test "joypad trace pins action write read tick ordering and final state" {
    const actions = [_]action_schedule.Action{
        .{ .mcycle = 100, .pressed = joypad.Key.a.mask() },
        .{
            .mcycle = 101,
            .pressed = joypad.Key.a.mask() |
                joypad.Key.right.mask(),
        },
    };
    const mapper = @import("cartridge/mbc3.zig").State{};
    const steps = [_]runner.CartridgeStepTrace{
        plainStep(mapper),
        accessStep(mapper, .write, .joypad_mmio, 0x10),
        accessStep(mapper, .read, .joypad_mmio, 0xde),
    };
    var trace = try trace_builder.generate(
        std.testing.allocator,
        100,
        103,
        .{},
        &actions,
        &steps,
    );
    defer trace.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 6), trace.rows.len);
    try expectAction(trace.rows[0], 100, 0);
    try expectTick(trace.rows[1], 100, 0, 0);
    try expectAction(trace.rows[2], 101, 1);
    try expectWrite(trace.rows[3], 101, 1, 0, 0x10);
    try expectTick(trace.rows[4], 101, 1, 0);
    try expectTick(trace.rows[5], 102, 2, 0);
    try std.testing.expect(trace.rows[0].transition.interrupt_requested);
    try std.testing.expect(!trace.rows[2].transition.interrupt_requested);
    try std.testing.expect(!trace.rows[3].transition.interrupt_requested);
    try std.testing.expectEqual(
        @as(u8, 0xde),
        trace.rows[3].transition.p1_read,
    );
    try std.testing.expectEqual(@as(u32, 103), trace.final_mcycle);
    try std.testing.expectEqual(@as(u8, 0x11), trace.final_state.pressed);
    try std.testing.expectEqual(@as(u8, 0xde), trace.final_state.readP1());
    try std.testing.expectEqual(@as(u8, 32), trace.final_state.switching_delay);
    for (trace.rows[0 .. trace.rows.len - 1], trace.rows[1..]) |
        before,
        after,
    | try std.testing.expectEqualDeep(
        before.transition.after,
        after.transition.before,
    );
}

test "joypad trace accepts an empty schedule with held initial buttons" {
    var initial = joypad.State{};
    _ = initial.setPressed(joypad.Key.start.mask());
    const mapper = @import("cartridge/mbc3.zig").State{};
    const steps = [_]runner.CartridgeStepTrace{plainStep(mapper)};
    var trace = try trace_builder.generate(
        std.testing.allocator,
        7,
        8,
        initial,
        &.{},
        &steps,
    );
    defer trace.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), trace.rows.len);
    try std.testing.expectEqual(
        joypad.Key.start.mask(),
        trace.final_state.pressed,
    );
}

test "joypad trace rejects schedule and time mismatches" {
    const mapper = @import("cartridge/mbc3.zig").State{};
    const one = [_]runner.CartridgeStepTrace{plainStep(mapper)};
    try std.testing.expectError(
        error.NonIncreasingActionTime,
        trace_builder.generate(
            std.testing.allocator,
            10,
            11,
            .{},
            &.{
                .{ .mcycle = 10, .pressed = 1 },
                .{ .mcycle = 10, .pressed = 2 },
            },
            &one,
        ),
    );
    try std.testing.expectError(
        error.NonIncreasingActionTime,
        trace_builder.generate(
            std.testing.allocator,
            10,
            12,
            .{},
            &.{
                .{ .mcycle = 11, .pressed = 1 },
                .{ .mcycle = 10, .pressed = 2 },
            },
            &.{
                plainStep(mapper),
                plainStep(mapper),
            },
        ),
    );
    try std.testing.expectError(
        error.ActionOutOfSegment,
        trace_builder.generate(
            std.testing.allocator,
            10,
            11,
            .{},
            &.{.{ .mcycle = 11, .pressed = 1 }},
            &one,
        ),
    );
    try std.testing.expectError(
        error.FinalMcycleMismatch,
        trace_builder.generate(
            std.testing.allocator,
            10,
            12,
            .{},
            &.{.{ .mcycle = 11, .pressed = 1 }},
            &one,
        ),
    );

    const two = [_]runner.CartridgeStepTrace{
        plainStep(mapper),
        plainStep(mapper),
    };
    try std.testing.expectError(
        error.FinalMcycleMismatch,
        trace_builder.generate(
            std.testing.allocator,
            10,
            11,
            .{},
            &.{},
            &two,
        ),
    );
    try std.testing.expectError(
        error.TimeOverflow,
        trace_builder.generate(
            std.testing.allocator,
            std.math.maxInt(u32) - 1,
            std.math.maxInt(u32),
            .{},
            &.{},
            &two,
        ),
    );
}

test "joypad trace rejects forged MMIO metadata and values" {
    const mapper = @import("cartridge/mbc3.zig").State{};
    const actions = [_]action_schedule.Action{
        .{ .mcycle = 20, .pressed = joypad.Key.a.mask() },
    };

    var metadata = accessStep(
        mapper,
        .read,
        .joypad_mmio,
        0xce,
    );
    metadata.accesses[0].?.region = .system;
    try std.testing.expectError(
        error.InvalidExecutionStep,
        trace_builder.generate(
            std.testing.allocator,
            20,
            21,
            .{},
            &actions,
            &.{metadata},
        ),
    );

    const forged_value = accessStep(
        mapper,
        .read,
        .joypad_mmio,
        0xcf,
    );
    try std.testing.expectError(
        error.InvalidJoypadReadValue,
        trace_builder.generate(
            std.testing.allocator,
            20,
            21,
            .{},
            &actions,
            &.{forged_value},
        ),
    );

    var malformed = forged_value;
    malformed.instruction.cycles[0].value ^= 1;
    try std.testing.expectError(
        error.InvalidExecutionStep,
        trace_builder.generate(
            std.testing.allocator,
            20,
            21,
            .{},
            &actions,
            &.{malformed},
        ),
    );
}

test "joypad trace rejects invalid initial state and execution step" {
    const mapper = @import("cartridge/mbc3.zig").State{};
    const one = [_]runner.CartridgeStepTrace{plainStep(mapper)};
    try std.testing.expectError(
        error.InvalidHighBits,
        trace_builder.generate(
            std.testing.allocator,
            0,
            1,
            .{ .p1 = 0x0f },
            &.{},
            &one,
        ),
    );

    var invalid = plainStep(mapper);
    invalid.instruction.cycle_count = 0;
    try std.testing.expectError(
        error.InvalidExecutionStep,
        trace_builder.generate(
            std.testing.allocator,
            0,
            1,
            .{},
            &.{},
            &.{invalid},
        ),
    );
}

test "joypad machine trace binds action instruction HALT and wake cycles" {
    const instruction = instructionResult(
        accessStep(.{}, .write, .joypad_mmio, 0x10),
        0,
        0,
    );
    const actions = [_]action_schedule.Action{
        .{ .mcycle = 40, .pressed = joypad.Key.a.mask() },
    };
    var trace = try trace_builder.generateFromMachineExecution(
        std.testing.allocator,
        40,
        41,
        .{},
        &actions,
        &.{instruction},
    );
    defer trace.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 3), trace.rows.len);
    try expectAction(trace.rows[0], 40, 0);
    try expectWrite(trace.rows[1], 40, 0, 0, 0x10);
    try expectTick(trace.rows[2], 40, 0, 0);

    const idle = haltResult(.halt_idle, 0, 0, 0);
    var idle_trace = try trace_builder.generateFromMachineExecution(
        std.testing.allocator,
        41,
        42,
        trace.final_state,
        &.{},
        &.{idle},
    );
    defer idle_trace.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), idle_trace.rows.len);
    try expectTick(idle_trace.rows[0], 41, 0, 0);

    const wake = haltResult(.halt_wake, 4, 1, 1);
    var wake_trace = try trace_builder.generateFromMachineExecution(
        std.testing.allocator,
        42,
        43,
        idle_trace.final_state,
        &.{},
        &.{wake},
    );
    defer wake_trace.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), wake_trace.rows.len);
    try expectTick(wake_trace.rows[0], 42, 0, 0);
}

test "joypad machine trace rejects scheduler and chain mutations" {
    var idle = haltResult(.halt_idle, 0, 0, 0);
    idle.m_cycles = 2;
    try std.testing.expectError(
        error.InvalidSchedulerStep,
        trace_builder.generateFromMachineExecution(
            std.testing.allocator,
            0,
            2,
            .{},
            &.{},
            &.{idle},
        ),
    );

    const first = haltResult(.halt_idle, 0, 0, 0);
    var second = haltResult(.halt_idle, 4, 0, 0);
    second.before.cpu.a = 1;
    second.after.cpu.a = 1;
    try std.testing.expectError(
        error.DisconnectedMachineExecution,
        trace_builder.generateFromMachineExecution(
            std.testing.allocator,
            0,
            2,
            .{},
            &.{},
            &.{ first, second },
        ),
    );

    second = haltResult(.halt_idle, 4, 0, 0);
    second.mapper_before.rom_bank_register = 2;
    second.mapper_after = second.mapper_before;
    try std.testing.expectError(
        error.DisconnectedMapperExecution,
        trace_builder.generateFromMachineExecution(
            std.testing.allocator,
            0,
            2,
            .{},
            &.{},
            &.{ first, second },
        ),
    );
}

test "joypad machine trace schedules exact service-cycle P1 alias" {
    const service = joypadService(0x2345, 0xff02);
    try std.testing.expect(service.hasCanonicalShape());
    var trace = try trace_builder.generateFromMachineExecution(
        std.testing.allocator,
        70,
        75,
        .{},
        &.{},
        &.{service},
    );
    defer trace.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 6), trace.rows.len);
    try expectTick(trace.rows[0], 70, 0, 0);
    try expectTick(trace.rows[1], 71, 0, 1);
    try expectTick(trace.rows[2], 72, 0, 2);
    try expectTick(trace.rows[3], 73, 0, 3);
    try expectWrite(trace.rows[4], 74, 0, 4, 0x45);
    try expectTick(trace.rows[5], 74, 0, 4);

    var forged = service;
    forged.service.cycles[4].access.?.region = .system;
    try std.testing.expectError(
        error.InvalidJoypadMetadata,
        trace_builder.generateFromMachineExecution(
            std.testing.allocator,
            70,
            75,
            .{},
            &.{},
            &.{forged},
        ),
    );
}

fn joypadService(
    return_pc: u16,
    sp: u16,
) machine.CartridgeStepResult {
    const cpu = runner.Cpu{
        .pc = return_pc,
        .sp = sp,
        .ime = true,
    };
    var after_cpu = cpu;
    after_cpu.pc = 0x40;
    after_cpu.sp -%= 2;
    after_cpu.ime = false;
    var result = machine.CartridgeStepResult{
        .before = machineState(cpu, 0, 1, 1),
        .after = machineState(after_cpu, 20, 0, 1),
        .event = .interrupt_service,
        .m_cycles = 5,
        .interrupt_index = 0,
    };
    result.service.count = 5;
    result.service.cycles[0] = .{
        .kind = .dummy_read,
        .access = serviceAccess(return_pc, .read, 0),
    };
    result.service.cycles[1].kind = .oam_bug;
    result.service.cycles[2].kind = .no_access;
    result.service.cycles[3] = .{
        .kind = .stack_high,
        .access = serviceAccess(sp -% 1, .write, @truncate(return_pc >> 8)),
    };
    result.service.cycles[4] = .{
        .kind = .stack_low,
        .access = serviceAccess(sp -% 2, .write, @truncate(return_pc)),
    };
    result.service.ie_resample = .{ .after_cycle = 3, .value = 1 };
    result.service.if_resample = .{ .after_cycle = 4, .value = 1 };
    result.service.acknowledgement = .{
        .during_cycle = 4,
        .index = 0,
        .before = 1,
        .after = 0,
    };
    return result;
}

fn serviceAccess(
    address: u16,
    action: memory.Action,
    value: u8,
) memory.Access {
    return .{
        .logical_address = address,
        .action = action,
        .region = if (address == joypad.P1_ADDRESS)
            .joypad_mmio
        else if (address <= 0x3fff and action == .read)
            .cartridge_rom
        else
            .system,
        .physical_offset = if (address <= 0x3fff and action == .read)
            address
        else
            null,
        .mapper_before = .{},
        .mapper_after = .{},
        .value = value,
    };
}

fn haltResult(
    event: machine.SchedulerEvent,
    div_counter: u16,
    flags: u8,
    enable: u8,
) machine.CartridgeStepResult {
    const before = machineState(
        .{ .halted = true },
        div_counter,
        flags,
        enable,
    );
    var after = before;
    after.cpu.halted = event == .halt_idle;
    after.div_counter += 4;
    return .{
        .before = before,
        .after = after,
        .event = event,
        .m_cycles = 1,
    };
}

fn instructionResult(
    trace: runner.CartridgeStepTrace,
    flags: u8,
    enable: u8,
) machine.CartridgeStepResult {
    var instruction = trace;
    instruction.instruction.before = .{};
    instruction.instruction.after = .{};
    return .{
        .before = machineState(.{}, 0, flags, enable),
        .after = machineState(.{}, 4, flags, enable),
        .event = .instruction,
        .m_cycles = instruction.instruction.cycle_count,
        .instruction = instruction,
    };
}

fn machineState(
    cpu: runner.Cpu,
    div_counter: u16,
    flags: u8,
    enable: u8,
) machine.MachineState {
    return .{
        .cpu = cpu,
        .halt_bug = false,
        .div_counter = div_counter,
        .tima = 0,
        .tma = 0,
        .tac = 0,
        .timer_reload = .running,
        .interrupt_flags = flags,
        .interrupt_enable = enable,
    };
}

fn plainStep(mapper: @import("cartridge/mbc3.zig").State) runner.CartridgeStepTrace {
    var step: runner.CartridgeStepTrace = undefined;
    step.instruction.cycle_count = 1;
    step.instruction.cycles[0] = .{
        .address = 0xc000,
        .value = 0,
        .action = .read,
    };
    step.accesses = [_]?memory.Access{null} ** 6;
    step.accesses[0] = .{
        .logical_address = 0xc000,
        .action = .read,
        .region = .system,
        .physical_offset = null,
        .mapper_before = mapper,
        .mapper_after = mapper,
        .value = 0,
    };
    return step;
}

fn accessStep(
    mapper: @import("cartridge/mbc3.zig").State,
    action: memory.Action,
    region: memory.Region,
    value: u8,
) runner.CartridgeStepTrace {
    var step: runner.CartridgeStepTrace = undefined;
    step.instruction.cycle_count = 1;
    step.instruction.cycles[0] = .{
        .address = joypad.P1_ADDRESS,
        .value = value,
        .action = switch (action) {
            .read => .read,
            .write => .write,
        },
    };
    step.accesses = [_]?memory.Access{null} ** 6;
    step.accesses[0] = .{
        .logical_address = joypad.P1_ADDRESS,
        .action = action,
        .region = region,
        .physical_offset = null,
        .mapper_before = mapper,
        .mapper_after = mapper,
        .value = value,
    };
    return step;
}

fn expectAction(
    row: trace_builder.EventRow,
    mcycle: u32,
    index: u32,
) !void {
    try std.testing.expectEqual(mcycle, row.mcycle);
    try std.testing.expectEqual(index, row.provenance.action_index);
    try std.testing.expect(
        row.transition.event == .set_pressed,
    );
}

fn expectWrite(
    row: trace_builder.EventRow,
    mcycle: u32,
    execution_row: u32,
    cycle: u3,
    value: u8,
) !void {
    try std.testing.expectEqual(mcycle, row.mcycle);
    try std.testing.expectEqualDeep(
        trace_builder.ExecutionPosition{
            .execution_row = execution_row,
            .cycle = cycle,
        },
        row.provenance.execution_write,
    );
    try std.testing.expectEqual(
        value,
        row.transition.event.write_p1,
    );
}

fn expectTick(
    row: trace_builder.EventRow,
    mcycle: u32,
    execution_row: u32,
    cycle: u3,
) !void {
    try std.testing.expectEqual(mcycle, row.mcycle);
    try std.testing.expectEqualDeep(
        trace_builder.ExecutionPosition{
            .execution_row = execution_row,
            .cycle = cycle,
        },
        row.provenance.execution_tick,
    );
    try std.testing.expect(row.transition.event == .tick_mcycle);
}
