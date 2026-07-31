const std = @import("std");
const M31_MODULUS = @import("stwo_core").fields.m31.Modulus;
const subject = @import("timer_binding.zig");
const runner = @import("../runner/mod.zig");
const machine = @import("../runner/machine.zig");
const timer = @import("../runner/timer.zig");

const memory = runner.cartridge_memory;
const mapper = @import("../cartridge/mbc3.zig");

test "timer binding derives write read tick order and phase clocks" {
    const initial = timer.Timer{};
    const steps = scenarioSteps();
    var trace = try subject.generateTrace(
        std.testing.allocator,
        100,
        111,
        initial,
        &steps,
    );
    defer trace.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 15), trace.rows.len);
    try std.testing.expectEqual(@as(u32, 111), trace.final_mcycle);
    try std.testing.expectEqual(
        timer.Timer{
            .div_counter = 44,
            .tima = 0x78,
            .tma = 0x66,
            .tac = 0x05,
        },
        trace.final_state,
    );

    var ticks: usize = 0;
    var writes: usize = 0;
    var reads: usize = 0;
    var expected_clock: u32 = 100;
    for (trace.rows) |row| {
        try std.testing.expectEqual(expected_clock, row.mcycle);
        const columns = try subject.columns(row, &steps);
        var marker_count: usize = 0;
        for (
            columns[subject.READ_MARKER_OFFSET..subject.READ_VALUE_OFFSET],
        ) |marker| marker_count += @intFromBool(marker.isOne());
        reads += marker_count;
        switch (row.transition.event) {
            .tick_mcycle => {
                ticks += 1;
                expected_clock += 1;
            },
            else => {
                writes += 1;
                try std.testing.expectEqual(
                    @as(usize, 0),
                    marker_count,
                );
            },
        }
    }
    try std.testing.expectEqual(@as(usize, 11), ticks);
    try std.testing.expectEqual(@as(usize, 4), writes);
    try std.testing.expectEqual(@as(usize, 4), reads);

    var witness = try subject.generateWitness(
        std.testing.allocator,
        trace,
        &steps,
    );
    defer witness.deinit();
    try std.testing.expectEqual(@as(u32, 4), witness.log_size);
    try std.testing.expectEqual(trace.rows.len, witness.event_count);
    for (subject.inactiveColumns()) |value|
        try std.testing.expect(value.isZero());
}

test "timer binding accepts idle cycles and rejects forged MMIO metadata" {
    const steps = [_]runner.CartridgeStepTrace{
        idleTailStep(.{}),
    };
    var trace = try subject.generateTrace(
        std.testing.allocator,
        0,
        2,
        .{},
        &steps,
    );
    defer trace.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), trace.rows.len);
    _ = try subject.columns(trace.rows[1], &steps);

    var wrong_read = accessStep(
        .{},
        subject.FIRST_ADDRESS + @intFromEnum(subject.Register.tima),
        .read,
        .timer_mmio,
        1,
    );
    try std.testing.expectError(
        error.InvalidTimerReadValue,
        subject.generateTrace(
            std.testing.allocator,
            0,
            1,
            .{},
            &.{wrong_read},
        ),
    );
    wrong_read.accesses[0].?.region = .system;
    try std.testing.expectError(
        error.InvalidExecutionStep,
        subject.generateTrace(
            std.testing.allocator,
            0,
            1,
            .{},
            &.{wrong_read},
        ),
    );

    var wrong_region = systemStep(.{});
    wrong_region.accesses[0].?.region = .timer_mmio;
    try std.testing.expectError(
        error.InvalidExecutionStep,
        subject.generateTrace(
            std.testing.allocator,
            0,
            1,
            .{},
            &.{wrong_region},
        ),
    );
    try std.testing.expectError(
        error.InvalidTimerFinalClock,
        subject.generateTrace(
            std.testing.allocator,
            0,
            3,
            .{},
            &steps,
        ),
    );
}

test "timer binding rejects forged provenance clocks state and endpoints" {
    const steps = [_]runner.CartridgeStepTrace{
        systemStep(.{}),
        systemStep(.{}),
    };
    var trace = try subject.generateTrace(
        std.testing.allocator,
        7,
        9,
        .{},
        &steps,
    );
    defer trace.deinit(std.testing.allocator);
    trace.rows[0].provenance.execution_tick.execution_row = 1;
    trace.rows[1].provenance.execution_tick.execution_row = 0;
    try std.testing.expectError(
        error.InvalidExecutionProvenance,
        subject.generateWitness(std.testing.allocator, trace, &steps),
    );
    trace.rows[0].provenance.execution_tick.execution_row = 0;
    trace.rows[1].provenance.execution_tick.execution_row = 1;

    trace.rows[1].mcycle = 7;
    try std.testing.expectError(
        error.DisconnectedTimerClock,
        subject.generateWitness(std.testing.allocator, trace, &steps),
    );
    trace.rows[1].mcycle = 8;
    trace.rows[1].transition.before.tima ^= 1;
    try std.testing.expectError(
        error.DisconnectedTimerState,
        subject.generateWitness(std.testing.allocator, trace, &steps),
    );
    trace.rows[1].transition.before.tima ^= 1;
    trace.final_state.tima ^= 1;
    try std.testing.expectError(
        error.InvalidTimerTraceEndpoint,
        subject.generateWitness(std.testing.allocator, trace, &steps),
    );

    var boundary = try subject.generateTrace(
        std.testing.allocator,
        M31_MODULUS - 2,
        M31_MODULUS - 1,
        .{},
        steps[0..1],
    );
    defer boundary.deinit(std.testing.allocator);
    boundary.final_mcycle = M31_MODULUS;
    try std.testing.expectError(
        error.NonCanonicalTimerClock,
        subject.generateWitness(
            std.testing.allocator,
            boundary,
            steps[0..1],
        ),
    );
}

test "timer machine adapter binds HALT wake endpoints and provenance" {
    const idle = haltResult(.halt_idle, 0, 0, 0);
    var trace = try subject.generateFromMachineExecution(
        std.testing.allocator,
        20,
        21,
        .{},
        &.{idle},
    );
    defer trace.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), trace.rows.len);
    try std.testing.expectEqual(@as(u16, 4), trace.final_state.div_counter);
    try std.testing.expectEqual(@as(u32, 21), trace.final_mcycle);
    var witness = try subject.generateMachineExecutionWitness(
        std.testing.allocator,
        trace,
        &.{idle},
    );
    witness.deinit();

    var forged_result = idle;
    forged_result.after.div_counter += 1;
    try std.testing.expectError(
        error.InvalidMachineTimerAfter,
        subject.generateFromMachineExecution(
            std.testing.allocator,
            20,
            21,
            .{},
            &.{forged_result},
        ),
    );
    try std.testing.expectError(
        error.InvalidMachineTimerAfter,
        subject.generateMachineExecutionWitness(
            std.testing.allocator,
            trace,
            &.{forged_result},
        ),
    );

    trace.rows[0].provenance.execution_tick.cycle = 1;
    try std.testing.expectError(
        error.InvalidExecutionProvenance,
        subject.generateMachineExecutionWitness(
            std.testing.allocator,
            trace,
            &.{idle},
        ),
    );
    trace.rows[0].provenance.execution_tick.cycle = 0;
    trace.rows[0].mcycle += 1;
    try std.testing.expectError(
        error.InvalidTimerTraceEndpoint,
        subject.generateMachineExecutionWitness(
            std.testing.allocator,
            trace,
            &.{idle},
        ),
    );
    trace.rows[0].mcycle -= 1;

    const wake = haltResult(.halt_wake, 4, 1, 1);
    var wake_trace = try subject.generateFromMachineExecution(
        std.testing.allocator,
        21,
        22,
        timer.Timer{ .div_counter = 4 },
        &.{wake},
    );
    defer wake_trace.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(u16, 8), wake_trace.final_state.div_counter);
}

test "timer machine adapter binds instruction MMIO and result chain" {
    var initial = timer.Timer{
        .div_counter = 8,
        .tima = 4,
        .tma = 3,
        .tac = 5,
    };
    const before = initial;
    initial.writeDiv();
    _ = initial.tickMcycle();
    const instruction = instructionResult(
        accessStep(.{}, 0xff04, .write, .timer_mmio, 0xaa),
        before,
        initial,
    );
    var trace = try subject.generateFromMachineExecution(
        std.testing.allocator,
        30,
        31,
        before,
        &.{instruction},
    );
    defer trace.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 2), trace.rows.len);
    try std.testing.expect(
        std.meta.activeTag(trace.rows[0].transition.event) == .write_div,
    );
    _ = try subject.machineColumns(trace.rows[0], &.{instruction});
    var witness = try subject.generateMachineExecutionWitness(
        std.testing.allocator,
        trace,
        &.{instruction},
    );
    witness.deinit();

    var noop_after = timer.Timer{};
    noop_after.writeDiv();
    _ = noop_after.tickMcycle();
    const noop_write = instructionResult(
        accessStep(.{}, 0xff04, .write, .timer_mmio, 0xaa),
        .{},
        noop_after,
    );
    var noop_trace = try subject.generateFromMachineExecution(
        std.testing.allocator,
        31,
        32,
        .{},
        &.{noop_write},
    );
    defer noop_trace.deinit(std.testing.allocator);
    try std.testing.expectError(
        error.InvalidTimerWriteProvenance,
        subject.generateMachineExecutionWitness(
            std.testing.allocator,
            .{
                .rows = noop_trace.rows[1..],
                .final_state = noop_trace.final_state,
                .final_mcycle = noop_trace.final_mcycle,
            },
            &.{noop_write},
        ),
    );

    const first = haltResult(.halt_idle, 0, 0, 0);
    var second = haltResult(.halt_idle, 4, 0, 0);
    second.before.cpu.a = 1;
    second.after.cpu.a = 1;
    try std.testing.expectError(
        error.DisconnectedMachineExecution,
        subject.generateFromMachineExecution(
            std.testing.allocator,
            0,
            2,
            .{},
            &.{ first, second },
        ),
    );
}

test "timer machine adapter binds exact service reads writes and ticks" {
    const initial = timer.Timer{
        .div_counter = 8,
        .tima = 4,
        .tma = 3,
        .tac = 5,
    };
    const service = timerServiceResult(0x2345, 0xff06, initial);
    try std.testing.expect(service.hasCanonicalShape());
    var trace = try subject.generateFromMachineExecution(
        std.testing.allocator,
        90,
        95,
        initial,
        &.{service},
    );
    defer trace.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 7), trace.rows.len);
    try std.testing.expectEqual(
        @as(u3, 3),
        trace.rows[3].provenance.execution_write.cycle,
    );
    try std.testing.expectEqual(
        @as(u3, 4),
        trace.rows[5].provenance.execution_write.cycle,
    );
    var witness = try subject.generateMachineExecutionWitness(
        std.testing.allocator,
        trace,
        &.{service},
    );
    witness.deinit();

    var forged = service;
    forged.service.cycles[3].access.?.region = .system;
    try std.testing.expectError(
        error.InvalidTimerMetadata,
        subject.machineColumns(trace.rows[3], &.{forged}),
    );
    try std.testing.expectError(
        error.InvalidTimerWriteProvenance,
        subject.generateMachineExecutionWitness(
            std.testing.allocator,
            trace,
            &.{forged},
        ),
    );
    forged = service;
    forged.service.cycles[2].kind = .stack_high;
    try std.testing.expectError(
        error.InvalidSchedulerStep,
        subject.generateMachineExecutionWitness(
            std.testing.allocator,
            trace,
            &.{forged},
        ),
    );

    const read_service = timerServiceResult(0xff04, 0xc102, initial);
    var read_trace = try subject.generateFromMachineExecution(
        std.testing.allocator,
        95,
        100,
        initial,
        &.{read_service},
    );
    defer read_trace.deinit(std.testing.allocator);
    const read_columns = try subject.machineColumns(
        read_trace.rows[0],
        &.{read_service},
    );
    try std.testing.expect(
        read_columns[
            subject.READ_MARKER_OFFSET +
                @intFromEnum(subject.Register.div)
        ].isOne(),
    );

    var no_rows: [0]subject.EventRow = .{};
    try std.testing.expectError(
        error.EmptyTimerTrace,
        subject.generateMachineExecutionWitness(
            std.testing.allocator,
            .{
                .rows = &no_rows,
                .final_state = initial,
                .final_mcycle = 100,
            },
            &.{read_service},
        ),
    );
}

fn timerServiceResult(
    return_pc: u16,
    sp: u16,
    initial: timer.Timer,
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
    var after_timer = initial;
    _ = after_timer.tickMcycle();
    _ = after_timer.tickMcycle();
    _ = after_timer.tickMcycle();
    applyTimerWrite(
        &after_timer,
        sp -% 1,
        @truncate(return_pc >> 8),
    );
    _ = after_timer.tickMcycle();
    applyTimerWrite(&after_timer, sp -% 2, @truncate(return_pc));
    _ = after_timer.tickMcycle();

    var result = machine.CartridgeStepResult{
        .before = machineState(cpu, initial, 1, 1),
        .after = machineState(after_cpu, after_timer, 0, 1),
        .event = .interrupt_service,
        .m_cycles = 5,
        .interrupt_index = 0,
    };
    result.service.count = 5;
    result.service.cycles[0] = .{
        .kind = .dummy_read,
        .access = timerServiceAccess(
            return_pc,
            .read,
            timerRead(initial, return_pc),
        ),
    };
    result.service.cycles[1].kind = .oam_bug;
    result.service.cycles[2].kind = .no_access;
    result.service.cycles[3] = .{
        .kind = .stack_high,
        .access = timerServiceAccess(
            sp -% 1,
            .write,
            @truncate(return_pc >> 8),
        ),
    };
    result.service.cycles[4] = .{
        .kind = .stack_low,
        .access = timerServiceAccess(
            sp -% 2,
            .write,
            @truncate(return_pc),
        ),
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

fn timerRead(device_timer: timer.Timer, address: u16) u8 {
    const register = subject.registerForAddress(address) catch return 0;
    return subject.readTimerRegister(device_timer, register);
}

fn applyTimerWrite(
    device_timer: *timer.Timer,
    address: u16,
    value: u8,
) void {
    switch (subject.registerForAddress(address) catch return) {
        .div => device_timer.writeDiv(),
        .tima => device_timer.writeTima(value),
        .tma => device_timer.writeTma(value),
        .tac => device_timer.writeTac(value),
    }
}

fn timerServiceAccess(
    address: u16,
    action: memory.Action,
    value: u8,
) memory.Access {
    const timer_address = subject.registerForAddress(address) catch null;
    const fixed_rom = address <= 0x3fff and action == .read;
    return .{
        .logical_address = address,
        .action = action,
        .region = if (timer_address != null)
            .timer_mmio
        else if (fixed_rom)
            .cartridge_rom
        else
            .system,
        .physical_offset = if (fixed_rom) address else null,
        .mapper_before = .{},
        .mapper_after = .{},
        .value = value,
    };
}

fn scenarioSteps() [10]runner.CartridgeStepTrace {
    const state = mapper.State{};
    return .{
        accessStep(state, 0xff04, .write, .timer_mmio, 0xaa),
        accessStep(state, 0xff04, .read, .timer_mmio, 0),
        accessStep(state, 0xff05, .write, .timer_mmio, 0x77),
        accessStep(state, 0xff05, .read, .timer_mmio, 0x77),
        accessStep(state, 0xff06, .write, .timer_mmio, 0x66),
        accessStep(state, 0xff06, .read, .timer_mmio, 0x66),
        accessStep(state, 0xff07, .write, .timer_mmio, 0x05),
        accessStep(state, 0xff07, .read, .timer_mmio, 0xfd),
        systemStep(state),
        idleTailStep(state),
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
        .{ .div_counter = div_counter },
        flags,
        enable,
    );
    var after = before;
    after.div_counter += 4;
    after.cpu.halted = event == .halt_idle;
    return .{
        .before = before,
        .after = after,
        .event = event,
        .m_cycles = 1,
    };
}

fn instructionResult(
    trace: runner.CartridgeStepTrace,
    before_timer: timer.Timer,
    after_timer: timer.Timer,
) machine.CartridgeStepResult {
    var instruction = trace;
    instruction.instruction.before = .{};
    instruction.instruction.after = .{};
    return .{
        .before = machineState(.{}, before_timer, 0, 0),
        .after = machineState(.{}, after_timer, 0, 0),
        .event = .instruction,
        .m_cycles = instruction.instruction.cycle_count,
        .instruction = instruction,
    };
}

fn machineState(
    cpu: runner.Cpu,
    device_timer: timer.Timer,
    flags: u8,
    enable: u8,
) machine.MachineState {
    return .{
        .cpu = cpu,
        .halt_bug = false,
        .div_counter = device_timer.div_counter,
        .tima = device_timer.readTima(),
        .tma = device_timer.tma,
        .tac = device_timer.tac,
        .timer_reload = device_timer.reload_state,
        .interrupt_flags = flags,
        .interrupt_enable = enable,
    };
}

fn systemStep(state: mapper.State) runner.CartridgeStepTrace {
    return accessStep(state, 0xc000, .read, .system, 0x42);
}

fn idleTailStep(state: mapper.State) runner.CartridgeStepTrace {
    var step = systemStep(state);
    step.instruction.cycle_count = 2;
    step.instruction.cycles[1] = .{
        .address = 0xc000,
        .value = 0x42,
        .action = .idle,
    };
    return step;
}

fn accessStep(
    state: mapper.State,
    address: u16,
    action: memory.Action,
    region: memory.Region,
    value: u8,
) runner.CartridgeStepTrace {
    var step: runner.CartridgeStepTrace = undefined;
    step.instruction.cycle_count = 1;
    step.instruction.cycles[0] = .{
        .address = address,
        .value = value,
        .action = switch (action) {
            .read => .read,
            .write => .write,
        },
    };
    step.accesses = [_]?memory.Access{null} ** 6;
    step.accesses[0] = .{
        .logical_address = address,
        .action = action,
        .region = region,
        .physical_offset = null,
        .mapper_before = state,
        .mapper_after = state,
        .value = value,
    };
    return step;
}
