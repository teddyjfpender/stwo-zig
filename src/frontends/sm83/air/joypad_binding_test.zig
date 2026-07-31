const std = @import("std");
const M31_MODULUS = @import("stwo_core").fields.m31.Modulus;
const action_schedule = @import("../action_schedule.zig");
const subject = @import("joypad_binding.zig");
const trace_builder = @import("../joypad_trace.zig");
const runner = @import("../runner/mod.zig");
const machine = @import("../runner/machine.zig");

const joypad = runner.joypad;
const memory = runner.cartridge_memory;

test "joypad binding owns one clock and authenticates P1 read provenance" {
    const mapper = @import("../cartridge/mbc3.zig").State{};
    const steps = [_]runner.CartridgeStepTrace{
        accessStep(mapper, .write, 0x10),
        accessStep(mapper, .read, 0xde),
    };
    const actions = [_]action_schedule.Action{
        .{ .mcycle = 7, .pressed = joypad.Key.a.mask() },
    };
    var trace = try trace_builder.generate(
        std.testing.allocator,
        7,
        9,
        .{},
        &actions,
        &steps,
    );
    defer trace.deinit(std.testing.allocator);

    var reads: usize = 0;
    for (trace.rows) |row| {
        const values = try subject.columns(row, &steps);
        try std.testing.expect(values[0].isOne());
        try std.testing.expectEqual(
            row.mcycle,
            values[subject.MCYCLE_OFFSET].v,
        );
        reads += @intFromBool(
            values[subject.READ_ENABLED_OFFSET].isOne(),
        );
    }
    try std.testing.expectEqual(@as(usize, 1), reads);
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

test "joypad binding accepts internal ticks without inventing P1 reads" {
    const mapper = @import("../cartridge/mbc3.zig").State{};
    const steps = [_]runner.CartridgeStepTrace{
        idleTailStep(mapper),
        accessStep(mapper, .read, 0xcf),
    };
    var trace = try trace_builder.generate(
        std.testing.allocator,
        20,
        23,
        .{},
        &.{},
        &steps,
    );
    defer trace.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 3), trace.rows.len);
    for (trace.rows, 0..) |row, index| {
        const values = try subject.columns(row, &steps);
        try std.testing.expectEqual(
            index == 2,
            values[subject.READ_ENABLED_OFFSET].isOne(),
        );
    }
    var witness = try subject.generateWitness(
        std.testing.allocator,
        trace,
        &steps,
    );
    defer witness.deinit();
    try std.testing.expectEqual(@as(usize, 3), witness.event_count);
}

test "joypad binding rejects forged event and execution provenance" {
    const mapper = @import("../cartridge/mbc3.zig").State{};
    const steps = [_]runner.CartridgeStepTrace{
        accessStep(mapper, .write, 0x10),
    };
    var trace = try trace_builder.generate(
        std.testing.allocator,
        0,
        1,
        .{},
        &.{},
        &steps,
    );
    defer trace.deinit(std.testing.allocator);

    var forged = trace.rows[0];
    forged.provenance = .{ .execution_tick = .{
        .execution_row = 1,
        .cycle = 0,
    } };
    try std.testing.expectError(
        error.InvalidExecutionProvenance,
        subject.columns(forged, &steps),
    );
    forged = trace.rows[0];
    forged.provenance = .{ .action_index = 0 };
    try std.testing.expectError(
        error.InvalidActionProvenance,
        subject.columns(forged, &steps),
    );
    forged = trace.rows[1];
    forged.provenance = .{ .execution_write = .{
        .execution_row = 0,
        .cycle = 0,
    } };
    try std.testing.expectError(
        error.InvalidWriteProvenance,
        subject.columns(forged, &steps),
    );
    forged.mcycle = M31_MODULUS;
    try std.testing.expectError(
        error.NonCanonicalJoypadClock,
        subject.columns(forged, &steps),
    );

    const original_second = trace.rows[1];
    var disconnected = trace;
    disconnected.rows[1].mcycle = 1;
    try std.testing.expectError(
        error.DisconnectedJoypadClock,
        subject.generateWitness(
            std.testing.allocator,
            disconnected,
            &steps,
        ),
    );
    disconnected.rows[1].mcycle = 0;
    disconnected.rows[1].transition.before.pressed ^= 1;
    try std.testing.expectError(
        error.DisconnectedJoypadState,
        subject.generateWitness(
            std.testing.allocator,
            disconnected,
            &steps,
        ),
    );
    disconnected.rows[1] = original_second;
    disconnected.rows[1].transition = try joypad.Transition.apply(
        disconnected.rows[0].transition.after,
        .{ .write_p1 = 0x20 },
    );
    try std.testing.expectError(
        error.InvalidJoypadEventOrder,
        subject.generateWitness(
            std.testing.allocator,
            disconnected,
            &steps,
        ),
    );
    disconnected.rows[1] = original_second;
    disconnected.final_state.pressed ^= 1;
    try std.testing.expectError(
        error.InvalidJoypadTraceEndpoint,
        subject.generateWitness(
            std.testing.allocator,
            disconnected,
            &steps,
        ),
    );

    var no_rows: [0]trace_builder.EventRow = .{};
    try std.testing.expectError(
        error.EmptyJoypadTrace,
        subject.generateWitness(
            std.testing.allocator,
            .{
                .rows = &no_rows,
                .final_state = .{},
                .final_mcycle = 0,
            },
            &steps,
        ),
    );
}

test "joypad binding rejects noncanonical provenance clocks and endpoints" {
    const mapper = @import("../cartridge/mbc3.zig").State{};
    const steps = [_]runner.CartridgeStepTrace{
        systemStep(mapper),
        systemStep(mapper),
    };
    var trace = try trace_builder.generate(
        std.testing.allocator,
        5,
        7,
        .{},
        &.{},
        &steps,
    );
    defer trace.deinit(std.testing.allocator);
    trace.rows[0].provenance.execution_tick.execution_row = 1;
    trace.rows[1].provenance.execution_tick.execution_row = 0;
    try std.testing.expectError(
        error.InvalidExecutionProvenance,
        subject.generateWitness(
            std.testing.allocator,
            trace,
            &steps,
        ),
    );

    const one = [_]runner.CartridgeStepTrace{systemStep(mapper)};
    const actions = [_]action_schedule.Action{
        .{ .mcycle = 5, .pressed = joypad.Key.a.mask() },
    };
    var action_trace = try trace_builder.generate(
        std.testing.allocator,
        5,
        6,
        .{},
        &actions,
        &one,
    );
    defer action_trace.deinit(std.testing.allocator);
    action_trace.rows[0].provenance.action_index = 1;
    try std.testing.expectError(
        error.InvalidActionProvenance,
        subject.generateWitness(
            std.testing.allocator,
            action_trace,
            &one,
        ),
    );

    var boundary = try trace_builder.generate(
        std.testing.allocator,
        M31_MODULUS - 1,
        M31_MODULUS,
        .{},
        &.{},
        &one,
    );
    defer boundary.deinit(std.testing.allocator);
    try std.testing.expectError(
        error.NonCanonicalJoypadClock,
        subject.generateWitness(
            std.testing.allocator,
            boundary,
            &one,
        ),
    );
}

test "joypad machine binding authenticates actions MMIO and scheduler cycles" {
    const write = instructionResult(
        accessStep(.{}, .write, 0x10),
    );
    const actions = [_]action_schedule.Action{
        .{ .mcycle = 50, .pressed = joypad.Key.a.mask() },
    };
    var trace = try trace_builder.generateFromMachineExecution(
        std.testing.allocator,
        50,
        51,
        .{},
        &actions,
        &.{write},
    );
    defer trace.deinit(std.testing.allocator);
    var witness = try subject.generateMachineExecutionWitness(
        std.testing.allocator,
        trace,
        &.{write},
    );
    witness.deinit();
    for (trace.rows) |row|
        _ = try subject.machineColumns(row, &.{write});

    trace.rows[0].provenance.action_index = 1;
    try std.testing.expectError(
        error.InvalidActionProvenance,
        subject.generateMachineExecutionWitness(
            std.testing.allocator,
            trace,
            &.{write},
        ),
    );
    trace.rows[0].provenance.action_index = 0;
    trace.rows[1].provenance.execution_write.cycle = 1;
    try std.testing.expectError(
        error.InvalidExecutionProvenance,
        subject.generateMachineExecutionWitness(
            std.testing.allocator,
            trace,
            &.{write},
        ),
    );
    trace.rows[1].provenance.execution_write.cycle = 0;
    trace.rows[2].mcycle += 1;
    try std.testing.expectError(
        error.DisconnectedJoypadClock,
        subject.generateMachineExecutionWitness(
            std.testing.allocator,
            trace,
            &.{write},
        ),
    );
    trace.rows[2].mcycle -= 1;
    trace.final_state.pressed ^= 1;
    try std.testing.expectError(
        error.InvalidJoypadTraceEndpoint,
        subject.generateMachineExecutionWitness(
            std.testing.allocator,
            trace,
            &.{write},
        ),
    );

    const noop_write = instructionResult(
        accessStep(.{}, .write, (joypad.State{}).readP1()),
    );
    var noop_trace = try trace_builder.generateFromMachineExecution(
        std.testing.allocator,
        51,
        52,
        .{},
        &.{},
        &.{noop_write},
    );
    defer noop_trace.deinit(std.testing.allocator);
    try std.testing.expectError(
        error.InvalidWriteProvenance,
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
}

test "joypad machine binding marks reads and rejects forged scheduler rows" {
    const read = instructionResult(accessStep(.{}, .read, 0xcf));
    var trace = try trace_builder.generateFromMachineExecution(
        std.testing.allocator,
        60,
        61,
        .{},
        &.{},
        &.{read},
    );
    defer trace.deinit(std.testing.allocator);
    const values = try subject.machineColumns(trace.rows[0], &.{read});
    try std.testing.expect(values[subject.READ_ENABLED_OFFSET].isOne());

    var forged = read;
    forged.m_cycles = 2;
    try std.testing.expectError(
        error.InvalidSchedulerStep,
        subject.generateMachineExecutionWitness(
            std.testing.allocator,
            trace,
            &.{forged},
        ),
    );

    const idle = haltResult();
    var idle_trace = try trace_builder.generateFromMachineExecution(
        std.testing.allocator,
        61,
        62,
        trace.final_state,
        &.{},
        &.{idle},
    );
    defer idle_trace.deinit(std.testing.allocator);
    var idle_witness = try subject.generateMachineExecutionWitness(
        std.testing.allocator,
        idle_trace,
        &.{idle},
    );
    idle_witness.deinit();
}

test "joypad machine binding authenticates exact service-cycle P1 reads" {
    const service = joypadServiceResult(0xff00, 0xc102);
    var trace = try trace_builder.generateFromMachineExecution(
        std.testing.allocator,
        80,
        85,
        .{},
        &.{},
        &.{service},
    );
    defer trace.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 5), trace.rows.len);
    const first = try subject.machineColumns(trace.rows[0], &.{service});
    try std.testing.expect(first[subject.READ_ENABLED_OFFSET].isOne());
    var witness = try subject.generateMachineExecutionWitness(
        std.testing.allocator,
        trace,
        &.{service},
    );
    witness.deinit();

    var forged = service;
    forged.service.cycles[0].access.?.region = .system;
    try std.testing.expectError(
        error.InvalidJoypadMetadata,
        subject.generateMachineExecutionWitness(
            std.testing.allocator,
            trace,
            &.{forged},
        ),
    );
    trace.rows[0].provenance.execution_tick.cycle = 1;
    try std.testing.expectError(
        error.InvalidExecutionProvenance,
        subject.generateMachineExecutionWitness(
            std.testing.allocator,
            trace,
            &.{service},
        ),
    );

    var no_rows: [0]trace_builder.EventRow = .{};
    try std.testing.expectError(
        error.EmptyJoypadTrace,
        subject.generateMachineExecutionWitness(
            std.testing.allocator,
            .{
                .rows = &no_rows,
                .final_state = .{},
                .final_mcycle = 85,
            },
            &.{service},
        ),
    );
}

fn joypadServiceResult(
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
        .access = serviceAccess(return_pc, .read, (joypad.State{}).readP1()),
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
        else
            .system,
        .physical_offset = null,
        .mapper_before = .{},
        .mapper_after = .{},
        .value = value,
    };
}

fn instructionResult(
    trace: runner.CartridgeStepTrace,
) machine.CartridgeStepResult {
    var instruction = trace;
    instruction.instruction.before = .{};
    instruction.instruction.after = .{};
    return .{
        .before = machineState(.{}, 0, 0, 0),
        .after = machineState(.{}, 4, 0, 0),
        .event = .instruction,
        .m_cycles = 1,
        .instruction = instruction,
    };
}

fn haltResult() machine.CartridgeStepResult {
    const before = machineState(.{ .halted = true }, 0, 0, 0);
    var after = before;
    after.div_counter = 4;
    return .{
        .before = before,
        .after = after,
        .event = .halt_idle,
        .m_cycles = 1,
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

fn accessStep(
    mapper: @import("../cartridge/mbc3.zig").State,
    action: memory.Action,
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
        .region = .joypad_mmio,
        .physical_offset = null,
        .mapper_before = mapper,
        .mapper_after = mapper,
        .value = value,
    };
    return step;
}

fn systemStep(
    mapper: @import("../cartridge/mbc3.zig").State,
) runner.CartridgeStepTrace {
    var step: runner.CartridgeStepTrace = undefined;
    step.instruction.cycle_count = 1;
    step.instruction.cycles[0] = .{
        .address = 0xc000,
        .value = 0x42,
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
        .value = 0x42,
    };
    return step;
}

fn idleTailStep(
    mapper: @import("../cartridge/mbc3.zig").State,
) runner.CartridgeStepTrace {
    var step = systemStep(mapper);
    step.instruction.cycle_count = 2;
    step.instruction.cycles[1] = .{
        .address = 0xc000,
        .value = 0x42,
        .action = .idle,
    };
    return step;
}
