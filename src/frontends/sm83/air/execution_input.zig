//! Canonical proof input at the instruction/scheduler boundary.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const execution = @import("execution.zig");
const interrupt_service = @import("interrupt_service.zig");
const machine = @import("../runner/machine.zig");
const runner = @import("../runner/mod.zig");

pub const Step = union(enum) {
    ordinary: runner.StepTrace,
    interrupt_service: machine.StepResult,
};

/// Cartridge-aware event input retained until scheduler, access, and device
/// components consume the same runner result. This is intentionally separate
/// from legacy `Step`, whose union shape is part of existing family callers.
pub const CartridgeStep = struct {
    result: machine.CartridgeStepResult,
};

pub const HaltBugBoundary = struct {
    before: bool,
    after: bool,
};

pub const InputError = error{
    UnsupportedMachineEvent,
    NonCanonicalMachineResult,
    HaltBugBoundary,
    UnsupportedSchedulerState,
    TimerEnabled,
    UnsupportedTimerState,
    UnsupportedTimerAccess,
    InvalidInterruptService,
    FlatServiceTraceUnavailable,
    ExecutionClockOverflow,
};

pub fn fromInstruction(trace: runner.StepTrace) Step {
    return .{ .ordinary = trace };
}

pub fn fromMachine(result: machine.StepResult) InputError!Step {
    if (!result.hasCanonicalShape()) return error.NonCanonicalMachineResult;
    return switch (result.event) {
        .halt_idle, .halt_wake => error.UnsupportedMachineEvent,
        .instruction => blk: {
            const trace = result.instruction orelse
                return error.NonCanonicalMachineResult;
            if (result.before.halt_bug or result.after.halt_bug)
                return error.HaltBugBoundary;
            if (result.before.cpu.ime or
                result.before.cpu.halted or
                result.before.cpu.stopped or
                trace.decoded.instruction.operation == .halt or
                trace.decoded.instruction.operation == .stop)
                return error.UnsupportedSchedulerState;
            if (result.before.tac & 0x04 != 0 or result.after.tac & 0x04 != 0)
                return error.TimerEnabled;
            if (result.before.timer_reload != .running or
                result.after.timer_reload != .running or
                result.before.div_counter >> 8 != result.after.div_counter >> 8)
                return error.UnsupportedTimerState;
            for (trace.activeCycles()) |cycle| {
                if (cycle.action != .idle and
                    cycle.address >= 0xff04 and cycle.address <= 0xff07)
                    return error.UnsupportedTimerAccess;
            }
            break :blk .{ .ordinary = trace };
        },
        // Flat results discard the pinned SameBoy cycle trace. Reconstructing
        // it from endpoints would make forged service witnesses admissible.
        .interrupt_service => error.FlatServiceTraceUnavailable,
    };
}

/// Retains every cartridge event and its metadata after canonical runner
/// validation, including the pinned SameBoy interrupt-service cycle trace.
pub fn fromCartridgeMachine(
    result: machine.CartridgeStepResult,
) InputError!CartridgeStep {
    const scheduler = result.schedulerResult();
    if (!scheduler.hasCanonicalShape() or !result.hasCanonicalShape())
        return error.NonCanonicalMachineResult;
    return .{ .result = result };
}

pub fn executionColumns(
    step: Step,
    mcycle_before: u32,
) [execution.N_MAIN_COLUMNS]M31 {
    return switch (step) {
        .ordinary => |trace| execution.columns(trace, mcycle_before),
        .interrupt_service => unreachable,
    };
}

pub fn cartridgeExecutionColumns(
    step: CartridgeStep,
    mcycle_before: u32,
) InputError![execution.N_MAIN_COLUMNS]M31 {
    const validated = try fromCartridgeMachine(step.result);
    const scheduler = validated.result.schedulerResult();
    return switch (scheduler.event) {
        .instruction => execution.columns(
            validated.result.instruction.?.instruction,
            mcycle_before,
        ),
        .halt_idle, .halt_wake => haltColumns(
            scheduler,
            mcycle_before,
        ),
        .interrupt_service => interrupt_service.executionColumns(
            interrupt_service.ValidatedStep.init(validated.result) catch
                return error.InvalidInterruptService,
            mcycle_before,
        ),
    };
}

pub fn instruction(step: Step) ?runner.StepTrace {
    return switch (step) {
        .ordinary => |trace| trace,
        .interrupt_service => null,
    };
}

pub fn cartridgeInstruction(
    step: CartridgeStep,
) ?runner.CartridgeStepTrace {
    return step.result.instruction;
}

pub fn cartridgeSchedulerResult(step: CartridgeStep) machine.StepResult {
    return step.result.schedulerResult();
}

pub fn cartridgeBeforeCpu(step: CartridgeStep) runner.Cpu {
    return step.result.before.cpu;
}

pub fn cartridgeAfterCpu(step: CartridgeStep) runner.Cpu {
    return step.result.after.cpu;
}

pub fn cartridgeMCycles(step: CartridgeStep) u3 {
    return step.result.m_cycles;
}

pub fn haltBugBoundary(step: CartridgeStep) HaltBugBoundary {
    return .{
        .before = step.result.before.halt_bug,
        .after = step.result.after.halt_bug,
    };
}

pub fn beforeCpu(step: Step) runner.Cpu {
    return switch (step) {
        .ordinary => |trace| trace.before,
        .interrupt_service => |result| result.before.cpu,
    };
}

pub fn afterCpu(step: Step) runner.Cpu {
    return switch (step) {
        .ordinary => |trace| trace.after,
        .interrupt_service => |result| result.after.cpu,
    };
}

pub fn mCycles(step: Step) u3 {
    return switch (step) {
        .ordinary => |trace| trace.cycle_count,
        .interrupt_service => |result| result.m_cycles,
    };
}

fn haltColumns(
    result: machine.StepResult,
    mcycle_before: u32,
) InputError![execution.N_MAIN_COLUMNS]M31 {
    const mcycle_after = std.math.add(
        u32,
        mcycle_before,
        1,
    ) catch return error.ExecutionClockOverflow;
    var out = [_]M31{M31.zero()} ** execution.N_MAIN_COLUMNS;
    const before = execution.stateFromCpu(M31, result.before.cpu);
    const after = execution.stateFromCpu(M31, result.after.cpu);
    @memcpy(out[0..execution.N_STATE_COLUMNS], &before.values);
    @memcpy(
        out[execution.N_STATE_COLUMNS .. 2 * execution.N_STATE_COLUMNS],
        &after.values,
    );
    const bus_offset = 2 * execution.N_STATE_COLUMNS;
    out[bus_offset + 2] = M31.one();
    const clock_offset = bus_offset +
        execution.N_BUS_CYCLES * execution.N_BUS_COLUMNS;
    out[clock_offset] = M31.fromCanonical(mcycle_before);
    out[clock_offset + 1] = M31.fromCanonical(mcycle_after);
    return out;
}

test "execution input accepts ordinary and rejects flat service rows" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.write(0, 0x00);
    var cpu = runner.Cpu{};
    const trace = try runner.step(&cpu, &memory);
    const ordinary = fromInstruction(trace);
    try std.testing.expect(instruction(ordinary) != null);
    try std.testing.expectEqual(trace.before, beforeCpu(ordinary));
    try std.testing.expectEqual(trace.after, afterCpu(ordinary));
    try std.testing.expectEqual(trace.cycle_count, mCycles(ordinary));
    try std.testing.expectEqualDeep(
        execution.columns(trace, 7),
        executionColumns(ordinary, 7),
    );

    memory.write(0xffff, 1);
    memory.write(0xff0f, 1);
    var scheduler = machine.Machine.init(
        &memory,
        .{ .sp = 0xc000, .pc = 0x1234, .ime = true },
    );
    const result = try scheduler.step();
    try std.testing.expectError(
        error.FlatServiceTraceUnavailable,
        fromMachine(result),
    );
}

test "execution input rejects unsupported and forged machine boundaries" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.write(0, 0x00);
    var scheduler = machine.Machine.init(&memory, .{ .halted = true });
    try std.testing.expectError(
        error.UnsupportedMachineEvent,
        fromMachine(try scheduler.step()),
    );

    memory.write(0xffff, 1);
    memory.write(0xff0f, 1);
    scheduler = machine.Machine.init(
        &memory,
        .{ .halted = true, .ime = false },
    );
    try std.testing.expectError(
        error.UnsupportedMachineEvent,
        fromMachine(try scheduler.step()),
    );

    scheduler = machine.Machine.init(
        &memory,
        .{ .sp = 0xc000, .ime = true },
    );
    var forged = try scheduler.step();
    forged.m_cycles = 4;
    try std.testing.expectError(
        error.NonCanonicalMachineResult,
        fromMachine(forged),
    );

    memory.write(0xff07, 0x04);
    memory.write(0xff0f, 1);
    scheduler = machine.Machine.init(
        &memory,
        .{ .sp = 0xc000, .ime = true },
    );
    try std.testing.expectError(
        error.FlatServiceTraceUnavailable,
        fromMachine(try scheduler.step()),
    );

    memory.write(0, 0x76);
    memory.write(0xffff, 1);
    memory.write(0xff0f, 1);
    scheduler = machine.Machine.init(&memory, .{});
    try std.testing.expectError(
        error.HaltBugBoundary,
        fromMachine(try scheduler.step()),
    );

    memory.write(0, 0x00);
    memory.write(0xffff, 0);
    memory.write(0xff0f, 0);
    scheduler = machine.Machine.init(&memory, .{ .ime = true });
    try std.testing.expectError(
        error.UnsupportedSchedulerState,
        fromMachine(try scheduler.step()),
    );

    var forged_cpu = runner.Cpu{ .ime = true };
    const raw_nop = try runner.step(&forged_cpu, &memory);
    const forged_ordinary = machine.StepResult{
        .before = .{
            .cpu = raw_nop.before,
            .halt_bug = false,
            .div_counter = 0,
            .tima = 0,
            .tma = 0,
            .tac = 0,
            .timer_reload = .running,
            .interrupt_flags = 1,
            .interrupt_enable = 1,
        },
        .after = .{
            .cpu = raw_nop.after,
            .halt_bug = false,
            .div_counter = 4,
            .tima = 0,
            .tma = 0,
            .tac = 0,
            .timer_reload = .running,
            .interrupt_flags = 1,
            .interrupt_enable = 1,
        },
        .event = .instruction,
        .m_cycles = raw_nop.cycle_count,
        .instruction = raw_nop,
    };
    try std.testing.expect(forged_ordinary.hasCanonicalShape());
    try std.testing.expectError(
        error.UnsupportedSchedulerState,
        fromMachine(forged_ordinary),
    );

    memory.write(0, 0x00);
    memory.write(0xff07, 0);
    scheduler = machine.Machine.init(&memory, .{});
    scheduler.timer.div_counter = 0x00fc;
    try std.testing.expectError(
        error.UnsupportedTimerState,
        fromMachine(try scheduler.step()),
    );

    memory.write(0, 0xf0); // LDH A,(a8)
    memory.write(1, 0x04); // DIV
    scheduler = machine.Machine.init(&memory, .{});
    try std.testing.expectError(
        error.UnsupportedTimerAccess,
        fromMachine(try scheduler.step()),
    );
}
