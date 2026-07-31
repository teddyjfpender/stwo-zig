//! Owned ordered execution columns in bit-reversed circle-domain order.

const std = @import("std");
const core_air_utils = @import("stwo_core").air.utils;
const M31_MODULUS = @import("stwo_core").fields.m31.Modulus;
const M31 = @import("stwo_core").fields.m31.M31;
const execution = @import("execution.zig");
const execution_input = @import("execution_input.zig");
const machine = @import("../runner/machine.zig");
const runner = @import("../runner/mod.zig");

pub const Trace = struct {
    log_size: u32,
    is_first: []M31,
    is_last: []M31,
    main: [execution.N_MAIN_COLUMNS][]M31,
    initial: execution.Boundary,
    final: execution.Boundary,
    cartridge_results: ?[]machine.CartridgeStepResult = null,
    allocator: std.mem.Allocator,
    selectors_owned: bool = true,
    main_owned: bool = true,

    pub fn disown(self: *Trace) void {
        self.selectors_owned = false;
        self.main_owned = false;
    }

    pub fn disownMain(self: *Trace) void {
        self.main_owned = false;
    }

    pub fn deinit(self: *Trace) void {
        if (self.selectors_owned) {
            self.allocator.free(self.is_first);
            self.allocator.free(self.is_last);
        }
        if (self.main_owned) {
            for (self.main) |column| self.allocator.free(column);
        }
        if (self.cartridge_results) |results|
            self.allocator.free(results);
        self.* = undefined;
    }

    pub fn cartridgeResults(
        self: *const Trace,
    ) ?[]const machine.CartridgeStepResult {
        return self.cartridge_results;
    }
};

pub fn generate(
    allocator: std.mem.Allocator,
    steps: anytype,
) !Trace {
    return generateAt(allocator, steps, 0);
}

pub fn generateAt(
    allocator: std.mem.Allocator,
    steps: anytype,
    initial_mcycle: u32,
) !Trace {
    if (steps.len < 16 or !std.math.isPowerOfTwo(steps.len))
        return error.InvalidTraceLength;
    if (initial_mcycle >= M31_MODULUS)
        return error.NonCanonicalExecutionClock;
    const log_size: u32 = @intCast(std.math.log2_int(usize, steps.len));
    var result = Trace{
        .log_size = log_size,
        .is_first = try allocator.alloc(M31, steps.len),
        .is_last = undefined,
        .main = undefined,
        .initial = .{
            .cpu = beforeCpu(steps[0]),
            .mcycle = initial_mcycle,
        },
        .final = undefined,
        .allocator = allocator,
    };
    errdefer allocator.free(result.is_first);
    result.is_last = try allocator.alloc(M31, steps.len);
    errdefer allocator.free(result.is_last);
    @memset(result.is_first, M31.zero());
    @memset(result.is_last, M31.zero());
    result.is_first[try core_air_utils.circleBitReversedIndex(log_size, 0)] = M31.one();
    result.is_last[
        try core_air_utils.circleBitReversedIndex(
            log_size,
            steps.len - 1,
        )
    ] = M31.one();

    var initialized: usize = 0;
    errdefer for (result.main[0..initialized]) |column| allocator.free(column);
    for (&result.main) |*column| {
        column.* = try allocator.alloc(M31, steps.len);
        @memset(column.*, M31.zero());
        initialized += 1;
    }

    var mcycle = initial_mcycle;
    for (steps, 0..) |step, row| {
        if (row != 0 and
            !std.meta.eql(afterCpu(steps[row - 1]), beforeCpu(step)))
            return error.DisconnectedExecution;
        if (comptime retainsCartridgeResults(@TypeOf(step))) {
            if (row != 0 and !std.meta.eql(
                cartridgeResult(steps[row - 1]).mapper_after,
                cartridgeResult(step).mapper_before,
            ))
                return error.DisconnectedMapperState;
        }
        const next_mcycle = std.math.add(u32, mcycle, mCycles(step)) catch
            return error.ExecutionClockOverflow;
        if (next_mcycle >= M31_MODULUS)
            return error.NonCanonicalExecutionClock;
        const values = try columns(step, mcycle);
        const storage = try core_air_utils.circleBitReversedIndex(log_size, row);
        for (&result.main, values) |column, value| column[storage] = value;
        mcycle = next_mcycle;
    }
    result.final = .{
        .cpu = afterCpu(steps[steps.len - 1]),
        .mcycle = mcycle,
    };
    if (comptime retainsCartridgeResults(@TypeOf(steps[0]))) {
        const saved = try allocator.alloc(
            machine.CartridgeStepResult,
            steps.len,
        );
        for (steps, saved) |step, *destination|
            destination.* = cartridgeResult(step);
        result.cartridge_results = saved;
    }
    return result;
}

fn columns(
    step: anytype,
    mcycle: u32,
) ![execution.N_MAIN_COLUMNS]M31 {
    if (@TypeOf(step) == runner.StepTrace)
        return execution.columns(step, mcycle);
    if (@TypeOf(step) == runner.CartridgeStepTrace)
        return execution.columns(step.instruction, mcycle);
    if (@TypeOf(step) == execution_input.Step)
        return execution_input.executionColumns(step, mcycle);
    if (@TypeOf(step) == execution_input.CartridgeStep)
        return execution_input.cartridgeExecutionColumns(step, mcycle);
    if (@TypeOf(step) == machine.CartridgeStepResult)
        return execution_input.cartridgeExecutionColumns(
            try execution_input.fromCartridgeMachine(step),
            mcycle,
        );
    @compileError("unsupported SM83 proof input");
}

fn beforeCpu(step: anytype) runner.Cpu {
    if (@TypeOf(step) == runner.StepTrace) return step.before;
    if (@TypeOf(step) == runner.CartridgeStepTrace)
        return step.instruction.before;
    if (@TypeOf(step) == execution_input.Step)
        return execution_input.beforeCpu(step);
    if (@TypeOf(step) == execution_input.CartridgeStep)
        return execution_input.cartridgeBeforeCpu(step);
    if (@TypeOf(step) == machine.CartridgeStepResult)
        return step.before.cpu;
    @compileError("unsupported SM83 proof input");
}

fn afterCpu(step: anytype) runner.Cpu {
    if (@TypeOf(step) == runner.StepTrace) return step.after;
    if (@TypeOf(step) == runner.CartridgeStepTrace)
        return step.instruction.after;
    if (@TypeOf(step) == execution_input.Step)
        return execution_input.afterCpu(step);
    if (@TypeOf(step) == execution_input.CartridgeStep)
        return execution_input.cartridgeAfterCpu(step);
    if (@TypeOf(step) == machine.CartridgeStepResult)
        return step.after.cpu;
    @compileError("unsupported SM83 proof input");
}

fn mCycles(step: anytype) u3 {
    if (@TypeOf(step) == runner.StepTrace) return step.cycle_count;
    if (@TypeOf(step) == runner.CartridgeStepTrace)
        return step.instruction.cycle_count;
    if (@TypeOf(step) == execution_input.Step)
        return execution_input.mCycles(step);
    if (@TypeOf(step) == execution_input.CartridgeStep)
        return execution_input.cartridgeMCycles(step);
    if (@TypeOf(step) == machine.CartridgeStepResult)
        return step.m_cycles;
    @compileError("unsupported SM83 proof input");
}

fn retainsCartridgeResults(comptime T: type) bool {
    return T == execution_input.CartridgeStep or
        T == machine.CartridgeStepResult;
}

fn cartridgeResult(step: anytype) machine.CartridgeStepResult {
    if (@TypeOf(step) == execution_input.CartridgeStep)
        return step.result;
    if (@TypeOf(step) == machine.CartridgeStepResult)
        return step;
    @compileError("proof input has no cartridge machine result");
}

test "execution trace rejects disconnected rows" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    @memset(memory.bytes[0..16], 0x80);
    var cpu = runner.Cpu{ .a = 1, .b = 2 };
    var steps: [16]runner.StepTrace = undefined;
    for (&steps) |*step| step.* = try runner.step(&cpu, &memory);
    steps[1].before.a +%= 1;
    try std.testing.expectError(
        error.DisconnectedExecution,
        generate(std.testing.allocator, &steps),
    );
}

test "execution trace accepts cartridge-wrapped instruction rows" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    @memset(memory.bytes[0..16], 0x80);
    var cpu = runner.Cpu{ .a = 1, .b = 2 };
    var steps: [16]runner.CartridgeStepTrace = undefined;
    for (&steps) |*step| step.* = .{
        .instruction = try runner.step(&cpu, &memory),
        .accesses = [_]?runner.cartridge_memory.Access{null} ** 6,
    };
    var trace = try generateAt(std.testing.allocator, &steps, 100);
    try std.testing.expectEqual(@as(u32, 100), trace.initial.mcycle);
    try std.testing.expectEqual(@as(u32, 116), trace.final.mcycle);
    trace.deinit();

    trace = try generateAt(
        std.testing.allocator,
        &steps,
        M31_MODULUS - 17,
    );
    try std.testing.expectEqual(M31_MODULUS - 1, trace.final.mcycle);
    trace.deinit();
    try std.testing.expectError(
        error.NonCanonicalExecutionClock,
        generateAt(
            std.testing.allocator,
            &steps,
            M31_MODULUS - 16,
        ),
    );
}
