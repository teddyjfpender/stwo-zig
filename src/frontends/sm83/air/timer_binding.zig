//! Canonical execution-derived timer event trace and checked witness layout.
//!
//! Each active execution M-cycle contributes an optional FF04..FF07 write
//! followed by exactly one timer tick. Reads are observed before that tick.

const std = @import("std");
const M31_MODULUS = @import("stwo_core").fields.m31.Modulus;
const M31 = @import("stwo_core").fields.m31.M31;
const runner = @import("../runner/mod.zig");
const machine = @import("../runner/machine.zig");
const timer_runner = @import("../runner/timer.zig");
const cartridge_access = @import("cartridge_access.zig");
const timer_air = @import("timer.zig");
const timer_component = @import("timer_component.zig");

pub const Register = enum(u2) { div, tima, tma, tac };
pub const FIRST_ADDRESS: u16 = 0xff04;

pub const ExecutionPosition = struct {
    execution_row: u32,
    cycle: u3,
};

pub const Provenance = union(enum) {
    execution_write: ExecutionPosition,
    execution_tick: ExecutionPosition,
};

pub const EventRow = struct {
    mcycle: u32,
    transition: timer_air.Transition,
    provenance: Provenance,
};

pub const Trace = struct {
    rows: []EventRow,
    final_state: timer_runner.Timer,
    final_mcycle: u32,

    pub fn deinit(self: *Trace, allocator: std.mem.Allocator) void {
        allocator.free(self.rows);
        self.* = undefined;
    }
};

pub const MCYCLE_OFFSET: usize = timer_component.N_MAIN_COLUMNS;
pub const READ_MARKER_OFFSET: usize = MCYCLE_OFFSET + 1;
pub const READ_VALUE_OFFSET: usize = READ_MARKER_OFFSET + 4;
pub const N_MAIN_COLUMNS: usize = READ_VALUE_OFFSET + 8;

pub const Witness = struct {
    log_size: u32,
    event_count: usize,
    main: [N_MAIN_COLUMNS][]M31,
    allocator: std.mem.Allocator,
    owned: bool = true,

    pub fn disown(self: *Witness) void {
        self.owned = false;
    }

    pub fn deinit(self: *Witness) void {
        if (self.owned)
            for (self.main) |column| self.allocator.free(column);
        self.* = undefined;
    }
};

pub fn generateTrace(
    allocator: std.mem.Allocator,
    initial_mcycle: u32,
    final_mcycle: u32,
    initial_state: timer_runner.Timer,
    steps: []const runner.CartridgeStepTrace,
) !Trace {
    if (initial_mcycle >= final_mcycle)
        return error.InvalidTimerSegment;
    if (final_mcycle >= M31_MODULUS)
        return error.NonCanonicalTimerClock;

    var cycle_count: u32 = 0;
    var event_count: usize = 0;
    for (steps) |step_value| {
        const step = cartridge_access.ValidatedStep.init(step_value) catch
            return error.InvalidExecutionStep;
        cycle_count = std.math.add(
            u32,
            cycle_count,
            step.trace.instruction.cycle_count,
        ) catch return error.TimerClockOverflow;
        event_count = std.math.add(
            usize,
            event_count,
            step.trace.instruction.cycle_count,
        ) catch return error.TooManyTimerEvents;
        for (step.trace.activeAccesses()) |maybe_access| {
            const access = maybe_access orelse continue;
            try validateMetadata(access);
            if (access.region == .timer_mmio and access.action == .write)
                event_count = std.math.add(
                    usize,
                    event_count,
                    1,
                ) catch return error.TooManyTimerEvents;
        }
    }
    const expected_final = std.math.add(
        u32,
        initial_mcycle,
        cycle_count,
    ) catch return error.TimerClockOverflow;
    if (expected_final != final_mcycle)
        return error.InvalidTimerFinalClock;

    const rows = try allocator.alloc(EventRow, event_count);
    errdefer allocator.free(rows);
    var state = initial_state;
    var mcycle = initial_mcycle;
    var row_index: usize = 0;
    for (steps, 0..) |step_value, execution_row| {
        const step = cartridge_access.ValidatedStep.init(step_value) catch
            return error.InvalidExecutionStep;
        for (step.trace.activeAccesses(), 0..) |maybe_access, cycle| {
            if (maybe_access) |access| {
                try validateMetadata(access);
                if (access.region == .timer_mmio) {
                    const register = try registerForAddress(
                        access.logical_address,
                    );
                    switch (access.action) {
                        .read => if (access.value != readTimerRegister(state, register)) return error.InvalidTimerReadValue,
                        .write => try append(
                            rows,
                            &row_index,
                            &state,
                            mcycle,
                            writeEvent(register, access.value),
                            .{ .execution_write = .{
                                .execution_row = @intCast(execution_row),
                                .cycle = @intCast(cycle),
                            } },
                        ),
                    }
                }
            }
            try append(
                rows,
                &row_index,
                &state,
                mcycle,
                .tick_mcycle,
                .{ .execution_tick = .{
                    .execution_row = @intCast(execution_row),
                    .cycle = @intCast(cycle),
                } },
            );
            mcycle = std.math.add(u32, mcycle, 1) catch
                return error.TimerClockOverflow;
        }
    }
    std.debug.assert(row_index == rows.len);
    return .{
        .rows = rows,
        .final_state = state,
        .final_mcycle = mcycle,
    };
}

/// Derives timer rows from every canonical cartridge scheduler M-cycle.
///
/// Each result's timer endpoints are checked against the generated semantic
/// transitions, so elapsed HALT and interrupt-service cycles cannot be omitted.
pub fn generateFromMachineExecution(
    allocator: std.mem.Allocator,
    initial_mcycle: u32,
    final_mcycle: u32,
    initial_state: timer_runner.Timer,
    results: []const machine.CartridgeStepResult,
) !Trace {
    if (initial_mcycle >= final_mcycle)
        return error.InvalidTimerSegment;
    if (final_mcycle >= M31_MODULUS)
        return error.NonCanonicalTimerClock;

    var cycle_count: u32 = 0;
    var event_count: usize = 0;
    for (results, 0..) |result, index| {
        try validateMachineResult(result);
        if (index != 0 and
            !std.meta.eql(results[index - 1].after, result.before))
            return error.DisconnectedMachineExecution;
        if (index != 0 and !std.meta.eql(
            results[index - 1].mapper_after,
            result.mapper_before,
        ))
            return error.DisconnectedMapperExecution;
        cycle_count = std.math.add(
            u32,
            cycle_count,
            result.m_cycles,
        ) catch return error.TimerClockOverflow;
        event_count = std.math.add(
            usize,
            event_count,
            result.m_cycles,
        ) catch return error.TooManyTimerEvents;
        for (0..result.m_cycles) |cycle| {
            const access = machineAccess(result, @intCast(cycle));
            if (access) |item| {
                try validateMetadata(item);
                if (item.region == .timer_mmio and item.action == .write)
                    event_count = std.math.add(
                        usize,
                        event_count,
                        1,
                    ) catch return error.TooManyTimerEvents;
            }
        }
    }
    if (results.len == 0) return error.EmptyTimerTrace;
    const expected_final = std.math.add(
        u32,
        initial_mcycle,
        cycle_count,
    ) catch return error.TimerClockOverflow;
    if (expected_final != final_mcycle)
        return error.InvalidTimerFinalClock;

    const rows = try allocator.alloc(EventRow, event_count);
    errdefer allocator.free(rows);
    var state = initial_state;
    var mcycle = initial_mcycle;
    var row_index: usize = 0;
    for (results, 0..) |result, execution_row| {
        if (!std.meta.eql(state, try timerState(result.before)))
            return error.InvalidMachineTimerBefore;
        for (0..result.m_cycles) |cycle| {
            if (machineAccess(result, @intCast(cycle))) |access| {
                if (access.region == .timer_mmio) {
                    const register = try registerForAddress(
                        access.logical_address,
                    );
                    switch (access.action) {
                        .read => if (access.value != readTimerRegister(state, register)) return error.InvalidTimerReadValue,
                        .write => try append(
                            rows,
                            &row_index,
                            &state,
                            mcycle,
                            writeEvent(register, access.value),
                            .{ .execution_write = .{
                                .execution_row = @intCast(execution_row),
                                .cycle = @intCast(cycle),
                            } },
                        ),
                    }
                }
            }
            try append(
                rows,
                &row_index,
                &state,
                mcycle,
                .tick_mcycle,
                .{ .execution_tick = .{
                    .execution_row = @intCast(execution_row),
                    .cycle = @intCast(cycle),
                } },
            );
            mcycle = std.math.add(u32, mcycle, 1) catch
                return error.TimerClockOverflow;
        }
        if (!std.meta.eql(state, try timerState(result.after)))
            return error.InvalidMachineTimerAfter;
    }
    std.debug.assert(row_index == rows.len);
    return .{
        .rows = rows,
        .final_state = state,
        .final_mcycle = mcycle,
    };
}

pub fn generateWitness(
    allocator: std.mem.Allocator,
    source: Trace,
    steps: []const runner.CartridgeStepTrace,
) !Witness {
    try validateTrace(source, steps);
    return allocateWitness(allocator, source, .{ .instruction = steps });
}

pub fn generateMachineExecutionWitness(
    allocator: std.mem.Allocator,
    source: Trace,
    results: []const machine.CartridgeStepResult,
) !Witness {
    try validateMachineTrace(source, results);
    return allocateWitness(allocator, source, .{ .machine = results });
}

const ColumnSource = union(enum) {
    instruction: []const runner.CartridgeStepTrace,
    machine: []const machine.CartridgeStepResult,
};

fn allocateWitness(
    allocator: std.mem.Allocator,
    source: Trace,
    column_source: ColumnSource,
) !Witness {
    const padded = std.math.ceilPowerOfTwo(
        usize,
        @max(source.rows.len, 16),
    ) catch return error.TimerTraceTooLong;
    const log_size: u32 = @intCast(std.math.log2_int(usize, padded));
    var result = Witness{
        .log_size = log_size,
        .event_count = source.rows.len,
        .main = undefined,
        .allocator = allocator,
    };
    var initialized: usize = 0;
    errdefer for (result.main[0..initialized]) |column|
        allocator.free(column);
    for (&result.main) |*column| {
        column.* = try allocator.alloc(M31, padded);
        @memset(column.*, M31.zero());
        initialized += 1;
    }
    for (source.rows, 0..) |row, index| {
        const values = switch (column_source) {
            .instruction => |steps| try columns(row, steps),
            .machine => |results| try machineColumns(row, results),
        };
        const storage = try @import("stwo_core").air.utils
            .circleBitReversedIndex(log_size, index);
        for (&result.main, values) |column, value|
            column[storage] = value;
    }
    return result;
}

pub fn columns(
    row: EventRow,
    steps: []const runner.CartridgeStepTrace,
) ![N_MAIN_COLUMNS]M31 {
    const access = switch (row.provenance) {
        .execution_write => |position| try accessAt(steps, position),
        .execution_tick => |position| blk: {
            const step = try stepAt(steps, position);
            break :blk step.trace.accesses[position.cycle];
        },
    };
    return columnsForAccess(row, access);
}

pub fn machineColumns(
    row: EventRow,
    results: []const machine.CartridgeStepResult,
) ![N_MAIN_COLUMNS]M31 {
    const access = try machineAccessAt(results, switch (row.provenance) {
        .execution_write => |position| position,
        .execution_tick => |position| position,
    });
    return columnsForAccess(row, access);
}

fn columnsForAccess(
    row: EventRow,
    access: ?runner.cartridge_memory.Access,
) ![N_MAIN_COLUMNS]M31 {
    if (row.mcycle >= M31_MODULUS)
        return error.NonCanonicalTimerClock;
    const validated = timer_air.ValidatedStep.init(row.transition) catch
        return error.InvalidTimerTransition;
    var result = [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
    const semantic = timer_component.columns(validated);
    @memcpy(result[0..timer_component.N_MAIN_COLUMNS], &semantic);
    result[MCYCLE_OFFSET] = M31.fromCanonical(row.mcycle);
    if (access) |item| try validateMetadata(item);

    switch (row.provenance) {
        .execution_write => {
            const item = access orelse
                return error.InvalidTimerWriteProvenance;
            if (item.region != .timer_mmio or item.action != .write)
                return error.InvalidTimerWriteProvenance;
            const register = try registerForAddress(item.logical_address);
            if (!std.meta.eql(
                row.transition.event,
                writeEvent(register, item.value),
            )) return error.InvalidTimerWriteProvenance;
        },
        .execution_tick => {
            if (row.transition.event != .tick_mcycle)
                return error.InvalidTimerTickProvenance;
            if (access) |item| {
                if (item.region == .timer_mmio and
                    item.action == .read)
                {
                    const register = try registerForAddress(
                        item.logical_address,
                    );
                    const expected = readTimerRegister(
                        row.transition.before,
                        register,
                    );
                    if (item.value != expected)
                        return error.InvalidTimerReadProvenance;
                    result[
                        READ_MARKER_OFFSET + @intFromEnum(register)
                    ] = M31.one();
                    writeBits(
                        result[READ_VALUE_OFFSET..N_MAIN_COLUMNS],
                        expected,
                    );
                }
            }
        },
    }
    return result;
}

pub fn inactiveColumns() [N_MAIN_COLUMNS]M31 {
    return [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
}

pub fn registerForAddress(address: u16) !Register {
    if (address < FIRST_ADDRESS or address > FIRST_ADDRESS + 3)
        return error.InvalidTimerRegister;
    return @enumFromInt(@as(u2, @truncate(address - FIRST_ADDRESS)));
}

pub fn readTimerRegister(
    state: timer_runner.Timer,
    register: Register,
) u8 {
    return switch (register) {
        .div => state.readDiv(),
        .tima => state.readTima(),
        .tma => state.readTma(),
        .tac => state.readTac(),
    };
}

fn validateTrace(
    source: Trace,
    steps: []const runner.CartridgeStepTrace,
) !void {
    if (source.rows.len == 0) return error.EmptyTimerTrace;
    if (source.final_mcycle >= M31_MODULUS)
        return error.NonCanonicalTimerClock;
    var execution_row: usize = 0;
    var cycle: usize = 0;
    var mcycle = source.rows[0].mcycle;
    for (source.rows, 0..) |row, index| {
        if (row.mcycle != mcycle)
            return error.DisconnectedTimerClock;
        if (index != 0)
            try validateSuccessor(source.rows[index - 1], row);
        if (execution_row >= steps.len)
            return error.InvalidExecutionProvenance;
        const position = switch (row.provenance) {
            .execution_write => |value| value,
            .execution_tick => |value| value,
        };
        if (position.execution_row != execution_row or
            position.cycle != cycle)
            return error.InvalidExecutionProvenance;
        if (row.provenance == .execution_tick) {
            const step = try stepAt(steps, position);
            mcycle = std.math.add(u32, mcycle, 1) catch
                return error.DisconnectedTimerClock;
            cycle += 1;
            if (cycle == step.trace.instruction.cycle_count) {
                execution_row += 1;
                cycle = 0;
            }
        }
        _ = try columns(row, steps);
    }
    if (execution_row != steps.len or cycle != 0)
        return error.InvalidExecutionProvenance;
    const last = source.rows[source.rows.len - 1];
    if (last.transition.event != .tick_mcycle or
        !std.meta.eql(last.transition.after, source.final_state) or
        mcycle != source.final_mcycle)
        return error.InvalidTimerTraceEndpoint;
}

fn validateMachineTrace(
    source: Trace,
    results: []const machine.CartridgeStepResult,
) !void {
    if (source.rows.len == 0) return error.EmptyTimerTrace;
    if (source.final_mcycle >= M31_MODULUS)
        return error.NonCanonicalTimerClock;
    var execution_row: usize = 0;
    var cycle: usize = 0;
    var mcycle = source.rows[0].mcycle;
    var state = source.rows[0].transition.before;
    var saw_write = false;
    for (source.rows, 0..) |row, index| {
        if (execution_row >= results.len or row.mcycle != mcycle)
            return error.InvalidExecutionProvenance;
        if (index != 0)
            try validateSuccessor(source.rows[index - 1], row);
        if (!std.meta.eql(row.transition.before, state))
            return error.DisconnectedTimerState;
        const position = switch (row.provenance) {
            .execution_write => |value| value,
            .execution_tick => |value| value,
        };
        const starts_result = index == 0 or
            position.execution_row != switch (source.rows[index - 1].provenance) {
                .execution_write => |value| value.execution_row,
                .execution_tick => |value| value.execution_row,
            };
        if (starts_result) {
            try validateMachineResult(results[execution_row]);
            if (!std.meta.eql(
                state,
                try timerState(results[execution_row].before),
            ))
                return error.InvalidMachineTimerBefore;
            if (execution_row != 0 and !std.meta.eql(
                results[execution_row - 1].after,
                results[execution_row].before,
            ))
                return error.DisconnectedMachineExecution;
            if (execution_row != 0 and !std.meta.eql(
                results[execution_row - 1].mapper_after,
                results[execution_row].mapper_before,
            ))
                return error.DisconnectedMapperExecution;
        }
        if (position.execution_row != execution_row or
            position.cycle != cycle)
            return error.InvalidExecutionProvenance;
        const access = try machineAccessAt(results, position);
        switch (row.provenance) {
            .execution_write => {
                if (saw_write)
                    return error.InvalidTimerWriteProvenance;
                const item = access orelse
                    return error.InvalidTimerWriteProvenance;
                if (item.region != .timer_mmio or item.action != .write)
                    return error.InvalidTimerWriteProvenance;
                saw_write = true;
            },
            .execution_tick => {
                const expects_write = if (access) |item|
                    item.region == .timer_mmio and item.action == .write
                else
                    false;
                if (expects_write != saw_write)
                    return error.InvalidTimerWriteProvenance;
            },
        }
        _ = try machineColumns(row, results);
        state = row.transition.after;
        if (row.provenance == .execution_tick) {
            mcycle = std.math.add(u32, mcycle, 1) catch
                return error.DisconnectedTimerClock;
            cycle += 1;
            saw_write = false;
            if (cycle == results[execution_row].m_cycles) {
                if (!std.meta.eql(
                    state,
                    try timerState(results[execution_row].after),
                ))
                    return error.InvalidMachineTimerAfter;
                execution_row += 1;
                cycle = 0;
            }
        }
    }
    if (execution_row != results.len or cycle != 0)
        return error.InvalidExecutionProvenance;
    if (mcycle != source.final_mcycle or
        !std.meta.eql(state, source.final_state))
        return error.InvalidTimerTraceEndpoint;
}

fn validateSuccessor(previous: EventRow, current: EventRow) !void {
    if (!std.meta.eql(previous.transition.after, current.transition.before))
        return error.DisconnectedTimerState;
    const previous_tick = previous.transition.event == .tick_mcycle;
    const expected_mcycle = std.math.add(
        u32,
        previous.mcycle,
        @intFromBool(previous_tick),
    ) catch return error.DisconnectedTimerClock;
    if (current.mcycle != expected_mcycle)
        return error.DisconnectedTimerClock;
    if (previous.transition.event != .tick_mcycle and
        current.transition.event != .tick_mcycle)
        return error.InvalidTimerEventOrder;
}

fn append(
    rows: []EventRow,
    index: *usize,
    state: *timer_runner.Timer,
    mcycle: u32,
    event_value: timer_air.Event,
    provenance: Provenance,
) !void {
    const transition = timer_air.Transition.apply(state.*, event_value);
    rows[index.*] = .{
        .mcycle = mcycle,
        .transition = transition,
        .provenance = provenance,
    };
    index.* += 1;
    state.* = transition.after;
}

fn writeEvent(register: Register, value: u8) timer_air.Event {
    return switch (register) {
        .div => .{ .write_div = value },
        .tima => .{ .write_tima = value },
        .tma => .{ .write_tma = value },
        .tac => .{ .write_tac = value },
    };
}

fn validateMetadata(access: runner.cartridge_memory.Access) !void {
    const is_timer = access.logical_address >= FIRST_ADDRESS and
        access.logical_address <= FIRST_ADDRESS + 3;
    if (is_timer != (access.region == .timer_mmio))
        return error.InvalidTimerMetadata;
}

fn machineAccessAt(
    results: []const machine.CartridgeStepResult,
    position: ExecutionPosition,
) !?runner.cartridge_memory.Access {
    if (position.execution_row >= results.len)
        return error.InvalidExecutionProvenance;
    const result = results[position.execution_row];
    try validateMachineResult(result);
    if (position.cycle >= result.m_cycles)
        return error.InvalidExecutionProvenance;
    return machineAccess(result, position.cycle);
}

fn machineAccess(
    result: machine.CartridgeStepResult,
    cycle: u3,
) ?runner.cartridge_memory.Access {
    if (result.instruction) |instruction|
        return instruction.accesses[cycle];
    if (result.event == .interrupt_service)
        return result.service.activeCycles()[cycle].access;
    return null;
}

fn validateMachineResult(
    result: machine.CartridgeStepResult,
) !void {
    if (!result.hasCanonicalShape())
        return error.InvalidSchedulerStep;
    if (result.instruction) |instruction|
        _ = cartridge_access.ValidatedStep.init(instruction) catch
            return error.InvalidExecutionStep;
}

fn timerState(state: machine.MachineState) !timer_runner.Timer {
    if (state.tac > 7 or
        (state.timer_reload == .reloading and state.tima != 0))
        return error.InvalidMachineTimerState;
    return .{
        .div_counter = state.div_counter,
        .tima = if (state.timer_reload == .reloading)
            state.tma
        else
            state.tima,
        .tma = state.tma,
        .tac = @truncate(state.tac),
        .reload_state = state.timer_reload,
    };
}

fn stepAt(
    steps: []const runner.CartridgeStepTrace,
    position: ExecutionPosition,
) !cartridge_access.ValidatedStep {
    if (position.execution_row >= steps.len)
        return error.InvalidExecutionProvenance;
    const step = cartridge_access.ValidatedStep.init(
        steps[position.execution_row],
    ) catch return error.InvalidExecutionProvenance;
    if (position.cycle >= step.trace.instruction.cycle_count)
        return error.InvalidExecutionProvenance;
    return step;
}

fn accessAt(
    steps: []const runner.CartridgeStepTrace,
    position: ExecutionPosition,
) !runner.cartridge_memory.Access {
    const step = try stepAt(steps, position);
    return step.trace.accesses[position.cycle] orelse
        return error.InvalidExecutionProvenance;
}

fn writeBits(out: []M31, value: u8) void {
    for (out, 0..) |*destination, index|
        destination.* = M31.fromCanonical(
            @intCast(value >> @intCast(index) & 1),
        );
}
