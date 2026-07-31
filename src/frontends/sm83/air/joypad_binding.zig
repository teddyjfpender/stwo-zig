//! Checked witness layout shared by joypad action and MMIO lookups.

const std = @import("std");
const M31_MODULUS = @import("stwo_core").fields.m31.Modulus;
const M31 = @import("stwo_core").fields.m31.M31;
const event_trace = @import("../joypad_trace.zig");
const runner = @import("../runner/mod.zig");
const machine = @import("../runner/machine.zig");
const cartridge_access = @import("cartridge_access.zig");
const joypad_component = @import("joypad_component.zig");

pub const MCYCLE_OFFSET: usize = joypad_component.N_MAIN_COLUMNS;
pub const READ_ENABLED_OFFSET: usize = MCYCLE_OFFSET + 1;
pub const N_MAIN_COLUMNS: usize = READ_ENABLED_OFFSET + 1;

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

pub fn generateWitness(
    allocator: std.mem.Allocator,
    source: event_trace.Trace,
    steps: []const runner.CartridgeStepTrace,
) !Witness {
    try validateTrace(source, steps);
    return allocateWitness(allocator, source, .{ .instruction = steps });
}

pub fn generateMachineExecutionWitness(
    allocator: std.mem.Allocator,
    source: event_trace.Trace,
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
    source: event_trace.Trace,
    column_source: ColumnSource,
) !Witness {
    const padded = std.math.ceilPowerOfTwo(
        usize,
        @max(source.rows.len, 16),
    ) catch return error.JoypadTraceTooLong;
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
    row: event_trace.EventRow,
    steps: []const runner.CartridgeStepTrace,
) ![N_MAIN_COLUMNS]M31 {
    const access = switch (row.provenance) {
        .action_index => null,
        .execution_write => |position| try accessAt(steps, position),
        .execution_tick => |position| blk: {
            const step = try stepAt(steps, position);
            break :blk step.trace.accesses[position.cycle];
        },
    };
    return columnsForAccess(row, access);
}

pub fn machineColumns(
    row: event_trace.EventRow,
    results: []const machine.CartridgeStepResult,
) ![N_MAIN_COLUMNS]M31 {
    const access = switch (row.provenance) {
        .action_index => null,
        .execution_write, .execution_tick => |position| event_trace.machineAccessAt(results, position) catch |err|
            switch (err) {
                error.InvalidSchedulerStep => return error.InvalidSchedulerStep,
                error.InvalidExecutionStep => return error.InvalidExecutionProvenance,
                else => return err,
            },
    };
    return columnsForAccess(row, access);
}

fn columnsForAccess(
    row: event_trace.EventRow,
    access: ?runner.cartridge_memory.Access,
) ![N_MAIN_COLUMNS]M31 {
    if (row.mcycle >= M31_MODULUS)
        return error.NonCanonicalJoypadClock;
    const validated = @import("joypad.zig").ValidatedStep.init(
        row.transition,
    ) catch return error.InvalidJoypadTransition;
    var result = [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
    const semantic = joypad_component.columns(validated);
    @memcpy(result[0..joypad_component.N_MAIN_COLUMNS], &semantic);
    result[MCYCLE_OFFSET] = M31.fromCanonical(row.mcycle);
    if (access) |item| try validateAccessMetadata(item);

    switch (row.provenance) {
        .action_index => if (row.transition.event != .set_pressed)
            return error.InvalidActionProvenance,
        .execution_write => {
            const item = access orelse
                return error.InvalidWriteProvenance;
            if (row.transition.event != .write_p1 or
                item.region != .joypad_mmio or
                item.action != .write or
                item.value != row.transition.event.write_p1)
                return error.InvalidWriteProvenance;
        },
        .execution_tick => {
            if (row.transition.event != .tick_mcycle)
                return error.InvalidTickProvenance;
            if (access) |item| {
                if (item.region == .joypad_mmio and
                    item.action == .read)
                    result[READ_ENABLED_OFFSET] = M31.one();
            }
        },
    }
    return result;
}

pub fn inactiveColumns() [N_MAIN_COLUMNS]M31 {
    return [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
}

fn validateTrace(
    source: event_trace.Trace,
    steps: []const runner.CartridgeStepTrace,
) !void {
    if (source.rows.len == 0) return error.EmptyJoypadTrace;
    if (source.final_mcycle >= M31_MODULUS)
        return error.NonCanonicalJoypadClock;

    var execution_row: usize = 0;
    var cycle: usize = 0;
    var mcycle = source.rows[0].mcycle;
    var action_index: u32 = 0;
    for (source.rows, 0..) |row, index| {
        if (row.mcycle != mcycle)
            return error.DisconnectedJoypadClock;
        if (index != 0)
            try validateSuccessor(source.rows[index - 1], row);
        if (execution_row >= steps.len)
            return error.InvalidExecutionProvenance;

        switch (row.provenance) {
            .action_index => |actual| {
                if (actual != action_index)
                    return error.InvalidActionProvenance;
                action_index = std.math.add(u32, action_index, 1) catch
                    return error.InvalidActionProvenance;
            },
            .execution_write => |position| {
                try validatePosition(position, execution_row, cycle);
            },
            .execution_tick => |position| {
                try validatePosition(position, execution_row, cycle);
                const step = try stepAt(steps, position);
                mcycle = std.math.add(u32, mcycle, 1) catch
                    return error.DisconnectedJoypadClock;
                cycle += 1;
                if (cycle == step.trace.instruction.cycle_count) {
                    execution_row += 1;
                    cycle = 0;
                }
            },
        }
        _ = try columns(row, steps);
    }
    if (execution_row != steps.len or cycle != 0)
        return error.InvalidExecutionProvenance;

    const last = source.rows[source.rows.len - 1];
    if (last.transition.event != .tick_mcycle or
        !std.meta.eql(last.transition.after, source.final_state))
        return error.InvalidJoypadTraceEndpoint;
    if (mcycle != source.final_mcycle)
        return error.InvalidJoypadTraceEndpoint;
}

fn validateMachineTrace(
    source: event_trace.Trace,
    results: []const machine.CartridgeStepResult,
) !void {
    if (source.rows.len == 0) return error.EmptyJoypadTrace;
    if (source.final_mcycle >= M31_MODULUS)
        return error.NonCanonicalJoypadClock;
    var execution_row: usize = 0;
    var cycle: usize = 0;
    var mcycle = source.rows[0].mcycle;
    var action_index: u32 = 0;
    var saw_action = false;
    var saw_write = false;
    for (source.rows, 0..) |row, index| {
        if (row.mcycle != mcycle)
            return error.DisconnectedJoypadClock;
        if (index != 0)
            try validateSuccessor(source.rows[index - 1], row);
        if (execution_row >= results.len)
            return error.InvalidExecutionProvenance;
        if (cycle == 0) {
            if (!results[execution_row].hasCanonicalShape())
                return error.InvalidSchedulerStep;
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
        switch (row.provenance) {
            .action_index => |actual| {
                if (actual != action_index or saw_action or saw_write)
                    return error.InvalidActionProvenance;
                action_index = std.math.add(u32, action_index, 1) catch
                    return error.InvalidActionProvenance;
                saw_action = true;
            },
            .execution_write => |position| {
                if (saw_write)
                    return error.InvalidWriteProvenance;
                try validatePosition(position, execution_row, cycle);
                const access = (event_trace.machineAccessAt(
                    results,
                    position,
                ) catch return error.InvalidExecutionProvenance) orelse
                    return error.InvalidWriteProvenance;
                if (access.region != .joypad_mmio or
                    access.action != .write)
                    return error.InvalidWriteProvenance;
                saw_write = true;
            },
            .execution_tick => |position| {
                try validatePosition(position, execution_row, cycle);
                const access = event_trace.machineAccessAt(
                    results,
                    position,
                ) catch return error.InvalidExecutionProvenance;
                const expects_write = if (access) |item|
                    item.region == .joypad_mmio and item.action == .write
                else
                    false;
                if (expects_write != saw_write)
                    return error.InvalidWriteProvenance;
                mcycle = std.math.add(u32, mcycle, 1) catch
                    return error.DisconnectedJoypadClock;
                cycle += 1;
                saw_action = false;
                saw_write = false;
                if (cycle == results[execution_row].m_cycles) {
                    execution_row += 1;
                    cycle = 0;
                }
            },
        }
        _ = try machineColumns(row, results);
    }
    if (execution_row != results.len or cycle != 0)
        return error.InvalidExecutionProvenance;
    const last = source.rows[source.rows.len - 1];
    if (last.transition.event != .tick_mcycle or
        !std.meta.eql(last.transition.after, source.final_state) or
        mcycle != source.final_mcycle)
        return error.InvalidJoypadTraceEndpoint;
}

fn validateSuccessor(
    previous: event_trace.EventRow,
    current: event_trace.EventRow,
) !void {
    if (!std.meta.eql(
        previous.transition.after,
        current.transition.before,
    )) return error.DisconnectedJoypadState;
    const previous_tick = previous.transition.event == .tick_mcycle;
    const expected_mcycle = std.math.add(
        u32,
        previous.mcycle,
        @intFromBool(previous_tick),
    ) catch return error.DisconnectedJoypadClock;
    if (current.mcycle != expected_mcycle)
        return error.DisconnectedJoypadClock;
    if (previous.transition.event == .set_pressed and
        current.transition.event == .set_pressed)
        return error.InvalidJoypadEventOrder;
    if (previous.transition.event == .write_p1 and
        current.transition.event != .tick_mcycle)
        return error.InvalidJoypadEventOrder;
}

fn validateAccessMetadata(
    access: runner.cartridge_memory.Access,
) !void {
    if ((access.logical_address == runner.joypad.P1_ADDRESS) !=
        (access.region == .joypad_mmio))
        return error.InvalidJoypadMetadata;
}

fn validatePosition(
    position: event_trace.ExecutionPosition,
    execution_row: usize,
    cycle: usize,
) !void {
    if (position.execution_row != execution_row or
        position.cycle != cycle)
        return error.InvalidExecutionProvenance;
}

fn stepAt(
    steps: []const runner.CartridgeStepTrace,
    position: event_trace.ExecutionPosition,
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
    position: event_trace.ExecutionPosition,
) !runner.cartridge_memory.Access {
    const step = try stepAt(steps, position);
    return step.trace.accesses[position.cycle] orelse
        return error.InvalidExecutionProvenance;
}
