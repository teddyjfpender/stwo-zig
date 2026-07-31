//! Canonical joypad-event trace derived from actions and cartridge execution.

const std = @import("std");
const action_schedule = @import("action_schedule.zig");
const cartridge_access = @import("air/cartridge_access.zig");
const runner = @import("runner/mod.zig");
const machine = @import("runner/machine.zig");

const joypad = runner.joypad;

pub const ExecutionPosition = struct {
    execution_row: u32,
    cycle: u3,
};

pub const Provenance = union(enum) {
    action_index: u32,
    execution_write: ExecutionPosition,
    execution_tick: ExecutionPosition,
};

pub const EventRow = struct {
    mcycle: u32,
    transition: joypad.Transition,
    provenance: Provenance,
};

pub const Error = action_schedule.Error || joypad.ValidationError || error{
    TooManyExecutionRows,
    TooManyEvents,
    TimeOverflow,
    FinalMcycleMismatch,
    InvalidExecutionStep,
    InvalidSchedulerStep,
    DisconnectedMachineExecution,
    DisconnectedMapperExecution,
    InvalidJoypadMetadata,
    InvalidJoypadReadValue,
    InvalidJoypadTransition,
    UnconsumedAction,
};

pub const Trace = struct {
    rows: []EventRow,
    final_state: joypad.State,
    final_mcycle: u32,

    pub fn deinit(self: *Trace, allocator: std.mem.Allocator) void {
        allocator.free(self.rows);
        self.* = undefined;
    }
};

pub fn generate(
    allocator: std.mem.Allocator,
    initial_mcycle: u32,
    final_mcycle: u32,
    initial_state: joypad.State,
    actions: []const action_schedule.Action,
    steps: []const runner.CartridgeStepTrace,
) (Error || std.mem.Allocator.Error)!Trace {
    try initial_state.validate();
    try action_schedule.validate(
        initial_mcycle,
        final_mcycle,
        actions,
    );
    _ = std.math.cast(u32, steps.len) orelse
        return error.TooManyExecutionRows;

    var mcycle_count: u32 = 0;
    var event_count = actions.len;
    for (steps) |step| {
        const validated = cartridge_access.ValidatedStep.init(step) catch
            return error.InvalidExecutionStep;
        mcycle_count = std.math.add(
            u32,
            mcycle_count,
            validated.trace.instruction.cycle_count,
        ) catch return error.TimeOverflow;
        event_count = std.math.add(
            usize,
            event_count,
            validated.trace.instruction.cycle_count,
        ) catch return error.TooManyEvents;
        for (validated.trace.activeAccesses()) |maybe_access| {
            const access = maybe_access orelse continue;
            try validateJoypadMetadata(access);
            if (access.region == .joypad_mmio and
                access.action == .write)
            {
                event_count = std.math.add(
                    usize,
                    event_count,
                    1,
                ) catch return error.TooManyEvents;
            }
        }
    }
    const expected_final = std.math.add(
        u32,
        initial_mcycle,
        mcycle_count,
    ) catch return error.TimeOverflow;
    if (expected_final != final_mcycle)
        return error.FinalMcycleMismatch;

    const rows = try allocator.alloc(EventRow, event_count);
    errdefer allocator.free(rows);
    var state = initial_state;
    var current_mcycle = initial_mcycle;
    var action_index: usize = 0;
    var row_index: usize = 0;

    for (steps, 0..) |step, execution_row| {
        const validated = cartridge_access.ValidatedStep.init(step) catch
            return error.InvalidExecutionStep;
        for (
            validated.trace.activeAccesses(),
            0..,
        ) |maybe_access, cycle| {
            if (action_index < actions.len and
                actions[action_index].mcycle == current_mcycle)
            {
                try append(
                    rows,
                    &row_index,
                    &state,
                    current_mcycle,
                    .{ .set_pressed = actions[action_index].pressed },
                    .{ .action_index = @intCast(action_index) },
                );
                action_index += 1;
            }

            if (maybe_access) |access| {
                try validateJoypadMetadata(access);
                if (access.region == .joypad_mmio) {
                    switch (access.action) {
                        .read => if (access.value != state.readP1())
                            return error.InvalidJoypadReadValue,
                        .write => try append(
                            rows,
                            &row_index,
                            &state,
                            current_mcycle,
                            .{ .write_p1 = access.value },
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
                current_mcycle,
                .tick_mcycle,
                .{ .execution_tick = .{
                    .execution_row = @intCast(execution_row),
                    .cycle = @intCast(cycle),
                } },
            );
            current_mcycle = std.math.add(
                u32,
                current_mcycle,
                1,
            ) catch return error.TimeOverflow;
        }
    }

    if (action_index != actions.len)
        return error.UnconsumedAction;
    if (current_mcycle != final_mcycle)
        return error.FinalMcycleMismatch;
    std.debug.assert(row_index == rows.len);
    return .{
        .rows = rows,
        .final_state = state,
        .final_mcycle = current_mcycle,
    };
}

/// Derives joypad events from every canonical cartridge scheduler M-cycle.
///
/// Interrupt service uses its pinned bus-cycle trace. Logical IE/IF samples
/// and acknowledgement are not CPU bus accesses.
pub fn generateFromMachineExecution(
    allocator: std.mem.Allocator,
    initial_mcycle: u32,
    final_mcycle: u32,
    initial_state: joypad.State,
    actions: []const action_schedule.Action,
    results: []const machine.CartridgeStepResult,
) (Error || std.mem.Allocator.Error)!Trace {
    try initial_state.validate();
    try action_schedule.validate(initial_mcycle, final_mcycle, actions);
    _ = std.math.cast(u32, results.len) orelse
        return error.TooManyExecutionRows;

    var mcycle_count: u32 = 0;
    var event_count = actions.len;
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
        mcycle_count = std.math.add(
            u32,
            mcycle_count,
            result.m_cycles,
        ) catch return error.TimeOverflow;
        event_count = std.math.add(
            usize,
            event_count,
            result.m_cycles,
        ) catch return error.TooManyEvents;
        for (0..result.m_cycles) |cycle| {
            const access = machineAccess(result, @intCast(cycle));
            if (access) |item| {
                try validateJoypadMetadata(item);
                if (item.region == .joypad_mmio and item.action == .write)
                    event_count = std.math.add(
                        usize,
                        event_count,
                        1,
                    ) catch return error.TooManyEvents;
            }
        }
    }
    const expected_final = std.math.add(
        u32,
        initial_mcycle,
        mcycle_count,
    ) catch return error.TimeOverflow;
    if (expected_final != final_mcycle)
        return error.FinalMcycleMismatch;

    const rows = try allocator.alloc(EventRow, event_count);
    errdefer allocator.free(rows);
    var state = initial_state;
    var current_mcycle = initial_mcycle;
    var action_index: usize = 0;
    var row_index: usize = 0;
    for (results, 0..) |result, execution_row| {
        for (0..result.m_cycles) |cycle| {
            if (action_index < actions.len and
                actions[action_index].mcycle == current_mcycle)
            {
                try append(
                    rows,
                    &row_index,
                    &state,
                    current_mcycle,
                    .{ .set_pressed = actions[action_index].pressed },
                    .{ .action_index = @intCast(action_index) },
                );
                action_index += 1;
            }
            if (machineAccess(result, @intCast(cycle))) |access| {
                if (access.region == .joypad_mmio) switch (access.action) {
                    .read => if (access.value != state.readP1())
                        return error.InvalidJoypadReadValue,
                    .write => try append(
                        rows,
                        &row_index,
                        &state,
                        current_mcycle,
                        .{ .write_p1 = access.value },
                        .{ .execution_write = .{
                            .execution_row = @intCast(execution_row),
                            .cycle = @intCast(cycle),
                        } },
                    ),
                };
            }
            try append(
                rows,
                &row_index,
                &state,
                current_mcycle,
                .tick_mcycle,
                .{ .execution_tick = .{
                    .execution_row = @intCast(execution_row),
                    .cycle = @intCast(cycle),
                } },
            );
            current_mcycle = std.math.add(
                u32,
                current_mcycle,
                1,
            ) catch return error.TimeOverflow;
        }
    }
    if (action_index != actions.len)
        return error.UnconsumedAction;
    if (current_mcycle != final_mcycle)
        return error.FinalMcycleMismatch;
    std.debug.assert(row_index == rows.len);
    return .{
        .rows = rows,
        .final_state = state,
        .final_mcycle = current_mcycle,
    };
}

pub fn machineAccessAt(
    results: []const machine.CartridgeStepResult,
    position: ExecutionPosition,
) Error!?runner.cartridge_memory.Access {
    if (position.execution_row >= results.len)
        return error.InvalidExecutionStep;
    const result = results[position.execution_row];
    try validateMachineResult(result);
    if (position.cycle >= result.m_cycles)
        return error.InvalidExecutionStep;
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
) Error!void {
    if (!result.hasCanonicalShape())
        return error.InvalidSchedulerStep;
    if (result.instruction) |instruction|
        _ = cartridge_access.ValidatedStep.init(instruction) catch
            return error.InvalidExecutionStep;
}

fn validateJoypadMetadata(
    access: runner.cartridge_memory.Access,
) Error!void {
    const is_p1 = access.logical_address == joypad.P1_ADDRESS;
    if (is_p1 != (access.region == .joypad_mmio))
        return error.InvalidJoypadMetadata;
}

fn append(
    rows: []EventRow,
    row_index: *usize,
    state: *joypad.State,
    mcycle: u32,
    event: joypad.Event,
    provenance: Provenance,
) Error!void {
    const transition = joypad.Transition.apply(
        state.*,
        event,
    ) catch return error.InvalidJoypadTransition;
    rows[row_index.*] = .{
        .mcycle = mcycle,
        .transition = transition,
        .provenance = provenance,
    };
    row_index.* += 1;
    state.* = transition.after;
}
