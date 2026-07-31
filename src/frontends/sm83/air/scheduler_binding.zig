//! Event-row binding between scheduler and execution components.
//!
//! Every cartridge scheduler row retains a six-column
//! execution provenance block: the four scheduler-event selectors and both
//! HALT-bug endpoints. The binding equates that provenance to the scheduler,
//! then ties each event to execution clock, CPU state, and first-bus shape.
//! The interrupt-service family owns the remaining pinned SameBoy bus cycles.
//!
//! IE and IF remain outside this binding. Sound authentication needs explicit
//! scheduler-sample memory accesses at FF0F/FFFF joined to the ordered mutable
//! memory relation; neither value appears in the current execution columns.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const machine = @import("../runner/machine.zig");
const execution = @import("execution.zig");
const execution_input = @import("execution_input.zig");
const scheduler = @import("scheduler.zig");
const scheduler_component = @import("scheduler_component.zig");

pub const N_EVENTS: usize = 4;
pub const N_PROVENANCE_COLUMNS: usize = N_EVENTS + 2;
pub const EVENT_OFFSET: usize = 0;
pub const BEFORE_HALT_BUG_OFFSET: usize = N_EVENTS;
pub const AFTER_HALT_BUG_OFFSET: usize = BEFORE_HALT_BUG_OFFSET + 1;
pub const N_CONSTRAINTS: usize = 31;
pub const MAX_CONSTRAINT_DEGREE: u32 = 3;

pub const Columns = struct {
    scheduler_main: [scheduler_component.N_MAIN_COLUMNS]M31,
    execution_main: [execution.N_MAIN_COLUMNS]M31,
    provenance_main: [N_PROVENANCE_COLUMNS]M31,
};

pub fn ProvenanceRow(comptime S: type) type {
    return struct {
        events: [N_EVENTS]S,
        before_halt_bug: S,
        after_halt_bug: S,

        pub fn fromColumns(values: []const S) !@This() {
            if (values.len != N_PROVENANCE_COLUMNS)
                return error.InvalidMainTraceShape;
            return .{
                .events = values[EVENT_OFFSET..BEFORE_HALT_BUG_OFFSET].*,
                .before_halt_bug = values[BEFORE_HALT_BUG_OFFSET],
                .after_halt_bug = values[AFTER_HALT_BUG_OFFSET],
            };
        }
    };
}

pub fn Evaluation(comptime S: type) type {
    return struct {
        values: [N_CONSTRAINTS]S,

        pub fn allZero(self: @This()) bool {
            for (self.values) |value|
                if (!value.isZero()) return false;
            return true;
        }
    };
}

pub fn evaluate(
    comptime S: type,
    scheduler_values: []const S,
    execution_values: []const S,
    provenance_values: []const S,
) !Evaluation(S) {
    const scheduled =
        try scheduler_component.Row(S).fromColumns(scheduler_values);
    const executed = try execution.Row(S).fromColumns(execution_values);
    const provenance = try ProvenanceRow(S).fromColumns(provenance_values);
    const one = S.one();
    const instruction = provenance.events[
        @intFromEnum(machine.SchedulerEvent.instruction)
    ];
    const idle = provenance.events[
        @intFromEnum(machine.SchedulerEvent.halt_idle)
    ];
    const wake = provenance.events[
        @intFromEnum(machine.SchedulerEvent.halt_wake)
    ];
    const service = provenance.events[
        @intFromEnum(machine.SchedulerEvent.interrupt_service)
    ];
    const halt = idle.add(wake);
    const supported = instruction.add(halt).add(service);
    const selector = scheduled.active.mul(supported);
    const mcycles = compose(scheduled.scheduler.mcycle_bits);
    var out: [N_CONSTRAINTS]S = undefined;
    var at: usize = 0;

    out[at] = one.sub(scheduled.active);
    at += 1;
    for (provenance.events ++ .{
        provenance.before_halt_bug,
        provenance.after_halt_bug,
    }) |value| {
        out[at] = value.mul(value.sub(one));
        at += 1;
    }
    var event_sum = S.zero();
    for (provenance.events) |event| event_sum = event_sum.add(event);
    out[at] = event_sum.sub(scheduled.active);
    at += 1;
    for (scheduled.scheduler.events, provenance.events) |
        scheduler_event,
        execution_event,
    | {
        out[at] = scheduler_event.sub(execution_event);
        at += 1;
    }
    out[at] = scheduled.scheduler.before_halt_bug.sub(
        provenance.before_halt_bug,
    );
    at += 1;
    out[at] = scheduled.scheduler.after_halt_bug.sub(
        provenance.after_halt_bug,
    );
    at += 1;
    bind(
        S,
        &out,
        &at,
        selector,
        scheduled.mcycle.sub(executed.mcycle_before),
    );
    bind(
        S,
        &out,
        &at,
        selector,
        mcycles.sub(
            executed.mcycle_after.sub(executed.mcycle_before),
        ),
    );
    for (
        [3]S{
            scheduled.scheduler.before_ime,
            scheduled.scheduler.before_pending,
            scheduled.scheduler.before_halted,
        },
        [3]S{
            executed.before.at(.ime),
            executed.before.at(.ime_enable_pending),
            executed.before.at(.halted),
        },
    ) |actual, expected| {
        bind(S, &out, &at, selector, actual.sub(expected));
    }
    for (
        [3]S{
            scheduled.scheduler.after_ime,
            scheduled.scheduler.after_pending,
            scheduled.scheduler.after_halted,
        },
        [3]S{
            executed.after.at(.ime),
            executed.after.at(.ime_enable_pending),
            executed.after.at(.halted),
        },
    ) |actual, expected| {
        bind(S, &out, &at, selector, actual.sub(expected));
    }
    bind(
        S,
        &out,
        &at,
        selector,
        executed.before.at(.stopped),
    );
    bind(
        S,
        &out,
        &at,
        selector,
        executed.after.at(.stopped),
    );
    const first_bus = executed.bus[0];
    bind(
        S,
        &out,
        &at,
        selector,
        first_bus.active.sub(scheduled.active),
    );
    bind(
        S,
        &out,
        &at,
        selector,
        first_bus.read.sub(
            supported.sub(scheduled.scheduler.before_halted),
        ),
    );
    bind(S, &out, &at, selector, first_bus.write);
    bind(S, &out, &at, selector, first_bus.program.sub(instruction));
    bind(S, &out, &at, scheduled.active.mul(halt), first_bus.address);
    bind(S, &out, &at, scheduled.active.mul(halt), first_bus.value);
    bind(
        S,
        &out,
        &at,
        scheduled.active.mul(halt),
        executed.branch_taken,
    );
    std.debug.assert(at == out.len);
    return .{ .values = out };
}

pub fn columns(
    source: anytype,
    mcycle_before: u32,
) !Columns {
    const T = @TypeOf(source);
    const validated = try scheduler.ValidatedStep.init(source);
    const result = validated.result;
    const execution_main = if (T == machine.CartridgeStepResult) blk: {
        const input = try execution_input.fromCartridgeMachine(source);
        break :blk try execution_input.cartridgeExecutionColumns(
            input,
            mcycle_before,
        );
    } else if (T == machine.StepResult) blk: {
        if (result.event != .instruction)
            return error.UnsupportedSchedulerEvent;
        const instruction = result.instruction orelse
            return error.UnsupportedSchedulerEvent;
        break :blk execution.columns(instruction, mcycle_before);
    } else @compileError("expected canonical scheduler result");
    return .{
        .scheduler_main = try scheduler_component.columns(
            validated,
            mcycle_before,
        ),
        .execution_main = execution_main,
        .provenance_main = provenanceColumns(result),
    };
}

pub fn evaluateM31(columns_value: Columns) !Evaluation(QM31) {
    var scheduler_values: [scheduler_component.N_MAIN_COLUMNS]QM31 = undefined;
    var execution_values: [execution.N_MAIN_COLUMNS]QM31 = undefined;
    var provenance_values: [N_PROVENANCE_COLUMNS]QM31 = undefined;
    for (&scheduler_values, columns_value.scheduler_main) |
        *destination,
        source,
    | destination.* = QM31.fromBase(source);
    for (&execution_values, columns_value.execution_main) |
        *destination,
        source,
    | destination.* = QM31.fromBase(source);
    for (&provenance_values, columns_value.provenance_main) |
        *destination,
        source,
    | destination.* = QM31.fromBase(source);
    return evaluate(
        QM31,
        &scheduler_values,
        &execution_values,
        &provenance_values,
    );
}

fn provenanceColumns(
    result: machine.StepResult,
) [N_PROVENANCE_COLUMNS]M31 {
    var out = [_]M31{M31.zero()} ** N_PROVENANCE_COLUMNS;
    out[EVENT_OFFSET + @intFromEnum(result.event)] = M31.one();
    out[BEFORE_HALT_BUG_OFFSET] = boolean(result.before.halt_bug);
    out[AFTER_HALT_BUG_OFFSET] = boolean(result.after.halt_bug);
    return out;
}

fn bind(
    comptime S: type,
    out: *[N_CONSTRAINTS]S,
    at: *usize,
    selector: S,
    difference: S,
) void {
    out[at.*] = selector.mul(difference);
    at.* += 1;
}

fn compose(bits: anytype) @TypeOf(bits[0]) {
    const S = @TypeOf(bits[0]);
    var result = S.zero();
    var power = S.one();
    for (bits) |bit_value| {
        result = result.add(power.mul(bit_value));
        power = power.add(power);
    }
    return result;
}

fn boolean(value: bool) M31 {
    return M31.fromCanonical(@intFromBool(value));
}
