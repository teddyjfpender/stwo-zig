//! Canonical CPU-M-cycle schedule for the deterministic PPU timing AIR.
//!
//! A cycle has at most one register access before exactly four dot ticks.
//! LCDC/STAT/LYC writes are timing events; the hardware-ignored LY write and
//! all reads are carried on dot phase zero. Execution-derived traces require
//! the attached runner's `.ppu_mmio` classification for FF40/41/42/43/44/45/4A; a
//! generic-system relabel cannot authenticate a device event.
//!
//! VBlank/STAT requests are exposed by the borrowed timing rows. Binding their
//! OR contribution into committed IF bits 0 and 1 is a separate memory lookup.

const std = @import("std");
const M31_MODULUS = @import("stwo_core").fields.m31.Modulus;
const M31 = @import("stwo_core").fields.m31.M31;
const runner = @import("../runner/mod.zig");
const machine = @import("../runner/machine.zig");
const cartridge_access = @import("cartridge_access.zig");
const ppu_air = @import("ppu_timing.zig");
const scheduler_air = @import("scheduler.zig");
const ppu = @import("../runner/ppu_timing.zig");
const ppu_mmio = @import("../runner/ppu_mmio.zig");
const types = @import("ppu_binding_types.zig");
const binding_columns = @import("ppu_binding_columns.zig");

pub const Register = types.Register;
pub const LATCH_REGISTERS = types.LATCH_REGISTERS;
pub const latchIndex = types.latchIndex;
pub const ExecutionPosition = types.ExecutionPosition;
pub const ExecutionDot = types.ExecutionDot;
pub const Provenance = types.Provenance;
pub const State = types.State;
pub const RegisterAccess = types.RegisterAccess;
pub const Access = types.Access;
pub const Cycle = types.Cycle;
pub const EventRow = types.EventRow;
pub const Trace = types.Trace;

pub const MCYCLE_OFFSET = binding_columns.MCYCLE_OFFSET;
pub const PHASE_OFFSET = binding_columns.PHASE_OFFSET;
pub const READ_MARKER_OFFSET = binding_columns.READ_MARKER_OFFSET;
pub const READ_VALUE_OFFSET = binding_columns.READ_VALUE_OFFSET;
pub const LY_WRITE_ENABLED_OFFSET = binding_columns.LY_WRITE_ENABLED_OFFSET;
pub const LATCH_WRITE_MARKER_OFFSET = binding_columns.LATCH_WRITE_MARKER_OFFSET;
pub const LATCH_WRITE_VALUE_OFFSET = binding_columns.LATCH_WRITE_VALUE_OFFSET;
pub const LATCH_BEFORE_OFFSET = binding_columns.LATCH_BEFORE_OFFSET;
pub const LATCH_AFTER_OFFSET = binding_columns.LATCH_AFTER_OFFSET;
pub const LCDC_BEFORE_OFFSET = binding_columns.LCDC_BEFORE_OFFSET;
pub const LCDC_AFTER_OFFSET = binding_columns.LCDC_AFTER_OFFSET;
pub const REQUEST_SEEN_OFFSET = binding_columns.REQUEST_SEEN_OFFSET;
pub const N_MAIN_COLUMNS = binding_columns.N_MAIN_COLUMNS;
pub const Witness = binding_columns.Witness;

/// Builds the future execution adapter's canonical device trace.
///
/// `cycles` are intentionally device-only inputs. They must not be treated as
/// authenticated CPU accesses until a dedicated execution-side PPU relation
/// cancels every read/write event.
pub fn generateTrace(
    allocator: std.mem.Allocator,
    initial_mcycle: u32,
    final_mcycle: u32,
    initial_state: State,
    cycles: []const Cycle,
) !Trace {
    try initial_state.validate();
    if (cycles.len == 0) return error.EmptyPpuSegment;
    const cycle_count: u32 = std.math.cast(u32, cycles.len) orelse
        return error.PpuClockOverflow;
    const expected_final = std.math.add(
        u32,
        initial_mcycle,
        cycle_count,
    ) catch return error.PpuClockOverflow;
    if (expected_final != final_mcycle or final_mcycle >= M31_MODULUS)
        return error.InvalidPpuClockBoundary;

    var event_count = std.math.mul(usize, cycles.len, 4) catch
        return error.TooManyPpuEvents;
    for (cycles) |cycle| {
        if (cycle.access) |access| switch (access) {
            .write => |write| {
                if (isTimingWrite(write.register))
                    event_count = std.math.add(
                        usize,
                        event_count,
                        1,
                    ) catch return error.TooManyPpuEvents;
            },
            .read => {},
        };
    }
    const rows = try allocator.alloc(EventRow, event_count);
    errdefer allocator.free(rows);

    var state = initial_state;
    var mcycle = initial_mcycle;
    var at: usize = 0;
    for (cycles) |cycle| {
        var read_register: ?Register = null;
        var ignored_ly_write: ?u8 = null;
        var latch_write: ?RegisterAccess = null;
        if (cycle.access) |access| switch (access) {
            .read => |read| {
                if (read.value != state.read(read.register))
                    return error.InvalidPpuReadValue;
                read_register = read.register;
            },
            .write => |write| switch (write.register) {
                .ly => ignored_ly_write = write.value,
                .scy, .scx, .wy => latch_write = write,
                .lcdc, .stat, .lyc => {
                    const event_value: ppu.Event = switch (write.register) {
                        .lcdc => .{ .write_lcdc = write.value },
                        .stat => .{ .write_stat = write.value },
                        .lyc => .{ .write_lyc = write.value },
                        else => unreachable,
                    };
                    try append(
                        rows,
                        &at,
                        &state,
                        mcycle,
                        event_value,
                        null,
                        null,
                        null,
                        null,
                        if (cycle.execution_position) |position|
                            .{ .execution_write = position }
                        else
                            .detached,
                    );
                },
            },
        };
        for (0..4) |phase| {
            try append(
                rows,
                &at,
                &state,
                mcycle,
                .tick_dot,
                @intCast(phase),
                if (phase == 0) read_register else null,
                if (phase == 0) ignored_ly_write else null,
                if (phase == 0) latch_write else null,
                if (cycle.execution_position) |position|
                    .{ .execution_tick = .{
                        .position = position,
                        .phase = @intCast(phase),
                    } }
                else
                    .detached,
            );
        }
        mcycle = std.math.add(u32, mcycle, 1) catch
            return error.PpuClockOverflow;
    }
    std.debug.assert(at == rows.len);
    return .{
        .rows = rows,
        .final_state = state,
        .final_mcycle = mcycle,
    };
}

/// Derives the canonical PPU schedule from authenticated execution metadata.
///
/// Attached FF40/41/42/43/44/45/4A accesses must be labelled `.ppu_mmio`. Ordinary
/// accesses contribute only the four dot ticks for their M-cycle.
pub fn generateFromExecution(
    allocator: std.mem.Allocator,
    initial_mcycle: u32,
    final_mcycle: u32,
    initial_state: State,
    steps: []const runner.CartridgeStepTrace,
) !Trace {
    var cycle_count: usize = 0;
    for (steps) |step_value| {
        const step = cartridge_access.ValidatedStep.init(step_value) catch
            return error.InvalidExecutionStep;
        cycle_count = std.math.add(
            usize,
            cycle_count,
            step.trace.instruction.cycle_count,
        ) catch return error.TooManyPpuEvents;
        for (step.trace.activeAccesses()) |maybe_access| {
            const access = maybe_access orelse continue;
            _ = try executionAccess(access);
        }
    }
    if (cycle_count == 0) return error.EmptyPpuSegment;
    const cycles = try allocator.alloc(Cycle, cycle_count);
    defer allocator.free(cycles);
    var at: usize = 0;
    for (steps, 0..) |step_value, execution_row| {
        const step = cartridge_access.ValidatedStep.init(step_value) catch
            return error.InvalidExecutionStep;
        const row = std.math.cast(u32, execution_row) orelse
            return error.TooManyPpuEvents;
        for (step.trace.activeAccesses(), 0..) |maybe_access, cycle| {
            cycles[at] = .{
                .access = if (maybe_access) |access|
                    try executionAccess(access)
                else
                    null,
                .execution_position = .{
                    .execution_row = row,
                    .cycle = @intCast(cycle),
                },
            };
            at += 1;
        }
    }
    std.debug.assert(at == cycles.len);
    return generateTrace(
        allocator,
        initial_mcycle,
        final_mcycle,
        initial_state,
        cycles,
    );
}

/// Derives PPU cycles from the canonical cartridge-aware scheduler stream.
///
/// Instruction rows retain their MMIO metadata. HALT idle/wake and interrupt
/// service rows contribute elapsed M-cycles only; service accesses have no
/// proven cycle position and therefore cannot be invented as PPU MMIO.
pub fn generateFromMachineExecution(
    allocator: std.mem.Allocator,
    initial_mcycle: u32,
    final_mcycle: u32,
    initial_state: State,
    results: []const machine.CartridgeStepResult,
) !Trace {
    var cycle_count: usize = 0;
    for (results, 0..) |result, index| {
        try validateMachineResult(result);
        if (index != 0 and
            !std.meta.eql(results[index - 1].after, result.before))
            return error.DisconnectedMachineExecution;
        cycle_count = std.math.add(
            usize,
            cycle_count,
            result.m_cycles,
        ) catch return error.TooManyPpuEvents;
        if (result.instruction) |instruction| {
            _ = cartridge_access.ValidatedStep.init(instruction) catch
                return error.InvalidExecutionStep;
        }
    }
    if (cycle_count == 0) return error.EmptyPpuSegment;
    const cycles = try allocator.alloc(Cycle, cycle_count);
    defer allocator.free(cycles);
    var at: usize = 0;
    for (results, 0..) |result, execution_row| {
        const row = std.math.cast(u32, execution_row) orelse
            return error.TooManyPpuEvents;
        const instruction = result.instruction;
        for (0..result.m_cycles) |cycle| {
            const access = if (instruction) |trace|
                if (trace.activeAccesses()[cycle]) |value|
                    try executionAccess(value)
                else
                    null
            else
                null;
            cycles[at] = .{
                .access = access,
                .execution_position = .{
                    .execution_row = row,
                    .cycle = @intCast(cycle),
                },
            };
            at += 1;
        }
    }
    std.debug.assert(at == cycles.len);
    return generateTrace(
        allocator,
        initial_mcycle,
        final_mcycle,
        initial_state,
        cycles,
    );
}

fn executionAccess(
    access: runner.cartridge_memory.Access,
) !?Access {
    const register = registerForAddress(access.logical_address);
    if (register == null) {
        if (access.region == .ppu_mmio)
            return error.InvalidPpuMmioMetadata;
        return null;
    }
    if (access.region != .ppu_mmio)
        return error.UnauthenticatedPpuMmioMetadata;
    return switch (access.action) {
        .read => .{ .read = .{
            .register = register.?,
            .value = access.value,
        } },
        .write => .{ .write = .{
            .register = register.?,
            .value = access.value,
        } },
    };
}

pub fn generateWitness(
    allocator: std.mem.Allocator,
    source: Trace,
) !Witness {
    try validateTrace(source);
    for (source.rows) |row|
        if (row.provenance != .detached)
            return error.ExecutionMetadataRequiresAuthentication;
    return allocateWitness(allocator, source);
}

/// Builds a witness only after every PPU row is tied to one execution cycle.
pub fn generateExecutionWitness(
    allocator: std.mem.Allocator,
    source: Trace,
    steps: []const runner.CartridgeStepTrace,
    initial_mcycle: u32,
) !Witness {
    try validateTrace(source);
    try validateExecutionRows(source.rows, steps, initial_mcycle);
    return allocateWitness(allocator, source);
}

pub fn generateMachineExecutionWitness(
    allocator: std.mem.Allocator,
    source: Trace,
    results: []const machine.CartridgeStepResult,
    initial_mcycle: u32,
) !Witness {
    try validateTrace(source);
    try validateMachineExecutionRows(
        source.rows,
        results,
        initial_mcycle,
    );
    return allocateWitness(allocator, source);
}

fn allocateWitness(
    allocator: std.mem.Allocator,
    source: Trace,
) !Witness {
    const padded = std.math.ceilPowerOfTwo(
        usize,
        @max(source.rows.len, 16),
    ) catch return error.PpuTraceTooLong;
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
    var request_seen = false;
    var mcycle = source.rows[0].mcycle;
    for (source.rows, 0..) |row, index| {
        if (row.mcycle != mcycle) {
            request_seen = false;
            mcycle = row.mcycle;
        }
        var values = try columns(row);
        values[REQUEST_SEEN_OFFSET] =
            M31.fromCanonical(@intFromBool(request_seen));
        request_seen = request_seen or
            row.transition.interrupts.vblank or
            row.transition.interrupts.stat;
        const storage = try @import("stwo_core").air.utils
            .circleBitReversedIndex(log_size, index);
        for (&result.main, values) |column, value|
            column[storage] = value;
    }
    return result;
}

/// Rejects detached, reordered, substituted, or incompletely covered rows.
///
/// The binding and lookup AIRs authenticate the resulting values; this check
/// makes the witness construction boundary fail closed on stale host metadata.
pub fn validateExecutionRows(
    rows: []const EventRow,
    steps: []const runner.CartridgeStepTrace,
    initial_mcycle: u32,
) !void {
    const endpoint = try validateRows(rows);
    if (rows[0].mcycle != initial_mcycle)
        return error.InvalidExecutionProvenance;

    var at: usize = 0;
    var mcycle = initial_mcycle;
    for (steps, 0..) |step_value, execution_row| {
        const step = cartridge_access.ValidatedStep.init(step_value) catch
            return error.InvalidExecutionStep;
        const row = std.math.cast(u32, execution_row) orelse
            return error.InvalidExecutionProvenance;
        for (step.trace.activeAccesses(), 0..) |maybe_access, cycle| {
            if (mcycle >= M31_MODULUS)
                return error.NonCanonicalPpuClock;
            const access = if (maybe_access) |value|
                try executionAccess(value)
            else
                null;
            const position = ExecutionPosition{
                .execution_row = row,
                .cycle = @intCast(cycle),
            };
            try validateExecutionCycle(
                rows,
                &at,
                position,
                access,
                mcycle,
            );
            mcycle = std.math.add(u32, mcycle, 1) catch
                return error.PpuClockOverflow;
        }
    }
    if (at != rows.len or endpoint.final_mcycle != mcycle)
        return error.InvalidExecutionProvenance;
    if (mcycle >= M31_MODULUS)
        return error.NonCanonicalPpuClock;
}

pub fn validateMachineExecutionRows(
    rows: []const EventRow,
    results: []const machine.CartridgeStepResult,
    initial_mcycle: u32,
) !void {
    const endpoint = try validateRows(rows);
    if (rows[0].mcycle != initial_mcycle)
        return error.InvalidExecutionProvenance;
    var at: usize = 0;
    var mcycle = initial_mcycle;
    for (results, 0..) |result, execution_row| {
        try validateMachineResult(result);
        if (execution_row != 0 and
            !std.meta.eql(results[execution_row - 1].after, result.before))
            return error.DisconnectedMachineExecution;
        const instruction = result.instruction;
        if (instruction) |trace| {
            _ = cartridge_access.ValidatedStep.init(trace) catch
                return error.InvalidExecutionStep;
        }
        const row = std.math.cast(u32, execution_row) orelse
            return error.InvalidExecutionProvenance;
        for (0..result.m_cycles) |cycle| {
            if (mcycle >= M31_MODULUS)
                return error.NonCanonicalPpuClock;
            const access = if (instruction) |trace|
                if (trace.activeAccesses()[cycle]) |value|
                    try executionAccess(value)
                else
                    null
            else
                null;
            try validateExecutionCycle(
                rows,
                &at,
                .{
                    .execution_row = row,
                    .cycle = @intCast(cycle),
                },
                access,
                mcycle,
            );
            mcycle = std.math.add(u32, mcycle, 1) catch
                return error.PpuClockOverflow;
        }
    }
    if (at != rows.len or endpoint.final_mcycle != mcycle)
        return error.InvalidExecutionProvenance;
    if (mcycle >= M31_MODULUS)
        return error.NonCanonicalPpuClock;
}

fn validateMachineResult(result: machine.CartridgeStepResult) !void {
    _ = scheduler_air.ValidatedStep.init(result) catch
        return error.InvalidSchedulerStep;
    if (result.event == .interrupt_service)
        for (result.service.activeCycles()) |cycle|
            if (cycle.access) |access|
                if (registerForAddress(access.logical_address) != null)
                    return error.UnscheduledServicePpuMmio;
}

pub fn columns(row: EventRow) ![N_MAIN_COLUMNS]M31 {
    if (row.mcycle >= M31_MODULUS)
        return error.NonCanonicalPpuClock;
    const validated = ppu_air.ValidatedStep.init(row.transition) catch
        return error.InvalidPpuTransition;
    try validateRowShape(row);
    switch (row.provenance) {
        .detached => {},
        .execution_write => if (row.dot_phase != null)
            return error.InvalidExecutionProvenance,
        .execution_tick => |tick| if (row.dot_phase != tick.phase)
            return error.InvalidExecutionProvenance,
    }
    _ = validated;
    return binding_columns.encode(row);
}

pub fn inactiveColumns() [N_MAIN_COLUMNS]M31 {
    return binding_columns.inactive();
}

pub fn registerForAddress(address: u16) ?Register {
    return switch (address) {
        ppu_mmio.LCDC_ADDRESS => .lcdc,
        ppu_mmio.STAT_ADDRESS => .stat,
        ppu_mmio.SCY_ADDRESS => .scy,
        ppu_mmio.SCX_ADDRESS => .scx,
        ppu_mmio.LY_ADDRESS => .ly,
        ppu_mmio.LYC_ADDRESS => .lyc,
        ppu_mmio.WY_ADDRESS => .wy,
        else => null,
    };
}

fn validateTrace(source: Trace) !void {
    if (source.final_mcycle >= M31_MODULUS)
        return error.NonCanonicalPpuClock;
    const endpoint = try validateRows(source.rows);
    if (!std.meta.eql(endpoint.state, source.final_state) or
        endpoint.final_mcycle != source.final_mcycle)
        return error.InvalidPpuTraceEndpoint;
}

const RowsEndpoint = struct {
    state: State,
    final_mcycle: u32,
};

fn validateRows(rows: []const EventRow) !RowsEndpoint {
    if (rows.len == 0) return error.EmptyPpuTrace;
    var state = State{
        .timing = rows[0].transition.before,
        .lcdc = rows[0].lcdc_before,
        .scy = rows[0].latches_before[0],
        .scx = rows[0].latches_before[1],
        .wy = rows[0].latches_before[2],
    };
    var expected_mcycle = rows[0].mcycle;
    for (rows, 0..) |row, index| {
        if (row.mcycle != expected_mcycle or
            !std.meta.eql(state.timing, row.transition.before) or
            state.lcdc != row.lcdc_before or
            !std.meta.eql(state.latches(), row.latches_before))
            return error.DisconnectedPpuTrace;
        _ = try columns(row);
        if (index != 0) try validateOrder(rows[index - 1], row);
        state = .{
            .timing = row.transition.after,
            .lcdc = row.lcdc_after,
            .scy = row.latches_after[0],
            .scx = row.latches_after[1],
            .wy = row.latches_after[2],
        };
        if (row.dot_phase == 3)
            expected_mcycle = std.math.add(
                u32,
                expected_mcycle,
                1,
            ) catch return error.PpuClockOverflow;
    }
    if (rows[rows.len - 1].dot_phase != 3)
        return error.InvalidPpuTraceEndpoint;
    return .{ .state = state, .final_mcycle = expected_mcycle };
}

fn validateExecutionCycle(
    rows: []const EventRow,
    at: *usize,
    position: ExecutionPosition,
    access: ?Access,
    mcycle: u32,
) !void {
    if (access) |value| switch (value) {
        .write => |write| if (isTimingWrite(write.register)) {
            if (at.* >= rows.len)
                return error.InvalidExecutionProvenance;
            try validateExecutionWrite(
                rows[at.*],
                position,
                write,
                mcycle,
            );
            at.* += 1;
        },
        .read => {},
    };
    for (0..4) |phase| {
        if (at.* >= rows.len)
            return error.InvalidExecutionProvenance;
        try validateExecutionTick(
            rows[at.*],
            position,
            @intCast(phase),
            access,
            mcycle,
        );
        at.* += 1;
    }
}

fn validateExecutionWrite(
    row: EventRow,
    position: ExecutionPosition,
    write: RegisterAccess,
    mcycle: u32,
) !void {
    if (row.mcycle != mcycle or
        !std.meta.eql(
            row.provenance,
            Provenance{ .execution_write = position },
        ))
        return error.InvalidPpuWriteProvenance;
    const event: ppu.Event = switch (write.register) {
        .lcdc => .{ .write_lcdc = write.value },
        .stat => .{ .write_stat = write.value },
        .lyc => .{ .write_lyc = write.value },
        else => unreachable,
    };
    if (!std.meta.eql(row.transition.event, event))
        return error.InvalidPpuWriteProvenance;
}

fn validateExecutionTick(
    row: EventRow,
    position: ExecutionPosition,
    phase: u2,
    access: ?Access,
    mcycle: u32,
) !void {
    if (row.mcycle != mcycle or
        !std.meta.eql(
            row.provenance,
            Provenance{ .execution_tick = .{
                .position = position,
                .phase = phase,
            } },
        ))
        return error.InvalidPpuTickProvenance;
    var expected_read: ?Register = null;
    var expected_ly_write: ?u8 = null;
    var expected_latch_write: ?RegisterAccess = null;
    if (phase == 0) if (access) |value| switch (value) {
        .read => |read| {
            expected_read = read.register;
            const state = State{
                .timing = row.transition.before,
                .lcdc = row.lcdc_before,
                .scy = row.latches_before[0],
                .scx = row.latches_before[1],
                .wy = row.latches_before[2],
            };
            if (read.value != state.read(read.register))
                return error.InvalidPpuReadProvenance;
        },
        .write => |write| switch (write.register) {
            .ly => expected_ly_write = write.value,
            .scy, .scx, .wy => expected_latch_write = write,
            .lcdc, .stat, .lyc => {},
        },
    };
    if (row.read_register != expected_read or
        row.ignored_ly_write != expected_ly_write or
        !std.meta.eql(row.latch_write, expected_latch_write))
        return error.InvalidPpuAccessProvenance;
}

fn validateOrder(previous: EventRow, current: EventRow) !void {
    const previous_write = previous.dot_phase == null;
    const expected_phase: ?u2 = if (previous_write)
        0
    else if (previous.dot_phase.? < 3)
        previous.dot_phase.? + 1
    else
        null;
    if (expected_phase) |phase| {
        if (current.dot_phase != phase)
            return error.InvalidPpuEventOrder;
    } else if (current.dot_phase != null and current.dot_phase != 0) {
        return error.InvalidPpuEventOrder;
    }
    const increment: u32 = @intFromBool(previous.dot_phase == 3);
    if (current.mcycle != previous.mcycle + increment)
        return error.DisconnectedPpuClock;
}

fn validateRowShape(row: EventRow) !void {
    const tag = std.meta.activeTag(row.transition.event);
    const tick = tag == .tick_dot;
    if (tick != (row.dot_phase != null))
        return error.InvalidPpuDotPhase;
    if ((row.read_register != null or row.ignored_ly_write != null or
        row.latch_write != null) and
        row.dot_phase != 0)
        return error.InvalidPpuAccessPhase;
    const access_count = @intFromBool(row.read_register != null) +
        @intFromBool(row.ignored_ly_write != null) +
        @intFromBool(row.latch_write != null);
    if (access_count > 1)
        return error.MultiplePpuAccesses;
    var expected_latches = row.latches_before;
    if (row.latch_write) |write| {
        const index = latchIndex(write.register) orelse
            return error.InvalidPpuLatchWrite;
        expected_latches[index] = write.value;
    }
    if (!std.meta.eql(expected_latches, row.latches_after))
        return error.InvalidPpuLatchState;
    if ((row.lcdc_before & 0x80 != 0) !=
        row.transition.before.lcd_enabled or
        (row.lcdc_after & 0x80 != 0) !=
            row.transition.after.lcd_enabled)
        return error.LcdcEnableMismatch;
    const expected_lcdc = switch (row.transition.event) {
        .write_lcdc => |value| value,
        else => row.lcdc_before,
    };
    if (row.lcdc_after != expected_lcdc)
        return error.InvalidLcdcState;
}

fn isTimingWrite(register: Register) bool {
    return switch (register) {
        .lcdc, .stat, .lyc => true,
        .scy, .scx, .ly, .wy => false,
    };
}

fn append(
    rows: []EventRow,
    at: *usize,
    state: *State,
    mcycle: u32,
    event_value: ppu.Event,
    dot_phase: ?u2,
    read_register: ?Register,
    ignored_ly_write: ?u8,
    latch_write: ?RegisterAccess,
    provenance: Provenance,
) !void {
    const transition = try ppu.Transition.apply(
        state.timing,
        event_value,
    );
    const lcdc_after = switch (event_value) {
        .write_lcdc => |value| value,
        else => state.lcdc,
    };
    const latches_before = state.latches();
    if (latch_write) |write|
        if (!state.writeLatch(write.register, write.value))
            return error.InvalidPpuLatchWrite;
    const latches_after = state.latches();
    rows[at.*] = .{
        .mcycle = mcycle,
        .transition = transition,
        .lcdc_before = state.lcdc,
        .lcdc_after = lcdc_after,
        .latches_before = latches_before,
        .latches_after = latches_after,
        .latch_write = latch_write,
        .dot_phase = dot_phase,
        .read_register = read_register,
        .ignored_ly_write = ignored_ly_write,
        .provenance = provenance,
    };
    at.* += 1;
    state.* = .{
        .timing = transition.after,
        .lcdc = lcdc_after,
        .scy = latches_after[0],
        .scx = latches_after[1],
        .wy = latches_after[2],
    };
}
