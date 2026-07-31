//! Canonical execution-derived OAM DMA schedule.
//!
//! Each active CPU M-cycle advances DMA exactly once, before the CPU access.
//! FF46 writes are derived from validated cartridge-access metadata. Today's
//! cartridge runner applies DMG bus blocking after that DMA transition. This
//! adapter derives the same post-transition class and rejects blocked cycles
//! until the shared memory proof models their redirected effects.
//!
//! Transfer source bytes are explicit witness inputs. `transferAccess` exposes
//! the source read and OAM write at the shared DMA memory phase; neither byte
//! is authenticated until the ROM/mutable-memory lookup claims cancel.

const std = @import("std");
const core_air_utils = @import("stwo_core").air.utils;
const M31_MODULUS = @import("stwo_core").fields.m31.Modulus;
const M31 = @import("stwo_core").fields.m31.M31;
const runner = @import("../runner/mod.zig");
const machine = @import("../runner/machine.zig");
const dma = @import("../runner/dma.zig");
const cartridge_access = @import("cartridge_access.zig");
const dma_air = @import("dma.zig");
const dma_component = @import("dma_component.zig");
const memory_clock = @import("cartridge_memory_clock.zig");
const scheduler_air = @import("scheduler.zig");

pub const ExecutionPosition = struct {
    execution_row: u32,
    cycle: u3,
};

pub const EventRow = struct {
    mcycle: u32,
    transition: dma.Transition,
    provenance: ExecutionPosition,
};

pub const Trace = struct {
    rows: []EventRow,
    final_state: dma.State,
    final_mcycle: u32,

    pub fn deinit(self: *Trace, allocator: std.mem.Allocator) void {
        allocator.free(self.rows);
        self.* = undefined;
    }
};

pub const TransferAccess = struct {
    clock: u32,
    source_address: u16,
    destination_address: u16,
    value: u8,
};

pub const MCYCLE_OFFSET: usize = dma_component.N_MAIN_COLUMNS;
pub const BUS_ADDRESS_OFFSET: usize = MCYCLE_OFFSET + 1;
pub const BUS_VALUE_OFFSET: usize = BUS_ADDRESS_OFFSET + 16;
pub const BUS_ACTION_OFFSET: usize = BUS_VALUE_OFFSET + 8;
pub const CPU_CLASS_OFFSET: usize = BUS_ACTION_OFFSET + 3;
pub const COPIED_NONZERO_OFFSET: usize = CPU_CLASS_OFFSET + 3;
pub const COPIED_INVERSE_OFFSET: usize = COPIED_NONZERO_OFFSET + 1;
pub const PAGE_VRAM_OFFSET: usize = COPIED_INVERSE_OFFSET + 1;
pub const HIGH_FE_CHAIN_OFFSET: usize = PAGE_VRAM_OFFSET + 1;
pub const ADDRESS_VRAM_OFFSET: usize = HIGH_FE_CHAIN_OFFSET + 7;
pub const ADDRESS_OAM_OFFSET: usize = ADDRESS_VRAM_OFFSET + 1;
pub const OAM_BLOCKED_OFFSET: usize = ADDRESS_OAM_OFFSET + 1;
pub const SOURCE_BLOCKED_OFFSET: usize = OAM_BLOCKED_OFFSET + 1;
pub const BUS_MATCH_OFFSET: usize = SOURCE_BLOCKED_OFFSET + 1;
pub const FF46_MATCH_OFFSET: usize = BUS_MATCH_OFFSET + 1;
pub const FF46_INVERSE_OFFSET: usize = FF46_MATCH_OFFSET + 1;
pub const CPU_PAGE_VRAM_OFFSET: usize = FF46_INVERSE_OFFSET + 1;
pub const N_MAIN_COLUMNS: usize = CPU_PAGE_VRAM_OFFSET + 1;

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
    initial_state: dma.State,
    steps: []const runner.CartridgeStepTrace,
    source_bytes: []const u8,
) !Trace {
    try initial_state.validate();
    if (initial_state.clock != initial_mcycle)
        return error.DmaClockMismatch;
    if (initial_mcycle >= final_mcycle or final_mcycle >= M31_MODULUS)
        return error.InvalidDmaClockBoundary;

    var cycle_count: usize = 0;
    for (steps) |step_value| {
        const step = cartridge_access.ValidatedStep.init(step_value) catch
            return error.InvalidExecutionStep;
        cycle_count = std.math.add(
            usize,
            cycle_count,
            step.trace.instruction.cycle_count,
        ) catch return error.TooManyDmaEvents;
    }
    if (cycle_count == 0) return error.EmptyDmaSegment;
    const expected_final = std.math.add(
        u32,
        initial_mcycle,
        std.math.cast(u32, cycle_count) orelse
            return error.DmaClockOverflow,
    ) catch return error.DmaClockOverflow;
    if (expected_final != final_mcycle)
        return error.InvalidDmaFinalClock;

    const rows = try allocator.alloc(EventRow, cycle_count);
    errdefer allocator.free(rows);
    var state = initial_state;
    var source_index: usize = 0;
    var row_index: usize = 0;
    var mcycle = initial_mcycle;
    for (steps, 0..) |step_value, execution_row| {
        const step = try validated(step_value);
        for (0..step.trace.instruction.cycle_count) |cycle| {
            const bus = step.trace.instruction.cycles[cycle];
            const access = step.trace.accesses[cycle];
            const action_active = bus.action != .idle;
            if (action_active != (access != null))
                return error.InvalidExecutionStep;
            var write_page: ?u8 = null;
            if (access) |item| {
                if (item.logical_address == dma.DMA_ADDRESS and
                    item.action == .write)
                {
                    if (item.region != .system or
                        bus.action != .write or item.value != bus.value)
                        return error.InvalidFf46Metadata;
                    write_page = item.value;
                }
            }
            const expects_transfer = state.phase == .transfer;
            const source_byte: u8 = if (expects_transfer) blk: {
                if (source_index >= source_bytes.len)
                    return error.MissingDmaSourceByte;
                defer source_index += 1;
                break :blk source_bytes[source_index];
            } else 0;
            const event: dma.Event = if (expects_transfer)
                if (write_page) |page|
                    .{ .transfer_and_write = .{
                        .source_byte = source_byte,
                        .page = page,
                    } }
                else
                    .{ .transfer = source_byte }
            else if (write_page) |page|
                .{ .write_ff46 = page }
            else
                .tick;
            const transition = try dma.Transition.apply(state, event);
            try validateCpuAccess(transition, bus, access);
            rows[row_index] = .{
                .mcycle = mcycle,
                .transition = transition,
                .provenance = .{
                    .execution_row = @intCast(execution_row),
                    .cycle = @intCast(cycle),
                },
            };
            row_index += 1;
            state = transition.after;
            mcycle += 1;
        }
    }
    if (source_index != source_bytes.len)
        return error.ExtraDmaSourceByte;
    std.debug.assert(row_index == rows.len);
    return .{
        .rows = rows,
        .final_state = state,
        .final_mcycle = mcycle,
    };
}

/// Derives one DMA row for every canonical cartridge scheduler M-cycle.
///
/// Interrupt-service bus cycles use the pinned SameBoy service trace. Logical
/// IE/IF resampling and acknowledgement remain scheduler-only operations.
pub fn generateFromMachineExecution(
    allocator: std.mem.Allocator,
    initial_mcycle: u32,
    final_mcycle: u32,
    initial_state: dma.State,
    results: []const machine.CartridgeStepResult,
    source_bytes: []const u8,
) !Trace {
    try initial_state.validate();
    if (initial_state.clock != initial_mcycle)
        return error.DmaClockMismatch;
    if (initial_mcycle >= final_mcycle or final_mcycle >= M31_MODULUS)
        return error.InvalidDmaClockBoundary;

    var cycle_count: usize = 0;
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
            usize,
            cycle_count,
            result.m_cycles,
        ) catch return error.TooManyDmaEvents;
    }
    if (cycle_count == 0) return error.EmptyDmaSegment;
    const expected_final = std.math.add(
        u32,
        initial_mcycle,
        std.math.cast(u32, cycle_count) orelse
            return error.DmaClockOverflow,
    ) catch return error.DmaClockOverflow;
    if (expected_final != final_mcycle)
        return error.InvalidDmaFinalClock;

    const rows = try allocator.alloc(EventRow, cycle_count);
    errdefer allocator.free(rows);
    var state = initial_state;
    var source_index: usize = 0;
    var row_index: usize = 0;
    var mcycle = initial_mcycle;
    for (results, 0..) |result, execution_row| {
        for (0..result.m_cycles) |cycle| {
            if (cycle == 0 and result.before.cpu.halted and state.isActive())
                return error.UnsupportedActiveDmaHalt;
            const position = ExecutionPosition{
                .execution_row = @intCast(execution_row),
                .cycle = @intCast(cycle),
            };
            const bus = try machineBusAt(
                results,
                position,
            );
            const access = try machineAccessAt(results, position);
            if ((bus.action != .idle) != (access != null))
                return error.InvalidExecutionStep;
            var write_page: ?u8 = null;
            if (access) |item| {
                if (item.logical_address == dma.DMA_ADDRESS and
                    item.action == .write)
                {
                    if (item.region != .system or
                        bus.action != .write or item.value != bus.value)
                        return error.InvalidFf46Metadata;
                    write_page = item.value;
                }
            }
            const expects_transfer = state.phase == .transfer;
            const source_byte: u8 = if (expects_transfer) blk: {
                if (source_index >= source_bytes.len)
                    return error.MissingDmaSourceByte;
                defer source_index += 1;
                break :blk source_bytes[source_index];
            } else 0;
            const event: dma.Event = if (expects_transfer)
                if (write_page) |page|
                    .{ .transfer_and_write = .{
                        .source_byte = source_byte,
                        .page = page,
                    } }
                else
                    .{ .transfer = source_byte }
            else if (write_page) |page|
                .{ .write_ff46 = page }
            else
                .tick;
            const transition = try dma.Transition.apply(state, event);
            try validateCpuAccess(transition, bus, access);
            rows[row_index] = .{
                .mcycle = mcycle,
                .transition = transition,
                .provenance = .{
                    .execution_row = @intCast(execution_row),
                    .cycle = @intCast(cycle),
                },
            };
            row_index += 1;
            state = transition.after;
            mcycle += 1;
        }
    }
    if (source_index != source_bytes.len)
        return error.ExtraDmaSourceByte;
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
    try validateAirRows(source);
    const padded = std.math.ceilPowerOfTwo(
        usize,
        @max(source.rows.len, 16),
    ) catch return error.DmaTraceTooLong;
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
        const values = try columns(row, steps);
        const storage = try core_air_utils.circleBitReversedIndex(
            log_size,
            index,
        );
        for (&result.main, values) |column, value|
            column[storage] = value;
    }
    return result;
}

pub fn generateMachineExecutionWitness(
    allocator: std.mem.Allocator,
    source: Trace,
    results: []const machine.CartridgeStepResult,
) !Witness {
    try validateMachineTrace(source, results);
    try validateAirRows(source);
    const padded = std.math.ceilPowerOfTwo(
        usize,
        @max(source.rows.len, 16),
    ) catch return error.DmaTraceTooLong;
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
        const values = try machineColumns(row, results);
        const storage = try core_air_utils.circleBitReversedIndex(
            log_size,
            index,
        );
        for (&result.main, values) |column, value|
            column[storage] = value;
    }
    return result;
}

pub fn columns(
    row: EventRow,
    steps: []const runner.CartridgeStepTrace,
) ![N_MAIN_COLUMNS]M31 {
    return columnsForBus(row, try busAt(steps, row.provenance));
}

pub fn machineColumns(
    row: EventRow,
    results: []const machine.CartridgeStepResult,
) ![N_MAIN_COLUMNS]M31 {
    return columnsForBus(
        row,
        try machineBusAt(results, row.provenance),
    );
}

fn validateAirRows(source: Trace) !void {
    var previous: ?[dma_air.N_MAIN_COLUMNS]M31 = null;
    for (source.rows) |row| {
        const current = dma_air.columns(
            dma_air.ValidatedStep.init(row.transition) catch
                return error.InvalidDmaTransition,
        );
        if (!(try dma_air.evaluate(current, true)).allZero())
            return error.InvalidDmaAirWitness;
        if (previous) |before|
            if (!(try dma_air.evaluateChain(before, current)).allZero())
                return error.InvalidDmaAirWitness;
        previous = current;
    }
}

fn columnsForBus(
    row: EventRow,
    bus: runner.BusCycle,
) ![N_MAIN_COLUMNS]M31 {
    if (row.mcycle >= M31_MODULUS)
        return error.NonCanonicalDmaClock;
    const validated_step = dma_air.ValidatedStep.init(row.transition) catch
        return error.InvalidDmaTransition;
    var out = inactiveColumns();
    const semantic = dma_component.columns(validated_step);
    @memcpy(out[0..dma_component.N_MAIN_COLUMNS], &semantic);
    out[MCYCLE_OFFSET] = M31.fromCanonical(row.mcycle);
    writeBits(out[BUS_ADDRESS_OFFSET..BUS_VALUE_OFFSET], bus.address);
    writeBits(out[BUS_VALUE_OFFSET..BUS_ACTION_OFFSET], bus.value);
    out[BUS_ACTION_OFFSET + @intFromEnum(bus.action)] = M31.one();

    const class = cpuAccessAfter(row.transition, bus);
    out[CPU_CLASS_OFFSET + @intFromEnum(class)] = M31.one();

    const copied = row.transition.after.copied;
    if (copied != 0) {
        out[COPIED_NONZERO_OFFSET] = M31.one();
        out[COPIED_INVERSE_OFFSET] =
            M31.fromCanonical(copied).inv() catch unreachable;
    }
    const page = row.transition.before.page;
    out[PAGE_VRAM_OFFSET] = boolean(page >= 0x80 and page < 0xa0);
    const cpu_page = row.transition.after.page;
    out[CPU_PAGE_VRAM_OFFSET] = boolean(
        cpu_page >= 0x80 and cpu_page < 0xa0,
    );
    var prefix = true;
    for (0..7) |index| {
        prefix = prefix and
            ((bus.address >> @intCast(15 - index)) & 1) == 1;
        out[HIGH_FE_CHAIN_OFFSET + index] = boolean(prefix);
    }
    out[ADDRESS_VRAM_OFFSET] = boolean(
        bus.address >= 0x8000 and bus.address < 0xa000,
    );
    out[ADDRESS_OAM_OFFSET] = boolean(
        bus.address >= 0xfe00 and bus.address < 0xff00,
    );
    out[OAM_BLOCKED_OFFSET] = boolean(
        row.transition.after.oamBlocked(),
    );
    out[SOURCE_BLOCKED_OFFSET] = boolean(
        row.transition.after.phase == .finishing or
            (row.transition.after.phase == .transfer and copied != 0),
    );
    const source_vram = cpu_page >= 0x80 and cpu_page < 0xa0;
    const address_vram = bus.address >= 0x8000 and bus.address < 0xa000;
    out[BUS_MATCH_OFFSET] = boolean(
        bus.address < 0xfe00 and source_vram == address_vram,
    );
    if (bus.address == dma.DMA_ADDRESS) {
        out[FF46_MATCH_OFFSET] = M31.one();
    } else {
        const difference = M31.fromCanonical(bus.address)
            .sub(M31.fromCanonical(dma.DMA_ADDRESS));
        out[FF46_INVERSE_OFFSET] = difference.inv() catch unreachable;
    }
    return out;
}

pub fn inactiveColumns() [N_MAIN_COLUMNS]M31 {
    return [_]M31{M31.zero()} ** N_MAIN_COLUMNS;
}

/// Returns the two memory operations that still need lookup authentication.
pub fn transferAccess(row: EventRow) !?TransferAccess {
    const transfer = row.transition.transfer orelse return null;
    return .{
        .clock = try memory_clock.phaseClock(
            row.mcycle,
            memory_clock.DMA_PHASE,
        ),
        .source_address = transfer.source_address,
        .destination_address = transfer.destination_address,
        .value = transfer.value,
    };
}

fn validateTrace(
    source: Trace,
    steps: []const runner.CartridgeStepTrace,
) !void {
    if (source.rows.len == 0) return error.EmptyDmaTrace;
    var mcycle = source.rows[0].mcycle;
    var state = source.rows[0].transition.before;
    var execution_row: usize = 0;
    var cycle: usize = 0;
    for (source.rows) |row| {
        if (row.mcycle != mcycle or
            row.transition.before.clock != row.mcycle or
            !std.meta.eql(row.transition.before, state) or
            row.provenance.execution_row != execution_row or
            row.provenance.cycle != cycle)
            return error.DisconnectedDmaTrace;
        const bus = try busAt(steps, row.provenance);
        const access = steps[execution_row].accesses[cycle];
        try validateCpuAccess(row.transition, bus, access);
        _ = try columns(row, steps);
        state = row.transition.after;
        mcycle += 1;
        cycle += 1;
        if (cycle == steps[execution_row].instruction.cycle_count) {
            execution_row += 1;
            cycle = 0;
        }
    }
    if (execution_row != steps.len or cycle != 0 or
        mcycle != source.final_mcycle or
        !std.meta.eql(state, source.final_state) or
        source.final_state.clock != source.final_mcycle)
        return error.InvalidDmaTraceEndpoint;
}

fn validateMachineTrace(
    source: Trace,
    results: []const machine.CartridgeStepResult,
) !void {
    if (source.rows.len == 0) return error.EmptyDmaTrace;
    var mcycle = source.rows[0].mcycle;
    var state = source.rows[0].transition.before;
    var execution_row: usize = 0;
    var cycle: usize = 0;
    for (source.rows) |row| {
        if (execution_row >= results.len or
            row.mcycle != mcycle or
            row.transition.before.clock != row.mcycle or
            !std.meta.eql(row.transition.before, state) or
            row.provenance.execution_row != execution_row or
            row.provenance.cycle != cycle)
            return error.DisconnectedDmaTrace;
        if (cycle == 0) {
            try validateMachineResult(results[execution_row]);
            if (results[execution_row].before.cpu.halted and state.isActive())
                return error.UnsupportedActiveDmaHalt;
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
        const bus = try machineBusAt(results, row.provenance);
        const access = try machineAccessAt(results, row.provenance);
        try validateCpuAccess(row.transition, bus, access);
        _ = try machineColumns(row, results);
        state = row.transition.after;
        mcycle += 1;
        cycle += 1;
        if (cycle == results[execution_row].m_cycles) {
            execution_row += 1;
            cycle = 0;
        }
    }
    if (execution_row != results.len or cycle != 0 or
        mcycle != source.final_mcycle or
        !std.meta.eql(state, source.final_state) or
        source.final_state.clock != source.final_mcycle)
        return error.InvalidDmaTraceEndpoint;
}

fn validated(
    step: runner.CartridgeStepTrace,
) !cartridge_access.ValidatedStep {
    return cartridge_access.ValidatedStep.init(step) catch
        error.InvalidExecutionStep;
}

fn busAt(
    steps: []const runner.CartridgeStepTrace,
    position: ExecutionPosition,
) !runner.BusCycle {
    if (position.execution_row >= steps.len)
        return error.InvalidExecutionProvenance;
    const step = try validated(steps[position.execution_row]);
    if (position.cycle >= step.trace.instruction.cycle_count)
        return error.InvalidExecutionProvenance;
    return step.trace.instruction.cycles[position.cycle];
}

fn machineBusAt(
    results: []const machine.CartridgeStepResult,
    position: ExecutionPosition,
) !runner.BusCycle {
    if (position.execution_row >= results.len)
        return error.InvalidExecutionProvenance;
    const result = results[position.execution_row];
    try validateMachineResult(result);
    if (position.cycle >= result.m_cycles)
        return error.InvalidExecutionProvenance;
    if (result.instruction) |instruction|
        return instruction.instruction.cycles[position.cycle];
    const access = (try machineAccessAt(results, position)) orelse
        return .{ .address = 0, .value = 0, .action = .idle };
    return .{
        .address = access.logical_address,
        .value = access.value,
        .action = switch (access.action) {
            .read => .read,
            .write => .write,
        },
    };
}

fn machineAccessAt(
    results: []const machine.CartridgeStepResult,
    position: ExecutionPosition,
) !?runner.cartridge_memory.Access {
    if (position.execution_row >= results.len)
        return error.InvalidExecutionProvenance;
    const result = results[position.execution_row];
    if (position.cycle >= result.m_cycles)
        return error.InvalidExecutionProvenance;
    if (result.instruction) |instruction|
        return instruction.accesses[position.cycle];
    if (result.event == .interrupt_service)
        return result.service.cycles[position.cycle].access;
    return null;
}

fn cpuAccessAfter(
    transition: dma.Transition,
    bus: runner.BusCycle,
) dma.CpuAccess {
    return switch (bus.action) {
        .idle => .allowed,
        .read => transition.after.cpuAccess(bus.address),
        .write => transition.after.cpuWriteAccess(bus.address),
    };
}

fn validateCpuAccess(
    transition: dma.Transition,
    bus: runner.BusCycle,
    access: ?runner.cartridge_memory.Access,
) !void {
    const class = cpuAccessAfter(transition, bus);
    if (access) |item| {
        if (item.dma_class != class)
            return error.InvalidDmaAccessMetadata;
    } else if (bus.action != .idle) {
        return error.InvalidExecutionStep;
    }
    if (class != .allowed) return error.UnsupportedBlockedCpuAccess;
}

fn validateMachineResult(
    result: machine.CartridgeStepResult,
) !void {
    _ = scheduler_air.ValidatedStep.init(result) catch
        return error.InvalidSchedulerStep;
    if (result.instruction) |instruction|
        _ = cartridge_access.ValidatedStep.init(instruction) catch
            return error.InvalidExecutionStep;
}

fn writeBits(out: []M31, value: anytype) void {
    const integer: u64 = @intCast(value);
    for (out, 0..) |*destination, index|
        destination.* = M31.fromCanonical(
            @intCast(integer >> @intCast(index) & 1),
        );
}

fn boolean(value: bool) M31 {
    return M31.fromCanonical(@intFromBool(value));
}
