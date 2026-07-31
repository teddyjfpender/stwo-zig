//! Zero-copy preprocessed and main commitment assembly for v7 execution.
//!
//! Every semantic column comes from an already-validated leaf witness. This
//! module owns ordering, geometry, the four new selectors, and ownership
//! transfer only.

const std = @import("std");
const core_air_utils = @import("stwo_core").air.utils;
const M31 = @import("stwo_core").fields.m31.M31;
const prover_pcs = @import("stwo_prover_engine").pcs;
const transaction = @import("stwo_prover_engine").transaction;
const cartridge_prover = @import("cartridge_prover.zig");
const base_geometry = @import("cartridge_proof_statement.zig");
const environment = @import("environment_statement.zig");
const geometry = @import("machine_environment_geometry.zig");
const replay = @import("machine_environment_memory_replay.zig");
const machine_trace = @import("air/machine_scheduler_trace.zig");
const rom_lookup = @import("air/cartridge_rom_lookup.zig");
const joypad_binding = @import("air/joypad_binding.zig");
const joypad_if = @import("air/joypad_if_memory_lookup.zig");
const timer_binding = @import("air/timer_binding.zig");
const timer_if = @import("air/timer_if_memory_lookup.zig");
const observation =
    @import("air/intermediate_ram_observation_lookup.zig");
const service_memory =
    @import("air/interrupt_service_memory_lookup.zig");
const ppu_binding = @import("air/ppu_binding.zig");
const ppu_mmio = @import("air/ppu_mmio_lookup.zig");
const ppu_if = @import("air/ppu_if_memory_lookup.zig");
const ppu_execution_policy = @import("ppu_execution_policy.zig");
const dma_binding = @import("air/dma_binding.zig");
const dma_memory = @import("air/dma_memory_lookup.zig");
const apu_binding = @import("air/apu_binding.zig");
const apu_execution = @import("air/apu_execution_lookup.zig");

const ColumnEvaluation = prover_pcs.ColumnEvaluation;

pub const Logs = struct {
    execution: u32,
    joypad: u32,
    timer: u32,
    observation: u32,
    ppu: u32,
    dma: u32,
    apu: u32,

    pub fn preprocessed(self: Logs) [geometry.N_PREPROCESSED_COLUMNS]u32 {
        return geometry.preprocessedLogSizes(
            self.execution,
            self.joypad,
            self.timer,
            self.observation,
            self.ppu,
            self.dma,
            self.apu,
        );
    }

    pub fn main(self: Logs) [geometry.N_MAIN_COLUMNS]u32 {
        return geometry.mainLogSizes(
            self.execution,
            self.joypad,
            self.timer,
            self.observation,
            self.ppu,
            self.dma,
            self.apu,
        );
    }
};

/// Explicit ownership wrapper for the canonical one-column ROM table witness.
pub const OwnedColumn = struct {
    log_size: u32,
    values: ?[]M31,

    pub fn init(log_size: u32, values: []M31) OwnedColumn {
        return .{ .log_size = log_size, .values = values };
    }

    pub fn deinit(self: *OwnedColumn, allocator: std.mem.Allocator) void {
        if (self.values) |values| allocator.free(values);
        self.* = undefined;
    }

    fn take(self: *OwnedColumn) []M31 {
        const values = self.values orelse unreachable;
        self.values = null;
        return values;
    }
};

/// Mutable pointers make the successful column-ownership transfer explicit.
/// Samples, predecessor arrays, and memory accesses remain source-owned.
pub const Sources = struct {
    v3_preprocessed: *transaction.OwnedColumns,
    machine: *machine_trace.Trace,
    packed_access: *cartridge_prover.PackedTrace,
    memory_replay: *replay.Replay,
    rom_multiplicity: *OwnedColumn,
    joypad_binding: *joypad_binding.Witness,
    joypad_if: *joypad_if.Witness,
    timer_binding: *timer_binding.Witness,
    timer_if: *timer_if.Witness,
    observation: *observation.Witness,
    service_memory: *service_memory.Witness,
    ppu_binding: *ppu_binding.Witness,
    ppu_auxiliary: *ppu_mmio.AuxiliaryWitness,
    ppu_if: *ppu_if.Witness,
    ppu_policy: *ppu_execution_policy.Witness,
    dma_binding: *dma_binding.Witness,
    dma_memory: *dma_memory.Witness,
    apu_binding: *apu_binding.Witness,
    apu_auxiliary: *apu_execution.AuxiliaryWitness,
};

pub const Prepared = struct {
    trace: transaction.PreparedTrace,
    logs: Logs,

    pub fn deinit(self: *Prepared, allocator: std.mem.Allocator) void {
        self.trace.deinit(allocator);
        self.* = undefined;
    }

    pub fn validate(self: *const Prepared) !void {
        const preprocessed = self.trace.preprocessed.columns orelse
            return error.PreparedInputConsumed;
        const main = self.trace.main.columns orelse
            return error.PreparedInputConsumed;
        try validateEvaluations(preprocessed, &self.logs.preprocessed());
        try validateEvaluations(main, &self.logs.main());
    }
};

/// Extends canonical v3 public columns for verifier-side root recomputation.
/// The prefix remains caller-owned on every error and is consumed on success.
pub fn extendPreprocessed(
    allocator: std.mem.Allocator,
    prefix_owned: *transaction.OwnedColumns,
    ppu_log_size: u32,
    dma_log_size: u32,
    apu_log_size: u32,
) !transaction.OwnedColumns {
    try validateLog(ppu_log_size);
    try validateLog(dma_log_size);
    try validateLog(apu_log_size);
    const prefix = prefix_owned.columns orelse
        return error.PreparedInputConsumed;
    if (prefix_owned.backing_buffers != null or
        !prefix_owned.source.isMaterialized())
        return error.UnsupportedPreprocessedOwnership;
    if (prefix.len != environment.N_PREPROCESSED_COLUMNS)
        return error.InvalidColumnCount;
    const prefix_logs = environment.preprocessedLogSizes(
        prefix[base_geometry.EXECUTION_FIRST_PREPROCESSED].log_size,
        prefix[environment.JOYPAD_FIRST_PREPROCESSED].log_size,
        prefix[environment.TIMER_FIRST_PREPROCESSED].log_size,
        prefix[environment.INTERMEDIATE_OBSERVATION_FIRST_PREPROCESSED].log_size,
    );
    try validateEvaluations(prefix, &prefix_logs);

    const result = try allocator.alloc(
        ColumnEvaluation,
        geometry.N_PREPROCESSED_COLUMNS,
    );
    errdefer allocator.free(result);
    @memcpy(result[0..environment.N_PREPROCESSED_COLUMNS], prefix);
    var initialized: usize = 0;
    errdefer for (
        result[environment.N_PREPROCESSED_COLUMNS .. environment.N_PREPROCESSED_COLUMNS + initialized],
    ) |column| allocator.free(column.values);
    result[geometry.PPU_FIRST_PREPROCESSED] =
        try selector(allocator, ppu_log_size, true);
    initialized += 1;
    result[geometry.PPU_LAST_PREPROCESSED] =
        try selector(allocator, ppu_log_size, false);
    initialized += 1;
    result[geometry.DMA_FIRST_PREPROCESSED] =
        try selector(allocator, dma_log_size, true);
    initialized += 1;
    result[geometry.DMA_LAST_PREPROCESSED] =
        try selector(allocator, dma_log_size, false);
    initialized += 1;
    result[geometry.APU_FIRST_PREPROCESSED] =
        try selector(allocator, apu_log_size, true);
    initialized += 1;
    result[geometry.APU_LAST_PREPROCESSED] =
        try selector(allocator, apu_log_size, false);
    initialized += 1;

    canonicalizeMemoryBoundary(prefix);
    const taken = prefix_owned.take();
    allocator.free(taken);
    initialized = 0;
    return transaction.OwnedColumns.init(result);
}

/// Validates every source before allocating or transferring any column.
/// Success consumes all source column allocations, but not lookup metadata.
pub fn assemble(
    allocator: std.mem.Allocator,
    sources: Sources,
) !Prepared {
    const logs = try validateSources(sources);
    const prefix = sources.v3_preprocessed.columns orelse
        return error.PreparedInputConsumed;

    const preprocessed = try allocator.alloc(
        ColumnEvaluation,
        geometry.N_PREPROCESSED_COLUMNS,
    );
    var preprocessed_moved = false;
    errdefer if (!preprocessed_moved) allocator.free(preprocessed);
    @memcpy(
        preprocessed[0..environment.N_PREPROCESSED_COLUMNS],
        prefix,
    );
    var selector_count: usize = 0;
    errdefer for (
        preprocessed[environment.N_PREPROCESSED_COLUMNS .. environment.N_PREPROCESSED_COLUMNS + selector_count],
    ) |column| allocator.free(column.values);
    preprocessed[geometry.PPU_FIRST_PREPROCESSED] =
        try selector(allocator, logs.ppu, true);
    selector_count += 1;
    preprocessed[geometry.PPU_LAST_PREPROCESSED] =
        try selector(allocator, logs.ppu, false);
    selector_count += 1;
    preprocessed[geometry.DMA_FIRST_PREPROCESSED] =
        try selector(allocator, logs.dma, true);
    selector_count += 1;
    preprocessed[geometry.DMA_LAST_PREPROCESSED] =
        try selector(allocator, logs.dma, false);
    selector_count += 1;
    preprocessed[geometry.APU_FIRST_PREPROCESSED] =
        try selector(allocator, logs.apu, true);
    selector_count += 1;
    preprocessed[geometry.APU_LAST_PREPROCESSED] =
        try selector(allocator, logs.apu, false);
    selector_count += 1;

    const main = try allocator.alloc(
        ColumnEvaluation,
        geometry.N_MAIN_COLUMNS,
    );
    var main_moved = false;
    errdefer if (!main_moved) allocator.free(main);
    setMain(main, sources, logs);

    canonicalizeMemoryBoundary(prefix);
    sources.machine.disownMain();
    sources.packed_access.disown();
    sources.memory_replay.memory.disownColumns();
    sources.joypad_binding.disown();
    sources.joypad_if.disownColumns();
    sources.timer_binding.disown();
    sources.timer_if.disownColumns();
    sources.observation.disownColumns();
    sources.service_memory.disownColumns();
    sources.ppu_binding.disown();
    sources.ppu_auxiliary.disown();
    sources.ppu_if.disownColumns();
    sources.ppu_policy.disown();
    sources.dma_binding.disown();
    sources.dma_memory.disownColumns();
    sources.apu_binding.disown();
    sources.apu_auxiliary.disown();

    const prefix_owned = sources.v3_preprocessed.take();
    allocator.free(prefix_owned);
    main[base_geometry.ROM_MULTIPLICITY_MAIN_OFFSET].values =
        sources.rom_multiplicity.take();
    selector_count = 0;
    preprocessed_moved = true;
    main_moved = true;
    return .{
        .trace = try transaction.PreparedTrace.initOwned(
            allocator,
            preprocessed,
            main,
        ),
        .logs = logs,
    };
}

fn validateSources(sources: Sources) !Logs {
    const machine = sources.machine;
    const logs = Logs{
        .execution = machine.log_size,
        .joypad = sources.joypad_binding.log_size,
        .timer = sources.timer_binding.log_size,
        .observation = sources.observation.log_size,
        .ppu = sources.ppu_binding.log_size,
        .dma = sources.dma_binding.log_size,
        .apu = sources.apu_binding.log_size,
    };
    try validateLog(logs.execution);
    try validateLog(logs.joypad);
    try validateLog(logs.timer);
    try validateLog(logs.observation);
    try validateLog(logs.ppu);
    try validateLog(logs.dma);
    try validateLog(logs.apu);

    const prefix = sources.v3_preprocessed.columns orelse
        return error.PreparedInputConsumed;
    if (sources.v3_preprocessed.backing_buffers != null or
        !sources.v3_preprocessed.source.isMaterialized())
        return error.UnsupportedPreprocessedOwnership;
    try validateEvaluations(
        prefix,
        &environment.preprocessedLogSizes(
            logs.execution,
            logs.joypad,
            logs.timer,
            logs.observation,
        ),
    );
    if (machine.execution.log_size != logs.execution or
        machine.families.log_size != logs.execution or
        machine.scheduler_memory.log_size != logs.execution)
        return error.DetachedMachineTrace;
    try validateSet(machine.execution.main, logs.execution);
    try validateSet(machine.families.main, logs.execution);
    try validateSet(machine.scheduler_main, logs.execution);
    try validateSet(machine.provenance_main, logs.execution);
    try validateSet(machine.scheduler_memory.main, logs.execution);
    try validateSet(sources.packed_access.columns, logs.execution);
    try validateSet(sources.memory_replay.memory.main, logs.execution);
    try validateColumn(
        sources.memory_replay.memory.final_clocks,
        @import("air/cartridge_memory_lookup.zig").BOUNDARY_LOG_SIZE,
    );
    if (sources.rom_multiplicity.log_size != rom_lookup.ROM_LOG_SIZE)
        return error.InvalidRomMultiplicityGeometry;
    try validateColumn(
        sources.rom_multiplicity.values orelse
            return error.PreparedInputConsumed,
        rom_lookup.ROM_LOG_SIZE,
    );
    try validateWitnessLogs(sources, logs);
    return logs;
}

fn validateWitnessLogs(sources: Sources, logs: Logs) !void {
    if (sources.joypad_if.log_size != logs.joypad or
        sources.timer_if.log_size != logs.timer or
        sources.service_memory.log_size != logs.execution or
        sources.ppu_auxiliary.log_size != logs.ppu or
        sources.ppu_if.log_size != logs.ppu or
        sources.ppu_policy.log_size != logs.ppu or
        sources.ppu_policy.event_count !=
            sources.ppu_binding.event_count or
        sources.dma_memory.log_size != logs.dma)
        return error.DetachedWitnessLog;
    if (sources.apu_auxiliary.execution_log_size != logs.execution or
        sources.apu_auxiliary.apu_log_size != logs.apu or
        sources.apu_auxiliary.event_count != sources.apu_binding.event_count)
        return error.DetachedWitnessLog;
    try validateSet(sources.joypad_binding.main, logs.joypad);
    try validateSet(sources.joypad_if.main, logs.joypad);
    try validateSet(sources.timer_binding.main, logs.timer);
    try validateSet(sources.timer_if.main, logs.timer);
    try validateSet(sources.observation.main, logs.observation);
    try validateSet(sources.service_memory.main, logs.execution);
    try validateSet(sources.ppu_binding.main, logs.ppu);
    try validateColumn(sources.ppu_auxiliary.ly_write_values, logs.ppu);
    try validateSet(sources.ppu_if.main, logs.ppu);
    try validateSet(sources.ppu_policy.main, logs.ppu);
    try validateSet(sources.dma_binding.main, logs.dma);
    try validateSet(sources.dma_memory.main, logs.dma);
    try validateSet(sources.apu_binding.main, logs.apu);
    try validateColumn(
        sources.apu_auxiliary.execution_order_before,
        logs.execution,
    );
    try validateColumn(sources.apu_auxiliary.apu_mcycle, logs.apu);
    try validateColumn(sources.apu_auxiliary.apu_order, logs.apu);
}

fn setMain(
    main: []ColumnEvaluation,
    sources: Sources,
    logs: Logs,
) void {
    set(main[base_geometry.EXECUTION_MAIN_OFFSET..], sources.machine.execution.main, logs.execution);
    set(main[base_geometry.FAMILY_MAIN_OFFSET..], sources.machine.families.main, logs.execution);
    set(main[base_geometry.PACKED_ACCESS_MAIN_OFFSET..], sources.packed_access.columns, logs.execution);
    set(main[base_geometry.MUTABLE_WITNESS_MAIN_OFFSET..], sources.memory_replay.memory.main, logs.execution);
    main[base_geometry.ROM_MULTIPLICITY_MAIN_OFFSET] = .{
        .log_size = rom_lookup.ROM_LOG_SIZE,
        .values = sources.rom_multiplicity.values.?,
    };
    main[base_geometry.FINAL_CLOCK_MAIN_OFFSET] = .{
        .log_size = @import("air/cartridge_memory_lookup.zig").BOUNDARY_LOG_SIZE,
        .values = sources.memory_replay.memory.final_clocks,
    };
    set(main[environment.JOYPAD_BINDING_MAIN_OFFSET..], sources.joypad_binding.main, logs.joypad);
    set(main[environment.JOYPAD_IF_MAIN_OFFSET..], sources.joypad_if.main, logs.joypad);
    set(main[environment.TIMER_BINDING_MAIN_OFFSET..], sources.timer_binding.main, logs.timer);
    set(main[environment.TIMER_IF_MAIN_OFFSET..], sources.timer_if.main, logs.timer);
    set(main[environment.INTERMEDIATE_OBSERVATION_MAIN_OFFSET..], sources.observation.main, logs.observation);
    set(main[geometry.SCHEDULER_MAIN_OFFSET..], sources.machine.scheduler_main, logs.execution);
    set(main[geometry.SCHEDULER_PROVENANCE_MAIN_OFFSET..], sources.machine.provenance_main, logs.execution);
    set(main[geometry.SCHEDULER_MEMORY_MAIN_OFFSET..], sources.machine.scheduler_memory.main, logs.execution);
    set(main[geometry.SERVICE_MEMORY_MAIN_OFFSET..], sources.service_memory.main, logs.execution);
    set(main[geometry.PPU_BINDING_MAIN_OFFSET..], sources.ppu_binding.main, logs.ppu);
    main[geometry.PPU_AUXILIARY_MAIN_OFFSET] = .{
        .log_size = logs.ppu,
        .values = sources.ppu_auxiliary.ly_write_values,
    };
    set(main[geometry.PPU_IF_MAIN_OFFSET..], sources.ppu_if.main, logs.ppu);
    set(main[geometry.PPU_EXECUTION_POLICY_MAIN_OFFSET..], sources.ppu_policy.main, logs.ppu);
    set(main[geometry.DMA_BINDING_MAIN_OFFSET..], sources.dma_binding.main, logs.dma);
    set(main[geometry.DMA_MEMORY_MAIN_OFFSET..], sources.dma_memory.main, logs.dma);
    set(main[geometry.APU_BINDING_MAIN_OFFSET..], sources.apu_binding.main, logs.apu);
    main[geometry.APU_EXECUTION_ORDER_MAIN_OFFSET] = .{
        .log_size = logs.execution,
        .values = sources.apu_auxiliary.execution_order_before,
    };
    main[geometry.APU_MCYCLE_MAIN_OFFSET] = .{
        .log_size = logs.apu,
        .values = sources.apu_auxiliary.apu_mcycle,
    };
    main[geometry.APU_ORDER_MAIN_OFFSET] = .{
        .log_size = logs.apu,
        .values = sources.apu_auxiliary.apu_order,
    };
}

fn canonicalizeMemoryBoundary(
    prefix: []ColumnEvaluation,
) void {
    const log_size =
        @import("air/cartridge_memory_lookup.zig").BOUNDARY_LOG_SIZE;
    const size = @as(usize, 1) << @intCast(log_size);
    for (0..size) |row| {
        if (!replay.memoryBoundaryEnabled(row)) {
            const storage = core_air_utils.circleBitReversedIndex(
                log_size,
                row,
            ) catch unreachable;
            inline for (.{
                base_geometry.MEMORY_ENABLED_PREPROCESSED,
                base_geometry.MEMORY_ADDRESS_PREPROCESSED,
                base_geometry.MEMORY_INITIAL_PREPROCESSED,
                base_geometry.MEMORY_FINAL_PREPROCESSED,
            }) |column|
                @constCast(prefix[column].values)[storage] = M31.zero();
        }
    }
}

fn selector(
    allocator: std.mem.Allocator,
    log_size: u32,
    first: bool,
) !ColumnEvaluation {
    const size = try traceSize(log_size);
    const values = try allocator.alloc(M31, size);
    errdefer allocator.free(values);
    @memset(values, M31.zero());
    const row = if (first) 0 else size - 1;
    values[try core_air_utils.circleBitReversedIndex(log_size, row)] =
        M31.one();
    return .{ .log_size = log_size, .values = values };
}

fn set(
    destination: []ColumnEvaluation,
    sources: anytype,
    log_size: u32,
) void {
    for (destination[0..sources.len], sources) |*target, values|
        target.* = .{ .log_size = log_size, .values = values };
}

fn validateEvaluations(
    columns: []const ColumnEvaluation,
    logs: []const u32,
) !void {
    if (columns.len != logs.len) return error.InvalidColumnCount;
    for (columns, logs) |column, log_size| {
        if (column.log_size != log_size)
            return error.DetachedColumnLog;
        try validateColumn(column.values, log_size);
    }
}

fn validateSet(columns: anytype, log_size: u32) !void {
    for (columns) |column| try validateColumn(column, log_size);
}

fn validateColumn(values: []const M31, log_size: u32) !void {
    if (values.len != try traceSize(log_size))
        return error.DetachedColumnLength;
}

fn validateLog(log_size: u32) !void {
    if (log_size < 4 or log_size >= @bitSizeOf(usize))
        return error.InvalidTraceLogSize;
}

fn traceSize(log_size: u32) !usize {
    if (log_size >= @bitSizeOf(usize))
        return error.InvalidTraceLogSize;
    return @as(usize, 1) << @intCast(log_size);
}
