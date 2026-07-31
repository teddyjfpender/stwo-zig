//! Canonical row-aligned scheduler witness for cartridge-machine execution.
//!
//! This owns only layout. Scheduler, execution, memory-sample, and pinned
//! SameBoy interrupt-service semantics remain in their existing leaf helpers.

const std = @import("std");
const core_air_utils = @import("stwo_core").air.utils;
const M31 = @import("stwo_core").fields.m31.M31;
const machine = @import("../runner/machine.zig");
const cartridge_access = @import("cartridge_access.zig");
const machine_access = @import("cartridge_machine_access.zig");
const memory_lookup = @import("cartridge_memory_lookup.zig");
const execution = @import("execution.zig");
const execution_trace = @import("execution_trace.zig");
const family_trace = @import("family_trace.zig");
const interrupt_service = @import("interrupt_service.zig");
const scheduler = @import("scheduler.zig");
const scheduler_binding = @import("scheduler_binding.zig");
const scheduler_component = @import("scheduler_component.zig");
const scheduler_memory = @import("scheduler_memory_lookup.zig");

pub const Trace = struct {
    log_size: u32,
    execution: execution_trace.Trace,
    scheduler_main: [scheduler_component.N_MAIN_COLUMNS][]M31,
    provenance_main: [scheduler_binding.N_PROVENANCE_COLUMNS][]M31,
    scheduler_memory: scheduler_memory.Witness,
    families: family_trace.Trace,
    scheduler_initial: scheduler_component.Boundary,
    scheduler_final: scheduler_component.Boundary,
    allocator: std.mem.Allocator,
    scheduler_main_owned: bool = true,
    provenance_main_owned: bool = true,

    pub fn disownMain(self: *Trace) void {
        self.execution.disownMain();
        self.families.disownMain();
        self.scheduler_memory.disownColumns();
        self.scheduler_main_owned = false;
        self.provenance_main_owned = false;
    }

    pub fn deinit(self: *Trace) void {
        self.families.deinit();
        self.scheduler_memory.deinit();
        if (self.provenance_main_owned)
            freeColumns(
                scheduler_binding.N_PROVENANCE_COLUMNS,
                self.allocator,
                &self.provenance_main,
            );
        if (self.scheduler_main_owned)
            freeColumns(
                scheduler_component.N_MAIN_COLUMNS,
                self.allocator,
                &self.scheduler_main,
            );
        self.execution.deinit();
        self.* = undefined;
    }

    /// Rejects detached or mutated owned rows by re-deriving every leaf.
    pub fn validate(
        self: *const Trace,
        results: []const machine.CartridgeStepResult,
        replay: anytype,
    ) !void {
        try validateSource(results, replay);
        try self.validateShape(results.len);
        if (self.log_size != logSize(results.len) or
            self.execution.log_size != self.log_size or
            self.scheduler_memory.log_size != self.log_size or
            self.families.log_size != self.log_size)
            return error.DetachedMachineSchedulerTrace;

        const initial = schedulerBoundary(
            results[0].before,
            replay.initial_mcycle,
        );
        const final = schedulerBoundary(
            results[results.len - 1].after,
            replay.final_mcycle,
        );
        if (!std.meta.eql(self.scheduler_initial, initial) or
            !std.meta.eql(self.scheduler_final, final) or
            !std.meta.eql(self.execution.initial, execution.Boundary{
                .cpu = results[0].before.cpu,
                .mcycle = replay.initial_mcycle,
            }) or
            !std.meta.eql(self.execution.final, execution.Boundary{
                .cpu = results[results.len - 1].after.cpu,
                .mcycle = replay.final_mcycle,
            }))
            return error.DetachedMachineSchedulerTrace;

        const saved = self.execution.cartridgeResults() orelse
            return error.DetachedMachineSchedulerTrace;
        if (saved.len != results.len)
            return error.DetachedMachineSchedulerTrace;
        var expected_families = family_trace.generate(
            self.allocator,
            results,
        ) catch return error.InvalidMachineFamilyTrace;
        defer expected_families.deinit();
        try expectColumnsEqual(
            family_trace.N_MAIN_COLUMNS,
            &self.families.main,
            &expected_families.main,
        );

        var mcycle = replay.initial_mcycle;
        for (results, replay.scheduler_predecessors, 0..) |
            result,
            predecessors,
            row,
        | {
            if (!std.meta.eql(saved[row], result))
                return error.DetachedMachineSchedulerTrace;
            const storage = try core_air_utils.circleBitReversedIndex(
                self.log_size,
                row,
            );
            try self.validateSelectors(storage, row, results.len);
            try self.validateRow(
                result,
                predecessors,
                row,
                storage,
                mcycle,
            );
            mcycle = std.math.add(
                u32,
                mcycle,
                result.m_cycles,
            ) catch return error.MachineSchedulerClockOverflow;
        }
        if (mcycle != replay.final_mcycle)
            return error.DetachedMachineSchedulerTrace;
    }

    fn validateShape(self: *const Trace, size: usize) !void {
        if (self.execution.is_first.len != size or
            self.execution.is_last.len != size or
            self.scheduler_memory.samples.len != size)
            return error.InvalidMachineSchedulerTraceShape;
        try expectColumnLengths(
            execution.N_MAIN_COLUMNS,
            &self.execution.main,
            size,
        );
        try expectColumnLengths(
            scheduler_component.N_MAIN_COLUMNS,
            &self.scheduler_main,
            size,
        );
        try expectColumnLengths(
            scheduler_binding.N_PROVENANCE_COLUMNS,
            &self.provenance_main,
            size,
        );
        try expectColumnLengths(
            scheduler_memory.N_MAIN_COLUMNS,
            &self.scheduler_memory.main,
            size,
        );
        try expectColumnLengths(
            family_trace.N_MAIN_COLUMNS,
            &self.families.main,
            size,
        );
    }

    fn validateSelectors(
        self: *const Trace,
        storage: usize,
        row: usize,
        size: usize,
    ) !void {
        if (!self.execution.is_first[storage].eql(
            boolean(row == 0),
        ) or !self.execution.is_last[storage].eql(
            boolean(row == size - 1),
        ))
            return error.DetachedMachineSchedulerTrace;
    }

    fn validateRow(
        self: *const Trace,
        result: machine.CartridgeStepResult,
        predecessors: scheduler_memory.Predecessors,
        row: usize,
        storage: usize,
        mcycle: u32,
    ) !void {
        const bound = scheduler_binding.columns(result, mcycle) catch
            return error.InvalidMachineSchedulerStep;
        if (!(scheduler_binding.evaluateM31(bound) catch
            return error.InvalidMachineSchedulerStep).allZero())
            return error.InvalidMachineSchedulerStep;
        try expectStored(
            scheduler_component.N_MAIN_COLUMNS,
            &self.scheduler_main,
            storage,
            &bound.scheduler_main,
        );
        try expectStored(
            execution.N_MAIN_COLUMNS,
            &self.execution.main,
            storage,
            &bound.execution_main,
        );
        try expectStored(
            scheduler_binding.N_PROVENANCE_COLUMNS,
            &self.provenance_main,
            storage,
            &bound.provenance_main,
        );

        const validated = scheduler.ValidatedStep.init(result) catch
            return error.InvalidMachineSchedulerStep;
        const memory = scheduler_memory.columns(
            validated,
            mcycle,
            predecessors,
        ) catch return error.InvalidSchedulerMemoryPredecessor;
        try expectStored(
            scheduler_memory.N_MAIN_COLUMNS,
            &self.scheduler_memory.main,
            storage,
            &memory,
        );
        const sample_clock = memory_lookup.memory_clock.phaseClock(
            mcycle,
            scheduler_memory.SCHEDULER_PHASE,
        ) catch return error.InvalidSchedulerMemoryPredecessor;
        const post_mcycle = std.math.add(
            u32,
            mcycle,
            @as(u32, result.m_cycles) - 1,
        ) catch return error.InvalidSchedulerMemoryPredecessor;
        const post_clock = memory_lookup.memory_clock.phaseClock(
            post_mcycle,
            scheduler_memory.OBSERVATION_PHASE,
        ) catch return error.InvalidSchedulerMemoryPredecessor;
        const expected_samples = scheduler_memory.RowSamples{
            .{
                .enabled = true,
                .previous_clock = predecessors.interrupt_enable.clock,
                .value = result.before.interrupt_enable,
                .clock = sample_clock,
            },
            .{
                .enabled = true,
                .previous_clock = predecessors.interrupt_flags.clock,
                .value = result.before.interrupt_flags,
                .clock = sample_clock,
            },
            .{
                .enabled = true,
                .previous_clock = predecessors.post_interrupt_flags.clock,
                .value = result.after.interrupt_flags,
                .clock = post_clock,
            },
        };
        if (!std.meta.eql(
            self.scheduler_memory.samples[row],
            expected_samples,
        )) return error.DetachedMachineSchedulerTrace;

        var family_activity = M31.zero();
        for (self.families.main[0..execution.N_FAMILY_SELECTORS]) |column|
            family_activity = family_activity.add(column[storage]);
        const expected_activity = result.event == .instruction or
            result.event == .interrupt_service;
        if (!family_activity.eql(boolean(expected_activity)))
            return error.DetachedMachineSchedulerTrace;
        if (result.event == .interrupt_service) {
            const service = interrupt_service.columns(
                interrupt_service.ValidatedStep.init(result) catch
                    return error.InvalidInterruptService,
            );
            for (
                self.families.main[family_trace.INTERRUPT_SERVICE_OFFSET..][0..interrupt_service.N_MAIN_COLUMNS],
                service,
            ) |column, value|
                if (!column[storage].eql(value))
                    return error.DetachedMachineSchedulerTrace;
            if (!(interrupt_service.evaluateBound(
                service,
                bound.execution_main,
                true,
            ) catch return error.InvalidInterruptService).allZero())
                return error.InvalidInterruptService;
        }
    }
};

pub fn generate(
    allocator: std.mem.Allocator,
    results: []const machine.CartridgeStepResult,
    replay: anytype,
) !Trace {
    try validateSource(results, replay);
    var executed = try execution_trace.generateAt(
        allocator,
        results,
        replay.initial_mcycle,
    );
    errdefer executed.deinit();
    if (executed.final.mcycle != replay.final_mcycle)
        return error.DetachedMachineMemoryReplay;

    const memory_boundary = scheduler_memory.Boundary{
        .initial_mcycle = replay.initial_mcycle,
        .final_mcycle = replay.final_mcycle,
    };
    var sampled = scheduler_memory.generateWitness(
        allocator,
        results,
        memory_boundary,
        replay.scheduler_predecessors,
    ) catch return error.InvalidSchedulerMemoryPredecessor;
    errdefer sampled.deinit();
    var families = family_trace.generate(
        allocator,
        results,
    ) catch return error.InvalidMachineFamilyTrace;
    errdefer families.deinit();

    const size = results.len;
    var scheduler_main = try allocateColumns(
        scheduler_component.N_MAIN_COLUMNS,
        allocator,
        size,
    );
    errdefer freeColumns(
        scheduler_component.N_MAIN_COLUMNS,
        allocator,
        &scheduler_main,
    );
    var provenance_main = try allocateColumns(
        scheduler_binding.N_PROVENANCE_COLUMNS,
        allocator,
        size,
    );
    errdefer freeColumns(
        scheduler_binding.N_PROVENANCE_COLUMNS,
        allocator,
        &provenance_main,
    );
    const log_size = logSize(size);
    var mcycle = replay.initial_mcycle;
    for (results, 0..) |result, row| {
        const values = scheduler_binding.columns(result, mcycle) catch
            return error.InvalidMachineSchedulerStep;
        if (!(scheduler_binding.evaluateM31(values) catch
            return error.InvalidMachineSchedulerStep).allZero())
            return error.InvalidMachineSchedulerStep;
        const storage = try core_air_utils.circleBitReversedIndex(
            log_size,
            row,
        );
        store(
            scheduler_component.N_MAIN_COLUMNS,
            &scheduler_main,
            storage,
            &values.scheduler_main,
        );
        store(
            scheduler_binding.N_PROVENANCE_COLUMNS,
            &provenance_main,
            storage,
            &values.provenance_main,
        );
        try expectStored(
            execution.N_MAIN_COLUMNS,
            &executed.main,
            storage,
            &values.execution_main,
        );
        if (result.event == .interrupt_service) {
            const service = interrupt_service.columns(
                interrupt_service.ValidatedStep.init(result) catch
                    return error.InvalidInterruptService,
            );
            if (!(interrupt_service.evaluateBound(
                service,
                values.execution_main,
                true,
            ) catch return error.InvalidInterruptService).allZero())
                return error.InvalidInterruptService;
        }
        mcycle = std.math.add(
            u32,
            mcycle,
            result.m_cycles,
        ) catch return error.MachineSchedulerClockOverflow;
    }
    if (mcycle != replay.final_mcycle)
        return error.DetachedMachineMemoryReplay;

    const result = Trace{
        .log_size = log_size,
        .execution = executed,
        .scheduler_main = scheduler_main,
        .provenance_main = provenance_main,
        .scheduler_memory = sampled,
        .families = families,
        .scheduler_initial = schedulerBoundary(
            results[0].before,
            replay.initial_mcycle,
        ),
        .scheduler_final = schedulerBoundary(
            results[size - 1].after,
            replay.final_mcycle,
        ),
        .allocator = allocator,
    };
    return result;
}

fn validateSource(
    results: []const machine.CartridgeStepResult,
    replay: anytype,
) !void {
    if (results.len < 16 or !std.math.isPowerOfTwo(results.len))
        return error.InvalidMachineSchedulerTraceLength;
    if (replay.scheduler_predecessors.len != results.len or
        replay.service_predecessors.len != results.len or
        replay.memory.accesses.len != results.len * execution.N_BUS_CYCLES)
        return error.DetachedMachineMemoryReplay;

    var mcycle = replay.initial_mcycle;
    for (results, 0..) |result, row| {
        if (row != 0 and
            !std.meta.eql(results[row - 1].after.cpu, result.before.cpu))
            return error.DisconnectedMachineCpu;
        if (row != 0 and !std.meta.eql(
            results[row - 1].mapper_after,
            result.mapper_before,
        )) return error.DisconnectedMachineMapper;
        const validated = machine_access.ValidatedStep.init(result) catch
            return error.InvalidMachineSchedulerStep;
        const storage = try core_air_utils.circleBitReversedIndex(
            logSize(results.len),
            row,
        );
        try validateReplayProjection(replay, validated, storage);
        mcycle = std.math.add(
            u32,
            mcycle,
            result.m_cycles,
        ) catch return error.MachineSchedulerClockOverflow;
    }
    if (mcycle != replay.final_mcycle)
        return error.DetachedMachineMemoryReplay;
}

fn validateReplayProjection(
    replay: anytype,
    step: machine_access.ValidatedStep,
    storage: usize,
) !void {
    try expectColumnLengths(
        memory_lookup.N_MAIN_COLUMNS,
        &replay.memory.main,
        replay.scheduler_predecessors.len,
    );
    for (0..execution.N_BUS_CYCLES) |cycle| {
        const source_values = if (cycle < step.count)
            machine_access.columnsForCycle(step, cycle)
        else
            cartridge_access.inactiveColumns();
        const source = cartridge_access.Semantics(M31).Row.fromColumns(
            &source_values,
        ) catch return error.InvalidMachineSchedulerStep;
        const expected = memory_lookup.Semantics(M31).project(source);
        const offset = cycle * memory_lookup.N_ACCESS_COLUMNS;
        const actual = [_]M31{
            replay.memory.main[
                offset + memory_lookup.PROJECTED_ENABLED_OFFSET
            ][storage],
            replay.memory.main[
                offset + memory_lookup.PROJECTED_READ_OFFSET
            ][storage],
            replay.memory.main[
                offset + memory_lookup.PROJECTED_WRITE_OFFSET
            ][storage],
            replay.memory.main[
                offset + memory_lookup.PROJECTED_KEY_OFFSET
            ][storage],
            replay.memory.main[
                offset + memory_lookup.PROJECTED_VALUE_OFFSET
            ][storage],
        };
        const projected = [_]M31{
            expected.enabled,
            expected.read,
            expected.write,
            expected.key,
            expected.value,
        };
        for (actual, projected) |got, want|
            if (!got.eql(want)) return error.DetachedMachineMemoryReplay;
    }
}

fn schedulerBoundary(
    state: machine.MachineState,
    mcycle: u32,
) scheduler_component.Boundary {
    return .{
        .mcycle = mcycle,
        .ime = state.cpu.ime,
        .ime_enable_pending = state.cpu.ime_enable_pending,
        .halted = state.cpu.halted,
        .halt_bug = state.halt_bug,
    };
}

fn allocateColumns(
    comptime count: usize,
    allocator: std.mem.Allocator,
    size: usize,
) ![count][]M31 {
    var result: [count][]M31 = undefined;
    var initialized: usize = 0;
    errdefer for (result[0..initialized]) |column|
        allocator.free(column);
    for (&result) |*column| {
        column.* = try allocator.alloc(M31, size);
        @memset(column.*, M31.zero());
        initialized += 1;
    }
    return result;
}

fn freeColumns(
    comptime count: usize,
    allocator: std.mem.Allocator,
    columns: *[count][]M31,
) void {
    for (columns) |column| allocator.free(column);
}

fn expectColumnLengths(
    comptime count: usize,
    columns: *const [count][]M31,
    size: usize,
) !void {
    for (columns) |column|
        if (column.len != size)
            return error.InvalidMachineSchedulerTraceShape;
}

fn store(
    comptime count: usize,
    columns: *[count][]M31,
    storage: usize,
    values: *const [count]M31,
) void {
    for (columns, values) |column, value| column[storage] = value;
}

fn expectStored(
    comptime count: usize,
    columns: *const [count][]M31,
    storage: usize,
    values: *const [count]M31,
) !void {
    for (columns, values) |column, value|
        if (!column[storage].eql(value))
            return error.DetachedMachineSchedulerTrace;
}

fn expectColumnsEqual(
    comptime count: usize,
    actual: *const [count][]M31,
    expected: *const [count][]M31,
) !void {
    for (actual, expected) |actual_column, expected_column| {
        if (actual_column.len != expected_column.len)
            return error.DetachedMachineSchedulerTrace;
        for (actual_column, expected_column) |got, want|
            if (!got.eql(want))
                return error.DetachedMachineSchedulerTrace;
    }
}

fn logSize(size: usize) u32 {
    return @intCast(std.math.log2_int(usize, size));
}

fn boolean(value: bool) M31 {
    return M31.fromCanonical(@intFromBool(value));
}
