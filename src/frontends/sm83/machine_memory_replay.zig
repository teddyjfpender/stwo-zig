//! Detached mutable-memory replay for canonical cartridge-machine rows.
//!
//! Scheduler samples and interrupt-service logical operations advance the
//! shared memory history in their ledger phases, but remain separate from the
//! CPU bus columns. Device MMIO is deliberately left to the environment
//! composition that owns the corresponding device traces.

const std = @import("std");
const core_air_utils = @import("stwo_core").air.utils;
const M31 = @import("stwo_core").fields.m31.M31;
const runner = @import("runner/mod.zig");
const machine = @import("runner/machine.zig");
const cartridge_access = @import("air/cartridge_access.zig");
const machine_access = @import("air/cartridge_machine_access.zig");
const execution = @import("air/execution.zig");
const memory_lookup = @import("air/cartridge_memory_lookup.zig");
const scheduler = @import("air/scheduler.zig");
const scheduler_memory = @import("air/scheduler_memory_lookup.zig");
const memory_clock = memory_lookup.memory_clock;

const IF: u17 = runner.cartridge_memory.INTERRUPT_FLAGS;
const IE: u17 = 0xffff;

pub const Predecessor = scheduler_memory.Predecessor;

/// Service-owned history endpoints. `if_logical_source` is the raw IF state
/// sampled before the low stack write; it differs from `if_resample` only when
/// the stack aliases FF0F.
pub const ServicePredecessors = struct {
    ie_resample: ?Predecessor = null,
    if_logical_source: ?Predecessor = null,
    if_resample: ?Predecessor = null,
    acknowledgement: ?Predecessor = null,
};

pub const Replay = struct {
    memory: memory_lookup.Witness,
    scheduler_predecessors: []scheduler_memory.Predecessors,
    service_predecessors: []ServicePredecessors,
    initial_mcycle: u32,
    final_mcycle: u32,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Replay) void {
        self.memory.deinit();
        self.allocator.free(self.service_predecessors);
        self.allocator.free(self.scheduler_predecessors);
        self.* = undefined;
    }

    /// Rebuilds every owned column, endpoint, and predecessor.
    pub fn validate(
        self: *const Replay,
        allocator: std.mem.Allocator,
        results: []const machine.CartridgeStepResult,
        initial: memory_lookup.Images,
        final: memory_lookup.Images,
        initial_mcycle: u32,
    ) !void {
        var expected = try generate(
            allocator,
            results,
            initial,
            final,
            initial_mcycle,
        );
        defer expected.deinit();
        if (self.initial_mcycle != expected.initial_mcycle or
            self.final_mcycle != expected.final_mcycle)
            return error.ReplayClockMismatch;
        if (!equalSchedulerPredecessors(
            self.scheduler_predecessors,
            expected.scheduler_predecessors,
        )) return error.SchedulerPredecessorMismatch;
        if (!equalServicePredecessors(
            self.service_predecessors,
            expected.service_predecessors,
        )) return error.ServicePredecessorMismatch;
        if (!equalWitness(self.memory, expected.memory))
            return error.ReplayMemoryMismatch;
    }
};

pub fn generate(
    allocator: std.mem.Allocator,
    results: []const machine.CartridgeStepResult,
    initial: memory_lookup.Images,
    final: memory_lookup.Images,
    initial_mcycle: u32,
) !Replay {
    try validateImageShapes(initial, final);
    if (results.len < 16 or !std.math.isPowerOfTwo(results.len))
        return error.InvalidTraceLength;
    if (initial_mcycle > memory_clock.MAX_FINAL_MCYCLE)
        return error.NonCanonicalMemoryClock;

    const log_size: u32 =
        @intCast(std.math.log2_int(usize, results.len));
    var main: [memory_lookup.N_MAIN_COLUMNS][]M31 = undefined;
    var initialized: usize = 0;
    errdefer for (main[0..initialized]) |column|
        allocator.free(column);
    for (&main) |*column| {
        column.* = try allocator.alloc(M31, results.len);
        @memset(column.*, M31.zero());
        initialized += 1;
    }
    const final_clocks = try allocator.alloc(
        M31,
        memory_lookup.BOUNDARY_SIZE,
    );
    errdefer allocator.free(final_clocks);
    @memset(final_clocks, M31.zero());
    const accesses = try allocator.alloc(
        memory_lookup.Access,
        results.len * execution.N_BUS_CYCLES,
    );
    errdefer allocator.free(accesses);
    @memset(accesses, memory_lookup.Access{});
    const scheduler_predecessors = try allocator.alloc(
        scheduler_memory.Predecessors,
        results.len,
    );
    errdefer allocator.free(scheduler_predecessors);
    @memset(scheduler_predecessors, scheduler_memory.Predecessors{});
    const service_predecessors = try allocator.alloc(
        ServicePredecessors,
        results.len,
    );
    errdefer allocator.free(service_predecessors);
    @memset(service_predecessors, ServicePredecessors{});

    const bytes = try allocator.alloc(u8, memory_lookup.KEY_COUNT);
    defer allocator.free(bytes);
    @memcpy(
        bytes[0..memory_lookup.SYSTEM_SIZE],
        initial.system.bytes,
    );
    @memcpy(
        bytes[memory_lookup.SYSTEM_SIZE..],
        initial.sram.bytes,
    );
    const clocks = try allocator.alloc(u32, memory_lookup.KEY_COUNT);
    defer allocator.free(clocks);
    @memset(clocks, 0);

    var mcycle = initial_mcycle;
    for (results, 0..) |result, row| {
        if (row != 0) {
            if (!std.meta.eql(results[row - 1].after, result.before))
                return error.DisconnectedMachineState;
            if (!std.meta.eql(
                results[row - 1].mapper_after,
                result.mapper_before,
            )) return error.DisconnectedMapperState;
        }
        const validated = machine_access.ValidatedStep.init(result) catch
            return error.InvalidMachineStep;
        if (validated.count == 0) return error.VacuousMachineStep;
        const storage = try core_air_utils.circleBitReversedIndex(
            log_size,
            row,
        );
        try replaySchedulerSample(
            result,
            mcycle,
            bytes,
            clocks,
            &scheduler_predecessors[row],
        );

        for (validated.activeCycles(), 0..) |cycle, cycle_index| {
            const absolute_mcycle = std.math.add(
                u32,
                mcycle,
                @intCast(cycle_index),
            ) catch return error.MemoryClockOverflow;
            try populateProjectedColumns(
                &main,
                storage,
                cycle_index,
                validated,
            );

            const if_sample = if (result.event == .interrupt_service and
                result.service.if_resample.?.after_cycle == cycle_index)
                result.service.if_resample
            else
                null;
            if (if_sample) |sample| {
                service_predecessors[row].if_logical_source =
                    predecessor(clocks, bytes, IF);
                if (sample.value != bytes[IF] & 0x1f)
                    return error.ServiceIfSampleMismatch;
            }

            if (cycle.access) |access| {
                try rejectDeviceMmio(access);
                if (try mutableKey(access)) |key| {
                    try replayCpuAccess(
                        &main,
                        accesses,
                        storage,
                        row,
                        cycle_index,
                        absolute_mcycle,
                        key,
                        access,
                        bytes,
                        clocks,
                    );
                }
            }

            if (result.event == .interrupt_service) {
                if (result.service.ie_resample.?.after_cycle ==
                    cycle_index)
                {
                    if (result.service.ie_resample.?.value != bytes[IE])
                        return error.ServiceIeSampleMismatch;
                    service_predecessors[row].ie_resample =
                        try replayRead(
                            IE,
                            absolute_mcycle,
                            memory_clock.SERVICE_RESAMPLE_PHASE,
                            bytes,
                            clocks,
                        );
                }
                if (if_sample != null) {
                    service_predecessors[row].if_resample =
                        try replayRead(
                            IF,
                            absolute_mcycle,
                            memory_clock.SERVICE_RESAMPLE_PHASE,
                            bytes,
                            clocks,
                        );
                }
                if (result.service.acknowledgement) |ack| {
                    if (ack.during_cycle == cycle_index) {
                        if (bytes[IF] != ack.before)
                            return error.ServiceAcknowledgementMismatch;
                        service_predecessors[row].acknowledgement =
                            try replayWrite(
                                IF,
                                ack.after,
                                absolute_mcycle,
                                memory_clock.SERVICE_ACK_PHASE,
                                bytes,
                                clocks,
                            );
                    }
                }
            }
            if (cycle_index + 1 ==
                @as(usize, validated.count))
            {
                try replaySchedulerPost(
                    result,
                    absolute_mcycle,
                    bytes,
                    clocks,
                    &scheduler_predecessors[row],
                );
            }
        }
        _ = try scheduler_memory.columns(
            scheduler.ValidatedStep.init(result) catch
                return error.InvalidMachineStep,
            mcycle,
            scheduler_predecessors[row],
        );
        mcycle = std.math.add(
            u32,
            mcycle,
            result.m_cycles,
        ) catch return error.MemoryClockOverflow;
        if (mcycle > memory_clock.MAX_FINAL_MCYCLE)
            return error.NonCanonicalMemoryClock;
    }

    if (!std.mem.eql(
        u8,
        bytes[0..memory_lookup.SYSTEM_SIZE],
        final.system.bytes,
    ) or !std.mem.eql(
        u8,
        bytes[memory_lookup.SYSTEM_SIZE..],
        final.sram.bytes,
    )) return error.FinalMemoryMismatch;
    for (clocks, 0..) |clock, key| {
        final_clocks[
            try core_air_utils.circleBitReversedIndex(
                memory_lookup.BOUNDARY_LOG_SIZE,
                key,
            )
        ] = M31.fromCanonical(clock);
    }
    return .{
        .memory = .{
            .main = main,
            .final_clocks = final_clocks,
            .accesses = accesses,
            .allocator = allocator,
        },
        .scheduler_predecessors = scheduler_predecessors,
        .service_predecessors = service_predecessors,
        .initial_mcycle = initial_mcycle,
        .final_mcycle = mcycle,
        .allocator = allocator,
    };
}

fn replaySchedulerSample(
    result: machine.CartridgeStepResult,
    mcycle: u32,
    bytes: []u8,
    clocks: []u32,
    out: *scheduler_memory.Predecessors,
) !void {
    out.* = .{
        .interrupt_enable = predecessor(clocks, bytes, IE),
        .interrupt_flags = predecessor(clocks, bytes, IF),
    };
    if (bytes[IE] != result.before.interrupt_enable or
        bytes[IF] != result.before.interrupt_flags)
        return error.SchedulerMemoryReadMismatch;
    const clock = try phaseClock(
        mcycle,
        memory_clock.SCHEDULER_PHASE,
    );
    clocks[IE] = clock;
    clocks[IF] = clock;
}

fn replaySchedulerPost(
    result: machine.CartridgeStepResult,
    mcycle: u32,
    bytes: []u8,
    clocks: []u32,
    out: *scheduler_memory.Predecessors,
) !void {
    if (bytes[IF] != result.after.interrupt_flags)
        return error.SchedulerMemoryReadMismatch;
    out.post_interrupt_flags =
        predecessor(clocks, bytes, IF);
    _ = try replayRead(
        IF,
        mcycle,
        memory_clock.OBSERVATION_PHASE,
        bytes,
        clocks,
    );
}

fn populateProjectedColumns(
    main: *[memory_lookup.N_MAIN_COLUMNS][]M31,
    storage: usize,
    cycle: usize,
    step: machine_access.ValidatedStep,
) !void {
    const source_values = machine_access.columnsForCycle(step, cycle);
    const source = try cartridge_access.Semantics(M31)
        .Row.fromColumns(&source_values);
    const projected = memory_lookup.Semantics(M31).project(source);
    const offset = cycle * memory_lookup.N_ACCESS_COLUMNS;
    main[offset + memory_lookup.PROJECTED_ENABLED_OFFSET][storage] =
        projected.enabled;
    main[offset + memory_lookup.PROJECTED_READ_OFFSET][storage] =
        projected.read;
    main[offset + memory_lookup.PROJECTED_WRITE_OFFSET][storage] =
        projected.write;
    main[offset + memory_lookup.PROJECTED_KEY_OFFSET][storage] =
        projected.key;
    main[offset + memory_lookup.PROJECTED_VALUE_OFFSET][storage] =
        projected.value;
}

fn replayCpuAccess(
    main: *[memory_lookup.N_MAIN_COLUMNS][]M31,
    accesses: []memory_lookup.Access,
    storage: usize,
    row: usize,
    cycle: usize,
    mcycle: u32,
    key: u17,
    access: runner.cartridge_memory.Access,
    bytes: []u8,
    clocks: []u32,
) !void {
    const clock = try phaseClock(mcycle, memory_clock.CPU_PHASE);
    const previous = predecessor(clocks, bytes, key);
    if (access.action == .read and access.value != previous.value)
        return error.MemoryReadMismatch;
    const next = if (access.action == .write)
        access.value
    else
        previous.value;
    const difference = try clockDifference(previous.clock, clock);
    bytes[key] = next;
    clocks[key] = clock;
    accesses[row * execution.N_BUS_CYCLES + cycle] = .{
        .enabled = true,
        .address = key,
        .previous_clock = previous.clock,
        .previous_value = previous.value,
        .clock = clock,
        .next_value = next,
    };
    const offset = cycle * memory_lookup.N_ACCESS_COLUMNS;
    main[offset + memory_lookup.PREVIOUS_CLOCK_OFFSET][storage] =
        M31.fromCanonical(previous.clock);
    main[offset + memory_lookup.PREVIOUS_VALUE_OFFSET][storage] =
        M31.fromCanonical(previous.value);
    main[offset + memory_lookup.NEXT_VALUE_OFFSET][storage] =
        M31.fromCanonical(next);
    writeDifference(
        main,
        storage,
        offset + memory_lookup.DIFFERENCE_BITS_OFFSET,
        difference,
    );
}

fn replayRead(
    key: u17,
    mcycle: u32,
    phase: u32,
    bytes: []u8,
    clocks: []u32,
) !Predecessor {
    const previous = predecessor(clocks, bytes, key);
    const clock = try phaseClock(mcycle, phase);
    _ = try clockDifference(previous.clock, clock);
    clocks[key] = clock;
    return previous;
}

fn replayWrite(
    key: u17,
    value: u8,
    mcycle: u32,
    phase: u32,
    bytes: []u8,
    clocks: []u32,
) !Predecessor {
    const previous = predecessor(clocks, bytes, key);
    const clock = try phaseClock(mcycle, phase);
    _ = try clockDifference(previous.clock, clock);
    bytes[key] = value;
    clocks[key] = clock;
    return previous;
}

fn predecessor(
    clocks: []const u32,
    bytes: []const u8,
    key: u17,
) Predecessor {
    return .{ .clock = clocks[key], .value = bytes[key] };
}

fn phaseClock(mcycle: u32, phase: u32) !u32 {
    return memory_clock.phaseClock(mcycle, phase) catch |err| switch (err) {
        error.MemoryClockOverflow => error.MemoryClockOverflow,
        error.MemoryClockOutsideField,
        error.InvalidMemoryClockPhase,
        => error.NonCanonicalMemoryClock,
    };
}

fn clockDifference(previous: u32, next: u32) !u32 {
    if (previous >= next) return error.InvalidMemoryClock;
    const difference = next - previous - 1;
    if (difference >= (@as(u32, 1) << memory_lookup.N_DIFF_BITS))
        return error.MemoryClockDifferenceTooLarge;
    return difference;
}

fn writeDifference(
    main: *[memory_lookup.N_MAIN_COLUMNS][]M31,
    storage: usize,
    offset: usize,
    difference: u32,
) void {
    for (0..memory_lookup.N_DIFF_BITS) |bit|
        main[offset + bit][storage] = M31.fromCanonical(
            difference >> @intCast(bit) & 1,
        );
}

fn rejectDeviceMmio(access: runner.cartridge_memory.Access) !void {
    switch (access.region) {
        .joypad_mmio,
        .timer_mmio,
        .ppu_mmio,
        .apu_mmio,
        => return error.AttachedDeviceMmio,
        else => {},
    }
}

fn mutableKey(access: runner.cartridge_memory.Access) !?u17 {
    return switch (access.region) {
        .system => if (access.physical_offset == null)
            @intCast(access.logical_address)
        else
            error.InvalidMutableAddress,
        .system_echo => if (access.physical_offset) |physical|
            if (physical < memory_lookup.SYSTEM_SIZE)
                @intCast(physical)
            else
                error.InvalidMutableAddress
        else
            error.InvalidMutableAddress,
        .cartridge_ram => if (access.physical_offset) |physical|
            if (physical < memory_lookup.SRAM_SIZE)
                @intCast(memory_lookup.SRAM_KEY_OFFSET + physical)
            else
                error.InvalidMutableAddress
        else
            error.InvalidMutableAddress,
        .cartridge_rom,
        .mapper_control,
        .cartridge_open_bus,
        .cartridge_ram_ignored,
        .joypad_mmio,
        .timer_mmio,
        .ppu_mmio,
        .apu_mmio,
        => null,
    };
}

fn validateImageShapes(
    initial: memory_lookup.Images,
    final: memory_lookup.Images,
) !void {
    if (initial.system.bytes.len != memory_lookup.SYSTEM_SIZE or
        final.system.bytes.len != memory_lookup.SYSTEM_SIZE)
        return error.InvalidSystemMemoryShape;
    if (initial.sram.bytes.len != memory_lookup.SRAM_SIZE or
        final.sram.bytes.len != memory_lookup.SRAM_SIZE)
        return error.InvalidSramShape;
}

fn equalWitness(
    left: memory_lookup.Witness,
    right: memory_lookup.Witness,
) bool {
    for (left.main, right.main) |a, b|
        if (!equalM31(a, b)) return false;
    if (!equalM31(left.final_clocks, right.final_clocks) or
        left.accesses.len != right.accesses.len)
        return false;
    for (left.accesses, right.accesses) |a, b|
        if (!std.meta.eql(a, b)) return false;
    return true;
}

fn equalSchedulerPredecessors(
    left: []const scheduler_memory.Predecessors,
    right: []const scheduler_memory.Predecessors,
) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b|
        if (!std.meta.eql(a, b)) return false;
    return true;
}

fn equalServicePredecessors(
    left: []const ServicePredecessors,
    right: []const ServicePredecessors,
) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b|
        if (!std.meta.eql(a, b)) return false;
    return true;
}

fn equalM31(left: []const M31, right: []const M31) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b|
        if (!a.eql(b)) return false;
    return true;
}
