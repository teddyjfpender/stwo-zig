//! One chronological memory replay for the canonical SM83 machine environment.
//!
//! The ledger order is protocol data: action, scheduler, CPU, service
//! resample, service acknowledgement, timer, joypad, PPU, DMA, observation.

const std = @import("std");
const core_air_utils = @import("stwo_core").air.utils;
const M31 = @import("stwo_core").fields.m31.M31;
const runner = @import("runner/mod.zig");
const machine = @import("runner/machine.zig");
const joypad_trace = @import("joypad_trace.zig");
const machine_replay = @import("machine_memory_replay.zig");
const ledger_mod = @import("machine_environment_memory_ledger.zig");
const device_endpoints = @import("machine_environment_device_endpoints.zig");
const cartridge_access = @import("air/cartridge_access.zig");
const machine_access = @import("air/cartridge_machine_access.zig");
const execution = @import("air/execution.zig");
const memory_lookup = @import("air/cartridge_memory_lookup.zig");
const scheduler = @import("air/scheduler.zig");
const scheduler_memory = @import("air/scheduler_memory_lookup.zig");
const service_memory =
    @import("air/interrupt_service_memory_lookup.zig");
const joypad_binding = @import("air/joypad_binding.zig");
const joypad_if = @import("air/joypad_if_memory_lookup.zig");
const timer_binding = @import("air/timer_binding.zig");
const timer_if = @import("air/timer_if_memory_lookup.zig");
const ppu_binding = @import("air/ppu_binding.zig");
const ppu_if = @import("air/ppu_if_memory_lookup.zig");
const ppu_mmio = @import("runner/ppu_mmio.zig");
const dma_binding = @import("air/dma_binding.zig");
const dma_memory = @import("air/dma_memory_lookup.zig");
const observation =
    @import("air/intermediate_ram_observation_lookup.zig");
const memory_clock = memory_lookup.memory_clock;

const IF: u17 = runner.cartridge_memory.INTERRUPT_FLAGS;
const IE: u17 = 0xffff;
const P1: u17 = runner.joypad.P1_ADDRESS;
const DIV: u17 = timer_binding.FIRST_ADDRESS;

pub const ServicePredecessors = machine_replay.ServicePredecessors;

/// Device register endpoints are committed by their own AIRs. FF46 remains
/// ordinary mutable memory because its CPU write starts DMA.
pub fn memoryBoundaryEnabled(row: usize) bool {
    return row < memory_lookup.KEY_COUNT and
        row != P1 and
        (row < DIV or row > DIV + 3) and
        row != ppu_mmio.LCDC_ADDRESS and
        row != ppu_mmio.STAT_ADDRESS and
        row != ppu_mmio.SCY_ADDRESS and
        row != ppu_mmio.SCX_ADDRESS and
        row != ppu_mmio.LY_ADDRESS and
        row != ppu_mmio.LYC_ADDRESS and
        row != ppu_mmio.WY_ADDRESS and
        (row < runner.apu_mmio.FIRST_ADDRESS or
            row > runner.apu_mmio.LAST_ADDRESS);
}

pub const Replay = struct {
    memory: memory_lookup.Witness,
    scheduler_predecessors: []scheduler_memory.Predecessors,
    service_predecessors: []ServicePredecessors,
    joypad_predecessors: []joypad_if.Predecessor,
    timer_predecessors: []timer_if.Predecessor,
    ppu_predecessors: []ppu_if.Predecessor,
    dma_predecessors: []dma_memory.Predecessors,
    observation_predecessors: []observation.Predecessor,
    initial_mcycle: u32,
    final_mcycle: u32,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Replay) void {
        self.memory.deinit();
        self.allocator.free(self.observation_predecessors);
        self.allocator.free(self.dma_predecessors);
        self.allocator.free(self.ppu_predecessors);
        self.allocator.free(self.timer_predecessors);
        self.allocator.free(self.joypad_predecessors);
        self.allocator.free(self.service_predecessors);
        self.allocator.free(self.scheduler_predecessors);
        self.* = undefined;
    }

    pub fn validate(
        self: *const Replay,
        allocator: std.mem.Allocator,
        results: []const machine.CartridgeStepResult,
        initial: memory_lookup.Images,
        final: memory_lookup.Images,
        initial_mcycle: u32,
        joypad_events: []const joypad_trace.EventRow,
        timer_events: []const timer_binding.EventRow,
        ppu_events: []const ppu_binding.EventRow,
        dma_events: []const dma_binding.EventRow,
        observations: []const observation.Sample,
    ) !void {
        var expected = try generate(
            allocator,
            results,
            initial,
            final,
            initial_mcycle,
            joypad_events,
            timer_events,
            ppu_events,
            dma_events,
            observations,
        );
        defer expected.deinit();
        if (self.initial_mcycle != expected.initial_mcycle or
            self.final_mcycle != expected.final_mcycle)
            return error.ReplayClockMismatch;
        if (!equalSlice(
            scheduler_memory.Predecessors,
            self.scheduler_predecessors,
            expected.scheduler_predecessors,
        )) return error.SchedulerPredecessorMismatch;
        if (!equalSlice(
            ServicePredecessors,
            self.service_predecessors,
            expected.service_predecessors,
        )) return error.ServicePredecessorMismatch;
        if (!equalSlice(
            joypad_if.Predecessor,
            self.joypad_predecessors,
            expected.joypad_predecessors,
        )) return error.JoypadPredecessorMismatch;
        if (!equalSlice(
            timer_if.Predecessor,
            self.timer_predecessors,
            expected.timer_predecessors,
        )) return error.TimerPredecessorMismatch;
        if (!equalSlice(
            ppu_if.Predecessor,
            self.ppu_predecessors,
            expected.ppu_predecessors,
        )) return error.PpuPredecessorMismatch;
        if (!equalSlice(
            dma_memory.Predecessors,
            self.dma_predecessors,
            expected.dma_predecessors,
        )) return error.DmaPredecessorMismatch;
        if (!equalSlice(
            observation.Predecessor,
            self.observation_predecessors,
            expected.observation_predecessors,
        )) return error.ObservationPredecessorMismatch;
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
    joypad_events: []const joypad_trace.EventRow,
    timer_events: []const timer_binding.EventRow,
    ppu_events: []const ppu_binding.EventRow,
    dma_events: []const dma_binding.EventRow,
    observations: []const observation.Sample,
) !Replay {
    try validateShapes(initial, final);
    if (results.len < 16 or !std.math.isPowerOfTwo(results.len))
        return error.InvalidTraceLength;
    if (joypad_events.len == 0 or timer_events.len == 0 or
        ppu_events.len == 0 or dma_events.len == 0)
        return error.VacuousDeviceTrace;
    if (initial_mcycle > memory_clock.MAX_FINAL_MCYCLE)
        return error.NonCanonicalMemoryClock;
    if (observations.len != 0) {
        try observation.validateSchedule(observations);
        if (observations[0].mcycle < initial_mcycle)
            return error.ObservationOutsideExecutionSegment;
    }
    try device_endpoints.validate(
        initial,
        final,
        joypad_events,
        timer_events,
        ppu_events,
        dma_events,
    );

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
    const joypad_predecessors = try allocator.alloc(
        joypad_if.Predecessor,
        joypad_events.len,
    );
    errdefer allocator.free(joypad_predecessors);
    @memset(joypad_predecessors, joypad_if.Predecessor{});
    const timer_predecessors = try allocator.alloc(
        timer_if.Predecessor,
        timer_events.len,
    );
    errdefer allocator.free(timer_predecessors);
    @memset(timer_predecessors, timer_if.Predecessor{});
    const ppu_predecessors = try allocator.alloc(
        ppu_if.Predecessor,
        ppu_events.len,
    );
    errdefer allocator.free(ppu_predecessors);
    @memset(ppu_predecessors, ppu_if.Predecessor{});
    const dma_predecessors = try allocator.alloc(
        dma_memory.Predecessors,
        dma_events.len,
    );
    errdefer allocator.free(dma_predecessors);
    @memset(dma_predecessors, dma_memory.Predecessors{});
    const observation_predecessors = try allocator.alloc(
        observation.Predecessor,
        observations.len,
    );
    errdefer allocator.free(observation_predecessors);
    @memset(observation_predecessors, .{ .clock = 0 });

    var ledger = try ledger_mod.Ledger.init(allocator, initial);
    defer ledger.deinit();
    var cursor = ledger_mod.Cursor{};
    var mcycle = initial_mcycle;
    for (results, 0..) |result, row| {
        if (row != 0) {
            try validateMachineSuccessor(results[row - 1], result);
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

        for (validated.activeCycles(), 0..) |cycle, cycle_index| {
            const absolute = std.math.add(
                u32,
                mcycle,
                @intCast(cycle_index),
            ) catch return error.MemoryClockOverflow;
            try ledger_mod.consumeAction(
                &cursor,
                absolute,
                results,
                joypad_events,
                joypad_predecessors,
                &ledger,
            );
            if (cycle_index == 0)
                try replayScheduler(
                    result,
                    absolute,
                    &scheduler_predecessors[row],
                    &ledger,
                );
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
                    asScheduler(ledger.predecessor(IF));
                if (sample.value != ledger.bytes[IF] & 0x1f)
                    return error.ServiceIfSampleMismatch;
            }
            if (cycle.access) |access| {
                try validateMmioMetadata(access);
                if (try mutableKey(access)) |key|
                    try replayCpu(
                        &main,
                        accesses,
                        storage,
                        row,
                        cycle_index,
                        absolute,
                        key,
                        access,
                        &ledger,
                    );
            }
            try ledger_mod.consumeJoypadWrite(
                &cursor,
                absolute,
                row,
                cycle_index,
                cycle.access,
                results,
                joypad_events,
                joypad_predecessors,
                &ledger,
            );
            try ledger_mod.consumeTimerWrite(
                &cursor,
                absolute,
                row,
                cycle_index,
                cycle.access,
                results,
                timer_events,
            );
            try ledger_mod.consumePpuWrite(
                &cursor,
                absolute,
                row,
                cycle_index,
                cycle.access,
                ppu_events,
            );
            try replayService(
                result,
                cycle_index,
                absolute,
                if_sample != null,
                &service_predecessors[row],
                &ledger,
            );
            try ledger_mod.consumeTimerTick(
                &cursor,
                absolute,
                row,
                cycle_index,
                results,
                timer_events,
                timer_predecessors,
                &ledger,
            );
            try ledger_mod.consumeJoypadTick(
                &cursor,
                absolute,
                row,
                cycle_index,
                results,
                joypad_events,
                joypad_predecessors,
                &ledger,
            );
            try ledger_mod.consumePpuTicks(
                &cursor,
                absolute,
                row,
                cycle_index,
                cycle.access,
                ppu_events,
                ppu_predecessors,
                &ledger,
            );
            try ledger_mod.consumeDma(
                &cursor,
                absolute,
                row,
                cycle_index,
                results,
                dma_events,
                dma_predecessors,
                &ledger,
            );
            try ledger_mod.consumeObservations(
                &cursor,
                absolute,
                observations,
                observation_predecessors,
                &ledger,
            );
            if (cycle_index + 1 ==
                @as(usize, validated.count))
            {
                scheduler_predecessors[row].post_interrupt_flags =
                    asScheduler(ledger.predecessor(IF));
                _ = try ledger.read(
                    IF,
                    result.after.interrupt_flags,
                    absolute,
                    memory_clock.OBSERVATION_PHASE,
                );
            }
        }
        _ = try scheduler_memory.columns(
            scheduler.ValidatedStep.init(result) catch
                return error.InvalidMachineStep,
            mcycle,
            scheduler_predecessors[row],
        );
        _ = try service_memory.columns(
            result,
            mcycle,
            service_predecessors[row],
        );
        mcycle = std.math.add(
            u32,
            mcycle,
            result.m_cycles,
        ) catch return error.MemoryClockOverflow;
        if (mcycle > memory_clock.MAX_FINAL_MCYCLE)
            return error.NonCanonicalMemoryClock;
    }
    try validateConsumed(cursor, joypad_events, timer_events, ppu_events, dma_events, observations);
    device_endpoints.installFinals(&ledger, final);
    if (!std.mem.eql(
        u8,
        ledger.bytes[0..memory_lookup.SYSTEM_SIZE],
        final.system.bytes,
    ) or !std.mem.eql(
        u8,
        ledger.bytes[memory_lookup.SYSTEM_SIZE..],
        final.sram.bytes,
    )) return error.FinalMemoryMismatch;
    try ledger.writeFinalClocks(final_clocks);

    return .{
        .memory = .{
            .main = main,
            .final_clocks = final_clocks,
            .accesses = accesses,
            .allocator = allocator,
        },
        .scheduler_predecessors = scheduler_predecessors,
        .service_predecessors = service_predecessors,
        .joypad_predecessors = joypad_predecessors,
        .timer_predecessors = timer_predecessors,
        .ppu_predecessors = ppu_predecessors,
        .dma_predecessors = dma_predecessors,
        .observation_predecessors = observation_predecessors,
        .initial_mcycle = initial_mcycle,
        .final_mcycle = mcycle,
        .allocator = allocator,
    };
}

fn replayScheduler(
    result: machine.CartridgeStepResult,
    mcycle: u32,
    out: *scheduler_memory.Predecessors,
    ledger: *ledger_mod.Ledger,
) !void {
    out.* = .{
        .interrupt_enable = asScheduler(ledger.predecessor(IE)),
        .interrupt_flags = asScheduler(ledger.predecessor(IF)),
    };
    _ = try ledger.read(
        IE,
        result.before.interrupt_enable,
        mcycle,
        memory_clock.SCHEDULER_PHASE,
    );
    _ = try ledger.read(
        IF,
        result.before.interrupt_flags,
        mcycle,
        memory_clock.SCHEDULER_PHASE,
    );
}

fn replayService(
    result: machine.CartridgeStepResult,
    cycle: usize,
    mcycle: u32,
    has_if_sample: bool,
    out: *ServicePredecessors,
    ledger: *ledger_mod.Ledger,
) !void {
    if (result.event != .interrupt_service) return;
    if (result.service.ie_resample.?.after_cycle == cycle) {
        const sample = result.service.ie_resample.?;
        out.ie_resample = asScheduler(try ledger.read(
            IE,
            sample.value,
            mcycle,
            memory_clock.SERVICE_RESAMPLE_PHASE,
        ));
    }
    if (has_if_sample) {
        out.if_resample = asScheduler(try ledger.read(
            IF,
            ledger.bytes[IF],
            mcycle,
            memory_clock.SERVICE_RESAMPLE_PHASE,
        ));
    }
    if (result.service.acknowledgement) |ack| {
        if (ack.during_cycle == cycle) {
            if (ledger.bytes[IF] != ack.before)
                return error.ServiceAcknowledgementMismatch;
            out.acknowledgement = asScheduler(try ledger.write(
                IF,
                ack.after,
                mcycle,
                memory_clock.SERVICE_ACK_PHASE,
            ));
        }
    }
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

fn replayCpu(
    main: *[memory_lookup.N_MAIN_COLUMNS][]M31,
    accesses: []memory_lookup.Access,
    storage: usize,
    row: usize,
    cycle: usize,
    mcycle: u32,
    key: u17,
    access: runner.cartridge_memory.Access,
    ledger: *ledger_mod.Ledger,
) !void {
    const previous = ledger.predecessor(key);
    const clock = try ledger_mod.canonicalClock(
        mcycle,
        memory_clock.CPU_PHASE,
    );
    const difference = try ledger_mod.difference(
        previous.clock,
        clock,
    );
    if (access.action == .read and access.value != previous.value)
        return error.MemoryReadMismatch;
    const next = if (access.action == .write)
        access.value
    else
        previous.value;
    try ledger.advance(key, next, mcycle, memory_clock.CPU_PHASE);
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
    for (0..memory_lookup.N_DIFF_BITS) |bit|
        main[offset + memory_lookup.DIFFERENCE_BITS_OFFSET + bit][storage] =
            M31.fromCanonical(difference >> @intCast(bit) & 1);
}

fn mutableKey(
    access: runner.cartridge_memory.Access,
) !?u17 {
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

fn validateMmioMetadata(
    access: runner.cartridge_memory.Access,
) !void {
    if (access.logical_address == IF)
        return error.UnsupportedIfBusAccess;
    const expected: ?runner.cartridge_memory.Region =
        switch (access.logical_address) {
            runner.joypad.P1_ADDRESS => .joypad_mmio,
            timer_binding.FIRST_ADDRESS...timer_binding.FIRST_ADDRESS + 3 => .timer_mmio,
            ppu_mmio.LCDC_ADDRESS,
            ppu_mmio.STAT_ADDRESS,
            ppu_mmio.SCY_ADDRESS,
            ppu_mmio.SCX_ADDRESS,
            ppu_mmio.LY_ADDRESS,
            ppu_mmio.LYC_ADDRESS,
            ppu_mmio.WY_ADDRESS,
            => .ppu_mmio,
            runner.apu_mmio.FIRST_ADDRESS...runner.apu_mmio.LAST_ADDRESS => .apu_mmio,
            else => null,
        };
    if (expected) |region| {
        if (access.region != region)
            return error.UnauthenticatedDeviceMmioMetadata;
    } else switch (access.region) {
        .joypad_mmio,
        .timer_mmio,
        .ppu_mmio,
        .apu_mmio,
        => return error.InvalidDeviceMmioMetadata,
        else => {},
    }
}

test "FF0F cannot enter the ordinary CPU memory replay" {
    for ([_]runner.cartridge_memory.Action{ .read, .write }) |action| {
        try std.testing.expectError(
            error.UnsupportedIfBusAccess,
            validateMmioMetadata(.{
                .logical_address = @intCast(IF),
                .action = action,
                .region = .system,
                .physical_offset = null,
                .mapper_before = .{},
                .mapper_after = .{},
                .value = 0x1f,
            }),
        );
    }
}

fn validateMachineSuccessor(
    previous: machine.CartridgeStepResult,
    next: machine.CartridgeStepResult,
) !void {
    var expected = previous.after;
    expected.interrupt_flags = next.before.interrupt_flags;
    if (!std.meta.eql(expected, next.before))
        return error.DisconnectedMachineState;
}

fn validateConsumed(
    cursor: ledger_mod.Cursor,
    joypad_events: []const joypad_trace.EventRow,
    timer_events: []const timer_binding.EventRow,
    ppu_events: []const ppu_binding.EventRow,
    dma_events: []const dma_binding.EventRow,
    observations: []const observation.Sample,
) !void {
    if (cursor.joypad != joypad_events.len)
        return error.UnconsumedJoypadEvent;
    if (cursor.timer != timer_events.len)
        return error.UnconsumedTimerEvent;
    if (cursor.ppu != ppu_events.len)
        return error.UnconsumedPpuEvent;
    if (cursor.dma != dma_events.len)
        return error.UnconsumedDmaEvent;
    if (cursor.observation != observations.len)
        return error.ObservationOutsideExecutionSegment;
}

fn validateShapes(
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

fn asScheduler(
    previous: ledger_mod.Predecessor,
) scheduler_memory.Predecessor {
    return .{ .clock = previous.clock, .value = previous.value };
}

fn equalSlice(
    comptime T: type,
    left: []const T,
    right: []const T,
) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b|
        if (!std.meta.eql(a, b)) return false;
    return true;
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

fn equalM31(left: []const M31, right: []const M31) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b|
        if (!a.eql(b)) return false;
    return true;
}
