//! Phase-ordered CPU, device, and observation replay for an environment.
//!
//! Device and CPU updates share one per-address history. Within an M-cycle the
//! order is action, CPU, timer, joypad, PPU, DMA, then observation. The owned
//! result supplies memory columns, final clocks, and exact predecessors.

const std = @import("std");
const core_air_utils = @import("stwo_core").air.utils;
const M31 = @import("stwo_core").fields.m31.M31;
const event_trace = @import("joypad_trace.zig");
const runner = @import("runner/mod.zig");
const timer_runner = @import("runner/timer.zig");
const cartridge_access = @import("air/cartridge_access.zig");
const execution = @import("air/execution.zig");
const joypad_binding = @import("air/joypad_binding.zig");
const joypad_if = @import("air/joypad_if_memory_lookup.zig");
const observation =
    @import("air/intermediate_ram_observation_lookup.zig");
const memory_lookup = @import("air/cartridge_memory_lookup.zig");
const timer_binding = @import("air/timer_binding.zig");
const timer_if = @import("air/timer_if_memory_lookup.zig");
const memory_clock = memory_lookup.memory_clock;

pub const Replay = struct {
    memory: memory_lookup.Witness,
    predecessors: []joypad_if.Predecessor,
    timer_predecessors: []timer_if.Predecessor,
    observation_predecessors: []observation.Predecessor,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *Replay) void {
        self.memory.deinit();
        self.allocator.free(self.observation_predecessors);
        self.allocator.free(self.timer_predecessors);
        self.allocator.free(self.predecessors);
        self.* = undefined;
    }

    /// Rebuilds the deterministic replay and rejects any drift in owned data.
    pub fn validate(
        self: *const Replay,
        allocator: std.mem.Allocator,
        steps: []const runner.CartridgeStepTrace,
        initial: memory_lookup.Images,
        final: memory_lookup.Images,
        initial_mcycle: u32,
        events: []const event_trace.EventRow,
    ) !void {
        try self.validateDevices(
            allocator,
            steps,
            initial,
            final,
            initial_mcycle,
            events,
            &.{},
        );
    }

    /// Rebuilds the complete device replay and rejects owned-data drift.
    pub fn validateDevices(
        self: *const Replay,
        allocator: std.mem.Allocator,
        steps: []const runner.CartridgeStepTrace,
        initial: memory_lookup.Images,
        final: memory_lookup.Images,
        initial_mcycle: u32,
        events: []const event_trace.EventRow,
        timer_events: []const timer_binding.EventRow,
    ) !void {
        try self.validateDevicesWithObservations(
            allocator,
            steps,
            initial,
            final,
            initial_mcycle,
            events,
            timer_events,
            &.{},
        );
    }

    /// Rebuilds device and observation replay and rejects owned-data drift.
    pub fn validateDevicesWithObservations(
        self: *const Replay,
        allocator: std.mem.Allocator,
        steps: []const runner.CartridgeStepTrace,
        initial: memory_lookup.Images,
        final: memory_lookup.Images,
        initial_mcycle: u32,
        events: []const event_trace.EventRow,
        timer_events: []const timer_binding.EventRow,
        observations: []const observation.Sample,
    ) !void {
        var expected = try generateDevicesWithObservations(
            allocator,
            steps,
            initial,
            final,
            initial_mcycle,
            events,
            timer_events,
            observations,
        );
        defer expected.deinit();
        if (!equalPredecessors(
            self.predecessors,
            expected.predecessors,
        )) return error.ReplayPredecessorMismatch;
        if (!equalTimerPredecessors(
            self.timer_predecessors,
            expected.timer_predecessors,
        )) return error.ReplayTimerPredecessorMismatch;
        if (!equalObservationPredecessors(
            self.observation_predecessors,
            expected.observation_predecessors,
        )) return error.ReplayObservationPredecessorMismatch;
        if (!equalWitness(self.memory, expected.memory))
            return error.ReplayMemoryMismatch;
    }
};

const Cursor = struct {
    events: []const event_trace.EventRow,
    predecessors: []joypad_if.Predecessor,
    steps: []const runner.CartridgeStepTrace,
    bytes: []u8,
    clocks: []u32,
    index: usize = 0,
    previous_after: ?runner.joypad.State = null,
    timer_events: []const timer_binding.EventRow,
    timer_predecessors: []timer_if.Predecessor,
    timer_index: usize = 0,
    previous_timer_after: ?timer_runner.Timer = null,
    observations: []const observation.Sample,
    observation_predecessors: []observation.Predecessor,
    observation_index: usize = 0,
};

pub fn generate(
    allocator: std.mem.Allocator,
    steps: []const runner.CartridgeStepTrace,
    initial: memory_lookup.Images,
    final: memory_lookup.Images,
    initial_mcycle: u32,
    events: []const event_trace.EventRow,
) !Replay {
    return generateDevices(
        allocator,
        steps,
        initial,
        final,
        initial_mcycle,
        events,
        &.{},
    );
}

pub fn generateDevices(
    allocator: std.mem.Allocator,
    steps: []const runner.CartridgeStepTrace,
    initial: memory_lookup.Images,
    final: memory_lookup.Images,
    initial_mcycle: u32,
    events: []const event_trace.EventRow,
    timer_events: []const timer_binding.EventRow,
) !Replay {
    return generateDevicesWithObservations(
        allocator,
        steps,
        initial,
        final,
        initial_mcycle,
        events,
        timer_events,
        &.{},
    );
}

pub fn generateDevicesWithObservations(
    allocator: std.mem.Allocator,
    steps: []const runner.CartridgeStepTrace,
    initial: memory_lookup.Images,
    final: memory_lookup.Images,
    initial_mcycle: u32,
    events: []const event_trace.EventRow,
    timer_events: []const timer_binding.EventRow,
    observations: []const observation.Sample,
) !Replay {
    try validateShapes(initial, final);
    if (steps.len < 16 or !std.math.isPowerOfTwo(steps.len))
        return error.InvalidTraceLength;
    try validateJoypadEndpoints(initial, final, events);
    try validateTimerEndpoints(initial, final, timer_events);
    if (observations.len != 0) {
        try observation.validateSchedule(observations);
        if (observations[0].mcycle < initial_mcycle)
            return error.ObservationOutsideExecutionSegment;
    }

    const log_size: u32 =
        @intCast(std.math.log2_int(usize, steps.len));
    var main: [memory_lookup.N_MAIN_COLUMNS][]M31 = undefined;
    var initialized: usize = 0;
    errdefer for (main[0..initialized]) |column|
        allocator.free(column);
    for (&main) |*column| {
        column.* = try allocator.alloc(M31, steps.len);
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
        steps.len * execution.N_BUS_CYCLES,
    );
    errdefer allocator.free(accesses);
    @memset(accesses, memory_lookup.Access{});
    const predecessors = try allocator.alloc(
        joypad_if.Predecessor,
        events.len,
    );
    errdefer allocator.free(predecessors);
    @memset(predecessors, joypad_if.Predecessor{});
    const timer_predecessors = try allocator.alloc(
        timer_if.Predecessor,
        timer_events.len,
    );
    errdefer allocator.free(timer_predecessors);
    @memset(timer_predecessors, timer_if.Predecessor{});
    const observation_predecessors = try allocator.alloc(
        observation.Predecessor,
        observations.len,
    );
    errdefer allocator.free(observation_predecessors);
    @memset(observation_predecessors, .{ .clock = 0 });

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

    var cursor = Cursor{
        .events = events,
        .predecessors = predecessors,
        .steps = steps,
        .bytes = bytes,
        .clocks = clocks,
        .timer_events = timer_events,
        .timer_predecessors = timer_predecessors,
        .observations = observations,
        .observation_predecessors = observation_predecessors,
    };
    var mcycle = initial_mcycle;
    var action_index: u32 = 0;
    for (steps, 0..) |step, row_index| {
        const validated = try cartridge_access.ValidatedStep.init(step);
        for (step.accesses[step.instruction.cycle_count..]) |tail|
            if (tail != null) return error.InvalidInactiveAccess;
        const storage = try core_air_utils.circleBitReversedIndex(
            log_size,
            row_index,
        );
        try populateProjectedColumns(
            &main,
            storage,
            validated,
        );

        for (step.activeAccesses(), 0..) |maybe_access, cycle| {
            if (nextIsAction(&cursor, mcycle)) {
                try consume(
                    &cursor,
                    mcycle,
                    memory_clock.ACTION_PHASE,
                    .{ .action_index = action_index },
                );
                action_index = std.math.add(
                    u32,
                    action_index,
                    1,
                ) catch return error.TooManyJoypadActions;
            }

            if (maybe_access) |access| {
                if (timer_events.len != 0)
                    try validateTimerMetadata(access);
                if (try mutableKey(access)) |key| {
                    try replayCpuAccess(
                        &main,
                        accesses,
                        storage,
                        row_index,
                        cycle,
                        mcycle,
                        key,
                        access,
                        bytes,
                        clocks,
                    );
                }
                if (access.region == .joypad_mmio and
                    access.action == .write)
                {
                    try consume(
                        &cursor,
                        mcycle,
                        memory_clock.CPU_PHASE,
                        .{ .execution_write = .{
                            .execution_row = @intCast(row_index),
                            .cycle = @intCast(cycle),
                        } },
                    );
                }
            }
            if (timer_events.len != 0) {
                if (maybe_access) |access| {
                    if (access.region == .timer_mmio and
                        access.action == .write)
                    {
                        try consumeTimer(
                            &cursor,
                            mcycle,
                            .{ .execution_write = .{
                                .execution_row = @intCast(row_index),
                                .cycle = @intCast(cycle),
                            } },
                        );
                    }
                }
                try consumeTimer(
                    &cursor,
                    mcycle,
                    .{ .execution_tick = .{
                        .execution_row = @intCast(row_index),
                        .cycle = @intCast(cycle),
                    } },
                );
            }
            try consume(
                &cursor,
                mcycle,
                memory_clock.JOYPAD_TICK_PHASE,
                .{ .execution_tick = .{
                    .execution_row = @intCast(row_index),
                    .cycle = @intCast(cycle),
                } },
            );
            try consumeObservations(&cursor, mcycle);
            mcycle = std.math.add(
                u32,
                mcycle,
                1,
            ) catch return error.MemoryClockOverflow;
        }
    }
    if (cursor.index != events.len)
        return error.UnconsumedJoypadEvent;
    if (cursor.timer_index != timer_events.len)
        return error.UnconsumedTimerEvent;
    if (cursor.observation_index != observations.len)
        return error.ObservationOutsideExecutionSegment;
    if (!equalSystemMemory(
        bytes[0..memory_lookup.SYSTEM_SIZE],
        final.system.bytes,
        timer_events.len != 0,
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
        .predecessors = predecessors,
        .timer_predecessors = timer_predecessors,
        .observation_predecessors = observation_predecessors,
        .allocator = allocator,
    };
}

fn populateProjectedColumns(
    main: *[memory_lookup.N_MAIN_COLUMNS][]M31,
    storage: usize,
    step: cartridge_access.ValidatedStep,
) !void {
    for (memory_lookup.accessColumns(step), 0..) |
        source_values,
        cycle,
    | {
        const source = try cartridge_access.Semantics(M31)
            .Row.fromColumns(&source_values);
        const projected =
            memory_lookup.Semantics(M31).project(source);
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
}

fn replayCpuAccess(
    main: *[memory_lookup.N_MAIN_COLUMNS][]M31,
    accesses: []memory_lookup.Access,
    storage: usize,
    row_index: usize,
    cycle: usize,
    mcycle: u32,
    key: u17,
    access: runner.cartridge_memory.Access,
    bytes: []u8,
    clocks: []u32,
) !void {
    const clock = try memory_clock.phaseClock(
        mcycle,
        memory_clock.CPU_PHASE,
    );
    const previous_clock = clocks[key];
    if (previous_clock >= clock) return error.InvalidMemoryClock;
    const previous_value = bytes[key];
    if (access.action == .read and access.value != previous_value)
        return error.MemoryReadMismatch;
    const difference = clock - previous_clock - 1;
    if (difference >= (@as(u32, 1) << memory_lookup.N_DIFF_BITS))
        return error.MemoryClockDifferenceTooLarge;
    const next_value = if (access.action == .write)
        access.value
    else
        previous_value;
    if (access.action == .write) bytes[key] = access.value;
    clocks[key] = clock;

    accesses[row_index * execution.N_BUS_CYCLES + cycle] = .{
        .enabled = true,
        .address = key,
        .previous_clock = previous_clock,
        .previous_value = previous_value,
        .clock = clock,
        .next_value = next_value,
    };
    const offset = cycle * memory_lookup.N_ACCESS_COLUMNS;
    main[offset + memory_lookup.PREVIOUS_CLOCK_OFFSET][storage] =
        M31.fromCanonical(previous_clock);
    main[offset + memory_lookup.PREVIOUS_VALUE_OFFSET][storage] =
        M31.fromCanonical(previous_value);
    main[offset + memory_lookup.NEXT_VALUE_OFFSET][storage] =
        M31.fromCanonical(next_value);
    for (0..memory_lookup.N_DIFF_BITS) |bit| {
        main[offset + memory_lookup.DIFFERENCE_BITS_OFFSET + bit][storage] =
            M31.fromCanonical(
                (difference >> @intCast(bit)) & 1,
            );
    }
}

fn nextIsAction(cursor: *const Cursor, mcycle: u32) bool {
    if (cursor.index >= cursor.events.len) return false;
    const event = cursor.events[cursor.index];
    if (event.mcycle != mcycle) return false;
    return switch (event.provenance) {
        .action_index => true,
        else => false,
    };
}

fn consume(
    cursor: *Cursor,
    mcycle: u32,
    phase: u32,
    expected: event_trace.Provenance,
) !void {
    if (cursor.index >= cursor.events.len)
        return error.MissingJoypadEvent;
    const event = cursor.events[cursor.index];
    if (event.mcycle != mcycle)
        return error.InvalidJoypadEventClock;
    if (!std.meta.eql(event.provenance, expected))
        return error.InvalidJoypadEventProvenance;
    _ = joypad_binding.columns(event, cursor.steps) catch
        return error.InvalidJoypadEvent;
    if (cursor.previous_after) |previous| {
        if (!std.meta.eql(previous, event.transition.before))
            return error.DisconnectedJoypadState;
    }

    if (event.transition.interrupt_requested) {
        const key: usize =
            runner.cartridge_memory.INTERRUPT_FLAGS;
        const clock = memory_clock.phaseClock(
            mcycle,
            phase,
        ) catch return error.NonCanonicalJoypadIfClock;
        const previous_clock = cursor.clocks[key];
        if (previous_clock >= clock)
            return error.InvalidJoypadIfPredecessorClock;
        if (clock - previous_clock - 1 >=
            (@as(u32, 1) << memory_lookup.N_DIFF_BITS))
            return error.JoypadIfClockDifferenceTooLarge;
        cursor.predecessors[cursor.index] = .{
            .clock = previous_clock,
            .value = cursor.bytes[key],
        };
        cursor.bytes[key] |= runner.joypad.JOYPAD_INTERRUPT;
        cursor.clocks[key] = clock;
    }
    cursor.previous_after = event.transition.after;
    cursor.index += 1;
}

fn consumeTimer(
    cursor: *Cursor,
    mcycle: u32,
    expected: timer_binding.Provenance,
) !void {
    if (cursor.timer_index >= cursor.timer_events.len)
        return error.MissingTimerEvent;
    const event = cursor.timer_events[cursor.timer_index];
    if (event.mcycle != mcycle)
        return error.InvalidTimerEventClock;
    if (!std.meta.eql(event.provenance, expected))
        return error.InvalidTimerEventProvenance;
    _ = timer_binding.columns(event, cursor.steps) catch
        return error.InvalidTimerEvent;
    if (cursor.previous_timer_after) |previous| {
        if (!std.meta.eql(previous, event.transition.before))
            return error.DisconnectedTimerState;
    }

    if (event.transition.interrupt_requested) {
        const key: usize =
            runner.cartridge_memory.INTERRUPT_FLAGS;
        const clock = memory_clock.phaseClock(
            mcycle,
            memory_clock.TIMER_PHASE,
        ) catch return error.NonCanonicalTimerIfClock;
        const previous_clock = cursor.clocks[key];
        if (previous_clock >= clock)
            return error.InvalidTimerIfPredecessorClock;
        if (clock - previous_clock - 1 >=
            (@as(u32, 1) << memory_lookup.N_DIFF_BITS))
            return error.TimerIfClockDifferenceTooLarge;
        cursor.timer_predecessors[cursor.timer_index] = .{
            .clock = previous_clock,
            .value = cursor.bytes[key],
        };
        cursor.bytes[key] |= timer_runner.TIMER_INTERRUPT;
        cursor.clocks[key] = clock;
    }
    cursor.previous_timer_after = event.transition.after;
    cursor.timer_index += 1;
}

fn consumeObservations(cursor: *Cursor, mcycle: u32) !void {
    while (cursor.observation_index < cursor.observations.len) {
        const index = cursor.observation_index;
        const sample = cursor.observations[index];
        if (sample.mcycle < mcycle)
            return error.ObservationOutsideExecutionSegment;
        if (sample.mcycle != mcycle) return;
        if (cursor.bytes[sample.key] != sample.expected)
            return error.ObservationValueMismatch;
        const clock = memory_clock.phaseClock(
            mcycle,
            memory_clock.OBSERVATION_PHASE,
        ) catch return error.NonCanonicalObservationMcycle;
        const previous_clock = cursor.clocks[sample.key];
        if (previous_clock >= clock)
            return error.InvalidObservationPredecessorClock;
        if (clock - previous_clock - 1 >=
            (@as(u32, 1) << memory_lookup.N_DIFF_BITS))
            return error.ObservationClockDifferenceTooLarge;
        cursor.observation_predecessors[index] = .{
            .clock = previous_clock,
        };
        cursor.clocks[sample.key] = clock;
        cursor.observation_index += 1;
    }
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

fn validateJoypadEndpoints(
    initial: memory_lookup.Images,
    final: memory_lookup.Images,
    events: []const event_trace.EventRow,
) !void {
    if (events.len == 0) return error.EmptyJoypadTrace;
    if (initial.system.bytes[runner.joypad.P1_ADDRESS] !=
        events[0].transition.before.readP1())
        return error.InitialJoypadP1Mismatch;
    if (final.system.bytes[runner.joypad.P1_ADDRESS] !=
        events[events.len - 1].transition.after.readP1())
        return error.FinalJoypadP1Mismatch;
}

fn validateTimerEndpoints(
    initial: memory_lookup.Images,
    final: memory_lookup.Images,
    events: []const timer_binding.EventRow,
) !void {
    if (events.len == 0) return;
    const before = events[0].transition.before;
    const after = events[events.len - 1].transition.after;
    inline for ([_]timer_binding.Register{
        .div,
        .tima,
        .tma,
        .tac,
    }) |register| {
        const address: usize =
            timer_binding.FIRST_ADDRESS + @intFromEnum(register);
        if (initial.system.bytes[address] !=
            timer_binding.readTimerRegister(before, register))
            return error.InitialTimerRegisterMismatch;
        if (final.system.bytes[address] !=
            timer_binding.readTimerRegister(after, register))
            return error.FinalTimerRegisterMismatch;
    }
}

fn validateTimerMetadata(
    access: runner.cartridge_memory.Access,
) !void {
    const timer_address =
        access.logical_address >= timer_binding.FIRST_ADDRESS and
        access.logical_address <= timer_binding.FIRST_ADDRESS + 3;
    if (timer_address != (access.region == .timer_mmio))
        return error.InvalidTimerMetadata;
}

fn equalSystemMemory(
    left: []const u8,
    right: []const u8,
    timer_owned: bool,
) bool {
    if (left.len != right.len) return false;
    for (left, right, 0..) |a, b, address|
        if (address != runner.joypad.P1_ADDRESS and
            !(timer_owned and
                address >= timer_binding.FIRST_ADDRESS and
                address <= timer_binding.FIRST_ADDRESS + 3) and
            a != b)
            return false;
    return true;
}

fn equalPredecessors(
    left: []const joypad_if.Predecessor,
    right: []const joypad_if.Predecessor,
) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b|
        if (a.clock != b.clock or a.value != b.value) return false;
    return true;
}

fn equalTimerPredecessors(
    left: []const timer_if.Predecessor,
    right: []const timer_if.Predecessor,
) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b|
        if (a.clock != b.clock or a.value != b.value) return false;
    return true;
}

fn equalObservationPredecessors(
    left: []const observation.Predecessor,
    right: []const observation.Predecessor,
) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b|
        if (a.clock != b.clock) return false;
    return true;
}

fn equalWitness(
    left: memory_lookup.Witness,
    right: memory_lookup.Witness,
) bool {
    for (left.main, right.main) |a, b|
        if (!equalM31(a, b)) return false;
    if (!equalM31(left.final_clocks, right.final_clocks))
        return false;
    if (left.accesses.len != right.accesses.len) return false;
    for (left.accesses, right.accesses) |a, b| {
        if (a.enabled != b.enabled or a.address != b.address or
            a.previous_clock != b.previous_clock or
            a.previous_value != b.previous_value or
            a.clock != b.clock or a.next_value != b.next_value)
            return false;
    }
    return true;
}

fn equalM31(left: []const M31, right: []const M31) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b|
        if (!a.eql(b)) return false;
    return true;
}
