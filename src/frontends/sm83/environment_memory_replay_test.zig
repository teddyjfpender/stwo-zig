const std = @import("std");
const core_air_utils = @import("stwo_core").air.utils;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const action_schedule = @import("action_schedule.zig");
const memory_image = @import("memory.zig");
const replay = @import("environment_memory_replay.zig");
const trace_builder = @import("joypad_trace.zig");
const runner = @import("runner/mod.zig");
const timer_runner = @import("runner/timer.zig");
const lookup = @import("air/cartridge_memory_lookup.zig");
const joypad_if = @import("air/joypad_if_memory_lookup.zig");
const timer_air = @import("air/timer.zig");
const timer_binding = @import("air/timer_binding.zig");
const timer_if = @import("air/timer_if_memory_lookup.zig");
const memory_clock = lookup.memory_clock;

const TRACE_SIZE: usize = 16;
const IF = runner.cartridge_memory.INTERRUPT_FLAGS;

test "action request precedes same-cycle CPU IF read" {
    var images = try ImagesFixture.init(std.testing.allocator);
    defer images.deinit();
    images.final_system[IF] = runner.joypad.JOYPAD_INTERRUPT;

    var steps = plainSteps();
    steps[0] = systemStep(
        .read,
        IF,
        runner.joypad.JOYPAD_INTERRUPT,
    );
    const actions = [_]action_schedule.Action{.{
        .mcycle = 100,
        .pressed = runner.joypad.Key.right.mask(),
    }};
    var events = try trace_builder.generate(
        std.testing.allocator,
        100,
        100 + TRACE_SIZE,
        .{},
        &actions,
        &steps,
    );
    defer events.deinit(std.testing.allocator);
    images.final_system[runner.joypad.P1_ADDRESS] =
        events.final_state.readP1();
    try std.testing.expect(
        events.rows[0].transition.interrupt_requested,
    );

    var result = try replay.generate(
        std.testing.allocator,
        &steps,
        try images.initial(),
        try images.final(),
        100,
        events.rows,
    );
    defer result.deinit();
    const cpu = result.memory.accesses[0];
    try std.testing.expect(cpu.enabled);
    try std.testing.expectEqual(@as(u8, 0x10), cpu.previous_value);
    try std.testing.expectEqual(
        try memory_clock.phaseClock(100, memory_clock.CPU_PHASE),
        cpu.clock,
    );
    try std.testing.expectEqual(
        joypad_if.Predecessor{},
        result.predecessors[0],
    );
    try std.testing.expectEqual(
        try memory_clock.phaseClock(100, memory_clock.CPU_PHASE),
        try finalClock(result.memory, IF),
    );

    const joypad_size = std.math.ceilPowerOfTwo(
        usize,
        @max(events.rows.len, 16),
    ) catch unreachable;
    var if_witness = try joypad_if.generateWitness(
        std.testing.allocator,
        @intCast(std.math.log2_int(usize, joypad_size)),
        events.rows,
        result.predecessors,
    );
    defer if_witness.deinit();
    try std.testing.expect(
        (try combinedIfClaim(
            result,
            events.rows,
            try images.initial(),
            try images.final(),
        )).isZero(),
    );
}

test "CPU IF write precedes a same-cycle tick request" {
    var images = try ImagesFixture.init(std.testing.allocator);
    defer images.deinit();
    images.final_system[IF] =
        1 | runner.joypad.JOYPAD_INTERRUPT;

    var steps = plainSteps();
    steps[0] = systemStep(.write, IF, 1);
    const initial_joypad = try runner.joypad.State.init(
        0xff,
        runner.joypad.Key.right.mask(),
        2,
        8,
    );
    var events = try trace_builder.generate(
        std.testing.allocator,
        0,
        TRACE_SIZE,
        initial_joypad,
        &.{},
        &steps,
    );
    defer events.deinit(std.testing.allocator);
    images.initial_system[runner.joypad.P1_ADDRESS] =
        initial_joypad.readP1();
    images.final_system[runner.joypad.P1_ADDRESS] =
        events.final_state.readP1();
    try std.testing.expect(
        events.rows[0].transition.interrupt_requested,
    );

    var result = try replay.generate(
        std.testing.allocator,
        &steps,
        try images.initial(),
        try images.final(),
        0,
        events.rows,
    );
    defer result.deinit();
    try std.testing.expectEqual(@as(u8, 0), result.memory.accesses[0].previous_value);
    try std.testing.expectEqual(@as(u8, 1), result.memory.accesses[0].next_value);
    try std.testing.expectEqual(
        joypad_if.Predecessor{
            .clock = try memory_clock.phaseClock(
                0,
                memory_clock.CPU_PHASE,
            ),
            .value = 1,
        },
        result.predecessors[0],
    );
    try std.testing.expectEqual(
        try memory_clock.phaseClock(
            0,
            memory_clock.JOYPAD_TICK_PHASE,
        ),
        try finalClock(result.memory, IF),
    );
    try std.testing.expect(
        (try combinedIfClaim(
            result,
            events.rows,
            try images.initial(),
            try images.final(),
        )).isZero(),
    );
}

test "replay rejects omitted and substituted canonical events" {
    var images = try ImagesFixture.init(std.testing.allocator);
    defer images.deinit();
    images.final_system[IF] = runner.joypad.JOYPAD_INTERRUPT;
    var steps = plainSteps();
    steps[0] = systemStep(
        .read,
        IF,
        runner.joypad.JOYPAD_INTERRUPT,
    );
    const actions = [_]action_schedule.Action{.{
        .mcycle = 9,
        .pressed = runner.joypad.Key.right.mask(),
    }};
    var events = try trace_builder.generate(
        std.testing.allocator,
        9,
        9 + TRACE_SIZE,
        .{},
        &actions,
        &steps,
    );
    defer events.deinit(std.testing.allocator);
    images.final_system[runner.joypad.P1_ADDRESS] =
        events.final_state.readP1();

    try std.testing.expectError(
        error.InitialJoypadP1Mismatch,
        replay.generate(
            std.testing.allocator,
            &steps,
            try images.initial(),
            try images.final(),
            9,
            events.rows[1..],
        ),
    );

    const substituted = try std.testing.allocator.dupe(
        trace_builder.EventRow,
        events.rows,
    );
    defer std.testing.allocator.free(substituted);
    substituted[1].provenance = .{ .action_index = 1 };
    try std.testing.expectError(
        error.InvalidJoypadEventProvenance,
        replay.generate(
            std.testing.allocator,
            &steps,
            try images.initial(),
            try images.final(),
            9,
            substituted,
        ),
    );
}

test "replay validation rejects predecessor drift" {
    var images = try ImagesFixture.init(std.testing.allocator);
    defer images.deinit();
    images.final_system[IF] = runner.joypad.JOYPAD_INTERRUPT;
    var steps = plainSteps();
    steps[0] = systemStep(
        .read,
        IF,
        runner.joypad.JOYPAD_INTERRUPT,
    );
    const actions = [_]action_schedule.Action{.{
        .mcycle = 3,
        .pressed = runner.joypad.Key.right.mask(),
    }};
    var events = try trace_builder.generate(
        std.testing.allocator,
        3,
        3 + TRACE_SIZE,
        .{},
        &actions,
        &steps,
    );
    defer events.deinit(std.testing.allocator);
    images.final_system[runner.joypad.P1_ADDRESS] =
        events.final_state.readP1();
    var result = try replay.generate(
        std.testing.allocator,
        &steps,
        try images.initial(),
        try images.final(),
        3,
        events.rows,
    );
    defer result.deinit();

    result.predecessors[0].value ^= 1;
    try std.testing.expect(
        !(try combinedIfClaim(
            result,
            events.rows,
            try images.initial(),
            try images.final(),
        )).isZero(),
    );
    try std.testing.expectError(
        error.ReplayPredecessorMismatch,
        result.validate(
            std.testing.allocator,
            &steps,
            try images.initial(),
            try images.final(),
            3,
            events.rows,
        ),
    );
}

test "replay rejects final-memory drift" {
    var images = try ImagesFixture.init(std.testing.allocator);
    defer images.deinit();
    var steps = plainSteps();
    steps[0] = systemStep(.write, 0xc001, 0x42);
    var events = try trace_builder.generate(
        std.testing.allocator,
        0,
        TRACE_SIZE,
        .{},
        &.{},
        &steps,
    );
    defer events.deinit(std.testing.allocator);

    try std.testing.expectError(
        error.FinalMemoryMismatch,
        replay.generate(
            std.testing.allocator,
            &steps,
            try images.initial(),
            try images.final(),
            0,
            events.rows,
        ),
    );
}

test "no-request replay equals the existing CPU memory witness" {
    var images = try ImagesFixture.init(std.testing.allocator);
    defer images.deinit();
    images.initial_system[0xc000] = 0x21;
    images.final_system[0xc000] = 0x21;
    images.final_system[0xc001] = 0x43;
    var steps = plainSteps();
    steps[0] = systemStep(.read, 0xc000, 0x21);
    steps[1] = systemStep(.write, 0xc001, 0x43);
    var events = try trace_builder.generate(
        std.testing.allocator,
        0,
        TRACE_SIZE,
        .{},
        &.{},
        &steps,
    );
    defer events.deinit(std.testing.allocator);

    const initial = try images.initial();
    const final = try images.final();
    var merged = try replay.generate(
        std.testing.allocator,
        &steps,
        initial,
        final,
        0,
        events.rows,
    );
    defer merged.deinit();
    var existing = try lookup.generateWitness(
        std.testing.allocator,
        &steps,
        initial,
        final,
    );
    defer existing.deinit();

    for (merged.memory.main, existing.main) |left, right|
        try std.testing.expectEqualSlices(
            M31,
            left,
            right,
        );
    try std.testing.expectEqualSlices(
        M31,
        merged.memory.final_clocks,
        existing.final_clocks,
    );
    try expectAccessesEqual(
        merged.memory.accesses,
        existing.accesses,
    );
    for (merged.predecessors) |predecessor|
        try std.testing.expectEqual(
            joypad_if.Predecessor{},
            predecessor,
        );
    try merged.validate(
        std.testing.allocator,
        &steps,
        initial,
        final,
        0,
        events.rows,
    );
}

test "device-owned P1 may change only to the proven joypad endpoint" {
    var images = try ImagesFixture.init(std.testing.allocator);
    defer images.deinit();
    const steps = plainSteps();
    const actions = [_]action_schedule.Action{.{
        .mcycle = 0,
        .pressed = runner.joypad.Key.right.mask(),
    }};
    var events = try trace_builder.generate(
        std.testing.allocator,
        0,
        TRACE_SIZE,
        .{},
        &actions,
        &steps,
    );
    defer events.deinit(std.testing.allocator);
    images.final_system[runner.joypad.P1_ADDRESS] =
        events.final_state.readP1();
    images.final_system[IF] = runner.joypad.JOYPAD_INTERRUPT;

    var result = try replay.generate(
        std.testing.allocator,
        &steps,
        try images.initial(),
        try images.final(),
        0,
        events.rows,
    );
    defer result.deinit();
    try std.testing.expectEqual(
        @as(u32, 0),
        try finalClock(result.memory, runner.joypad.P1_ADDRESS),
    );

    images.final_system[runner.joypad.P1_ADDRESS] ^= 1;
    try std.testing.expectError(
        error.FinalJoypadP1Mismatch,
        replay.generate(
            std.testing.allocator,
            &steps,
            try images.initial(),
            try images.final(),
            0,
            events.rows,
        ),
    );
}

test "timer replay composes CPU and joypad IF updates and rejects drift" {
    var images = try ImagesFixture.init(std.testing.allocator);
    defer images.deinit();
    var steps = plainSteps();
    steps[0] = systemStep(.write, IF, 1);
    steps[1] = timerStep(
        .write,
        timer_binding.FIRST_ADDRESS + @intFromEnum(timer_binding.Register.tma),
        0x66,
    );
    const initial_joypad = try runner.joypad.State.init(
        0xff,
        runner.joypad.Key.right.mask(),
        2,
        8,
    );
    var joypad = try trace_builder.generate(
        std.testing.allocator,
        0,
        TRACE_SIZE,
        initial_joypad,
        &.{},
        &steps,
    );
    defer joypad.deinit(std.testing.allocator);
    const initial_timer = timer_runner.Timer{
        .tima = 0x42,
        .tma = 0x42,
        .reload_state = .reloading,
    };
    var timer = try timer_binding.generateTrace(
        std.testing.allocator,
        0,
        TRACE_SIZE,
        initial_timer,
        &steps,
    );
    defer timer.deinit(std.testing.allocator);
    images.initial_system[runner.joypad.P1_ADDRESS] =
        initial_joypad.readP1();
    images.final_system[runner.joypad.P1_ADDRESS] =
        joypad.final_state.readP1();
    setTimerEndpoints(&images, initial_timer, timer.final_state);
    images.final_system[IF] =
        1 | timer_runner.TIMER_INTERRUPT |
        runner.joypad.JOYPAD_INTERRUPT;

    var result = try replay.generateDevices(
        std.testing.allocator,
        &steps,
        try images.initial(),
        try images.final(),
        0,
        joypad.rows,
        timer.rows,
    );
    defer result.deinit();
    try std.testing.expectEqual(
        timer_if.Predecessor{
            .clock = try memory_clock.phaseClock(0, memory_clock.CPU_PHASE),
            .value = 1,
        },
        result.timer_predecessors[0],
    );
    try std.testing.expectEqual(
        joypad_if.Predecessor{
            .clock = try memory_clock.phaseClock(0, memory_clock.TIMER_PHASE),
            .value = 1 | timer_runner.TIMER_INTERRUPT,
        },
        result.predecessors[0],
    );
    try std.testing.expectEqual(
        try memory_clock.phaseClock(0, memory_clock.JOYPAD_TICK_PHASE),
        try finalClock(result.memory, IF),
    );
    try std.testing.expect(
        (try combinedDeviceIfClaim(
            result,
            joypad.rows,
            timer.rows,
            try images.initial(),
            try images.final(),
        )).isZero(),
    );
    try result.validateDevices(
        std.testing.allocator,
        &steps,
        try images.initial(),
        try images.final(),
        0,
        joypad.rows,
        timer.rows,
    );

    result.timer_predecessors[0].value ^= 1;
    try std.testing.expect(
        !(try combinedDeviceIfClaim(
            result,
            joypad.rows,
            timer.rows,
            try images.initial(),
            try images.final(),
        )).isZero(),
    );
    try std.testing.expectError(
        error.ReplayTimerPredecessorMismatch,
        result.validateDevices(
            std.testing.allocator,
            &steps,
            try images.initial(),
            try images.final(),
            0,
            joypad.rows,
            timer.rows,
        ),
    );
    result.timer_predecessors[0].value ^= 1;
    result.timer_predecessors[0].clock =
        try memory_clock.phaseClock(0, memory_clock.TIMER_PHASE);
    try std.testing.expectError(
        error.InvalidTimerIfPredecessorClock,
        timer_if.accessForEvent(timer.rows[0], result.timer_predecessors[0]),
    );
    result.timer_predecessors[0].clock =
        try memory_clock.phaseClock(0, memory_clock.CPU_PHASE);

    const forged = try std.testing.allocator.dupe(
        timer_binding.EventRow,
        timer.rows,
    );
    defer std.testing.allocator.free(forged);
    forged[0].mcycle += 1;
    try expectTimerError(error.InvalidTimerEventClock, &steps, images, joypad.rows, forged);
    @memcpy(forged, timer.rows);
    std.mem.swap(timer_binding.EventRow, &forged[1], &forged[2]);
    try expectTimerError(error.InvalidTimerEventProvenance, &steps, images, joypad.rows, forged);
    @memcpy(forged, timer.rows);
    forged[1].transition = timer_air.Transition.apply(
        .{},
        timer.rows[1].transition.event,
    );
    try expectTimerError(error.DisconnectedTimerState, &steps, images, joypad.rows, forged);

    images.final_system[timer_binding.FIRST_ADDRESS] ^= 1;
    try expectTimerError(error.FinalTimerRegisterMismatch, &steps, images, joypad.rows, timer.rows);
    images.final_system[timer_binding.FIRST_ADDRESS] ^= 1;
    images.final_system[IF] = 1 | runner.joypad.JOYPAD_INTERRUPT;
    try std.testing.expectError(
        error.FinalMemoryMismatch,
        replay.generate(
            std.testing.allocator,
            &steps,
            try images.initial(),
            try images.final(),
            0,
            joypad.rows,
        ),
    );
}

const ImagesFixture = struct {
    initial_system: []u8,
    initial_sram: []u8,
    final_system: []u8,
    final_sram: []u8,
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator) !ImagesFixture {
        const initial_system = try allocator.alloc(
            u8,
            lookup.SYSTEM_SIZE,
        );
        errdefer allocator.free(initial_system);
        @memset(initial_system, 0);
        initial_system[runner.joypad.P1_ADDRESS] =
            (runner.joypad.State{}).readP1();
        const initial_sram = try allocator.alloc(
            u8,
            lookup.SRAM_SIZE,
        );
        errdefer allocator.free(initial_sram);
        @memset(initial_sram, 0);
        const final_system = try allocator.dupe(
            u8,
            initial_system,
        );
        errdefer allocator.free(final_system);
        const final_sram = try allocator.dupe(u8, initial_sram);
        return .{
            .initial_system = initial_system,
            .initial_sram = initial_sram,
            .final_system = final_system,
            .final_sram = final_sram,
            .allocator = allocator,
        };
    }

    fn deinit(self: *ImagesFixture) void {
        self.allocator.free(self.final_sram);
        self.allocator.free(self.final_system);
        self.allocator.free(self.initial_sram);
        self.allocator.free(self.initial_system);
        self.* = undefined;
    }

    fn initial(self: ImagesFixture) !lookup.Images {
        return .{
            .system = try memory_image.Image.init(
                self.initial_system,
            ),
            .sram = try lookup.SramImage.init(self.initial_sram),
        };
    }

    fn final(self: ImagesFixture) !lookup.Images {
        return .{
            .system = try memory_image.Image.init(self.final_system),
            .sram = try lookup.SramImage.init(self.final_sram),
        };
    }
};

fn plainSteps() [TRACE_SIZE]runner.CartridgeStepTrace {
    var steps: [TRACE_SIZE]runner.CartridgeStepTrace = undefined;
    for (&steps) |*step|
        step.* = systemStep(.read, 0xc002, 0);
    return steps;
}

fn systemStep(
    action: runner.cartridge_memory.Action,
    address: u16,
    value: u8,
) runner.CartridgeStepTrace {
    const mapper = @import("cartridge/mbc3.zig").State{};
    var step: runner.CartridgeStepTrace = undefined;
    step.instruction.cycle_count = 1;
    step.instruction.cycles[0] = .{
        .address = address,
        .value = value,
        .action = switch (action) {
            .read => .read,
            .write => .write,
        },
    };
    step.accesses = [_]?runner.cartridge_memory.Access{null} ** 6;
    step.accesses[0] = .{
        .logical_address = address,
        .action = action,
        .region = .system,
        .physical_offset = null,
        .mapper_before = mapper,
        .mapper_after = mapper,
        .value = value,
    };
    return step;
}

fn timerStep(
    action: runner.cartridge_memory.Action,
    address: u16,
    value: u8,
) runner.CartridgeStepTrace {
    var step = systemStep(action, address, value);
    step.accesses[0].?.region = .timer_mmio;
    return step;
}

fn setTimerEndpoints(
    images: *ImagesFixture,
    initial: timer_runner.Timer,
    final: timer_runner.Timer,
) void {
    inline for ([_]timer_binding.Register{
        .div,
        .tima,
        .tma,
        .tac,
    }) |register| {
        const address: usize =
            timer_binding.FIRST_ADDRESS + @intFromEnum(register);
        images.initial_system[address] =
            timer_binding.readTimerRegister(initial, register);
        images.final_system[address] =
            timer_binding.readTimerRegister(final, register);
    }
}

fn expectTimerError(
    expected: anyerror,
    steps: []const runner.CartridgeStepTrace,
    images: ImagesFixture,
    joypad: []const trace_builder.EventRow,
    timer: []const timer_binding.EventRow,
) !void {
    try std.testing.expectError(
        expected,
        replay.generateDevices(
            std.testing.allocator,
            steps,
            try images.initial(),
            try images.final(),
            0,
            joypad,
            timer,
        ),
    );
}

fn finalClock(
    witness: lookup.Witness,
    key: usize,
) !u32 {
    const storage = try core_air_utils.circleBitReversedIndex(
        lookup.BOUNDARY_LOG_SIZE,
        key,
    );
    return witness.final_clocks[storage].toU32();
}

fn expectAccessesEqual(
    left: []const lookup.Access,
    right: []const lookup.Access,
) !void {
    try std.testing.expectEqual(left.len, right.len);
    for (left, right) |a, b| {
        try std.testing.expectEqual(a.enabled, b.enabled);
        try std.testing.expectEqual(a.address, b.address);
        try std.testing.expectEqual(
            a.previous_clock,
            b.previous_clock,
        );
        try std.testing.expectEqual(
            a.previous_value,
            b.previous_value,
        );
        try std.testing.expectEqual(a.clock, b.clock);
        try std.testing.expectEqual(a.next_value, b.next_value);
    }
}

fn combinedIfClaim(
    result: replay.Replay,
    events: []const trace_builder.EventRow,
    initial: lookup.Images,
    final: lookup.Images,
) !QM31 {
    const relation = lookup.Relation.dummy();
    var claim = try joypad_if.accumulate(
        QM31.zero(),
        try lookup.boundaryPairForRow(
            IF,
            .{
                .enabled = true,
                .address = IF,
                .initial_value = initial.system.bytes[IF],
                .final_clock = try finalClock(result.memory, IF),
                .final_value = final.system.bytes[IF],
            },
            relation,
        ),
    );
    for (result.memory.accesses) |access| {
        if (!access.enabled or access.address != IF) continue;
        claim = try joypad_if.accumulate(
            claim,
            .{
                .n1 = QM31.one().neg(),
                .d1 = relation.combine(
                    q(IF),
                    q(access.previous_clock),
                    q(access.previous_value),
                ),
                .n2 = QM31.one(),
                .d2 = relation.combine(
                    q(IF),
                    q(access.clock),
                    q(access.next_value),
                ),
            },
        );
    }
    for (events, result.predecessors) |event, predecessor| {
        claim = try joypad_if.accumulate(
            claim,
            try joypad_if.pair(
                try joypad_if.accessForEvent(event, predecessor),
                relation,
            ),
        );
    }
    return claim;
}

fn combinedDeviceIfClaim(
    result: replay.Replay,
    joypad: []const trace_builder.EventRow,
    timer: []const timer_binding.EventRow,
    initial: lookup.Images,
    final: lookup.Images,
) !QM31 {
    const relation = lookup.Relation.dummy();
    var claim = try combinedIfClaim(
        result,
        joypad,
        initial,
        final,
    );
    for (timer, result.timer_predecessors) |event, predecessor|
        claim = try timer_if.accumulate(
            claim,
            try timer_if.pair(
                try timer_if.accessForEvent(event, predecessor),
                relation,
            ),
        );
    return claim;
}

fn q(value: anytype) QM31 {
    return QM31.fromBase(M31.fromU64(@intCast(value)));
}
