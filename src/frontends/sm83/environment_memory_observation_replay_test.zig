const std = @import("std");
const core_air_utils = @import("stwo_core").air.utils;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const memory_image = @import("memory.zig");
const replay = @import("environment_memory_replay.zig");
const joypad_trace = @import("joypad_trace.zig");
const runner = @import("runner/mod.zig");
const memory_lookup = @import("air/cartridge_memory_lookup.zig");
const observation =
    @import("air/intermediate_ram_observation_lookup.zig");
const memory_clock = memory_lookup.memory_clock;

const TRACE_SIZE: usize = 16;
const INITIAL_MCYCLE: u32 = 5;

test "observations join memory replay and reject every owned mutation" {
    var images = try ImagesFixture.init(std.testing.allocator);
    defer images.deinit();
    var steps = plainSteps();
    steps[0] = systemStep(.write, 0xc000, 0x42);
    images.final_system[0xc000] = 0x42;
    var joypad = try joypad_trace.generate(
        std.testing.allocator,
        INITIAL_MCYCLE,
        INITIAL_MCYCLE + TRACE_SIZE,
        .{},
        &.{},
        &steps,
    );
    defer joypad.deinit(std.testing.allocator);
    images.final_system[runner.joypad.P1_ADDRESS] =
        joypad.final_state.readP1();
    const samples = [_]observation.Sample{
        .{ .mcycle = 5, .key = 0xc000, .expected = 0x42 },
        .{ .mcycle = 5, .key = 0xc001, .expected = 0 },
        .{ .mcycle = 6, .key = 0xc000, .expected = 0x42 },
    };

    var result = try replay.generateDevicesWithObservations(
        std.testing.allocator,
        &steps,
        try images.initial(),
        try images.final(),
        INITIAL_MCYCLE,
        joypad.rows,
        &.{},
        &samples,
    );
    defer result.deinit();
    try std.testing.expectEqual(
        observation.Predecessor{
            .clock = try memory_clock.phaseClock(
                INITIAL_MCYCLE,
                memory_clock.CPU_PHASE,
            ),
        },
        result.observation_predecessors[0],
    );
    try std.testing.expectEqual(
        observation.Predecessor{ .clock = 0 },
        result.observation_predecessors[1],
    );
    try std.testing.expectEqual(
        observation.Predecessor{
            .clock = try memory_clock.phaseClock(
                INITIAL_MCYCLE,
                memory_clock.OBSERVATION_PHASE,
            ),
        },
        result.observation_predecessors[2],
    );
    try std.testing.expectEqual(
        try memory_clock.phaseClock(6, memory_clock.OBSERVATION_PHASE),
        try finalClock(result.memory, 0xc000),
    );
    try std.testing.expectEqual(
        try memory_clock.phaseClock(5, memory_clock.OBSERVATION_PHASE),
        try finalClock(result.memory, 0xc001),
    );
    try std.testing.expect(
        (try combinedClaim(
            result,
            &samples,
            try images.initial(),
            try images.final(),
        )).isZero(),
    );
    var witness = try observation.generateWitness(
        std.testing.allocator,
        4,
        &samples,
        result.observation_predecessors,
    );
    defer witness.deinit();
    try result.validateDevicesWithObservations(
        std.testing.allocator,
        &steps,
        try images.initial(),
        try images.final(),
        INITIAL_MCYCLE,
        joypad.rows,
        &.{},
        &samples,
    );

    try std.testing.expectError(
        error.ReplayObservationPredecessorMismatch,
        result.validateDevicesWithObservations(
            std.testing.allocator,
            &steps,
            try images.initial(),
            try images.final(),
            INITIAL_MCYCLE,
            joypad.rows,
            &.{},
            samples[0..2],
        ),
    );
    var substituted = samples;
    substituted[0].expected ^= 1;
    try expectGenerateError(
        error.ObservationValueMismatch,
        &steps,
        images,
        joypad.rows,
        &substituted,
    );
    substituted = samples;
    substituted[1].key = 0xc002;
    try std.testing.expectError(
        error.ReplayMemoryMismatch,
        result.validateDevicesWithObservations(
            std.testing.allocator,
            &steps,
            try images.initial(),
            try images.final(),
            INITIAL_MCYCLE,
            joypad.rows,
            &.{},
            &substituted,
        ),
    );
    var reordered = samples;
    std.mem.swap(observation.Sample, &reordered[0], &reordered[1]);
    try expectGenerateError(
        error.NonCanonicalObservationOrder,
        &steps,
        images,
        joypad.rows,
        &reordered,
    );

    result.observation_predecessors[0].clock =
        try memory_clock.phaseClock(5, memory_clock.OBSERVATION_PHASE);
    try std.testing.expectError(
        error.InvalidObservationPredecessorClock,
        observation.accessForSample(
            samples[0],
            result.observation_predecessors[0],
        ),
    );
    try std.testing.expectError(
        error.ReplayObservationPredecessorMismatch,
        result.validateDevicesWithObservations(
            std.testing.allocator,
            &steps,
            try images.initial(),
            try images.final(),
            INITIAL_MCYCLE,
            joypad.rows,
            &.{},
            &samples,
        ),
    );
    result.observation_predecessors[0].clock =
        try memory_clock.phaseClock(5, memory_clock.CPU_PHASE);

    const storage = try core_air_utils.circleBitReversedIndex(
        memory_lookup.BOUNDARY_LOG_SIZE,
        0xc000,
    );
    result.memory.final_clocks[storage] =
        result.memory.final_clocks[storage].add(M31.one());
    try std.testing.expectError(
        error.ReplayMemoryMismatch,
        result.validateDevicesWithObservations(
            std.testing.allocator,
            &steps,
            try images.initial(),
            try images.final(),
            INITIAL_MCYCLE,
            joypad.rows,
            &.{},
            &samples,
        ),
    );
    result.memory.final_clocks[storage] =
        result.memory.final_clocks[storage].sub(M31.one());

    const outside = [_]observation.Sample{
        .{ .mcycle = INITIAL_MCYCLE + TRACE_SIZE, .key = 0xc000, .expected = 0x42 },
    };
    try expectGenerateError(
        error.ObservationOutsideExecutionSegment,
        &steps,
        images,
        joypad.rows,
        &outside,
    );
    const before = [_]observation.Sample{
        .{ .mcycle = INITIAL_MCYCLE - 1, .key = 0xc000, .expected = 0 },
    };
    try expectGenerateError(
        error.ObservationOutsideExecutionSegment,
        &steps,
        images,
        joypad.rows,
        &before,
    );
}

fn expectGenerateError(
    expected: anyerror,
    steps: []const runner.CartridgeStepTrace,
    images: ImagesFixture,
    joypad: []const joypad_trace.EventRow,
    samples: []const observation.Sample,
) !void {
    try std.testing.expectError(
        expected,
        replay.generateDevicesWithObservations(
            std.testing.allocator,
            steps,
            try images.initial(),
            try images.final(),
            INITIAL_MCYCLE,
            joypad,
            &.{},
            samples,
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
            memory_lookup.SYSTEM_SIZE,
        );
        errdefer allocator.free(initial_system);
        @memset(initial_system, 0);
        initial_system[runner.joypad.P1_ADDRESS] =
            (runner.joypad.State{}).readP1();
        const initial_sram = try allocator.alloc(
            u8,
            memory_lookup.SRAM_SIZE,
        );
        errdefer allocator.free(initial_sram);
        @memset(initial_sram, 0);
        const final_system = try allocator.dupe(u8, initial_system);
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

    fn initial(self: ImagesFixture) !memory_lookup.Images {
        return .{
            .system = try memory_image.Image.init(self.initial_system),
            .sram = try memory_lookup.SramImage.init(self.initial_sram),
        };
    }

    fn final(self: ImagesFixture) !memory_lookup.Images {
        return .{
            .system = try memory_image.Image.init(self.final_system),
            .sram = try memory_lookup.SramImage.init(self.final_sram),
        };
    }
};

fn plainSteps() [TRACE_SIZE]runner.CartridgeStepTrace {
    var steps: [TRACE_SIZE]runner.CartridgeStepTrace = undefined;
    for (&steps) |*step| step.* = systemStep(.read, 0xc002, 0);
    return steps;
}

fn systemStep(
    action: runner.cartridge_memory.Action,
    address: u16,
    value: u8,
) runner.CartridgeStepTrace {
    const mapper = @import("cartridge/mbc3.zig").State{};
    var step = std.mem.zeroes(runner.CartridgeStepTrace);
    step.instruction.cycle_count = 1;
    step.instruction.cycles[0] = .{
        .address = address,
        .value = value,
        .action = switch (action) {
            .read => .read,
            .write => .write,
        },
    };
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

fn finalClock(witness: memory_lookup.Witness, key: usize) !u32 {
    const storage = try core_air_utils.circleBitReversedIndex(
        memory_lookup.BOUNDARY_LOG_SIZE,
        key,
    );
    return witness.final_clocks[storage].toU32();
}

fn combinedClaim(
    result: replay.Replay,
    samples: []const observation.Sample,
    initial: memory_lookup.Images,
    final: memory_lookup.Images,
) !QM31 {
    const relation = memory_lookup.Relation.dummy();
    var claim = QM31.zero();
    for ([_]usize{ 0xc000, 0xc001 }) |key|
        claim = try observation.accumulate(
            claim,
            try memory_lookup.boundaryPairForRow(
                key,
                .{
                    .enabled = true,
                    .address = @intCast(key),
                    .initial_value = initial.system.bytes[key],
                    .final_clock = try finalClock(result.memory, key),
                    .final_value = final.system.bytes[key],
                },
                relation,
            ),
        );
    for (result.memory.accesses) |access| {
        if (!access.enabled or
            (access.address != 0xc000 and access.address != 0xc001))
            continue;
        claim = try observation.accumulate(claim, .{
            .n1 = QM31.one().neg(),
            .d1 = relation.combine(
                q(access.address),
                q(access.previous_clock),
                q(access.previous_value),
            ),
            .n2 = QM31.one(),
            .d2 = relation.combine(
                q(access.address),
                q(access.clock),
                q(access.next_value),
            ),
        });
    }
    for (samples, result.observation_predecessors) |sample, predecessor|
        claim = try observation.accumulate(
            claim,
            try observation.pair(
                try observation.accessForSample(sample, predecessor),
                relation,
            ),
        );
    return claim;
}

fn q(value: anytype) QM31 {
    return QM31.fromBase(M31.fromU64(@intCast(value)));
}
