const std = @import("std");
const core_air_utils = @import("stwo_core").air.utils;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const action_schedule = @import("action_schedule.zig");
const base_statement = @import("cartridge_proof_statement.zig");
const cartridge = @import("cartridge/mod.zig");
const environment = @import("environment_statement.zig");
const memory = @import("memory.zig");
const memory_lookup = @import("air/cartridge_memory_lookup.zig");
const action_lookup = @import("air/joypad_action_lookup.zig");
const intermediate_observation =
    @import("air/intermediate_ram_observation_lookup.zig");
const observation = @import("ram_observation.zig");
const joypad = @import("runner/joypad.zig");
const timer = @import("runner/timer.zig");
const timer_binding = @import("air/timer_binding.zig");

const actions = [_]action_schedule.Action{
    .{ .mcycle = 100, .pressed = joypad.Key.a.mask() },
    .{ .mcycle = 108, .pressed = joypad.Key.start.mask() },
};
const regions = [_]observation.Region{
    .{ .space = .system, .start = 0xc000, .length = 1 },
    .{ .space = .sram, .start = 0, .length = 1 },
};
const intermediate_observations =
    [_]intermediate_observation.Sample{
        .{ .mcycle = 100, .key = 0xc000, .expected = 0 },
        .{
            .mcycle = 108,
            .key = memory_lookup.SRAM_KEY_OFFSET,
            .expected = 0x33,
        },
    };

const Fixture = struct {
    rom_bytes: *[cartridge.header.ROM_SIZE]u8,
    initial_system: *[memory_lookup.SYSTEM_SIZE]u8,
    final_system: *[memory_lookup.SYSTEM_SIZE]u8,
    initial_sram: *[memory_lookup.SRAM_SIZE]u8,
    final_sram: *[memory_lookup.SRAM_SIZE]u8,
    initial_joypad: joypad.State,
    final_joypad: joypad.State,
    initial_timer: timer.Timer,
    final_timer: timer.Timer,
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator) !Fixture {
        const rom_bytes =
            try allocator.create([cartridge.header.ROM_SIZE]u8);
        errdefer allocator.destroy(rom_bytes);
        const initial_system =
            try allocator.create([memory_lookup.SYSTEM_SIZE]u8);
        errdefer allocator.destroy(initial_system);
        const final_system =
            try allocator.create([memory_lookup.SYSTEM_SIZE]u8);
        errdefer allocator.destroy(final_system);
        const initial_sram =
            try allocator.create([memory_lookup.SRAM_SIZE]u8);
        errdefer allocator.destroy(initial_sram);
        const final_sram =
            try allocator.create([memory_lookup.SRAM_SIZE]u8);
        errdefer allocator.destroy(final_sram);
        @memset(rom_bytes, 0);
        @memset(initial_system, 0);
        @memset(final_system, 0);
        @memset(initial_sram, 0);
        @memset(final_sram, 0);

        rom_bytes[cartridge.header.CARTRIDGE_TYPE_OFFSET] =
            cartridge.header.CARTRIDGE_TYPE_MBC3_RAM_BATTERY;
        rom_bytes[cartridge.header.ROM_SIZE_CODE_OFFSET] =
            cartridge.header.ROM_SIZE_CODE_1_MIB;
        rom_bytes[cartridge.header.RAM_SIZE_CODE_OFFSET] =
            cartridge.header.RAM_SIZE_CODE_32_KIB;
        rom_bytes[cartridge.header.HEADER_CHECKSUM_OFFSET] =
            cartridge.header.headerChecksum(rom_bytes);
        std.mem.writeInt(
            u16,
            rom_bytes[cartridge.header.GLOBAL_CHECKSUM_OFFSET..cartridge.header.HEADER_END][0..2],
            cartridge.header.globalChecksum(rom_bytes),
            .big,
        );

        const initial_joypad = joypad.State{};
        var final_joypad = joypad.State{};
        const initial_timer = timer.Timer{};
        const final_timer = timer.Timer{};
        _ = final_joypad.setPressed(joypad.Key.a.mask());
        initial_system[joypad.P1_ADDRESS] = initial_joypad.readP1();
        final_system[joypad.P1_ADDRESS] = final_joypad.readP1();
        setTimerRegisters(initial_system, initial_timer);
        setTimerRegisters(final_system, final_timer);
        final_system[0xc000] = 0x2a;
        final_sram[0] = 0x55;
        return .{
            .rom_bytes = rom_bytes,
            .initial_system = initial_system,
            .final_system = final_system,
            .initial_sram = initial_sram,
            .final_sram = final_sram,
            .initial_joypad = initial_joypad,
            .final_joypad = final_joypad,
            .initial_timer = initial_timer,
            .final_timer = final_timer,
            .allocator = allocator,
        };
    }

    fn rom(self: *const Fixture) !cartridge.Cartridge {
        return cartridge.Cartridge.init(self.rom_bytes);
    }

    fn initialImages(self: *const Fixture) !memory_lookup.Images {
        return .{
            .system = try memory.Image.init(self.initial_system),
            .sram = try memory_lookup.SramImage.init(self.initial_sram),
        };
    }

    fn finalImages(self: *const Fixture) !memory_lookup.Images {
        return .{
            .system = try memory.Image.init(self.final_system),
            .sram = try memory_lookup.SramImage.init(self.final_sram),
        };
    }

    fn base(self: *const Fixture) !base_statement.ExecutionStatement {
        return base_statement.init(
            4,
            .{ .cpu = .{}, .mcycle = 100 },
            .{ .cpu = .{}, .mcycle = 116 },
            .{},
            .{},
            try self.rom(),
            try self.initialImages(),
            try self.finalImages(),
        );
    }

    fn statement(self: *const Fixture) !environment.ExecutionStatement {
        return environment.init(
            try self.base(),
            try self.rom(),
            try self.initialImages(),
            try self.finalImages(),
            &actions,
            self.initial_joypad,
            self.final_joypad,
            5,
            self.initial_timer,
            self.final_timer,
            4,
            &regions,
            &intermediate_observations,
            4,
        );
    }

    fn deinit(self: *Fixture) void {
        self.allocator.destroy(self.final_sram);
        self.allocator.destroy(self.initial_sram);
        self.allocator.destroy(self.final_system);
        self.allocator.destroy(self.initial_system);
        self.allocator.destroy(self.rom_bytes);
        self.* = undefined;
    }
};

test "environment statement initializes and validates canonical witnesses" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const statement = try fixture.statement();
    try validate(&fixture, statement, &actions, &regions);
    try std.testing.expectEqual(environment.VERSION, statement.version);
    try std.testing.expectEqual(@as(u32, 2), statement.action_count);
    try std.testing.expectEqual(@as(u32, 4), statement.timer_log_size);
    try std.testing.expectEqual(
        @as(u32, 2),
        statement.observation_region_count,
    );
    try std.testing.expectEqual(
        @as(u32, intermediate_observations.len),
        statement.intermediate_observation_schedule_claim.count,
    );
    try std.testing.expectEqual(
        @as(u32, 4),
        statement.intermediate_observation_log_size,
    );
}

test "environment preprocessing appends canonical action and observation domains" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const statement = try fixture.statement();
    const columns = try environment.canonicalPreprocessed(
        std.testing.allocator,
        statement,
        try fixture.rom(),
        try fixture.initialImages(),
        try fixture.finalImages(),
        &actions,
        &regions,
        &intermediate_observations,
    );
    defer {
        for (columns) |column|
            std.testing.allocator.free(@constCast(column.values));
        std.testing.allocator.free(columns);
    }
    try std.testing.expectEqual(
        environment.N_PREPROCESSED_COLUMNS,
        columns.len,
    );
    const first = try core_air_utils.circleBitReversedIndex(5, 0);
    const last = try core_air_utils.circleBitReversedIndex(5, 31);
    try std.testing.expect(
        columns[environment.JOYPAD_FIRST_PREPROCESSED]
            .values[first].isOne(),
    );
    try std.testing.expect(
        columns[environment.JOYPAD_LAST_PREPROCESSED]
            .values[last].isOne(),
    );
    const public = [_][]const M31{
        columns[environment.ACTION_ACTIVE_PREPROCESSED].values,
        columns[environment.ACTION_MCYCLE_PREPROCESSED].values,
        columns[environment.ACTION_PRESSED_PREPROCESSED].values,
    };
    try action_lookup.validatePublicTable(
        &public,
        statement.joypad_log_size,
        statement.base.initial.mcycle,
        statement.base.final.mcycle,
        &actions,
    );
    const intermediate_public =
        [_][]const M31{
            columns[
                environment.OBSERVATION_ACTIVE_PREPROCESSED
            ].values,
            columns[
                environment.OBSERVATION_MCYCLE_PREPROCESSED
            ].values,
            columns[
                environment.OBSERVATION_KEY_PREPROCESSED
            ].values,
            columns[
                environment.OBSERVATION_VALUE_PREPROCESSED
            ].values,
        };
    try intermediate_observation.validatePublicTable(
        &intermediate_public,
        statement.intermediate_observation_log_size,
        &intermediate_observations,
    );
    const observation_first = try core_air_utils.circleBitReversedIndex(
        statement.intermediate_observation_log_size,
        0,
    );
    const first_values =
        columns[environment.INTERMEDIATE_OBSERVATION_FIRST_PREPROCESSED].values;
    for (first_values, 0..) |value, row| try std.testing.expectEqual(
        row == observation_first,
        value.isOne(),
    );
    inline for (environment.INTERMEDIATE_OBSERVATION_FIRST_PREPROCESSED..environment.N_PREPROCESSED_COLUMNS) |column| try std.testing.expectEqual(
        statement.intermediate_observation_log_size,
        columns[column].log_size,
    );
    const p1 = try core_air_utils.circleBitReversedIndex(
        memory_lookup.BOUNDARY_LOG_SIZE,
        joypad.P1_ADDRESS,
    );
    inline for (.{
        base_statement.MEMORY_ENABLED_PREPROCESSED,
        base_statement.MEMORY_ADDRESS_PREPROCESSED,
        base_statement.MEMORY_INITIAL_PREPROCESSED,
        base_statement.MEMORY_FINAL_PREPROCESSED,
    }) |column| try std.testing.expect(
        columns[column].values[p1].isZero(),
    );
    try std.testing.expect(!environment.memoryBoundaryEnabled(
        joypad.P1_ADDRESS,
    ));
    try std.testing.expect(environment.memoryBoundaryEnabled(
        joypad.P1_ADDRESS + 1,
    ));
    try std.testing.expect(environment.memoryBoundaryEnabled(0xc000));
    try std.testing.expect(environment.memoryBoundaryEnabled(
        memory_lookup.SRAM_KEY_OFFSET,
    ));
    inline for (0..4) |register| {
        const address = timer_binding.FIRST_ADDRESS + register;
        const row = try core_air_utils.circleBitReversedIndex(
            memory_lookup.BOUNDARY_LOG_SIZE,
            address,
        );
        inline for (.{
            base_statement.MEMORY_ENABLED_PREPROCESSED,
            base_statement.MEMORY_ADDRESS_PREPROCESSED,
            base_statement.MEMORY_INITIAL_PREPROCESSED,
            base_statement.MEMORY_FINAL_PREPROCESSED,
        }) |column| try std.testing.expect(
            columns[column].values[row].isZero(),
        );
        try std.testing.expect(!environment.memoryBoundaryEnabled(address));
    }

    const main_logs = environment.mainLogSizes(4, 5, 4, 6);
    try std.testing.expectEqual(
        @as(u32, 5),
        main_logs[environment.JOYPAD_BINDING_MAIN_OFFSET],
    );
    try std.testing.expectEqual(
        @as(u32, 6),
        main_logs[environment.N_MAIN_COLUMNS - 1],
    );
    try std.testing.expectEqual(
        @as(u32, 6),
        main_logs[environment.INTERMEDIATE_OBSERVATION_MAIN_OFFSET],
    );
    try std.testing.expectEqual(
        @as(u32, 4),
        main_logs[environment.TIMER_BINDING_MAIN_OFFSET],
    );
    const interaction_logs = environment.interactionLogSizes(4, 5, 4, 6);
    try std.testing.expectEqual(
        @as(u32, 5),
        interaction_logs[environment.ACTION_INTERACTION_OFFSET],
    );
    try std.testing.expectEqual(
        @as(u32, 4),
        interaction_logs[environment.MMIO_EXECUTION_INTERACTION_OFFSET],
    );
    try std.testing.expectEqual(
        @as(u32, 5),
        interaction_logs[environment.JOYPAD_IF_INTERACTION_OFFSET],
    );
    try std.testing.expectEqual(
        @as(u32, 4),
        interaction_logs[environment.TIMER_MMIO_EXECUTION_INTERACTION_OFFSET],
    );
    try std.testing.expectEqual(
        @as(u32, 4),
        interaction_logs[environment.TIMER_IF_INTERACTION_OFFSET],
    );
    try std.testing.expectEqual(
        @as(u32, 6),
        interaction_logs[environment.INTERMEDIATE_OBSERVATION_INTERACTION_OFFSET],
    );
}

test "environment lookup cancellation includes device and observation memory" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const statement = try fixture.statement();
    try environment.verifyLookupCancellation(statement);

    var unbalanced = statement;
    unbalanced.joypad_if_memory_claim = QM31.one();
    try std.testing.expectError(
        error.CartridgeMemoryLookupSumNonZero,
        environment.verifyLookupCancellation(unbalanced),
    );

    var balanced = statement;
    balanced.base.memory_lookup_claims.boundary = QM31.one().neg();
    balanced.joypad_if_memory_claim = QM31.one();
    try environment.verifyLookupCancellation(balanced);

    balanced = statement;
    balanced.base.memory_lookup_claims.boundary = QM31.one().neg();
    balanced.intermediate_observation_memory_claim = QM31.one();
    try environment.verifyLookupCancellation(balanced);
}

test "environment statement field and delegated claim changes transcript" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const statement = try fixture.statement();
    const baseline = transcript(statement);
    var mutated = statement;

    mutated.version +%= 1;
    try expectTranscriptChange(baseline, mutated);
    mutated = statement;
    mutated.base.final_mapper.rom_bank_register = 2;
    try expectTranscriptChange(baseline, mutated);
    mutated = statement;
    mutated.base.rom_lookup_claims.rom = QM31.one();
    try expectTranscriptChange(baseline, mutated);
    mutated = statement;
    mutated.action_lookup_claims.events = QM31.one();
    try expectTranscriptChange(baseline, mutated);
    mutated = statement;
    mutated.action_lookup_claims.public = QM31.one();
    try expectTranscriptChange(baseline, mutated);
    mutated = statement;
    mutated.joypad_mmio_lookup_claims.execution[0][0] = QM31.one();
    try expectTranscriptChange(baseline, mutated);
    mutated = statement;
    mutated.joypad_mmio_lookup_claims.joypad[0] = QM31.one();
    try expectTranscriptChange(baseline, mutated);
    mutated = statement;
    mutated.joypad_if_memory_claim = QM31.one();
    try expectTranscriptChange(baseline, mutated);
    mutated = statement;
    mutated.action_count +%= 1;
    try expectTranscriptChange(baseline, mutated);
    mutated = statement;
    mutated.action_digest[0] ^= 1;
    try expectTranscriptChange(baseline, mutated);
    mutated = statement;
    mutated.initial_joypad.p1 ^= 1;
    try expectTranscriptChange(baseline, mutated);
    mutated = statement;
    mutated.initial_joypad.pressed ^= 1;
    try expectTranscriptChange(baseline, mutated);
    mutated = statement;
    mutated.initial_joypad.pending_selection ^= 1;
    try expectTranscriptChange(baseline, mutated);
    mutated = statement;
    mutated.initial_joypad.switching_delay ^= 1;
    try expectTranscriptChange(baseline, mutated);
    mutated = statement;
    mutated.final_joypad.p1 ^= 1;
    try expectTranscriptChange(baseline, mutated);
    mutated = statement;
    mutated.final_joypad.pressed ^= 1;
    try expectTranscriptChange(baseline, mutated);
    mutated = statement;
    mutated.final_joypad.pending_selection ^= 1;
    try expectTranscriptChange(baseline, mutated);
    mutated = statement;
    mutated.final_joypad.switching_delay ^= 1;
    try expectTranscriptChange(baseline, mutated);
    mutated = statement;
    mutated.joypad_log_size += 1;
    try expectTranscriptChange(baseline, mutated);
    mutated = statement;
    mutated.initial_timer.div_counter +%= 1;
    try expectTranscriptChange(baseline, mutated);
    mutated = statement;
    mutated.final_timer.tima +%= 1;
    try expectTranscriptChange(baseline, mutated);
    mutated = statement;
    mutated.timer_log_size += 1;
    try expectTranscriptChange(baseline, mutated);
    mutated = statement;
    mutated.timer_mmio_lookup_claims.execution[0][0] = QM31.one();
    try expectTranscriptChange(baseline, mutated);
    mutated = statement;
    mutated.timer_mmio_lookup_claims.timer[0] = QM31.one();
    try expectTranscriptChange(baseline, mutated);
    mutated = statement;
    mutated.timer_if_memory_claim = QM31.one();
    try expectTranscriptChange(baseline, mutated);
    mutated = statement;
    mutated.intermediate_observation_memory_claim = QM31.one();
    try expectTranscriptChange(baseline, mutated);
    mutated = statement;
    mutated.observation_region_count +%= 1;
    try expectTranscriptChange(baseline, mutated);
    mutated = statement;
    mutated.observation_digest[0] ^= 1;
    try expectTranscriptChange(baseline, mutated);
    mutated = statement;
    mutated.intermediate_observation_log_size += 1;
    try expectTranscriptChange(baseline, mutated);
    mutated = statement;
    mutated.intermediate_observation_schedule_claim.count += 1;
    try expectTranscriptChange(baseline, mutated);
    mutated = statement;
    mutated.intermediate_observation_schedule_claim.digest[0] ^= 1;
    try expectTranscriptChange(baseline, mutated);
}

test "environment statement rejects action substitutions and ordering" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const statement = try fixture.statement();
    var substituted = actions;
    substituted[1].pressed ^= 1;
    try std.testing.expectError(
        error.ActionDigestMismatch,
        validate(&fixture, statement, &substituted, &regions),
    );
    var reordered = actions;
    std.mem.swap(
        action_schedule.Action,
        &reordered[0],
        &reordered[1],
    );
    try std.testing.expectError(
        error.NonIncreasingActionTime,
        validate(&fixture, statement, &reordered, &regions),
    );
}

test "environment statement rejects observation substitutions" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var statement = try fixture.statement();
    var moved = regions;
    moved[0].start += 1;
    try std.testing.expectError(
        error.ObservationDigestMismatch,
        validate(&fixture, statement, &actions, &moved),
    );

    fixture.final_system[0xc000] ^= 1;
    statement.base = try fixture.base();
    try std.testing.expectError(
        error.ObservationDigestMismatch,
        validate(&fixture, statement, &actions, &regions),
    );
}

test "environment statement rejects intermediate observation substitutions" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const statement = try fixture.statement();
    var substituted = intermediate_observations;
    substituted[0].expected ^= 1;
    try std.testing.expectError(
        error.IntermediateObservationDigestMismatch,
        validateWithIntermediate(
            &fixture,
            statement,
            &substituted,
        ),
    );
    substituted = intermediate_observations;
    substituted[1].mcycle = 99;
    try std.testing.expectError(
        error.NonCanonicalObservationOrder,
        validateWithIntermediate(
            &fixture,
            statement,
            &substituted,
        ),
    );
    substituted = intermediate_observations;
    substituted[0].mcycle = 99;
    try std.testing.expectError(
        error.IntermediateObservationOutOfSegment,
        validateWithIntermediate(
            &fixture,
            statement,
            &substituted,
        ),
    );
    for ([_]u32{ 116, 117 }) |mcycle| {
        substituted = intermediate_observations;
        substituted[1].mcycle = mcycle;
        try std.testing.expectError(
            error.IntermediateObservationOutOfSegment,
            validateWithIntermediate(
                &fixture,
                statement,
                &substituted,
            ),
        );
    }
    try std.testing.expectError(
        error.EmptyObservationSchedule,
        validateWithIntermediate(&fixture, statement, &.{}),
    );
}

test "environment statement rejects P1 state and base mismatches" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const statement = try fixture.statement();

    var invalid_state = statement;
    invalid_state.initial_joypad.p1 = 0x0f;
    try std.testing.expectError(
        error.InvalidHighBits,
        validate(&fixture, invalid_state, &actions, &regions),
    );
    var base_mismatch = statement;
    base_mismatch.base.rom_digest[0] ^= 1;
    try std.testing.expectError(
        error.RomDigestMismatch,
        validate(&fixture, base_mismatch, &actions, &regions),
    );

    fixture.initial_system[joypad.P1_ADDRESS] ^= 1;
    try std.testing.expectError(
        error.InitialJoypadP1Mismatch,
        environment.init(
            try fixture.base(),
            try fixture.rom(),
            try fixture.initialImages(),
            try fixture.finalImages(),
            &actions,
            fixture.initial_joypad,
            fixture.final_joypad,
            5,
            fixture.initial_timer,
            fixture.final_timer,
            4,
            &regions,
            &intermediate_observations,
            4,
        ),
    );
    fixture.initial_system[joypad.P1_ADDRESS] ^= 1;
    fixture.final_system[joypad.P1_ADDRESS] ^= 1;
    try std.testing.expectError(
        error.FinalJoypadP1Mismatch,
        environment.init(
            try fixture.base(),
            try fixture.rom(),
            try fixture.initialImages(),
            try fixture.finalImages(),
            &actions,
            fixture.initial_joypad,
            fixture.final_joypad,
            5,
            fixture.initial_timer,
            fixture.final_timer,
            4,
            &regions,
            &intermediate_observations,
            4,
        ),
    );
}

test "environment statement rejects direct count digest and version mutation" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const statement = try fixture.statement();
    var mutated = statement;
    mutated.version = environment.VERSION + 1;
    try std.testing.expectError(
        error.InvalidEnvironmentVersion,
        validate(&fixture, mutated, &actions, &regions),
    );
    mutated = statement;
    mutated.action_count += 1;
    try std.testing.expectError(
        error.ActionCountMismatch,
        validate(&fixture, mutated, &actions, &regions),
    );
    mutated = statement;
    mutated.action_digest[0] ^= 1;
    try std.testing.expectError(
        error.ActionDigestMismatch,
        validate(&fixture, mutated, &actions, &regions),
    );
    mutated = statement;
    mutated.joypad_log_size = 3;
    try std.testing.expectError(
        error.InvalidJoypadLogSize,
        validate(&fixture, mutated, &actions, &regions),
    );
    mutated = statement;
    mutated.timer_log_size = 3;
    try std.testing.expectError(
        error.InvalidTimerLogSize,
        validate(&fixture, mutated, &actions, &regions),
    );
    mutated = statement;
    mutated.observation_region_count += 1;
    try std.testing.expectError(
        error.ObservationRegionCountMismatch,
        validate(&fixture, mutated, &actions, &regions),
    );
    mutated = statement;
    mutated.observation_digest[0] ^= 1;
    try std.testing.expectError(
        error.ObservationDigestMismatch,
        validate(&fixture, mutated, &actions, &regions),
    );
    mutated = statement;
    mutated.intermediate_observation_log_size = 3;
    try std.testing.expectError(
        error.InvalidIntermediateObservationLogSize,
        validate(&fixture, mutated, &actions, &regions),
    );
    mutated = statement;
    mutated.intermediate_observation_schedule_claim.count += 1;
    try std.testing.expectError(
        error.IntermediateObservationCountMismatch,
        validate(&fixture, mutated, &actions, &regions),
    );
    mutated = statement;
    mutated.intermediate_observation_schedule_claim.digest[0] ^= 1;
    try std.testing.expectError(
        error.IntermediateObservationDigestMismatch,
        validate(&fixture, mutated, &actions, &regions),
    );
}

fn setTimerRegisters(
    bytes: []u8,
    state: timer.Timer,
) void {
    bytes[timer_binding.FIRST_ADDRESS + 0] = state.readDiv();
    bytes[timer_binding.FIRST_ADDRESS + 1] = state.readTima();
    bytes[timer_binding.FIRST_ADDRESS + 2] = state.readTma();
    bytes[timer_binding.FIRST_ADDRESS + 3] = state.readTac();
}

fn validate(
    fixture: *const Fixture,
    statement: environment.ExecutionStatement,
    provided_actions: []const action_schedule.Action,
    provided_regions: []const observation.Region,
) !void {
    return environment.validate(
        statement,
        try fixture.rom(),
        try fixture.initialImages(),
        try fixture.finalImages(),
        provided_actions,
        provided_regions,
        &intermediate_observations,
    );
}

fn validateWithIntermediate(
    fixture: *const Fixture,
    statement: environment.ExecutionStatement,
    provided: []const intermediate_observation.Sample,
) !void {
    return environment.validate(
        statement,
        try fixture.rom(),
        try fixture.initialImages(),
        try fixture.finalImages(),
        &actions,
        &regions,
        provided,
    );
}

fn transcript(statement: environment.ExecutionStatement) [32]u8 {
    var channel = environment.Channel{};
    environment.mixPublic(&channel, statement);
    environment.mixLookupClaims(&channel, statement);
    return channel.digestBytes();
}

fn expectTranscriptChange(
    baseline: [32]u8,
    statement: environment.ExecutionStatement,
) !void {
    try std.testing.expect(!std.mem.eql(
        u8,
        &baseline,
        &transcript(statement),
    ));
}
