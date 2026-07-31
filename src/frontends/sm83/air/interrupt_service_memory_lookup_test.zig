//! Exact, sampled, and prover-domain controls for service-owned IE/IF history.

const std = @import("std");
const core = @import("stwo_core");
const TreeVec = core.pcs.TreeVec;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const air_utils = core.air.utils;
const prover_accumulation =
    @import("stwo_prover_engine").air.accumulation;
const prover_component =
    @import("stwo_prover_engine").air.component_prover;
const cartridge = @import("../cartridge/mod.zig");
const memory_image = @import("../memory.zig");
const machine = @import("../runner/machine.zig");
const runner = @import("../runner/mod.zig");
const replay_subject = @import("../machine_memory_replay.zig");
const execution = @import("execution.zig");
const execution_input = @import("execution_input.zig");
const service_air = @import("interrupt_service.zig");
const memory_lookup = @import("cartridge_memory_lookup.zig");
const lookup = @import("interrupt_service_memory_lookup.zig");
const subject = @import("interrupt_service_memory_lookup_component.zig");

const LOG_SIZE: u32 = 4;
const SIZE: usize = 1 << LOG_SIZE;
const EVALUATION_LOG_SIZE: u32 = LOG_SIZE + 1;
const EVALUATION_SIZE: usize = 1 << EVALUATION_LOG_SIZE;
const FIRST_COLUMN: usize = 0;
const LAST_COLUMN: usize = 1;
const ACTIVE_COLUMN: usize = 2;
const EXECUTION_OFFSET: usize = 3;
const SERVICE_OFFSET: usize =
    EXECUTION_OFFSET + execution.N_MAIN_COLUMNS + 1;
const MEMORY_OFFSET: usize =
    SERVICE_OFFSET + service_air.N_MAIN_COLUMNS + 1;
const LOOKUP_OFFSET: usize =
    MEMORY_OFFSET + memory_lookup.N_MAIN_COLUMNS + 1;
const MAIN_COLUMNS: usize = LOOKUP_OFFSET + lookup.N_MAIN_COLUMNS;
const INTERACTION_OFFSET: usize = 2;
const INTERACTION_COLUMNS: usize =
    INTERACTION_OFFSET + lookup.N_INTERACTION_COLUMNS;
const IF: u16 = runner.cartridge_memory.INTERRUPT_FLAGS;
const IE: u16 = 0xffff;

test "interrupt service memory lookup authenticates exact logical operations" {
    var scenario = try Scenario.init(
        .{ .pc = 0x2345, .sp = 0xc102, .ime = true },
        1,
        1,
        7,
    );
    defer scenario.deinit();
    var trace = try TraceData.init(&scenario);
    defer trace.deinit();

    try std.testing.expectEqual(@as(u32, 1), trace.witness.service_count);
    try std.testing.expectEqual(
        @as(u32, 1),
        trace.interaction.claims.service_count,
    );
    try expectAllDirectRows(&scenario, &trace);

    const samples = trace.witness.samples[0].operations;
    for (samples) |sample|
        try std.testing.expect(sample.enabled);

    var cancelled = try Scenario.init(.{ .ime = true }, 1, 1, 0);
    defer cancelled.deinit();
    var cancelled_trace = try TraceData.init(&cancelled);
    defer cancelled_trace.deinit();
    try expectAllDirectRows(&cancelled, &cancelled_trace);
    try std.testing.expect(!cancelled_trace.witness.samples[0].operations[
        @intFromEnum(lookup.Operation.acknowledgement)
    ].enabled);
}

test "interrupt service memory lookup rejects mutations and binds zero-service segments" {
    var scenario = try Scenario.init(
        .{ .pc = 0x2345, .sp = 0xc102, .ime = true },
        1,
        1,
        0,
    );
    defer scenario.deinit();
    var trace = try TraceData.init(&scenario);
    defer trace.deinit();
    const execution_values = try executionValues(scenario.results[0], 0);
    const service_values = try serviceValues(scenario.results[0]);
    const memory_values = try memoryValues(&scenario, 0);
    const lookup_values = try lookupValues(&trace, 0);

    var predecessor = scenario.replay.service_predecessors[0];
    predecessor.ie_resample.?.value ^= 1;
    try std.testing.expectError(
        error.ServiceMemoryValueMismatch,
        lookup.columns(scenario.results[0], 0, predecessor),
    );
    predecessor = scenario.replay.service_predecessors[0];
    predecessor.acknowledgement.?.value ^= 1;
    try std.testing.expectError(
        error.ServiceMemoryValueMismatch,
        lookup.columns(scenario.results[0], 0, predecessor),
    );
    predecessor = scenario.replay.service_predecessors[0];
    predecessor.if_logical_source.?.clock += 1;
    const forged_source = try lookup.columns(
        scenario.results[0],
        0,
        predecessor,
    );
    try expectDirectRejected(
        execution_values,
        service_values,
        memory_values,
        forged_source,
        true,
    );

    var forged_lookup = lookup_values;
    const ack_offset =
        @intFromEnum(lookup.Operation.acknowledgement) *
        lookup.N_OPERATION_COLUMNS;
    forged_lookup[ack_offset + lookup.PREVIOUS_CLOCK_OFFSET] =
        forged_lookup[ack_offset + lookup.PREVIOUS_CLOCK_OFFSET]
            .add(M31.one());
    try expectDirectRejected(
        execution_values,
        service_values,
        memory_values,
        forged_lookup,
        true,
    );
    try expectDirectRejected(
        execution_values,
        service_values,
        memory_values,
        lookup_values,
        false,
    );

    var alias = try Scenario.init(
        .{ .pc = 2, .sp = IF + 2, .ime = true, .halted = true },
        1,
        1,
        0,
    );
    defer alias.deinit();
    var alias_trace = try TraceData.init(&alias);
    defer alias_trace.deinit();
    const alias_execution = try executionValues(alias.results[0], 0);
    const alias_service = try serviceValues(alias.results[0]);
    var alias_memory = try memoryValues(&alias, 0);
    const alias_lookup = try lookupValues(&alias_trace, 0);
    const low_previous =
        5 * memory_lookup.N_ACCESS_COLUMNS +
        memory_lookup.PREVIOUS_VALUE_OFFSET;
    alias_memory[low_previous] =
        alias_memory[low_previous].add(M31.one());
    try expectDirectRejected(
        alias_execution,
        alias_service,
        alias_memory,
        alias_lookup,
        true,
    );
    forged_lookup = alias_lookup;
    forged_lookup[lookup.SOURCE_CLOCK_OFFSET] =
        forged_lookup[lookup.SOURCE_CLOCK_OFFSET].add(M31.one());
    try expectDirectRejected(
        alias_execution,
        alias_service,
        try memoryValues(&alias, 0),
        forged_lookup,
        true,
    );

    var empty = [_]lookup.RowSamples{.{}} ** SIZE;
    empty[0].active = true;
    try std.testing.expectError(
        error.InvalidServiceActivity,
        lookup.generateInteraction(
            std.testing.allocator,
            &empty,
            LOG_SIZE,
            memory_lookup.Relation.dummy(),
        ),
    );
    empty[0] = .{};
    var inactive = try lookup.generateInteraction(
        std.testing.allocator,
        &empty,
        LOG_SIZE,
        memory_lookup.Relation.dummy(),
    );
    defer inactive.deinit();
    try std.testing.expectEqual(@as(u32, 0), inactive.claims.service_count);
    try std.testing.expect(inactive.claims.total().isZero());
}

test "interrupt service memory lookup component rejects sampled and domain mutations" {
    var scenario = try Scenario.init(
        .{ .pc = 0x2345, .sp = 0xc102, .ime = true },
        1,
        1,
        0,
    );
    defer scenario.deinit();
    var trace_data = try TraceData.init(&scenario);
    defer trace_data.deinit();
    const relation = memory_lookup.Relation.dummy();
    var component = makeComponent(
        &relation,
        trace_data.interaction.claims,
    );
    try std.testing.expectEqual(subject.N_CONSTRAINTS, component.nConstraints());

    var point = try sampledFixture(&scenario, &trace_data, 0);
    try expectSampled(&component, &point, true);
    point.main_values[LOOKUP_OFFSET + lookup.SOURCE_CLOCK_OFFSET][0] =
        point.main_values[LOOKUP_OFFSET + lookup.SOURCE_CLOCK_OFFSET][0]
            .add(QM31.one());
    try expectSampled(&component, &point, false);
    point = try sampledFixture(&scenario, &trace_data, 0);
    point.interaction_values[INTERACTION_OFFSET][0] =
        point.interaction_values[INTERACTION_OFFSET][0].add(QM31.one());
    try expectSampled(&component, &point, false);
    point = try sampledFixture(&scenario, &trace_data, SIZE - 1);
    try expectSampled(&component, &point, true);
    component.claims.service_count += 1;
    try expectSampled(&component, &point, false);
    component.claims = trace_data.interaction.claims;

    var domain = try DomainFixture.init(&scenario, &relation);
    domain.bind();
    var domain_component = makeComponent(&relation, domain.claims);
    const challenge = QM31.fromU32Unchecked(3, 5, 7, 11);
    try expectDomain(&domain_component, &domain.trace, challenge, true);
    domain.main_values[
        LOOKUP_OFFSET + lookup.SOURCE_CLOCK_OFFSET
    ][0] = domain.main_values[
        LOOKUP_OFFSET + lookup.SOURCE_CLOCK_OFFSET
    ][0].add(M31.one());
    try expectDomain(&domain_component, &domain.trace, challenge, false);
}

const Fixture = struct {
    rom: *[cartridge.header.ROM_SIZE]u8,
    sram: *[cartridge.header.RAM_SIZE]u8,
    system: *[runner.cartridge_memory.SYSTEM_SIZE]u8,
    memory: runner.cartridge_memory.Memory,

    fn init() !Fixture {
        const allocator = std.testing.allocator;
        const rom = try allocator.create([cartridge.header.ROM_SIZE]u8);
        errdefer allocator.destroy(rom);
        const sram = try allocator.create([cartridge.header.RAM_SIZE]u8);
        errdefer allocator.destroy(sram);
        const system = try allocator.create(
            [runner.cartridge_memory.SYSTEM_SIZE]u8,
        );
        errdefer allocator.destroy(system);
        @memset(rom, 0);
        @memset(sram, 0);
        @memset(system, 0);
        rom[cartridge.header.CARTRIDGE_TYPE_OFFSET] =
            cartridge.header.CARTRIDGE_TYPE_MBC3_RAM_BATTERY;
        rom[cartridge.header.ROM_SIZE_CODE_OFFSET] =
            cartridge.header.ROM_SIZE_CODE_1_MIB;
        rom[cartridge.header.RAM_SIZE_CODE_OFFSET] =
            cartridge.header.RAM_SIZE_CODE_32_KIB;
        rom[cartridge.header.HEADER_CHECKSUM_OFFSET] =
            cartridge.header.headerChecksum(rom);
        std.mem.writeInt(
            u16,
            rom[cartridge.header.GLOBAL_CHECKSUM_OFFSET..cartridge.header.HEADER_END][0..2],
            cartridge.header.globalChecksum(rom),
            .big,
        );
        return .{
            .rom = rom,
            .sram = sram,
            .system = system,
            .memory = runner.cartridge_memory.Memory.init(
                try cartridge.Cartridge.init(rom),
                sram,
                system,
                .{},
                0xff,
            ),
        };
    }

    fn deinit(self: *Fixture) void {
        const allocator = std.testing.allocator;
        allocator.destroy(self.system);
        allocator.destroy(self.sram);
        allocator.destroy(self.rom);
        self.* = undefined;
    }
};

const Snapshot = struct {
    system: []u8,
    sram: []u8,

    fn capture(fixture: Fixture) !Snapshot {
        const allocator = std.testing.allocator;
        const system = try allocator.dupe(u8, fixture.system);
        errdefer allocator.free(system);
        return .{
            .system = system,
            .sram = try allocator.dupe(u8, fixture.sram),
        };
    }

    fn deinit(self: *Snapshot) void {
        std.testing.allocator.free(self.sram);
        std.testing.allocator.free(self.system);
        self.* = undefined;
    }

    fn images(self: Snapshot) !memory_lookup.Images {
        return .{
            .system = try memory_image.Image.init(self.system),
            .sram = try memory_lookup.SramImage.init(self.sram),
        };
    }
};

const Scenario = struct {
    fixture: Fixture,
    initial: Snapshot,
    final: Snapshot,
    results: [SIZE]machine.CartridgeStepResult,
    replay: replay_subject.Replay,

    fn init(
        cpu: runner.Cpu,
        interrupt_enable: u8,
        interrupt_flags: u8,
        initial_mcycle: u32,
    ) !Scenario {
        var fixture = try Fixture.init();
        errdefer fixture.deinit();
        fixture.system[IE] = interrupt_enable;
        fixture.system[IF] = interrupt_flags;
        var initial = try Snapshot.capture(fixture);
        errdefer initial.deinit();
        var scheduler = try machine.CartridgeMachine.init(
            &fixture.memory,
            cpu,
        );
        var results: [SIZE]machine.CartridgeStepResult = undefined;
        for (&results) |*result| result.* = try scheduler.step();
        var final = try Snapshot.capture(fixture);
        errdefer final.deinit();
        var replay = try replay_subject.generate(
            std.testing.allocator,
            &results,
            try initial.images(),
            try final.images(),
            initial_mcycle,
        );
        errdefer replay.deinit();
        return .{
            .fixture = fixture,
            .initial = initial,
            .final = final,
            .results = results,
            .replay = replay,
        };
    }

    fn deinit(self: *Scenario) void {
        self.replay.deinit();
        self.final.deinit();
        self.initial.deinit();
        self.fixture.deinit();
        self.* = undefined;
    }
};

const TraceData = struct {
    witness: lookup.Witness,
    interaction: lookup.Interaction,

    fn init(scenario: *const Scenario) !TraceData {
        const boundary = lookup.Boundary{
            .initial_mcycle = scenario.replay.initial_mcycle,
            .final_mcycle = scenario.replay.final_mcycle,
            .expected_service_count = 1,
        };
        var witness = try lookup.generateWitness(
            std.testing.allocator,
            &scenario.results,
            boundary,
            scenario.replay.service_predecessors,
        );
        errdefer witness.deinit();
        return .{
            .witness = witness,
            .interaction = try lookup.generateInteraction(
                std.testing.allocator,
                witness.samples,
                witness.log_size,
                memory_lookup.Relation.dummy(),
            ),
        };
    }

    fn deinit(self: *TraceData) void {
        self.interaction.deinit();
        self.witness.deinit();
        self.* = undefined;
    }
};

const SampledFixture = struct {
    preprocessed_values: [LAST_COLUMN + 1][1]QM31,
    main_values: [MAIN_COLUMNS][1]QM31,
    interaction_values: [INTERACTION_COLUMNS][2]QM31,
};

fn sampledFixture(
    scenario: *const Scenario,
    trace: *const TraceData,
    row: usize,
) !SampledFixture {
    var result = SampledFixture{
        .preprocessed_values = [_][1]QM31{.{QM31.zero()}} ** (LAST_COLUMN + 1),
        .main_values = [_][1]QM31{.{QM31.zero()}} ** MAIN_COLUMNS,
        .interaction_values = [_][2]QM31{.{ QM31.zero(), QM31.zero() }} **
            INTERACTION_COLUMNS,
    };
    result.preprocessed_values[FIRST_COLUMN][0] =
        booleanQ(row == 0);
    result.preprocessed_values[LAST_COLUMN][0] =
        booleanQ(row == SIZE - 1);
    result.main_values[ACTIVE_COLUMN][0] =
        booleanQ(scenario.results[row].event == .interrupt_service);
    fillPoint(
        result.main_values[EXECUTION_OFFSET..][0..execution.N_MAIN_COLUMNS],
        &(try executionValues(
            scenario.results[row],
            try mcycleBefore(scenario, row),
        )),
    );
    fillPoint(
        result.main_values[SERVICE_OFFSET..][0..service_air.N_MAIN_COLUMNS],
        &(try serviceValues(scenario.results[row])),
    );
    fillPoint(
        result.main_values[MEMORY_OFFSET..][0..memory_lookup.N_MAIN_COLUMNS],
        &(try memoryValues(scenario, row)),
    );
    fillPoint(
        result.main_values[LOOKUP_OFFSET..][0..lookup.N_MAIN_COLUMNS],
        &(try lookupValues(trace, row)),
    );
    const storage = try air_utils.circleBitReversedIndex(LOG_SIZE, row);
    const previous_row = if (row == 0) SIZE - 1 else row - 1;
    const previous_storage = try air_utils.circleBitReversedIndex(
        LOG_SIZE,
        previous_row,
    );
    for (0..lookup.N_OPERATIONS) |operation| {
        const source = trace.interaction.columns[4 * operation ..][0..4];
        writePointSecure(
            result.interaction_values[INTERACTION_OFFSET + 4 * operation ..][0..4],
            readSecure(source, storage),
            readSecure(source, previous_storage),
        );
    }
    const activity = lookup.N_INTERACTION_COLUMNS - 1;
    result.interaction_values[INTERACTION_OFFSET + activity] = .{
        QM31.fromBase(trace.interaction.columns[activity][storage]),
        QM31.fromBase(
            trace.interaction.columns[activity][previous_storage],
        ),
    };
    return result;
}

const DomainFixture = struct {
    preprocessed_values: [LAST_COLUMN + 1][EVALUATION_SIZE]M31,
    main_values: [MAIN_COLUMNS][EVALUATION_SIZE]M31,
    interaction_values: [INTERACTION_COLUMNS][EVALUATION_SIZE]M31,
    preprocessed: [LAST_COLUMN + 1]prover_component.Poly,
    main: [MAIN_COLUMNS]prover_component.Poly,
    interaction: [INTERACTION_COLUMNS]prover_component.Poly,
    trees: [3][]const prover_component.Poly,
    trace: prover_component.Trace,
    claims: lookup.Claims,

    fn init(
        scenario: *const Scenario,
        relation: *const memory_lookup.Relation,
    ) !DomainFixture {
        var result: DomainFixture = undefined;
        @memset(
            &result.preprocessed_values,
            [_]M31{M31.zero()} ** EVALUATION_SIZE,
        );
        @memset(
            &result.main_values,
            [_]M31{M31.zero()} ** EVALUATION_SIZE,
        );
        @memset(
            &result.interaction_values,
            [_]M31{M31.zero()} ** EVALUATION_SIZE,
        );
        const executed = try executionValues(scenario.results[0], 0);
        const service = try serviceValues(scenario.results[0]);
        const memory = try memoryValues(scenario, 0);
        const predecessor = scenario.replay.service_predecessors[0];
        const memory_row = try lookup.columns(
            scenario.results[0],
            0,
            predecessor,
        );
        fillDomainConstants(
            result.main_values[EXECUTION_OFFSET..][0..execution.N_MAIN_COLUMNS],
            &executed,
        );
        fillDomainConstants(
            result.main_values[SERVICE_OFFSET..][0..service_air.N_MAIN_COLUMNS],
            &service,
        );
        fillDomainConstants(
            result.main_values[MEMORY_OFFSET..][0..memory_lookup.N_MAIN_COLUMNS],
            &memory,
        );
        fillDomainConstants(
            result.main_values[LOOKUP_OFFSET..][0..lookup.N_MAIN_COLUMNS],
            &memory_row,
        );
        @memset(&result.main_values[ACTIVE_COLUMN], M31.one());
        var executed_q: [execution.N_MAIN_COLUMNS]QM31 = undefined;
        var service_q: [service_air.N_MAIN_COLUMNS]QM31 = undefined;
        var memory_q: [lookup.N_MAIN_COLUMNS]QM31 = undefined;
        lift(&executed_q, &executed);
        lift(&service_q, &service);
        lift(&memory_q, &memory_row);
        const pairs = lookup.pairsForRows(
            try execution.Row(QM31).fromColumns(&executed_q),
            try service_air.Shipped.Row.fromColumns(&service_q),
            try lookup.Row(QM31).fromColumns(&memory_q),
            QM31.one(),
            relation.*,
        );
        var increments: [lookup.N_OPERATIONS]QM31 = undefined;
        for (&increments, pairs) |*increment, pair|
            increment.* = try pairIncrement(pair);
        const cycle_size: usize = SIZE;
        var sums =
            [_][EVALUATION_SIZE]QM31{
                [_]QM31{QM31.zero()} ** EVALUATION_SIZE,
            } ** lookup.N_OPERATIONS;
        for (0..SIZE) |position| {
            const first_row = core.utils.bitReverseIndex(
                position,
                EVALUATION_LOG_SIZE,
            );
            const second_order = if (position == 0)
                SIZE
            else
                EVALUATION_SIZE - position;
            const second_row = core.utils.bitReverseIndex(
                second_order,
                EVALUATION_LOG_SIZE,
            );
            if (position == 0) {
                result.preprocessed_values[FIRST_COLUMN][first_row] =
                    M31.one();
                result.preprocessed_values[FIRST_COLUMN][second_row] =
                    M31.one();
            }
            if (position == SIZE - 1) {
                result.preprocessed_values[LAST_COLUMN][first_row] =
                    M31.one();
                result.preprocessed_values[LAST_COLUMN][second_row] =
                    M31.one();
            }
            const activity = M31.fromCanonical(@intCast(position + 1));
            for (increments, 0..) |increment, operation| {
                const value = increment.mul(q(position));
                sums[operation][first_row] = value;
                sums[operation][second_row] = value;
            }
            result.interaction_values[
                INTERACTION_OFFSET + lookup.N_INTERACTION_COLUMNS - 1
            ][first_row] = activity;
            result.interaction_values[
                INTERACTION_OFFSET + lookup.N_INTERACTION_COLUMNS - 1
            ][second_row] = activity;
        }
        for (sums, 0..) |operation, index| {
            for (operation, 0..) |value, row| {
                for (value.toM31Array(), 0..) |coordinate, column| {
                    result.interaction_values[
                        INTERACTION_OFFSET + 4 * index + column
                    ][row] = coordinate;
                }
            }
        }
        result.claims = .{
            .operations = undefined,
            .service_count = @intCast(cycle_size),
        };
        for (&result.claims.operations, increments) |*claim, increment|
            claim.* = increment.mul(q(cycle_size));
        return result;
    }

    fn bind(self: *DomainFixture) void {
        domainPolys(&self.preprocessed, &self.preprocessed_values);
        domainPolys(&self.main, &self.main_values);
        domainPolys(&self.interaction, &self.interaction_values);
        self.trees = .{ &self.preprocessed, &self.main, &self.interaction };
        self.trace = .{
            .polys = TreeVec([]const prover_component.Poly).initOwned(
                &self.trees,
            ),
        };
    }
};

fn expectAllDirectRows(
    scenario: *const Scenario,
    trace: *const TraceData,
) !void {
    var mcycle = scenario.replay.initial_mcycle;
    for (scenario.results, 0..) |result, row| {
        try std.testing.expect(
            (try lookup.evaluateM31(
                try executionValues(result, mcycle),
                try serviceValues(result),
                try memoryValues(scenario, row),
                try lookupValues(trace, row),
                result.event == .interrupt_service,
            )).allZero(),
        );
        mcycle += result.m_cycles;
    }
}

fn expectDirectRejected(
    execution_values: [execution.N_MAIN_COLUMNS]M31,
    service_values: [service_air.N_MAIN_COLUMNS]M31,
    memory_values: [memory_lookup.N_MAIN_COLUMNS]M31,
    lookup_values: [lookup.N_MAIN_COLUMNS]M31,
    active: bool,
) !void {
    try std.testing.expect(
        !(try lookup.evaluateM31(
            execution_values,
            service_values,
            memory_values,
            lookup_values,
            active,
        )).allZero(),
    );
}

fn executionValues(
    result: machine.CartridgeStepResult,
    mcycle: u32,
) ![execution.N_MAIN_COLUMNS]M31 {
    return execution_input.cartridgeExecutionColumns(
        try execution_input.fromCartridgeMachine(result),
        mcycle,
    );
}

fn serviceValues(
    result: machine.CartridgeStepResult,
) ![service_air.N_MAIN_COLUMNS]M31 {
    if (result.event != .interrupt_service)
        return [_]M31{M31.zero()} ** service_air.N_MAIN_COLUMNS;
    return service_air.columns(try service_air.ValidatedStep.init(result));
}

fn memoryValues(
    scenario: *const Scenario,
    row: usize,
) ![memory_lookup.N_MAIN_COLUMNS]M31 {
    const storage = try air_utils.circleBitReversedIndex(LOG_SIZE, row);
    var result: [memory_lookup.N_MAIN_COLUMNS]M31 = undefined;
    for (&result, scenario.replay.memory.main) |*value, column|
        value.* = column[storage];
    return result;
}

fn lookupValues(
    trace: *const TraceData,
    row: usize,
) ![lookup.N_MAIN_COLUMNS]M31 {
    const storage = try air_utils.circleBitReversedIndex(LOG_SIZE, row);
    var result: [lookup.N_MAIN_COLUMNS]M31 = undefined;
    for (&result, trace.witness.main) |*value, column|
        value.* = column[storage];
    return result;
}

fn mcycleBefore(scenario: *const Scenario, target: usize) !u32 {
    var mcycle = scenario.replay.initial_mcycle;
    for (scenario.results[0..target]) |result|
        mcycle = std.math.add(u32, mcycle, result.m_cycles) catch
            return error.ServiceMemoryClockOverflow;
    return mcycle;
}

fn makeComponent(
    relation: *const memory_lookup.Relation,
    claims: lookup.Claims,
) subject.Component {
    return .{
        .log_size = LOG_SIZE,
        .is_first_column = FIRST_COLUMN,
        .is_last_column = LAST_COLUMN,
        .service_active_column = ACTIVE_COLUMN,
        .execution_offset = EXECUTION_OFFSET,
        .service_offset = SERVICE_OFFSET,
        .memory_offset = MEMORY_OFFSET,
        .lookup_offset = LOOKUP_OFFSET,
        .interaction_offset = INTERACTION_OFFSET,
        .relation = relation,
        .claims = claims,
    };
}

fn expectSampled(
    component: *const subject.Component,
    fixture: *SampledFixture,
    expected: bool,
) !void {
    var preprocessed: [LAST_COLUMN + 1][]QM31 = undefined;
    pointSlices(&preprocessed, &fixture.preprocessed_values);
    var main: [MAIN_COLUMNS][]QM31 = undefined;
    pointSlices(&main, &fixture.main_values);
    var interaction: [INTERACTION_COLUMNS][]QM31 = undefined;
    pointSlices(&interaction, &fixture.interaction_values);
    var constraints: [subject.N_CONSTRAINTS]QM31 = undefined;
    try component.evaluateSampled(
        &preprocessed,
        &main,
        &interaction,
        &constraints,
    );
    try std.testing.expectEqual(expected, allZero(&constraints));
}

fn expectDomain(
    component: *const subject.Component,
    trace: *const prover_component.Trace,
    challenge: QM31,
    expected: bool,
) !void {
    var accumulator =
        try prover_accumulation.DomainEvaluationAccumulator.init(
            std.testing.allocator,
            challenge,
            EVALUATION_LOG_SIZE,
            component.nConstraints(),
        );
    defer accumulator.deinit();
    try component.evaluateConstraintQuotientsOnDomain(trace, &accumulator);
    var result = try accumulator.finalize();
    defer result.deinit(std.testing.allocator);
    var zero = true;
    for (0..result.len()) |row|
        zero = zero and result.at(row).isZero();
    try std.testing.expectEqual(expected, zero);
}

fn readSecure(columns: []const []M31, row: usize) QM31 {
    return QM31.fromM31(
        columns[0][row],
        columns[1][row],
        columns[2][row],
        columns[3][row],
    );
}

fn writePointSecure(
    columns: [][2]QM31,
    current: QM31,
    previous: QM31,
) void {
    const now = current.toM31Array();
    const prior = previous.toM31Array();
    for (columns, 0..) |*column, index|
        column.* = .{
            QM31.fromBase(now[index]),
            QM31.fromBase(prior[index]),
        };
}

fn fillPoint(destinations: anytype, values: []const M31) void {
    for (destinations, values) |*destination, value|
        destination[0] = QM31.fromBase(value);
}

fn fillDomainConstants(destinations: anytype, values: []const M31) void {
    for (destinations, values) |*destination, value|
        @memset(destination, value);
}

fn domainPolys(output: anytype, values: anytype) void {
    for (output, values) |*polynomial, *column|
        polynomial.* = .{
            .log_size = EVALUATION_LOG_SIZE,
            .values = column,
        };
}

fn lift(output: []QM31, input: []const M31) void {
    for (output, input) |*value, source|
        value.* = QM31.fromBase(source);
}

fn pairIncrement(pair: memory_lookup.RowPair) !QM31 {
    if (pair.n1.isZero() and pair.n2.isZero()) return QM31.zero();
    const denominator = pair.d1.mul(pair.d2);
    const numerator = pair.n1.mul(pair.d2).add(pair.n2.mul(pair.d1));
    return numerator.mul(try denominator.inv());
}

fn q(value: anytype) QM31 {
    return QM31.fromBase(M31.fromU64(@intCast(value)));
}

fn pointSlices(output: anytype, values: anytype) void {
    for (output, values) |*column, *source| column.* = source;
}

fn allZero(values: []const QM31) bool {
    for (values) |value|
        if (!value.isZero()) return false;
    return true;
}

fn booleanQ(value: bool) QM31 {
    return QM31.fromBase(M31.fromCanonical(@intFromBool(value)));
}
