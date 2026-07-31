//! Direct, sampled, and cancellation controls for scheduler IE/IF.

const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const air_utils = core.air.utils;
const core_air_accumulation = core.air.accumulation;
const core_air_components = core.air.components;
const runner = @import("../runner/mod.zig");
const machine = @import("../runner/machine.zig");
const scheduler = @import("scheduler.zig");
const scheduler_component = @import("scheduler_component.zig");
const memory_lookup = @import("cartridge_memory_lookup.zig");
const lookup = @import("scheduler_memory_lookup.zig");
const subject = @import("scheduler_memory_lookup_component.zig");

const LOG_SIZE: u32 = 4;
const SIZE: usize = 1 << LOG_SIZE;
const FIRST_COLUMN: usize = 2;
const LAST_COLUMN: usize = 4;
const SCHEDULER_OFFSET: usize = 5;
const MEMORY_OFFSET: usize =
    SCHEDULER_OFFSET + scheduler_component.N_MAIN_COLUMNS + 3;
const MAIN_COLUMNS: usize = MEMORY_OFFSET + lookup.N_MAIN_COLUMNS;
const INTERACTION_OFFSET: usize = 7;
const INTERACTION_COLUMNS: usize =
    INTERACTION_OFFSET + lookup.N_INTERACTION_COLUMNS;
const SCHEDULER_IE_OFFSET: usize = 2 + 9;
const SCHEDULER_MCYCLE_OFFSET: usize = 1;
const IE_SAMPLE_OFFSET: usize =
    @intFromEnum(lookup.SampleIndex.interrupt_enable) *
    lookup.N_SAMPLE_COLUMNS;
const IF_SAMPLE_OFFSET: usize =
    @intFromEnum(lookup.SampleIndex.interrupt_flags) *
    lookup.N_SAMPLE_COLUMNS;
const POST_IF_SAMPLE_OFFSET: usize =
    @intFromEnum(lookup.SampleIndex.post_interrupt_flags) *
    lookup.N_SAMPLE_COLUMNS;
const INITIAL_IE: u8 = 0xa5;
const INITIAL_IF: u8 = 0x92;
const BOUNDARY = lookup.Boundary{
    .initial_mcycle = 0,
    .final_mcycle = SIZE,
};

test "scheduler memory lookup has exact cubic L plus one geometry" {
    const scheduler_values =
        [_]Degree{Degree.variable()} **
        scheduler_component.N_MAIN_COLUMNS;
    const memory_values =
        [_]Degree{Degree.variable()} ** lookup.N_MAIN_COLUMNS;
    const evaluation = try lookup.evaluate(
        Degree,
        &scheduler_values,
        &memory_values,
        Degree.variable(),
        Degree.variable(),
        BOUNDARY,
    );
    var maximum: u32 = 0;
    for (evaluation.values) |constraint|
        maximum = @max(maximum, constraint.degree);
    try std.testing.expectEqual(
        lookup.MAX_CONSTRAINT_DEGREE,
        maximum,
    );

    const relation = memory_lookup.Relation.dummy();
    const component = makeComponent(
        &relation,
        .{ .samples = [_]QM31{QM31.zero()} ** lookup.N_SAMPLES },
        BOUNDARY,
    );
    try std.testing.expectEqual(
        lookup.N_CONSTRAINTS + lookup.N_SAMPLES,
        component.nConstraints(),
    );
    try std.testing.expectEqual(
        @as(u32, LOG_SIZE + 1),
        component.maxConstraintLogDegreeBound(),
    );
    _ = component.asVerifierComponent();
    _ = component.asProverComponent();

    var bounds =
        try component.traceLogDegreeBounds(std.testing.allocator);
    defer bounds.deinitDeep(std.testing.allocator);
    try expectShape(
        bounds.items,
        LAST_COLUMN + 1,
        MAIN_COLUMNS,
        INTERACTION_COLUMNS,
    );
    var mask = try component.maskPoints(
        std.testing.allocator,
        core.circle.SECURE_FIELD_CIRCLE_GEN,
        component.maxConstraintLogDegreeBound(),
    );
    defer mask.deinitDeep(std.testing.allocator);
    try expectShape(
        mask.items,
        LAST_COLUMN + 1,
        MAIN_COLUMNS,
        INTERACTION_COLUMNS,
    );
    for (mask.items[2]) |points|
        try std.testing.expectEqual(@as(usize, 2), points.len);
    const indices = try component.preprocessedColumnIndices(
        std.testing.allocator,
    );
    defer std.testing.allocator.free(indices);
    try std.testing.expectEqualSlices(
        usize,
        &.{ FIRST_COLUMN, LAST_COLUMN },
        indices,
    );

    var overlapping = component;
    overlapping.memory_offset = SCHEDULER_OFFSET + 1;
    try std.testing.expectError(
        error.OverlappingSchedulerMemoryColumns,
        overlapping.traceLogDegreeBounds(std.testing.allocator),
    );
    var wrapping = component;
    wrapping.boundary.final_mcycle =
        memory_lookup.memory_clock.MAX_FINAL_MCYCLE + 1;
    try std.testing.expectError(
        error.NonCanonicalSchedulerMemoryClock,
        wrapping.traceLogDegreeBounds(std.testing.allocator),
    );
}

test "scheduler memory direct rows reject clock value endpoint and vacuity" {
    const steps = try instructionSteps();
    const predecessors = stablePredecessors();
    for (steps, predecessors, 0..) |step, predecessor, row| {
        const scheduled = try scheduler_component.columns(
            try scheduler.ValidatedStep.init(step),
            @intCast(row),
        );
        const memory = try lookup.columns(
            try scheduler.ValidatedStep.init(step),
            @intCast(row),
            predecessor,
        );
        try std.testing.expect(
            (try lookup.evaluateM31(
                scheduled,
                memory,
                row == 0,
                row == SIZE - 1,
                BOUNDARY,
            )).allZero(),
        );
    }

    const first_scheduled = try scheduler_component.columns(
        try scheduler.ValidatedStep.init(steps[0]),
        0,
    );
    const first_memory = try lookup.columns(
        try scheduler.ValidatedStep.init(steps[0]),
        0,
        predecessors[0],
    );
    var action_predecessors = predecessors[0];
    const action_clock = try memory_lookup.memory_clock.phaseClock(
        0,
        memory_lookup.memory_clock.ACTION_PHASE,
    );
    action_predecessors.interrupt_enable.clock = action_clock;
    action_predecessors.interrupt_flags.clock = action_clock;
    const after_action = try lookup.columns(
        try scheduler.ValidatedStep.init(steps[0]),
        0,
        action_predecessors,
    );
    try std.testing.expect(
        (try lookup.evaluateM31(
            first_scheduled,
            after_action,
            true,
            false,
            BOUNDARY,
        )).allZero(),
    );
    var invalid_predecessor = predecessors[0];
    invalid_predecessor.interrupt_enable.clock = schedulerClock(0);
    try std.testing.expectError(
        error.InvalidSchedulerMemoryClock,
        lookup.columns(
            try scheduler.ValidatedStep.init(steps[0]),
            0,
            invalid_predecessor,
        ),
    );
    invalid_predecessor = predecessors[0];
    invalid_predecessor.interrupt_flags.value ^= 1;
    try std.testing.expectError(
        error.SchedulerMemoryReadMismatch,
        lookup.columns(
            try scheduler.ValidatedStep.init(steps[0]),
            0,
            invalid_predecessor,
        ),
    );
    invalid_predecessor = predecessors[0];
    invalid_predecessor.post_interrupt_flags.value ^= 1;
    try std.testing.expectError(
        error.SchedulerMemoryReadMismatch,
        lookup.columns(
            try scheduler.ValidatedStep.init(steps[0]),
            0,
            invalid_predecessor,
        ),
    );
    var forged_scheduler = first_scheduled;
    forged_scheduler[0] = M31.zero();
    try expectDirectRejected(
        forged_scheduler,
        first_memory,
        true,
        false,
        BOUNDARY,
    );
    var forged_memory = first_memory;
    forged_memory[IE_SAMPLE_OFFSET + lookup.PREVIOUS_CLOCK_OFFSET] =
        M31.one();
    try expectDirectRejected(
        first_scheduled,
        forged_memory,
        true,
        false,
        BOUNDARY,
    );
    var forged_boundary = BOUNDARY;
    forged_boundary.initial_mcycle += 1;
    try expectDirectRejected(
        first_scheduled,
        first_memory,
        true,
        false,
        forged_boundary,
    );
    const middle: usize = 5;
    const middle_scheduled = try scheduler_component.columns(
        try scheduler.ValidatedStep.init(steps[middle]),
        middle,
    );
    const middle_memory = try lookup.columns(
        try scheduler.ValidatedStep.init(steps[middle]),
        middle,
        predecessors[middle],
    );
    forged_memory = middle_memory;
    forged_memory[
        IF_SAMPLE_OFFSET + lookup.PREVIOUS_CLOCK_OFFSET
    ] = forged_memory[
        IF_SAMPLE_OFFSET + lookup.PREVIOUS_CLOCK_OFFSET
    ].add(M31.one());
    try expectDirectRejected(
        middle_scheduled,
        forged_memory,
        false,
        false,
        BOUNDARY,
    );
    forged_memory = middle_memory;
    forged_memory[
        POST_IF_SAMPLE_OFFSET + lookup.PREVIOUS_CLOCK_OFFSET
    ] = forged_memory[
        POST_IF_SAMPLE_OFFSET + lookup.PREVIOUS_CLOCK_OFFSET
    ].add(M31.one());
    try expectDirectRejected(
        middle_scheduled,
        forged_memory,
        false,
        false,
        BOUNDARY,
    );
    forged_memory = middle_memory;
    forged_memory[
        IE_SAMPLE_OFFSET + lookup.DIFFERENCE_BITS_OFFSET
    ] = flip(forged_memory[
        IE_SAMPLE_OFFSET + lookup.DIFFERENCE_BITS_OFFSET
    ]);
    try expectDirectRejected(
        middle_scheduled,
        forged_memory,
        false,
        false,
        BOUNDARY,
    );
    forged_scheduler = middle_scheduled;
    forged_scheduler[SCHEDULER_MCYCLE_OFFSET] =
        forged_scheduler[SCHEDULER_MCYCLE_OFFSET].add(M31.one());
    try expectDirectRejected(
        forged_scheduler,
        middle_memory,
        false,
        false,
        BOUNDARY,
    );

    const last = SIZE - 1;
    const last_scheduled = try scheduler_component.columns(
        try scheduler.ValidatedStep.init(steps[last]),
        last,
    );
    const last_memory = try lookup.columns(
        try scheduler.ValidatedStep.init(steps[last]),
        last,
        predecessors[last],
    );
    forged_boundary = BOUNDARY;
    forged_boundary.final_mcycle += 1;
    try expectDirectRejected(
        last_scheduled,
        last_memory,
        false,
        true,
        forged_boundary,
    );
}

test "scheduler memory claims cancel only complete ordered IE IF samples" {
    const relation = memory_lookup.Relation.dummy();
    const steps = try instructionSteps();
    const predecessors = stablePredecessors();
    var witness = try lookup.generateWitness(
        std.testing.allocator,
        &steps,
        BOUNDARY,
        &predecessors,
    );
    defer witness.deinit();
    try std.testing.expectEqual(
        lookup.RowSamples{
            .{
                .enabled = true,
                .previous_clock = 0,
                .value = INITIAL_IE,
                .clock = schedulerClock(0),
            },
            .{
                .enabled = true,
                .previous_clock = 0,
                .value = INITIAL_IF,
                .clock = schedulerClock(0),
            },
            .{
                .enabled = true,
                .previous_clock = schedulerClock(0),
                .value = INITIAL_IF,
                .clock = postClock(0),
            },
        },
        witness.samples[0],
    );
    var interaction = try lookup.generateInteraction(
        std.testing.allocator,
        witness.samples,
        witness.log_size,
        relation,
    );
    defer interaction.deinit();
    const memory_claims = try stableMemoryClaims(relation);
    try lookup.verifyCancellation(memory_claims, interaction.claims);

    var forged = try std.testing.allocator.dupe(
        lookup.RowSamples,
        witness.samples,
    );
    defer std.testing.allocator.free(forged);
    const first = forged[0][0];
    forged[0][0] = .{};
    try expectCancellationRejected(forged, relation, memory_claims);
    forged[0][0] = first;
    const honest = forged[5][0];
    forged[5][0] = .{};
    try expectCancellationRejected(forged, relation, memory_claims);
    forged[5][0] = honest;
    forged[5][0].value ^= 1;
    try expectCancellationRejected(forged, relation, memory_claims);
    forged[5][0] = honest;
    const honest_post = forged[5][2];
    forged[5][2].value ^= 1;
    try expectCancellationRejected(forged, relation, memory_claims);
    forged[5][2] = honest_post;
    forged[5][0].previous_clock -=
        memory_lookup.memory_clock.PHASES;
    try expectCancellationRejected(forged, relation, memory_claims);
    forged[5][0] = honest;
    for (forged) |*row|
        row.* = [_]lookup.Sample{.{}} ** lookup.N_SAMPLES;
    try expectCancellationRejected(forged, relation, memory_claims);

    var drifted_memory = memory_claims;
    drifted_memory.boundary =
        drifted_memory.boundary.add(QM31.one());
    try std.testing.expectError(
        error.SchedulerMemoryLookupSumNonZero,
        lookup.verifyCancellation(
            drifted_memory,
            interaction.claims,
        ),
    );
}

test "scheduler memory sampled OODS rejects values claims and recurrence" {
    const relation = memory_lookup.Relation.dummy();
    const steps = try instructionSteps();
    const predecessors = stablePredecessors();
    var witness = try lookup.generateWitness(
        std.testing.allocator,
        &steps,
        BOUNDARY,
        &predecessors,
    );
    defer witness.deinit();
    var interaction = try lookup.generateInteraction(
        std.testing.allocator,
        witness.samples,
        witness.log_size,
        relation,
    );
    defer interaction.deinit();
    var component = makeComponent(
        &relation,
        interaction.claims,
        BOUNDARY,
    );
    var point = try sampledFixture(
        steps,
        predecessors,
        interaction,
        1,
    );
    try expectSampled(&component, &point, true);

    point.main_values[
        MEMORY_OFFSET + IE_SAMPLE_OFFSET +
            lookup.PREVIOUS_CLOCK_OFFSET
    ][0] = point.main_values[
        MEMORY_OFFSET + IE_SAMPLE_OFFSET +
            lookup.PREVIOUS_CLOCK_OFFSET
    ][0].add(QM31.one());
    try expectSampled(&component, &point, false);
    point = try sampledFixture(
        steps,
        predecessors,
        interaction,
        1,
    );
    point.main_values[
        SCHEDULER_OFFSET + SCHEDULER_IE_OFFSET
    ][0] = flipQ(point.main_values[
        SCHEDULER_OFFSET + SCHEDULER_IE_OFFSET
    ][0]);
    try expectSampled(&component, &point, false);
    point = try sampledFixture(
        steps,
        predecessors,
        interaction,
        1,
    );
    point.interaction_values[INTERACTION_OFFSET][0] =
        point.interaction_values[INTERACTION_OFFSET][0]
            .add(QM31.one());
    try expectSampled(&component, &point, false);
    point = try sampledFixture(
        steps,
        predecessors,
        interaction,
        1,
    );
    point.preprocessed_values[FIRST_COLUMN][0] = QM31.one();
    try expectSampled(&component, &point, false);

    point = try sampledFixture(
        steps,
        predecessors,
        interaction,
        0,
    );
    try expectSampled(&component, &point, true);
    component.claims.samples[0] =
        component.claims.samples[0].add(QM31.one());
    try expectSampled(&component, &point, false);
}

const SampledFixture = struct {
    preprocessed_values: [LAST_COLUMN + 1][1]QM31,
    main_values: [MAIN_COLUMNS][1]QM31,
    interaction_values: [INTERACTION_COLUMNS][2]QM31,
};

fn sampledFixture(
    steps: [SIZE]machine.StepResult,
    predecessors: [SIZE]lookup.Predecessors,
    interaction: lookup.Interaction,
    row: usize,
) !SampledFixture {
    var result = SampledFixture{
        .preprocessed_values = [_][1]QM31{.{QM31.zero()}} ** (LAST_COLUMN + 1),
        .main_values = [_][1]QM31{.{QM31.zero()}} ** MAIN_COLUMNS,
        .interaction_values = [_][2]QM31{.{ QM31.zero(), QM31.zero() }} **
            INTERACTION_COLUMNS,
    };
    result.preprocessed_values[FIRST_COLUMN][0] =
        if (row == 0) QM31.one() else QM31.zero();
    result.preprocessed_values[LAST_COLUMN][0] =
        if (row == SIZE - 1) QM31.one() else QM31.zero();
    const scheduled = try scheduler_component.columns(
        try scheduler.ValidatedStep.init(steps[row]),
        @intCast(row),
    );
    const memory = try lookup.columns(
        try scheduler.ValidatedStep.init(steps[row]),
        @intCast(row),
        predecessors[row],
    );
    fillPointConstants(
        result.main_values[SCHEDULER_OFFSET..][0..scheduler_component.N_MAIN_COLUMNS],
        &scheduled,
    );
    fillPointConstants(
        result.main_values[MEMORY_OFFSET..][0..lookup.N_MAIN_COLUMNS],
        &memory,
    );
    const current_storage =
        try air_utils.circleBitReversedIndex(LOG_SIZE, row);
    const previous_row = if (row == 0) SIZE - 1 else row - 1;
    const previous_storage =
        try air_utils.circleBitReversedIndex(LOG_SIZE, previous_row);
    for (0..lookup.N_SAMPLES) |sample_index| {
        const source =
            interaction.columns[4 * sample_index ..][0..4];
        const current = readSecure(source, current_storage);
        const previous = readSecure(source, previous_storage);
        const coordinates = current.toM31Array();
        const previous_coordinates = previous.toM31Array();
        for (0..4) |coordinate| {
            result.interaction_values[
                INTERACTION_OFFSET + 4 * sample_index + coordinate
            ] = .{
                QM31.fromBase(coordinates[coordinate]),
                QM31.fromBase(previous_coordinates[coordinate]),
            };
        }
    }
    return result;
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

    var trees = [_][][]QM31{
        &preprocessed,
        &main,
        &interaction,
    };
    const mask = core_air_components.MaskValues.initOwned(&trees);
    var accumulator =
        core_air_accumulation.PointEvaluationAccumulator.init(
            QM31.one(),
        );
    try component.evaluateConstraintQuotientsAtPoint(
        core.circle.SECURE_FIELD_CIRCLE_GEN.mul(29),
        &mask,
        &accumulator,
        component.maxConstraintLogDegreeBound(),
    );
    try std.testing.expectEqual(
        expected,
        accumulator.finalize().isZero(),
    );
}

fn instructionSteps() ![SIZE]machine.StepResult {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    @memset(memory.bytes[0..SIZE], 0);
    memory.write(0xffff, INITIAL_IE);
    memory.write(0xff0f, INITIAL_IF);
    var scheduler_machine = machine.Machine.init(&memory, .{});
    var steps: [SIZE]machine.StepResult = undefined;
    for (&steps) |*step| step.* = try scheduler_machine.step();
    return steps;
}

fn stablePredecessors() [SIZE]lookup.Predecessors {
    var result = [_]lookup.Predecessors{.{}} ** SIZE;
    for (&result, 0..) |*row, index| {
        row.* = .{
            .interrupt_enable = .{
                .clock = if (index == 0)
                    0
                else
                    schedulerClock(index - 1),
                .value = INITIAL_IE,
            },
            .interrupt_flags = .{
                .clock = if (index == 0)
                    0
                else
                    postClock(index - 1),
                .value = INITIAL_IF,
            },
            .post_interrupt_flags = .{
                .clock = schedulerClock(index),
                .value = INITIAL_IF,
            },
        };
    }
    return result;
}

fn stableMemoryClaims(
    relation: memory_lookup.Relation,
) !memory_lookup.Claims {
    var boundary = QM31.zero();
    for ([_]memory_lookup.BoundaryEntry{
        .{
            .enabled = true,
            .address = 0xffff,
            .initial_value = INITIAL_IE,
            .final_clock = schedulerClock(SIZE - 1),
            .final_value = INITIAL_IE,
        },
        .{
            .enabled = true,
            .address = 0xff0f,
            .initial_value = INITIAL_IF,
            .final_clock = postClock(SIZE - 1),
            .final_value = INITIAL_IF,
        },
    }) |entry| {
        boundary = boundary.add(try pairIncrement(
            try memory_lookup.boundaryPairForRow(
                entry.address,
                entry,
                relation,
            ),
        ));
    }
    return .{
        .execution = [_]QM31{QM31.zero()} **
            memory_lookup.N_EXECUTION_SUMS,
        .boundary = boundary,
    };
}

fn schedulerClock(mcycle: usize) u32 {
    return memory_lookup.memory_clock.phaseClock(
        @intCast(mcycle),
        lookup.SCHEDULER_PHASE,
    ) catch unreachable;
}

fn postClock(mcycle: usize) u32 {
    return memory_lookup.memory_clock.phaseClock(
        @intCast(mcycle),
        lookup.OBSERVATION_PHASE,
    ) catch unreachable;
}

fn expectCancellationRejected(
    samples: []const lookup.RowSamples,
    relation: memory_lookup.Relation,
    memory_claims: memory_lookup.Claims,
) !void {
    var interaction = try lookup.generateInteraction(
        std.testing.allocator,
        samples,
        LOG_SIZE,
        relation,
    );
    defer interaction.deinit();
    try std.testing.expectError(
        error.SchedulerMemoryLookupSumNonZero,
        lookup.verifyCancellation(
            memory_claims,
            interaction.claims,
        ),
    );
}

fn pairIncrement(pair: memory_lookup.RowPair) !QM31 {
    if (pair.n1.isZero() and pair.n2.isZero())
        return QM31.zero();
    const denominator = pair.d1.mul(pair.d2);
    const numerator =
        pair.n1.mul(pair.d2).add(pair.n2.mul(pair.d1));
    return numerator.mul(try denominator.inv());
}

fn makeComponent(
    relation: *const memory_lookup.Relation,
    claims: lookup.Claims,
    boundary: lookup.Boundary,
) subject.Component {
    return .{
        .log_size = LOG_SIZE,
        .is_first_column = FIRST_COLUMN,
        .is_last_column = LAST_COLUMN,
        .scheduler_offset = SCHEDULER_OFFSET,
        .memory_offset = MEMORY_OFFSET,
        .interaction_offset = INTERACTION_OFFSET,
        .relation = relation,
        .claims = claims,
        .boundary = boundary,
    };
}

fn expectDirectRejected(
    scheduled: [scheduler_component.N_MAIN_COLUMNS]M31,
    memory: [lookup.N_MAIN_COLUMNS]M31,
    is_first: bool,
    is_last: bool,
    boundary: lookup.Boundary,
) !void {
    try std.testing.expect(
        !(try lookup.evaluateM31(
            scheduled,
            memory,
            is_first,
            is_last,
            boundary,
        )).allZero(),
    );
}

fn expectShape(
    items: anytype,
    preprocessed: usize,
    main: usize,
    interaction: usize,
) !void {
    try std.testing.expectEqual(@as(usize, 3), items.len);
    try std.testing.expectEqual(preprocessed, items[0].len);
    try std.testing.expectEqual(main, items[1].len);
    try std.testing.expectEqual(interaction, items[2].len);
}

fn readSecure(columns: []const []M31, row: usize) QM31 {
    return QM31.fromM31(
        columns[0][row],
        columns[1][row],
        columns[2][row],
        columns[3][row],
    );
}

fn pointSlices(output: anytype, values: anytype) void {
    for (output, values) |*column, *source| column.* = source;
}

fn fillPointConstants(destinations: anytype, values: []const M31) void {
    for (destinations, values) |*destination, value|
        destination[0] = QM31.fromBase(value);
}

fn allZero(values: []const QM31) bool {
    for (values) |value|
        if (!value.isZero()) return false;
    return true;
}

fn flip(value: M31) M31 {
    return if (value.isZero()) M31.one() else M31.zero();
}

fn flipQ(value: QM31) QM31 {
    return if (value.isZero()) QM31.one() else QM31.zero();
}

const Degree = struct {
    degree: u32,

    fn variable() Degree {
        return .{ .degree = 1 };
    }

    pub fn zero() Degree {
        return .{ .degree = 0 };
    }

    pub fn one() Degree {
        return .{ .degree = 0 };
    }

    pub fn fromBase(_: M31) Degree {
        return .{ .degree = 0 };
    }

    pub fn add(left: Degree, right: Degree) Degree {
        return .{ .degree = @max(left.degree, right.degree) };
    }

    pub fn sub(left: Degree, right: Degree) Degree {
        return left.add(right);
    }

    pub fn mul(left: Degree, right: Degree) Degree {
        return .{ .degree = left.degree + right.degree };
    }

    pub fn isZero(_: Degree) bool {
        return false;
    }
};
