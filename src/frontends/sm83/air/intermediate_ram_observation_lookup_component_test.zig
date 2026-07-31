const std = @import("std");
const core_air_accumulation = @import("stwo_core").air.accumulation;
const core_air_components = @import("stwo_core").air.components;
const TreeVec = @import("stwo_core").pcs.TreeVec;
const circle = @import("stwo_core").circle;
const utils = @import("stwo_core").utils;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const prover_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const lookup = @import("intermediate_ram_observation_lookup.zig");
const memory_lookup = @import("cartridge_memory_lookup.zig");
const subject =
    @import("intermediate_ram_observation_lookup_component.zig");

const LOG_SIZE: u32 = 4;
const EVALUATION_LOG_SIZE: u32 = LOG_SIZE + 1;
const EVALUATION_SIZE: usize = 1 << EVALUATION_LOG_SIZE;
const FIRST_COLUMN: usize = 2;
const ACTIVE_COLUMN: usize = 4;
const MCYCLE_COLUMN: usize = 6;
const KEY_COLUMN: usize = 8;
const VALUE_COLUMN: usize = 10;
const PREDECESSOR_OFFSET: usize = 3;
const MAIN_COLUMNS: usize =
    PREDECESSOR_OFFSET + lookup.N_MAIN_COLUMNS;
const INTERACTION_OFFSET: usize = 7;
const INTERACTION_COLUMNS: usize =
    INTERACTION_OFFSET + lookup.N_INTERACTION_COLUMNS;
const PREPROCESSED_COLUMNS: usize = VALUE_COLUMN + 1;

test "observation component is exactly cubic L plus one and offset safe" {
    const relation_values = lookup.RelationValues(Degree){
        .z = Degree.zero(),
        .clock_coefficient = Degree.zero(),
        .value_coefficient = Degree.zero(),
    };
    const predecessor_values =
        [_]Degree{Degree.variable()} ** lookup.N_MAIN_COLUMNS;
    const evaluation = lookup.evaluateRows(
        Degree,
        .{
            Degree.variable(),
            Degree.variable(),
            Degree.variable(),
            Degree.variable(),
        },
        try lookup.Row(Degree).fromColumns(&predecessor_values),
        Degree.variable(),
        Degree.variable(),
        Degree.variable(),
        Degree.zero(),
        relation_values,
    );
    var maximum: u32 = 0;
    for (evaluation.values) |constraint|
        maximum = @max(maximum, constraint.degree);
    try std.testing.expectEqual(lookup.MAX_CONSTRAINT_DEGREE, maximum);

    const fixture = try makeFixture();
    const component = makeComponent(
        &fixture.relation,
        &fixture.schedule_claim,
        fixture.increment,
    );
    try std.testing.expectEqual(
        lookup.N_CONSTRAINTS,
        component.nConstraints(),
    );
    try std.testing.expectEqual(
        @as(u32, LOG_SIZE + 1),
        component.maxConstraintLogDegreeBound(),
    );
    _ = component.asVerifierComponent();
    _ = component.asProverComponent();

    var bounds = try component.traceLogDegreeBounds(
        std.testing.allocator,
    );
    defer bounds.deinitDeep(std.testing.allocator);
    try expectShape(
        bounds.items,
        PREPROCESSED_COLUMNS,
        MAIN_COLUMNS,
        INTERACTION_COLUMNS,
    );
    var mask = try component.maskPoints(
        std.testing.allocator,
        circle.SECURE_FIELD_CIRCLE_GEN,
        LOG_SIZE + 1,
    );
    defer mask.deinitDeep(std.testing.allocator);
    try expectShape(
        mask.items,
        PREPROCESSED_COLUMNS,
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
        &.{
            FIRST_COLUMN,
            ACTIVE_COLUMN,
            MCYCLE_COLUMN,
            KEY_COLUMN,
            VALUE_COLUMN,
        },
        indices,
    );

    var empty_claim = fixture.schedule_claim;
    empty_claim.count = 0;
    const invalid = makeComponent(
        &fixture.relation,
        &empty_claim,
        QM31.zero(),
    );
    try std.testing.expectError(
        error.EmptyObservationSchedule,
        invalid.traceLogDegreeBounds(std.testing.allocator),
    );
}

test "sampled observation component rejects omission substitution and vacuity" {
    const fixture = try makeFixture();
    var component = makeComponent(
        &fixture.relation,
        &fixture.schedule_claim,
        fixture.increment,
    );
    var preprocessed_values =
        [_][1]QM31{.{QM31.zero()}} ** PREPROCESSED_COLUMNS;
    preprocessed_values[FIRST_COLUMN][0] = QM31.one();
    fillPublicPoint(&preprocessed_values, fixture.sample);
    var preprocessed: [PREPROCESSED_COLUMNS][]QM31 = undefined;
    pointSlices(&preprocessed, &preprocessed_values);
    var main_values =
        [_][1]QM31{.{QM31.zero()}} ** MAIN_COLUMNS;
    fillPointConstants(
        main_values[PREDECESSOR_OFFSET..][0..lookup.N_MAIN_COLUMNS],
        &fixture.predecessor,
    );
    var main: [MAIN_COLUMNS][]QM31 = undefined;
    pointSlices(&main, &main_values);
    var interaction_values =
        [_][2]QM31{.{ QM31.zero(), QM31.zero() }} **
        INTERACTION_COLUMNS;
    var interaction: [INTERACTION_COLUMNS][]QM31 = undefined;
    pointSlices(&interaction, &interaction_values);
    var constraints: [lookup.N_CONSTRAINTS]QM31 = undefined;
    try component.evaluateSampled(
        &preprocessed,
        &main,
        &interaction,
        &constraints,
    );
    try std.testing.expect(allZero(&constraints));

    var trees = [_][][]QM31{
        &preprocessed,
        &main,
        &interaction,
    };
    const mask = core_air_components.MaskValues.initOwned(&trees);
    const point = circle.SECURE_FIELD_CIRCLE_GEN.mul(29);
    var honest =
        core_air_accumulation.PointEvaluationAccumulator.init(
            QM31.one(),
        );
    try component.evaluateConstraintQuotientsAtPoint(
        point,
        &mask,
        &honest,
        component.maxConstraintLogDegreeBound(),
    );
    try std.testing.expect(honest.finalize().isZero());

    preprocessed_values[VALUE_COLUMN][0] =
        preprocessed_values[VALUE_COLUMN][0].add(QM31.one());
    try expectSampledNonzero(
        &component,
        &preprocessed,
        &main,
        &interaction,
    );
    preprocessed_values[VALUE_COLUMN][0] =
        q(fixture.sample.expected);
    preprocessed_values[KEY_COLUMN][0] =
        preprocessed_values[KEY_COLUMN][0].add(QM31.one());
    try expectSampledNonzero(
        &component,
        &preprocessed,
        &main,
        &interaction,
    );
    preprocessed_values[KEY_COLUMN][0] = q(fixture.sample.key);
    preprocessed_values[MCYCLE_COLUMN][0] =
        preprocessed_values[MCYCLE_COLUMN][0].add(QM31.one());
    try expectSampledNonzero(
        &component,
        &preprocessed,
        &main,
        &interaction,
    );
    preprocessed_values[MCYCLE_COLUMN][0] =
        q(fixture.sample.mcycle);

    preprocessed_values[ACTIVE_COLUMN][0] = QM31.zero();
    preprocessed_values[MCYCLE_COLUMN][0] = QM31.zero();
    preprocessed_values[KEY_COLUMN][0] = QM31.zero();
    preprocessed_values[VALUE_COLUMN][0] = QM31.zero();
    try expectSampledNonzero(
        &component,
        &preprocessed,
        &main,
        &interaction,
    );
    fillPublicPoint(&preprocessed_values, fixture.sample);

    main_values[
        PREDECESSOR_OFFSET + lookup.PREVIOUS_CLOCK_OFFSET
    ][0] = main_values[
        PREDECESSOR_OFFSET + lookup.PREVIOUS_CLOCK_OFFSET
    ][0].add(QM31.one());
    try expectSampledNonzero(
        &component,
        &preprocessed,
        &main,
        &interaction,
    );
    main_values[
        PREDECESSOR_OFFSET + lookup.PREVIOUS_CLOCK_OFFSET
    ][0] = QM31.fromBase(
        fixture.predecessor[lookup.PREVIOUS_CLOCK_OFFSET],
    );
    main_values[
        PREDECESSOR_OFFSET + lookup.DIFFERENCE_BITS_OFFSET
    ][0] = main_values[
        PREDECESSOR_OFFSET + lookup.DIFFERENCE_BITS_OFFSET
    ][0].sub(QM31.one());
    try expectSampledNonzero(
        &component,
        &preprocessed,
        &main,
        &interaction,
    );

    component.claim = component.claim.add(QM31.one());
    try expectSampledNonzero(
        &component,
        &preprocessed,
        &main,
        &interaction,
    );
}

test "observation prover domain rejects omission substitution claim and vacuity" {
    const fixture = try makeFixture();
    var component = makeComponent(
        &fixture.relation,
        &fixture.schedule_claim,
        QM31.zero(),
    );
    var preprocessed_values =
        [_][EVALUATION_SIZE]M31{
            [_]M31{M31.zero()} ** EVALUATION_SIZE,
        } ** PREPROCESSED_COLUMNS;
    fillPublicDomain(&preprocessed_values, fixture.sample);
    var main_values =
        [_][EVALUATION_SIZE]M31{
            [_]M31{M31.zero()} ** EVALUATION_SIZE,
        } ** MAIN_COLUMNS;
    fillDomainConstants(
        main_values[PREDECESSOR_OFFSET..][0..lookup.N_MAIN_COLUMNS],
        &fixture.predecessor,
    );
    var interaction_values =
        [_][EVALUATION_SIZE]M31{
            [_]M31{M31.zero()} ** EVALUATION_SIZE,
        } ** INTERACTION_COLUMNS;
    const cycle_size = try writeAccumulatorCycle(
        &preprocessed_values[FIRST_COLUMN],
        interaction_values[INTERACTION_OFFSET..][0..4],
        fixture.increment,
    );
    component.claim = fixture.increment.mul(q(cycle_size));

    var preprocessed: [PREPROCESSED_COLUMNS]prover_component.Poly =
        undefined;
    domainPolys(&preprocessed, &preprocessed_values);
    var main: [MAIN_COLUMNS]prover_component.Poly = undefined;
    domainPolys(&main, &main_values);
    var interaction: [INTERACTION_COLUMNS]prover_component.Poly =
        undefined;
    domainPolys(&interaction, &interaction_values);
    var trees = [_][]const prover_component.Poly{
        &preprocessed,
        &main,
        &interaction,
    };
    const trace = prover_component.Trace{
        .polys = TreeVec([]const prover_component.Poly).initOwned(
            &trees,
        ),
    };
    const challenge = QM31.fromU32Unchecked(3, 5, 7, 11);
    try expectDomainZero(&component, &trace, challenge, true);

    @memset(
        &preprocessed_values[VALUE_COLUMN],
        M31.fromCanonical(fixture.sample.expected ^ 1),
    );
    try expectDomainZero(&component, &trace, challenge, false);
    @memset(
        &preprocessed_values[VALUE_COLUMN],
        M31.fromCanonical(fixture.sample.expected),
    );
    @memset(&preprocessed_values[ACTIVE_COLUMN], M31.zero());
    @memset(&preprocessed_values[MCYCLE_COLUMN], M31.zero());
    @memset(&preprocessed_values[KEY_COLUMN], M31.zero());
    @memset(&preprocessed_values[VALUE_COLUMN], M31.zero());
    try expectDomainZero(&component, &trace, challenge, false);
    fillPublicDomain(&preprocessed_values, fixture.sample);

    main_values[
        PREDECESSOR_OFFSET + lookup.DIFFERENCE_BITS_OFFSET
    ][0] = main_values[
        PREDECESSOR_OFFSET + lookup.DIFFERENCE_BITS_OFFSET
    ][0].add(M31.one());
    try expectDomainZero(&component, &trace, challenge, false);
    main_values[
        PREDECESSOR_OFFSET + lookup.DIFFERENCE_BITS_OFFSET
    ][0] = fixture.predecessor[lookup.DIFFERENCE_BITS_OFFSET];

    component.claim = component.claim.add(QM31.one());
    try expectDomainZero(&component, &trace, challenge, false);
}

const Fixture = struct {
    sample: lookup.Sample,
    schedule_claim: lookup.ScheduleClaim,
    predecessor: [lookup.N_MAIN_COLUMNS]M31,
    relation: memory_lookup.Relation,
    increment: QM31,
};

fn makeFixture() !Fixture {
    const observation = lookup.Sample{
        .mcycle = 5,
        .key = 0xc000,
        .expected = 0x42,
    };
    const relation = memory_lookup.Relation.dummy();
    var witness = try lookup.generateWitness(
        std.testing.allocator,
        LOG_SIZE,
        &.{observation},
        &.{.{ .clock = 2 }},
    );
    defer witness.deinit();
    const storage =
        @import("stwo_core").air.utils.circleBitReversedIndex(
            LOG_SIZE,
            0,
        ) catch unreachable;
    var predecessor: [lookup.N_MAIN_COLUMNS]M31 = undefined;
    for (&predecessor, witness.main) |*target, column|
        target.* = column[storage];
    const access = witness.accesses[0];
    return .{
        .sample = observation,
        .schedule_claim = try lookup.scheduleClaim(&.{observation}),
        .predecessor = predecessor,
        .relation = relation,
        .increment = try lookup.accumulate(
            QM31.zero(),
            try lookup.pair(access, relation),
        ),
    };
}

fn makeComponent(
    relation: *const memory_lookup.Relation,
    schedule_claim: *const lookup.ScheduleClaim,
    claim: QM31,
) subject.Component {
    return .{
        .log_size = LOG_SIZE,
        .is_first_column = FIRST_COLUMN,
        .public_active_column = ACTIVE_COLUMN,
        .public_mcycle_column = MCYCLE_COLUMN,
        .public_key_column = KEY_COLUMN,
        .public_value_column = VALUE_COLUMN,
        .predecessor_offset = PREDECESSOR_OFFSET,
        .interaction_offset = INTERACTION_OFFSET,
        .relation = relation,
        .schedule_claim = schedule_claim,
        .claim = claim,
    };
}

fn fillPublicPoint(
    values: anytype,
    sample: lookup.Sample,
) void {
    values[ACTIVE_COLUMN][0] = QM31.one();
    values[MCYCLE_COLUMN][0] = q(sample.mcycle);
    values[KEY_COLUMN][0] = q(sample.key);
    values[VALUE_COLUMN][0] = q(sample.expected);
}

fn fillPublicDomain(
    values: anytype,
    sample: lookup.Sample,
) void {
    @memset(&values[ACTIVE_COLUMN], M31.one());
    @memset(
        &values[MCYCLE_COLUMN],
        M31.fromCanonical(sample.mcycle),
    );
    @memset(
        &values[KEY_COLUMN],
        M31.fromCanonical(sample.key),
    );
    @memset(
        &values[VALUE_COLUMN],
        M31.fromCanonical(sample.expected),
    );
}

fn expectSampledNonzero(
    component: *const subject.Component,
    preprocessed: [][]QM31,
    main: [][]QM31,
    interaction: [][]QM31,
) !void {
    var constraints: [lookup.N_CONSTRAINTS]QM31 = undefined;
    try component.evaluateSampled(
        preprocessed,
        main,
        interaction,
        &constraints,
    );
    try std.testing.expect(!allZero(&constraints));
}

fn writeAccumulatorCycle(
    first: *[EVALUATION_SIZE]M31,
    columns: [][EVALUATION_SIZE]M31,
    increment: QM31,
) !usize {
    var next: [EVALUATION_SIZE]usize = undefined;
    for (0..EVALUATION_SIZE) |row| {
        const previous = utils.previousBitReversedCircleDomainIndex(
            row,
            LOG_SIZE,
            EVALUATION_LOG_SIZE,
        );
        next[previous] = row;
    }
    var visited = [_]bool{false} ** EVALUATION_SIZE;
    var values = [_]QM31{QM31.zero()} ** EVALUATION_SIZE;
    var cycle_size: usize = 0;
    for (0..EVALUATION_SIZE) |start| {
        if (visited[start]) continue;
        first[start] = M31.one();
        visited[start] = true;
        var current = start;
        var length: usize = 1;
        while (next[current] != start) {
            const following = next[current];
            values[following] = values[current].add(increment);
            visited[following] = true;
            current = following;
            length += 1;
        }
        if (cycle_size == 0)
            cycle_size = length
        else
            try std.testing.expectEqual(cycle_size, length);
    }
    for (columns, 0..) |*column, coordinate| {
        for (column, values) |*target, value|
            target.* = value.toM31Array()[coordinate];
    }
    return cycle_size;
}

fn expectDomainZero(
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
    try component.evaluateConstraintQuotientsOnDomain(
        trace,
        &accumulator,
    );
    var result = try accumulator.finalize();
    defer result.deinit(std.testing.allocator);
    var zero = true;
    for (0..result.len()) |index|
        zero = zero and result.at(index).isZero();
    try std.testing.expectEqual(expected, zero);
}

fn domainPolys(output: anytype, values: anytype) void {
    for (output, values) |*polynomial, *source|
        polynomial.* = .{
            .log_size = EVALUATION_LOG_SIZE,
            .values = source,
        };
}

fn pointSlices(output: anytype, values: anytype) void {
    for (output, values) |*column, *source| column.* = source;
}

fn fillPointConstants(destinations: anytype, values: []const M31) void {
    for (destinations, values) |*destination, value|
        destination[0] = QM31.fromBase(value);
}

fn fillDomainConstants(destinations: anytype, values: []const M31) void {
    for (destinations, values) |*destination, value|
        @memset(destination, value);
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

fn allZero(values: []const QM31) bool {
    for (values) |value|
        if (!value.isZero()) return false;
    return true;
}

fn q(value: anytype) QM31 {
    return QM31.fromBase(M31.fromU64(@intCast(value)));
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
    pub fn neg(value: Degree) Degree {
        return value;
    }
    pub fn isZero(_: Degree) bool {
        return false;
    }
};
