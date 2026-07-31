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
const timer_air = @import("timer.zig");
const timer_binding = @import("timer_binding.zig");
const timer_component = @import("timer_component.zig");
const lookup = @import("timer_if_memory_lookup.zig");
const memory_lookup = @import("cartridge_memory_lookup.zig");
const subject = @import("timer_if_memory_lookup_component.zig");

const LOG_SIZE: u32 = 4;
const EVALUATION_LOG_SIZE: u32 = LOG_SIZE + 1;
const EVALUATION_SIZE: usize = 1 << EVALUATION_LOG_SIZE;
const FIRST_COLUMN: usize = 2;
const BINDING_OFFSET: usize = 5;
const PREDECESSOR_OFFSET: usize =
    BINDING_OFFSET + timer_binding.N_MAIN_COLUMNS + 3;
const MAIN_COLUMNS: usize =
    PREDECESSOR_OFFSET + lookup.N_MAIN_COLUMNS;
const INTERACTION_OFFSET: usize = 7;
const INTERACTION_COLUMNS: usize =
    INTERACTION_OFFSET + lookup.N_INTERACTION_COLUMNS;
const REQUEST_COLUMN: usize = 1 + timer_air.INTERRUPT_COLUMN;

test "timer IF adapter owns cubic offset-safe geometry" {
    const binding_variables =
        [_]Degree{Degree.variable()} ** timer_binding.N_MAIN_COLUMNS;
    const predecessor_variables =
        [_]Degree{Degree.variable()} ** lookup.N_MAIN_COLUMNS;
    const timer = try lookup.TimerRow(Degree).fromColumns(
        &binding_variables,
    );
    const predecessor = try lookup.Row(Degree).fromColumns(
        &predecessor_variables,
    );
    const semantic = lookup.evaluate(Degree, timer, predecessor);
    var semantic_maximum: u32 = 0;
    for (semantic.values) |constraint|
        semantic_maximum = @max(semantic_maximum, constraint.degree);
    try std.testing.expectEqual(@as(u32, 2), semantic_maximum);
    const recurrence = subject.recurrenceConstraint(
        Degree,
        Degree.variable(),
        Degree.variable(),
        Degree.variable(),
        Degree.zero(),
        Degree.variable(),
        Degree.variable(),
        Degree.variable(),
        Degree.variable(),
    );
    try std.testing.expectEqual(
        subject.MAX_CONSTRAINT_DEGREE,
        recurrence.degree,
    );

    const relation = memory_lookup.Relation.dummy();
    const component = makeComponent(&relation, QM31.zero());
    try std.testing.expectEqual(
        lookup.N_CONSTRAINTS + 1,
        component.nConstraints(),
    );
    try std.testing.expectEqual(
        @as(u32, 3),
        subject.MAX_CONSTRAINT_DEGREE,
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
        FIRST_COLUMN + 1,
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
        FIRST_COLUMN + 1,
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
        &.{FIRST_COLUMN},
        indices,
    );

    var invalid = component;
    invalid.log_size = 3;
    try std.testing.expectError(
        error.InvalidTimerLogSize,
        invalid.traceLogDegreeBounds(std.testing.allocator),
    );
}

test "timer IF sampled OODS rejects request clock value and claim drift" {
    const relation = memory_lookup.Relation.dummy();
    const fixture = try honestFixture(relation);
    var component = makeComponent(&relation, fixture.increment);
    var preprocessed_values =
        [_][1]QM31{.{QM31.zero()}} ** (FIRST_COLUMN + 1);
    preprocessed_values[FIRST_COLUMN][0] = QM31.one();
    var preprocessed: [FIRST_COLUMN + 1][]QM31 = undefined;
    pointSlices(&preprocessed, &preprocessed_values);
    var main_values =
        [_][1]QM31{.{QM31.zero()}} ** MAIN_COLUMNS;
    fillPointConstants(
        main_values[BINDING_OFFSET..][0..timer_binding.N_MAIN_COLUMNS],
        &fixture.binding,
    );
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
    var constraints: [subject.N_CONSTRAINTS]QM31 = undefined;
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
    var honest_oods =
        core_air_accumulation.PointEvaluationAccumulator.init(QM31.one());
    try component.evaluateConstraintQuotientsAtPoint(
        point,
        &mask,
        &honest_oods,
        component.maxConstraintLogDegreeBound(),
    );
    try std.testing.expect(honest_oods.finalize().isZero());

    component.claim = component.claim.add(QM31.one());
    try component.evaluateSampled(
        &preprocessed,
        &main,
        &interaction,
        &constraints,
    );
    try std.testing.expect(!allZero(&constraints));
    var forged_oods =
        core_air_accumulation.PointEvaluationAccumulator.init(QM31.one());
    try component.evaluateConstraintQuotientsAtPoint(
        point,
        &mask,
        &forged_oods,
        component.maxConstraintLogDegreeBound(),
    );
    try std.testing.expect(!forged_oods.finalize().isZero());
    component.claim = fixture.increment;

    main_values[BINDING_OFFSET + REQUEST_COLUMN][0] = QM31.zero();
    try component.evaluateSampled(
        &preprocessed,
        &main,
        &interaction,
        &constraints,
    );
    try std.testing.expect(!allZero(&constraints));
    main_values[BINDING_OFFSET + REQUEST_COLUMN][0] = QM31.one();

    main_values[BINDING_OFFSET + timer_binding.MCYCLE_OFFSET][0] =
        QM31.fromBase(M31.fromCanonical(8));
    try component.evaluateSampled(
        &preprocessed,
        &main,
        &interaction,
        &constraints,
    );
    try std.testing.expect(!allZero(&constraints));
    main_values[BINDING_OFFSET + timer_binding.MCYCLE_OFFSET][0] =
        QM31.fromBase(M31.fromCanonical(7));

    main_values[
        PREDECESSOR_OFFSET + lookup.PREVIOUS_CLOCK_OFFSET
    ][0] = QM31.fromBase(M31.fromCanonical(4));
    try component.evaluateSampled(
        &preprocessed,
        &main,
        &interaction,
        &constraints,
    );
    try std.testing.expect(!allZero(&constraints));
    main_values[
        PREDECESSOR_OFFSET + lookup.PREVIOUS_CLOCK_OFFSET
    ][0] = QM31.fromBase(M31.fromCanonical(3));

    main_values[
        PREDECESSOR_OFFSET + lookup.PREVIOUS_VALUE_OFFSET
    ][0] = QM31.zero();
    try component.evaluateSampled(
        &preprocessed,
        &main,
        &interaction,
        &constraints,
    );
    try std.testing.expect(!allZero(&constraints));
}

test "timer IF component preserves every predecessor byte while setting bit 2" {
    const relation = memory_lookup.Relation.dummy();
    const event = requestingEvent(7);
    const binding_base = bindingColumns(event);
    var binding: [timer_binding.N_MAIN_COLUMNS]QM31 = undefined;
    lift(&binding, &binding_base);
    for (0..256) |value| {
        const access = try lookup.accessForEvent(
            event,
            .{
                .clock = 3,
                .value = @intCast(value),
            },
        );
        try std.testing.expectEqual(
            @as(u8, @intCast(value)) |
                @import("../runner/timer.zig").TIMER_INTERRUPT,
            access.next_value,
        );
        const predecessor_base = try lookup.columnsForAccess(access);
        var predecessor: [lookup.N_MAIN_COLUMNS]QM31 = undefined;
        lift(&predecessor, &predecessor_base);
        const increment = try lookup.accumulate(
            QM31.zero(),
            try lookup.pair(access, relation),
        );
        const component = makeComponent(&relation, increment);
        const constraints = try component.evaluateRow(
            &binding,
            &predecessor,
            QM31.zero(),
            QM31.zero(),
            QM31.one(),
        );
        try std.testing.expect(allZero(&constraints));
    }
}

test "timer IF prover domain rejects request clock value claim and vacuity" {
    const relation = memory_lookup.Relation.dummy();
    const fixture = try honestFixture(relation);
    var component = makeComponent(&relation, QM31.zero());
    var preprocessed_values =
        [_][EVALUATION_SIZE]M31{
            [_]M31{M31.zero()} ** EVALUATION_SIZE,
        } ** (FIRST_COLUMN + 1);
    var main_values =
        [_][EVALUATION_SIZE]M31{
            [_]M31{M31.zero()} ** EVALUATION_SIZE,
        } ** MAIN_COLUMNS;
    fillDomainConstants(
        main_values[BINDING_OFFSET..][0..timer_binding.N_MAIN_COLUMNS],
        &fixture.binding,
    );
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

    var preprocessed: [FIRST_COLUMN + 1]prover_component.Poly =
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
        .polys = TreeVec([]const prover_component.Poly).initOwned(&trees),
    };
    const challenge = QM31.fromU32Unchecked(3, 5, 7, 11);
    try expectDomainZero(&component, &trace, challenge, true);

    component.claim = component.claim.add(QM31.one());
    try expectDomainZero(&component, &trace, challenge, false);
    component.claim = component.claim.sub(QM31.one());

    @memset(
        &main_values[BINDING_OFFSET + REQUEST_COLUMN],
        M31.zero(),
    );
    try expectDomainZero(&component, &trace, challenge, false);
    @memset(
        &main_values[BINDING_OFFSET + REQUEST_COLUMN],
        M31.one(),
    );

    @memset(
        &main_values[
            BINDING_OFFSET + timer_binding.MCYCLE_OFFSET
        ],
        M31.fromCanonical(8),
    );
    try expectDomainZero(&component, &trace, challenge, false);
    @memset(
        &main_values[
            BINDING_OFFSET + timer_binding.MCYCLE_OFFSET
        ],
        M31.fromCanonical(7),
    );

    @memset(
        &main_values[
            PREDECESSOR_OFFSET + lookup.PREVIOUS_CLOCK_OFFSET
        ],
        M31.fromCanonical(4),
    );
    try expectDomainZero(&component, &trace, challenge, false);
    @memset(
        &main_values[
            PREDECESSOR_OFFSET + lookup.PREVIOUS_CLOCK_OFFSET
        ],
        M31.fromCanonical(3),
    );

    @memset(
        &main_values[
            PREDECESSOR_OFFSET + lookup.PREVIOUS_VALUE_OFFSET
        ],
        M31.zero(),
    );
    try expectDomainZero(&component, &trace, challenge, false);
    @memset(
        &main_values[
            PREDECESSOR_OFFSET + lookup.PREVIOUS_VALUE_OFFSET
        ],
        M31.one(),
    );

    const honest_claim = component.claim;
    component.claim = QM31.zero();
    for (
        interaction_values[INTERACTION_OFFSET..][0..4],
    ) |*column| @memset(column, M31.zero());
    try expectDomainZero(&component, &trace, challenge, false);
    component.claim = honest_claim;
}

test "timer IF neutral padding relies on companion and memory owners" {
    const relation = memory_lookup.Relation.dummy();
    const component = makeComponent(&relation, QM31.zero());
    const binding =
        [_]QM31{QM31.zero()} ** timer_binding.N_MAIN_COLUMNS;
    const predecessor =
        [_]QM31{QM31.zero()} ** lookup.N_MAIN_COLUMNS;
    const constraints = try component.evaluateRow(
        &binding,
        &predecessor,
        QM31.zero(),
        QM31.zero(),
        QM31.zero(),
    );
    try std.testing.expect(allZero(&constraints));
    // Padding is deliberately neutral. The timer prefix owner rejects an
    // empty active trace, while the shared-memory owner cancels this claim.
}

const Fixture = struct {
    binding: [timer_binding.N_MAIN_COLUMNS]M31,
    predecessor: [lookup.N_MAIN_COLUMNS]M31,
    increment: QM31,
};

fn honestFixture(relation: memory_lookup.Relation) !Fixture {
    const event = requestingEvent(7);
    const access = try lookup.accessForEvent(
        event,
        .{ .clock = 3, .value = 0x01 },
    );
    return .{
        .binding = bindingColumns(event),
        .predecessor = try lookup.columnsForAccess(access),
        .increment = try lookup.accumulate(
            QM31.zero(),
            try lookup.pair(access, relation),
        ),
    };
}

fn requestingEvent(mcycle: u32) timer_binding.EventRow {
    const transition = timer_air.Transition.apply(
        .{
            .tima = 0x42,
            .tma = 0x42,
            .reload_state = .reloading,
        },
        .tick_mcycle,
    );
    std.debug.assert(transition.interrupt_requested);
    return .{
        .mcycle = mcycle,
        .transition = transition,
        .provenance = .{ .execution_tick = .{
            .execution_row = 0,
            .cycle = 0,
        } },
    };
}

fn bindingColumns(
    event: timer_binding.EventRow,
) [timer_binding.N_MAIN_COLUMNS]M31 {
    var values = timer_binding.inactiveColumns();
    const semantic = timer_component.columns(
        timer_air.ValidatedStep.init(event.transition) catch unreachable,
    );
    @memcpy(values[0..semantic.len], &semantic);
    values[timer_binding.MCYCLE_OFFSET] =
        M31.fromCanonical(event.mcycle);
    return values;
}

fn lift(output: []QM31, values: []const M31) void {
    for (output, values) |*target, value|
        target.* = QM31.fromBase(value);
}

fn makeComponent(
    relation: *const memory_lookup.Relation,
    claim: QM31,
) subject.Component {
    return .{
        .log_size = LOG_SIZE,
        .is_first_column = FIRST_COLUMN,
        .binding_offset = BINDING_OFFSET,
        .predecessor_offset = PREDECESSOR_OFFSET,
        .interaction_offset = INTERACTION_OFFSET,
        .relation = relation,
        .claim = claim,
    };
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
    for (values, 0..) |value, row| {
        const coordinates = value.toM31Array();
        for (coordinates, 0..) |coordinate, column|
            columns[column][row] = coordinate;
    }
    return cycle_size;
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

fn domainPolys(output: anytype, values: anytype) void {
    for (output, values) |*polynomial, *column| {
        polynomial.* = .{
            .log_size = EVALUATION_LOG_SIZE,
            .values = column,
        };
    }
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
    try component.evaluateConstraintQuotientsOnDomain(trace, &accumulator);
    var result = try accumulator.finalize();
    defer result.deinit(std.testing.allocator);
    var zero = true;
    for (0..result.len()) |row|
        zero = zero and result.at(row).isZero();
    try std.testing.expectEqual(expected, zero);
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
    pub fn isZero(_: Degree) bool {
        return false;
    }
};
