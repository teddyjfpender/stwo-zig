const std = @import("std");
const core_air_accumulation = @import("stwo_core").air.accumulation;
const core_air_components = @import("stwo_core").air.components;
const circle = @import("stwo_core").circle;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const ppu_runner = @import("../runner/ppu_timing.zig");
const ppu_binding = @import("ppu_binding.zig");
const lookup = @import("ppu_if_memory_lookup.zig");
const memory_lookup = @import("cartridge_memory_lookup.zig");
const subject = @import("ppu_if_memory_lookup_component.zig");

const LOG_SIZE: u32 = 4;
const FIRST_COLUMN: usize = 2;
const BINDING_OFFSET: usize = 5;
const PREDECESSOR_OFFSET: usize =
    BINDING_OFFSET + ppu_binding.N_MAIN_COLUMNS + 3;
const MAIN_COLUMNS: usize =
    PREDECESSOR_OFFSET + lookup.N_MAIN_COLUMNS;
const INTERACTION_OFFSET: usize = 7;
const INTERACTION_COLUMNS: usize =
    INTERACTION_OFFSET + lookup.N_INTERACTION_COLUMNS;

test "PPU IF adapter owns exact cubic offset-safe geometry" {
    const binding_variables =
        [_]Degree{Degree.variable()} ** ppu_binding.N_MAIN_COLUMNS;
    const predecessor_variables =
        [_]Degree{Degree.variable()} ** lookup.N_MAIN_COLUMNS;
    const ppu = try lookup.PpuRow(Degree).fromColumns(
        &binding_variables,
    );
    const predecessor = try lookup.Row(Degree).fromColumns(
        &predecessor_variables,
    );
    const semantic = lookup.evaluate(Degree, ppu, predecessor);
    var semantic_maximum: u32 = 0;
    for (semantic.values) |constraint|
        semantic_maximum = @max(
            semantic_maximum,
            constraint.degree,
        );
    try std.testing.expectEqual(@as(u32, 3), semantic_maximum);
    const recurrence = subject.recurrenceConstraint(
        Degree,
        Degree.variable(),
        Degree.variable(),
        Degree.variable(),
        Degree.zero(),
        .{ .degree = 2 },
        Degree.variable(),
        .{ .degree = 2 },
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
        error.InvalidPpuLogSize,
        invalid.traceLogDegreeBounds(std.testing.allocator),
    );
}

test "PPU IF sampled OODS rejects request clock value masked-bit and claim drift" {
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
        main_values[BINDING_OFFSET..][0..ppu_binding.N_MAIN_COLUMNS],
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
        core_air_accumulation.PointEvaluationAccumulator.init(
            QM31.one(),
        );
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
    component.claim = fixture.increment;

    const stat_only = try ppu_binding.columns(statEvent(7));
    fillPointConstants(
        main_values[BINDING_OFFSET..][0..ppu_binding.N_MAIN_COLUMNS],
        &stat_only,
    );
    try component.evaluateSampled(
        &preprocessed,
        &main,
        &interaction,
        &constraints,
    );
    try std.testing.expect(!allZero(&constraints));
    fillPointConstants(
        main_values[BINDING_OFFSET..][0..ppu_binding.N_MAIN_COLUMNS],
        &fixture.binding,
    );

    main_values[BINDING_OFFSET + ppu_binding.MCYCLE_OFFSET][0] =
        QM31.fromBase(M31.fromCanonical(8));
    try component.evaluateSampled(
        &preprocessed,
        &main,
        &interaction,
        &constraints,
    );
    try std.testing.expect(!allZero(&constraints));
    main_values[BINDING_OFFSET + ppu_binding.MCYCLE_OFFSET][0] =
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
        PREDECESSOR_OFFSET + lookup.PREVIOUS_VALUE_OFFSET + 2
    ][0] = QM31.zero();
    try component.evaluateSampled(
        &preprocessed,
        &main,
        &interaction,
        &constraints,
    );
    try std.testing.expect(!allZero(&constraints));
    main_values[
        PREDECESSOR_OFFSET + lookup.PREVIOUS_VALUE_OFFSET + 2
    ][0] = QM31.one();

    main_values[
        PREDECESSOR_OFFSET + lookup.MASKED_BITS_OFFSET
    ][0] = QM31.one();
    try component.evaluateSampled(
        &preprocessed,
        &main,
        &interaction,
        &constraints,
    );
    try std.testing.expect(!allZero(&constraints));
}

test "PPU IF component preserves all bytes for VBlank STAT and dual requests" {
    const relation = memory_lookup.Relation.dummy();
    const events = [_]ppu_binding.EventRow{
        vblankEvent(7),
        statEvent(7),
        dualEvent(7),
    };
    for (events) |event| {
        const binding_base = try ppu_binding.columns(event);
        var binding: [ppu_binding.N_MAIN_COLUMNS]QM31 = undefined;
        lift(&binding, &binding_base);
        for (0..256) |value| {
            const access = try lookup.accessForEvent(
                event,
                .{
                    .clock = 3,
                    .value = @intCast(value),
                },
            );
            const predecessor_base =
                try lookup.columnsForAccess(access);
            var predecessor: [lookup.N_MAIN_COLUMNS]QM31 =
                undefined;
            lift(&predecessor, &predecessor_base);
            const ppu = try lookup.PpuRow(QM31).fromColumns(
                &binding,
            );
            const row = try lookup.Row(QM31).fromColumns(
                &predecessor,
            );
            try std.testing.expect(
                lookup.evaluate(QM31, ppu, row).allZero(),
            );
            const host = try lookup.pair(access, relation);
            const proof = lookup.pairForRows(ppu, row, relation);
            try std.testing.expectEqual(host.n1, proof.n1);
            try std.testing.expectEqual(host.d1, proof.d1);
            try std.testing.expectEqual(host.n2, proof.n2);
            try std.testing.expectEqual(host.d2, proof.d2);
        }
    }
}

test "PPU IF all-inactive component rejects vacuous predecessor activity" {
    const relation = memory_lookup.Relation.dummy();
    const component = makeComponent(&relation, QM31.zero());
    var binding = [
        _
    ]QM31{QM31.zero()} ** ppu_binding.N_MAIN_COLUMNS;
    var predecessor =
        [_]QM31{QM31.zero()} ** lookup.N_MAIN_COLUMNS;
    var constraints = try component.evaluateRow(
        &binding,
        &predecessor,
        QM31.zero(),
        QM31.zero(),
        QM31.one(),
    );
    try std.testing.expect(allZero(&constraints));

    predecessor[lookup.PREVIOUS_VALUE_OFFSET + 7] = QM31.one();
    constraints = try component.evaluateRow(
        &binding,
        &predecessor,
        QM31.zero(),
        QM31.zero(),
        QM31.one(),
    );
    try std.testing.expect(!allZero(&constraints));
    predecessor[lookup.PREVIOUS_VALUE_OFFSET + 7] = QM31.zero();
    predecessor[lookup.MASKED_BITS_OFFSET] = QM31.one();
    constraints = try component.evaluateRow(
        &binding,
        &predecessor,
        QM31.zero(),
        QM31.zero(),
        QM31.one(),
    );
    try std.testing.expect(!allZero(&constraints));
    _ = &binding;
}

const Fixture = struct {
    binding: [ppu_binding.N_MAIN_COLUMNS]M31,
    predecessor: [lookup.N_MAIN_COLUMNS]M31,
    increment: QM31,
};

fn honestFixture(relation: memory_lookup.Relation) !Fixture {
    const event = dualEvent(7);
    const access = try lookup.accessForEvent(
        event,
        .{ .clock = 3, .value = 0x04 },
    );
    return .{
        .binding = try ppu_binding.columns(event),
        .predecessor = try lookup.columnsForAccess(access),
        .increment = try lookup.accumulate(
            QM31.zero(),
            try lookup.pair(access, relation),
        ),
    };
}

fn dualEvent(mcycle: u32) ppu_binding.EventRow {
    return eventAt(mcycle, 144, 0, true, 0);
}

fn vblankEvent(mcycle: u32) ppu_binding.EventRow {
    return eventAt(mcycle, 144, 0, false, 0);
}

fn statEvent(mcycle: u32) ppu_binding.EventRow {
    return eventAt(
        mcycle,
        1,
        ppu_runner.DOTS_PER_LINE - 1,
        true,
        3,
    );
}

fn eventAt(
    mcycle: u32,
    line: u8,
    dot: u16,
    enable_mode2: bool,
    phase: u2,
) ppu_binding.EventRow {
    const before = ppu_runner.State{
        .lcd_enabled = true,
        .line = line,
        .dot = dot,
        .stat_enable = if (enable_mode2) 0x4 else 0,
        .coincidence = false,
        .lyc_interrupt_line = false,
        .stat_interrupt_line = false,
    };
    const transition = ppu_runner.Transition.apply(
        before,
        .tick_dot,
    ) catch unreachable;
    return .{
        .mcycle = mcycle,
        .transition = transition,
        .lcdc_before = 0x80,
        .lcdc_after = 0x80,
        .dot_phase = phase,
    };
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

fn pointSlices(output: anytype, values: anytype) void {
    for (output, values) |*column, *source| column.* = source;
}

fn fillPointConstants(destinations: anytype, values: []const M31) void {
    for (destinations, values) |*destination, value|
        destination[0] = QM31.fromBase(value);
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
