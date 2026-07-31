const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const TreeVec = core.pcs.TreeVec;
const utils = core.utils;
const prover_accumulation =
    @import("stwo_prover_engine").air.accumulation;
const prover_component =
    @import("stwo_prover_engine").air.component_prover;
const action_schedule = @import("../action_schedule.zig");
const trace_builder = @import("../joypad_trace.zig");
const runner = @import("../runner/mod.zig");
const binding = @import("joypad_binding.zig");
const subject = @import("joypad_action_lookup.zig");

const LOG_SIZE: u32 = 4;
const EVALUATION_LOG_SIZE: u32 = LOG_SIZE + 1;
const EVALUATION_SIZE: usize = 1 << EVALUATION_LOG_SIZE;

test "public action table is canonical and padding is zero" {
    const actions = [_]action_schedule.Action{
        .{ .mcycle = 7, .pressed = runner.joypad.Key.a.mask() },
        .{ .mcycle = 9, .pressed = runner.joypad.Key.left.mask() },
    };
    var table = try subject.generatePublicTable(
        std.testing.allocator,
        LOG_SIZE,
        7,
        10,
        &actions,
    );
    defer table.deinit();
    try subject.validatePublicTable(
        &table.columns,
        LOG_SIZE,
        7,
        10,
        &actions,
    );
    const padding = try core.air.utils.circleBitReversedIndex(LOG_SIZE, 2);
    try std.testing.expect(table.columns[0][padding].isZero());
    try std.testing.expect(table.columns[1][padding].isZero());
    try std.testing.expect(table.columns[2][padding].isZero());

    table.columns[2][padding] = M31.one();
    try std.testing.expectError(
        error.NonCanonicalPublicTable,
        subject.validatePublicTable(
            &table.columns,
            LOG_SIZE,
            7,
            10,
            &actions,
        ),
    );
}

test "checked witness and honest interaction cancel exactly" {
    const actions = honestActions();
    const steps = [_]runner.CartridgeStepTrace{accessStep(.write, 0x30)};
    var trace = try trace_builder.generate(
        std.testing.allocator,
        7,
        8,
        .{},
        &actions,
        &steps,
    );
    defer trace.deinit(std.testing.allocator);
    var witness = try subject.generateWitness(
        std.testing.allocator,
        trace,
        &steps,
    );
    defer witness.deinit();
    try std.testing.expectEqual(LOG_SIZE, witness.log_size);
    try std.testing.expectEqual(trace.rows.len, witness.event_count);
    try std.testing.expectEqual(
        binding.N_MAIN_COLUMNS,
        witness.main.len,
    );

    var interaction = try subject.generateInteraction(
        std.testing.allocator,
        witness.log_size,
        7,
        8,
        &actions,
        trace.rows,
        &steps,
        subject.Relation.dummy(),
    );
    defer interaction.deinit();
    try subject.verifyCancellation(interaction.claims);
}

test "lookup rejects omissions duplicates substitutions and forged events" {
    const actions = honestActions();
    const steps = [_]runner.CartridgeStepTrace{accessStep(.write, 0x30)};
    var trace = try trace_builder.generate(
        std.testing.allocator,
        7,
        8,
        .{},
        &actions,
        &steps,
    );
    defer trace.deinit(std.testing.allocator);
    const relation = subject.Relation.dummy();

    try expectNonCancellation(
        &actions,
        trace.rows[1..],
        &steps,
        relation,
    );
    const duplicate = [_]trace_builder.EventRow{
        trace.rows[0],
        trace.rows[0],
        trace.rows[1],
        trace.rows[2],
    };
    try expectNonCancellation(&actions, &duplicate, &steps, relation);

    const substituted = [_]action_schedule.Action{.{
        .mcycle = 7,
        .pressed = runner.joypad.Key.left.mask(),
    }};
    try expectNonCancellation(
        &substituted,
        trace.rows,
        &steps,
        relation,
    );

    var forged_time = trace.rows[0];
    forged_time.mcycle = 8;
    var forged_rows = [_]trace_builder.EventRow{
        forged_time,
        trace.rows[1],
        trace.rows[2],
    };
    try expectNonCancellation(&actions, &forged_rows, &steps, relation);

    forged_rows[0] = trace.rows[0];
    forged_rows[0].transition = try runner.joypad.Transition.apply(
        forged_rows[0].transition.before,
        .{ .set_pressed = runner.joypad.Key.left.mask() },
    );
    try expectNonCancellation(&actions, &forged_rows, &steps, relation);

    try expectNonCancellation(
        &actions,
        trace.rows[1..],
        &steps,
        relation,
    );
    const duplicate_schedule = [_]action_schedule.Action{
        actions[0],
        actions[0],
    };
    try std.testing.expectError(
        error.NonIncreasingActionTime,
        subject.generateInteraction(
            std.testing.allocator,
            LOG_SIZE,
            7,
            8,
            &duplicate_schedule,
            trace.rows,
            &steps,
            relation,
        ),
    );
}

test "zero denominators claim mutations and all inactive fail closed" {
    const actions = honestActions();
    const steps = [_]runner.CartridgeStepTrace{accessStep(.write, 0x30)};
    var trace = try trace_builder.generate(
        std.testing.allocator,
        7,
        8,
        .{},
        &actions,
        &steps,
    );
    defer trace.deinit(std.testing.allocator);
    const singular = subject.Relation{
        .z = q(7),
        .alpha = QM31.zero(),
    };
    try std.testing.expectError(
        error.JoypadActionLookupZeroDenominator,
        subject.generateInteraction(
            std.testing.allocator,
            LOG_SIZE,
            7,
            8,
            &actions,
            trace.rows,
            &steps,
            singular,
        ),
    );

    var interaction = try subject.generateInteraction(
        std.testing.allocator,
        LOG_SIZE,
        7,
        8,
        &actions,
        trace.rows,
        &steps,
        subject.Relation.dummy(),
    );
    defer interaction.deinit();
    interaction.claims.public = interaction.claims.public.add(QM31.one());
    try std.testing.expectError(
        error.JoypadActionLookupSumNonZero,
        subject.verifyCancellation(interaction.claims),
    );
    try expectNonCancellation(
        &actions,
        trace.rows[1..],
        &steps,
        subject.Relation.dummy(),
    );
}

test "lookup constraints have exact cubic degree and adapter geometry" {
    const variables =
        [_]Degree{Degree.variable()} ** @import("joypad.zig").N_MAIN_COLUMNS;
    const evaluation = try subject.evaluateRows(
        Degree,
        [_]Degree{Degree.variable()} ** subject.N_PUBLIC_COLUMNS,
        Degree.variable(),
        &variables,
        Degree.variable(),
        Degree.variable(),
        Degree.variable(),
        Degree.variable(),
        Degree.variable(),
        Degree.variable(),
        Degree.zero(),
        Degree.zero(),
        .{ .z = Degree.zero(), .alpha = Degree.zero() },
    );
    var maximum: u32 = 0;
    for (evaluation.values) |constraint|
        maximum = @max(maximum, constraint.degree);
    try std.testing.expectEqual(subject.MAX_CONSTRAINT_DEGREE, maximum);

    const relation = subject.Relation.dummy();
    var component = proofComponent(&relation, .{
        .events = QM31.zero(),
        .public = QM31.zero(),
    });
    component.is_first_column = 2;
    component.public_active_column = 4;
    component.public_mcycle_column = 6;
    component.public_pressed_column = 8;
    component.binding_main_offset = 7;
    component.interaction_offset = 11;
    try std.testing.expectEqual(
        LOG_SIZE + 1,
        component.maxConstraintLogDegreeBound(),
    );
    _ = component.asVerifierComponent();
    _ = component.asProverComponent();
    var bounds = try component.traceLogDegreeBounds(std.testing.allocator);
    defer bounds.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 9), bounds.items[0].len);
    try std.testing.expectEqual(
        @as(usize, 7 + binding.MCYCLE_OFFSET + 1),
        bounds.items[1].len,
    );
    try std.testing.expectEqual(
        11 + subject.N_INTERACTION_COLUMNS,
        bounds.items[2].len,
    );
    var mask = try component.maskPoints(
        std.testing.allocator,
        core.circle.SECURE_FIELD_CIRCLE_GEN,
        component.maxConstraintLogDegreeBound(),
    );
    defer mask.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 9), mask.items[0].len);
    try std.testing.expectEqual(
        @as(usize, 7 + binding.MCYCLE_OFFSET + 1),
        mask.items[1].len,
    );
    try std.testing.expectEqual(
        @as(usize, 11 + subject.N_INTERACTION_COLUMNS),
        mask.items[2].len,
    );
}

test "domain evaluator rejects public event and vacuity mutations" {
    const actions = honestActions();
    const steps = [_]runner.CartridgeStepTrace{accessStep(.write, 0x30)};
    var event_trace = try trace_builder.generate(
        std.testing.allocator,
        7,
        8,
        .{},
        &actions,
        &steps,
    );
    defer event_trace.deinit(std.testing.allocator);
    const event_row = try binding.columns(event_trace.rows[0], &steps);
    const relation = subject.Relation.dummy();
    const denominator = relation.combine(q(7), q(actions[0].pressed));
    const inverse = try denominator.inv();
    const event_increment = inverse.neg();
    const public_increment = inverse;

    var first_values = [_]M31{M31.zero()} ** EVALUATION_SIZE;
    var preprocessed_values =
        [_][EVALUATION_SIZE]M31{
            [_]M31{M31.zero()} ** EVALUATION_SIZE,
        } ** 4;
    @memset(&preprocessed_values[1], M31.one());
    @memset(&preprocessed_values[2], M31.fromCanonical(7));
    @memset(
        &preprocessed_values[3],
        M31.fromCanonical(actions[0].pressed),
    );
    var main_values =
        [_][EVALUATION_SIZE]M31{
            [_]M31{M31.zero()} ** EVALUATION_SIZE,
        } ** binding.N_MAIN_COLUMNS;
    fillConstants(&main_values, &event_row);
    var interaction_values =
        [_][EVALUATION_SIZE]M31{
            [_]M31{M31.zero()} ** EVALUATION_SIZE,
        } ** subject.N_INTERACTION_COLUMNS;
    const cycle_size = try writeAccumulatorCycle(
        &first_values,
        interaction_values[0..4],
        event_increment,
    );
    try std.testing.expectEqual(
        cycle_size,
        try writeAccumulatorCycle(
            &first_values,
            interaction_values[4..8],
            public_increment,
        ),
    );
    @memcpy(&preprocessed_values[0], &first_values);
    const claims = subject.Claims{
        .events = event_increment.mul(q(cycle_size)),
        .public = public_increment.mul(q(cycle_size)),
    };
    var component = proofComponent(&relation, claims);

    var preprocessed: [4]prover_component.Poly = undefined;
    initPolys(&preprocessed, &preprocessed_values);
    var main: [binding.N_MAIN_COLUMNS]prover_component.Poly = undefined;
    initPolys(&main, &main_values);
    var interaction: [subject.N_INTERACTION_COLUMNS]prover_component.Poly = undefined;
    initPolys(&interaction, &interaction_values);
    var trees = [_][]const prover_component.Poly{
        &preprocessed,
        &main,
        &interaction,
    };
    const trace = prover_component.Trace{
        .polys = TreeVec([]const prover_component.Poly).initOwned(&trees),
    };
    try expectDomain(&component, &trace, true);

    @memset(&main_values[binding.MCYCLE_OFFSET], M31.fromCanonical(8));
    try expectDomain(&component, &trace, false);
    @memset(&main_values[binding.MCYCLE_OFFSET], M31.fromCanonical(7));

    @memset(&preprocessed_values[3], M31.fromCanonical(2));
    try expectDomain(&component, &trace, false);
    @memset(
        &preprocessed_values[3],
        M31.fromCanonical(actions[0].pressed),
    );

    @memset(&preprocessed_values[1], M31.zero());
    try expectDomain(&component, &trace, false);
    @memset(&preprocessed_values[2], M31.zero());
    @memset(&preprocessed_values[3], M31.zero());
    for (&main_values) |*column| @memset(column, M31.zero());
    try expectDomain(&component, &trace, false);

    component.claims.public = component.claims.public.add(QM31.one());
    try expectDomain(&component, &trace, false);
}

fn honestActions() [1]action_schedule.Action {
    return .{.{
        .mcycle = 7,
        .pressed = runner.joypad.Key.a.mask(),
    }};
}

fn expectNonCancellation(
    actions: []const action_schedule.Action,
    events: []const trace_builder.EventRow,
    steps: []const runner.CartridgeStepTrace,
    relation: subject.Relation,
) !void {
    var interaction = try subject.generateInteraction(
        std.testing.allocator,
        LOG_SIZE,
        7,
        8,
        actions,
        events,
        steps,
        relation,
    );
    defer interaction.deinit();
    try std.testing.expectError(
        error.JoypadActionLookupSumNonZero,
        subject.verifyCancellation(interaction.claims),
    );
}

fn proofComponent(
    relation: *const subject.Relation,
    claims: subject.Claims,
) subject.Component {
    return .{
        .log_size = LOG_SIZE,
        .is_first_column = 0,
        .public_active_column = 1,
        .public_mcycle_column = 2,
        .public_pressed_column = 3,
        .binding_main_offset = 0,
        .interaction_offset = 0,
        .relation = relation,
        .claims = claims,
    };
}

fn accessStep(
    action: runner.cartridge_memory.Action,
    value: u8,
) runner.CartridgeStepTrace {
    var step: runner.CartridgeStepTrace = undefined;
    step.instruction.cycle_count = 1;
    step.instruction.cycles[0] = .{
        .address = runner.joypad.P1_ADDRESS,
        .value = value,
        .action = switch (action) {
            .read => .read,
            .write => .write,
        },
    };
    step.accesses = [_]?runner.cartridge_memory.Access{null} ** 6;
    step.accesses[0] = .{
        .logical_address = runner.joypad.P1_ADDRESS,
        .action = action,
        .region = .joypad_mmio,
        .physical_offset = null,
        .mapper_before = .{},
        .mapper_after = .{},
        .value = value,
    };
    return step;
}

fn fillConstants(
    destinations: [][EVALUATION_SIZE]M31,
    values: []const M31,
) void {
    for (destinations, values) |*destination, value|
        @memset(destination, value);
}

fn initPolys(
    polynomials: []prover_component.Poly,
    values: [][EVALUATION_SIZE]M31,
) void {
    for (polynomials, values) |*polynomial, *column|
        polynomial.* = .{
            .log_size = EVALUATION_LOG_SIZE,
            .values = column,
        };
}

fn writeAccumulatorCycle(
    first_values: *[EVALUATION_SIZE]M31,
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
    var accumulators = [_]QM31{QM31.zero()} ** EVALUATION_SIZE;
    var cycle_size: usize = 0;
    for (0..EVALUATION_SIZE) |start| {
        if (visited[start]) continue;
        first_values[start] = M31.one();
        visited[start] = true;
        var current = start;
        var length: usize = 1;
        while (next[current] != start) {
            const following = next[current];
            accumulators[following] =
                accumulators[current].add(increment);
            visited[following] = true;
            current = following;
            length += 1;
        }
        if (cycle_size == 0)
            cycle_size = length
        else
            try std.testing.expectEqual(cycle_size, length);
    }
    for (accumulators, 0..) |value, row| {
        for (value.toM31Array(), 0..) |coordinate, column|
            columns[column][row] = coordinate;
    }
    return cycle_size;
}

fn expectDomain(
    component: *const subject.Component,
    trace: *const prover_component.Trace,
    expected_zero: bool,
) !void {
    var accumulator =
        try prover_accumulation.DomainEvaluationAccumulator.init(
            std.testing.allocator,
            QM31.fromU32Unchecked(3, 5, 7, 11),
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
    try std.testing.expectEqual(expected_zero, zero);
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

    pub fn add(left: Degree, right: Degree) Degree {
        return .{ .degree = @max(left.degree, right.degree) };
    }

    pub fn sub(left: Degree, right: Degree) Degree {
        return left.add(right);
    }

    pub fn mul(left: Degree, right: Degree) Degree {
        return .{ .degree = left.degree + right.degree };
    }

    pub fn neg(self: Degree) Degree {
        return self;
    }

    pub fn isZero(_: Degree) bool {
        return false;
    }
};
