const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const prover_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const subject = @import("timer_component.zig");
const timer_air = @import("timer.zig");
const timer = @import("../runner/timer.zig");

test "timer component has exact cubic geometry and adapter shape" {
    try std.testing.expectEqual(@as(usize, 124), subject.N_MAIN_COLUMNS);
    try std.testing.expectEqual(@as(usize, 446), subject.N_CONSTRAINTS);
    const variables =
        [_]Degree{Degree.variable()} ** timer_air.N_MAIN_COLUMNS;
    const initial = timer.Timer{};
    const evaluation = try subject.evaluateRows(
        Degree,
        &variables,
        &variables,
        Degree.variable(),
        Degree.variable(),
        Degree.variable(),
        Degree.variable(),
        initial,
        initial,
    );
    var maximum: u32 = 0;
    for (evaluation.values) |constraint|
        maximum = @max(maximum, constraint.degree);
    try std.testing.expectEqual(subject.MAX_CONSTRAINT_DEGREE, maximum);

    const component = subject.Component{
        .log_size = 4,
        .is_first_column = 2,
        .is_last_column = 4,
        .main_offset = 7,
        .initial = initial,
        .final = initial,
    };
    try std.testing.expectEqual(
        subject.N_CONSTRAINTS,
        component.nConstraints(),
    );
    try std.testing.expectEqual(
        @as(u32, 5),
        component.maxConstraintLogDegreeBound(),
    );
    _ = component.asVerifierComponent();
    _ = component.asProverComponent();
    const indices = try component.preprocessedColumnIndices(
        std.testing.allocator,
    );
    defer std.testing.allocator.free(indices);
    try std.testing.expectEqualSlices(usize, &.{ 2, 4 }, indices);
    var bounds = try component.traceLogDegreeBounds(
        std.testing.allocator,
    );
    defer bounds.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 5), bounds.items[0].len);
    try std.testing.expectEqual(@as(usize, 131), bounds.items[1].len);
    var mask = try component.maskPoints(
        std.testing.allocator,
        core.circle.SECURE_FIELD_CIRCLE_GEN,
        component.maxConstraintLogDegreeBound(),
    );
    defer mask.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 5), mask.items[0].len);
    try std.testing.expectEqual(@as(usize, 131), mask.items[1].len);
    for (mask.items[0]) |column|
        try std.testing.expectEqual(@as(usize, 1), column.len);
    for (mask.items[1]) |column|
        try std.testing.expectEqual(@as(usize, 2), column.len);
}

test "timer component binds chain activity endpoints and physical wrap" {
    const first_transition = timer_air.Transition.apply(
        .{
            .div_counter = 12,
            .tima = 0xff,
            .tma = 0x42,
            .tac = 0x05,
            .reload_state = .reloading,
        },
        .tick_mcycle,
    );
    const second_transition = timer_air.Transition.apply(
        first_transition.after,
        .{ .write_tma = 0x99 },
    );
    var first = lift(timer_air.columns(
        try timer_air.ValidatedStep.init(first_transition),
    ));
    var second = lift(timer_air.columns(
        try timer_air.ValidatedStep.init(second_transition),
    ));
    const inactive =
        [_]QM31{QM31.zero()} ** timer_air.N_MAIN_COLUMNS;
    const honest = subject.Component{
        .log_size = 4,
        .is_first_column = 0,
        .is_last_column = 1,
        .main_offset = 0,
        .initial = first_transition.before,
        .final = second_transition.after,
    };
    try expectRow(
        &honest,
        &first,
        &second,
        true,
        true,
        true,
        false,
        true,
    );
    try expectRow(
        &honest,
        &second,
        &inactive,
        true,
        false,
        false,
        false,
        true,
    );
    try expectRow(
        &honest,
        &second,
        &first,
        true,
        true,
        false,
        true,
        true,
    );

    for (0..timer_air.N_STATE_COLUMNS) |field| {
        var forged = honest;
        forged.initial = mutateTimer(forged.initial, field);
        try expectRow(
            &forged,
            &first,
            &second,
            true,
            true,
            true,
            false,
            false,
        );
        forged = honest;
        forged.final = mutateTimer(forged.final, field);
        try expectRow(
            &forged,
            &second,
            &inactive,
            true,
            false,
            false,
            false,
            false,
        );
    }
    for (0..timer_air.N_STATE_COLUMNS) |field| {
        second[timer_air.BEFORE_STATE_OFFSET + field] =
            QM31.one().sub(
                second[timer_air.BEFORE_STATE_OFFSET + field],
            );
        try expectRow(
            &honest,
            &first,
            &second,
            true,
            true,
            true,
            false,
            false,
        );
        second[timer_air.BEFORE_STATE_OFFSET + field] =
            QM31.one().sub(
                second[timer_air.BEFORE_STATE_OFFSET + field],
            );
    }

    try expectRow(
        &honest,
        &inactive,
        &inactive,
        false,
        false,
        true,
        false,
        false,
    );
    try expectRow(
        &honest,
        &inactive,
        &second,
        false,
        true,
        false,
        false,
        false,
    );
    var non_vacuous = inactive;
    non_vacuous[0] = QM31.one();
    try expectRow(
        &honest,
        &non_vacuous,
        &inactive,
        false,
        false,
        false,
        true,
        false,
    );
    first[0] = QM31.one().sub(first[0]);
    try expectRow(
        &honest,
        &first,
        &second,
        true,
        true,
        true,
        false,
        false,
    );
}

test "timer component point path observes offsets and next state" {
    const first_transition = timer_air.Transition.apply(
        .{ .div_counter = 8, .tima = 9, .tac = 0x05 },
        .tick_mcycle,
    );
    const second_transition = timer_air.Transition.apply(
        first_transition.after,
        .{ .write_tima = 0x44 },
    );
    const first = subject.columns(
        try timer_air.ValidatedStep.init(first_transition),
    );
    const second = subject.columns(
        try timer_air.ValidatedStep.init(second_transition),
    );
    const component = subject.Component{
        .log_size = 4,
        .is_first_column = 2,
        .is_last_column = 4,
        .main_offset = 3,
        .initial = first_transition.before,
        .final = second_transition.after,
    };
    var preprocessed_storage =
        [_][1]QM31{.{QM31.zero()}} ** 5;
    preprocessed_storage[2][0] = QM31.one();
    var preprocessed: [5][]QM31 = undefined;
    for (&preprocessed, &preprocessed_storage) |*column, *values|
        column.* = values;
    var main_storage =
        [_][2]QM31{.{ QM31.zero(), QM31.zero() }} **
        (3 + subject.N_MAIN_COLUMNS);
    for (
        main_storage[3..][0..subject.N_MAIN_COLUMNS],
        first,
        second,
    ) |*values, current, next| {
        values[0] = QM31.fromBase(current);
        values[1] = QM31.fromBase(next);
    }
    var main: [main_storage.len][]QM31 = undefined;
    for (&main, &main_storage) |*column, *values|
        column.* = values;
    var trees = [_][][]QM31{ &preprocessed, &main };
    const mask = core.air.components.MaskValues.initOwned(&trees);
    const point = core.circle.SECURE_FIELD_CIRCLE_GEN.mul(29);
    var honest =
        core.air.accumulation.PointEvaluationAccumulator.init(QM31.one());
    try component.evaluateConstraintQuotientsAtPoint(
        point,
        &mask,
        &honest,
        component.maxConstraintLogDegreeBound(),
    );
    try std.testing.expect(honest.finalize().isZero());

    const chain_column =
        3 + 1 + timer_air.BEFORE_STATE_OFFSET;
    main_storage[chain_column][1] =
        QM31.one().sub(main_storage[chain_column][1]);
    var forged =
        core.air.accumulation.PointEvaluationAccumulator.init(QM31.one());
    try component.evaluateConstraintQuotientsAtPoint(
        point,
        &mask,
        &forged,
        component.maxConstraintLogDegreeBound(),
    );
    try std.testing.expect(!forged.finalize().isZero());
}

test "timer component domain rejects semantic chain endpoint and vacuity" {
    const allocator = std.testing.allocator;
    const log_size: u32 = 4;
    const evaluation_log_size: u32 = log_size + 1;
    const evaluation_size: usize = 1 << evaluation_log_size;
    const first_transition = timer_air.Transition.apply(
        .{
            .div_counter = 12,
            .tima = 0xff,
            .tma = 0x42,
            .tac = 0x05,
            .reload_state = .reloading,
        },
        .tick_mcycle,
    );
    const second_transition = timer_air.Transition.apply(
        first_transition.after,
        .{ .write_tma = 0x99 },
    );
    const first_witness = timer_air.columns(
        try timer_air.ValidatedStep.init(first_transition),
    );
    const second_witness = timer_air.columns(
        try timer_air.ValidatedStep.init(second_transition),
    );
    const first_index: usize = 0;
    const second_index = core.utils.offsetBitReversedCircleDomainIndex(
        first_index,
        log_size,
        evaluation_log_size,
        1,
    );
    var predecessor: ?usize = null;
    for (0..evaluation_size) |row| {
        if (core.utils.offsetBitReversedCircleDomainIndex(
            row,
            log_size,
            evaluation_log_size,
            1,
        ) == first_index) predecessor = row;
    }
    const last_index = predecessor orelse return error.InvalidProofShape;

    var first_values = [_]M31{M31.zero()} ** evaluation_size;
    var last_values = [_]M31{M31.zero()} ** evaluation_size;
    var active_values = [_]M31{M31.zero()} ** evaluation_size;
    first_values[first_index] = M31.one();
    last_values[last_index] = M31.one();
    active_values[first_index] = M31.one();
    active_values[second_index] = M31.one();
    var air_values: [timer_air.N_MAIN_COLUMNS][evaluation_size]M31 = undefined;
    var air_polynomials: [timer_air.N_MAIN_COLUMNS]prover_component.Poly = undefined;
    for (
        &air_values,
        &air_polynomials,
        first_witness,
        second_witness,
    ) |*values, *polynomial, first_value, second_value| {
        @memset(values, M31.zero());
        values[first_index] = first_value;
        values[second_index] = second_value;
        polynomial.* = .{
            .log_size = evaluation_log_size,
            .values = values,
        };
    }
    var preprocessed = [_]prover_component.Poly{
        .{ .log_size = evaluation_log_size, .values = &first_values },
        .{ .log_size = evaluation_log_size, .values = &last_values },
    };
    var main: [subject.N_MAIN_COLUMNS]prover_component.Poly = undefined;
    main[0] = .{
        .log_size = evaluation_log_size,
        .values = &active_values,
    };
    @memcpy(main[1..], &air_polynomials);
    var trees = [_][]const prover_component.Poly{
        &preprocessed,
        &main,
    };
    const trace = prover_component.Trace{
        .polys = core.pcs.TreeVec(
            []const prover_component.Poly,
        ).initOwned(&trees),
    };
    var component = subject.Component{
        .log_size = log_size,
        .is_first_column = 0,
        .is_last_column = 1,
        .main_offset = 0,
        .initial = first_transition.before,
        .final = second_transition.after,
    };
    const challenge = QM31.fromU32Unchecked(3, 5, 7, 11);
    try expectDomain(
        allocator,
        &component,
        &trace,
        challenge,
        evaluation_log_size,
        true,
    );

    air_values[timer_air.BASE_N_MAIN_COLUMNS][first_index] =
        M31.one().sub(first_witness[timer_air.BASE_N_MAIN_COLUMNS]);
    try expectDomain(
        allocator,
        &component,
        &trace,
        challenge,
        evaluation_log_size,
        false,
    );
    air_values[timer_air.BASE_N_MAIN_COLUMNS][first_index] =
        first_witness[timer_air.BASE_N_MAIN_COLUMNS];

    air_values[timer_air.BEFORE_STATE_OFFSET][second_index] =
        M31.one().sub(
            second_witness[timer_air.BEFORE_STATE_OFFSET],
        );
    try expectDomain(
        allocator,
        &component,
        &trace,
        challenge,
        evaluation_log_size,
        false,
    );
    air_values[timer_air.BEFORE_STATE_OFFSET][second_index] =
        second_witness[timer_air.BEFORE_STATE_OFFSET];

    component.final = mutateTimer(component.final, 23);
    try expectDomain(
        allocator,
        &component,
        &trace,
        challenge,
        evaluation_log_size,
        false,
    );
    component.final = second_transition.after;

    active_values[first_index] = M31.zero();
    try expectDomain(
        allocator,
        &component,
        &trace,
        challenge,
        evaluation_log_size,
        false,
    );
    active_values[first_index] = M31.one();
    active_values[second_index] = M31.zero();
    for (&air_values) |*values| values[second_index] = M31.zero();
    try expectDomain(
        allocator,
        &component,
        &trace,
        challenge,
        evaluation_log_size,
        false,
    );
}

fn expectRow(
    component: *const subject.Component,
    current: []const QM31,
    next: []const QM31,
    current_active: bool,
    next_active: bool,
    is_first: bool,
    is_last: bool,
    expected: bool,
) !void {
    const evaluation = try component.evaluateRow(
        current,
        next,
        qBool(current_active),
        qBool(next_active),
        qBool(is_first),
        qBool(is_last),
    );
    try std.testing.expectEqual(expected, evaluation.allZero());
}

fn expectDomain(
    allocator: std.mem.Allocator,
    component: *const subject.Component,
    trace: *const prover_component.Trace,
    challenge: QM31,
    evaluation_log_size: u32,
    expected: bool,
) !void {
    var accumulator =
        try prover_accumulation.DomainEvaluationAccumulator.init(
            allocator,
            challenge,
            evaluation_log_size,
            subject.N_CONSTRAINTS,
        );
    defer accumulator.deinit();
    try component.evaluateConstraintQuotientsOnDomain(
        trace,
        &accumulator,
    );
    var result = try accumulator.finalize();
    defer result.deinit(allocator);
    var all_zero = true;
    for (0..result.len()) |row|
        all_zero = all_zero and result.at(row).isZero();
    try std.testing.expectEqual(expected, all_zero);
}

fn mutateTimer(value: timer.Timer, field: usize) timer.Timer {
    var result = value;
    if (field < 16)
        result.div_counter ^= @as(u16, 1) << @intCast(field)
    else if (field < 24)
        result.tima ^= @as(u8, 1) << @intCast(field - 16)
    else if (field < 32)
        result.tma ^= @as(u8, 1) << @intCast(field - 24)
    else if (field < 35)
        result.tac ^= @as(u3, 1) << @intCast(field - 32)
    else
        result.reload_state = @enumFromInt(
            @as(u2, @intCast(
                (@intFromEnum(result.reload_state) +
                    1 + (field - 35) % 2) % 3,
            )),
        );
    return result;
}

fn lift(
    values: [timer_air.N_MAIN_COLUMNS]M31,
) [timer_air.N_MAIN_COLUMNS]QM31 {
    var result: [timer_air.N_MAIN_COLUMNS]QM31 = undefined;
    for (&result, values) |*destination, value|
        destination.* = QM31.fromBase(value);
    return result;
}

fn qBool(value: bool) QM31 {
    return if (value) QM31.one() else QM31.zero();
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
