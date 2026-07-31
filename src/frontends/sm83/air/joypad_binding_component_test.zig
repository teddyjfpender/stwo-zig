const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const prover_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const subject = @import("joypad_binding_component.zig");
const binding = @import("joypad_binding.zig");
const joypad_air = @import("joypad.zig");
const joypad = @import("../runner/joypad.zig");

const TICK_EVENT_OFFSET: usize = 1 + 2;

test "joypad binding component is cubic and binds clock order endpoints" {
    const variables =
        [_]Degree{Degree.variable()} ** binding.N_MAIN_COLUMNS;
    const degree = try subject.evaluateRows(
        Degree,
        &variables,
        &variables,
        Degree.variable(),
        Degree.variable(),
        7,
        9,
    );
    var maximum: u32 = 0;
    for (degree.values) |constraint|
        maximum = @max(maximum, constraint.degree);
    try std.testing.expectEqual(subject.MAX_CONSTRAINT_DEGREE, maximum);

    const action_transition = try joypad.Transition.apply(
        .{},
        .{ .set_pressed = joypad.Key.a.mask() },
    );
    const tick_transition = try joypad.Transition.apply(
        action_transition.after,
        .tick_mcycle,
    );
    var action = row(action_transition, 7, false);
    var tick = row(tick_transition, 7, true);
    const inactive = [_]QM31{QM31.zero()} ** binding.N_MAIN_COLUMNS;
    const component = subject.Component{
        .log_size = 4,
        .is_first_column = 0,
        .is_last_column = 1,
        .main_offset = 0,
        .initial_mcycle = 7,
        .final_mcycle = 8,
    };
    try expect(&component, &action, &tick, true, false, true);
    try expect(&component, &tick, &inactive, false, false, true);

    tick[binding.MCYCLE_OFFSET] = QM31.fromBase(M31.fromCanonical(8));
    try expect(&component, &action, &tick, true, false, false);
    tick[binding.MCYCLE_OFFSET] = QM31.fromBase(M31.fromCanonical(7));
    action[binding.READ_ENABLED_OFFSET] = QM31.one();
    try expect(&component, &action, &tick, true, false, false);
    action[binding.READ_ENABLED_OFFSET] = QM31.zero();

    const repeated_action = action;
    try expect(
        &component,
        &action,
        &repeated_action,
        true,
        false,
        false,
    );
    var forged_endpoint = component;
    forged_endpoint.final_mcycle = 9;
    try expect(
        &forged_endpoint,
        &tick,
        &inactive,
        false,
        false,
        false,
    );
    try std.testing.expectEqual(
        @as(usize, 10),
        component.nConstraints(),
    );
    try std.testing.expectEqual(
        @as(u32, 5),
        component.maxConstraintLogDegreeBound(),
    );
    _ = component.asVerifierComponent();
    _ = component.asProverComponent();

    const offset_component = subject.Component{
        .log_size = 4,
        .is_first_column = 2,
        .is_last_column = 4,
        .main_offset = 7,
        .initial_mcycle = 7,
        .final_mcycle = 8,
    };
    var bounds = try offset_component.traceLogDegreeBounds(
        std.testing.allocator,
    );
    defer bounds.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 5), bounds.items[0].len);
    try std.testing.expectEqual(
        @as(usize, 7 + binding.N_MAIN_COLUMNS),
        bounds.items[1].len,
    );
    var mask = try offset_component.maskPoints(
        std.testing.allocator,
        core.circle.SECURE_FIELD_CIRCLE_GEN,
        offset_component.maxConstraintLogDegreeBound(),
    );
    defer mask.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 5), mask.items[0].len);
    try std.testing.expectEqual(
        @as(usize, 7 + binding.N_MAIN_COLUMNS),
        mask.items[1].len,
    );
    for (mask.items[0]) |column|
        try std.testing.expectEqual(@as(usize, 1), column.len);
    for (mask.items[1]) |column|
        try std.testing.expectEqual(@as(usize, 2), column.len);
}

test "joypad binding component rejects write reordering and inactive data" {
    const first = try joypad.Transition.apply(
        .{},
        .{ .write_p1 = 0x10 },
    );
    const second = try joypad.Transition.apply(
        first.after,
        .{ .set_pressed = joypad.Key.right.mask() },
    );
    const write = row(first, 0, false);
    const action = row(second, 0, false);
    const component = subject.Component{
        .log_size = 4,
        .is_first_column = 0,
        .is_last_column = 1,
        .main_offset = 0,
        .initial_mcycle = 0,
        .final_mcycle = 1,
    };
    try expect(&component, &write, &action, true, false, false);

    var inactive = [_]QM31{QM31.zero()} ** binding.N_MAIN_COLUMNS;
    inactive[binding.MCYCLE_OFFSET] = QM31.one();
    try expect(
        &component,
        &inactive,
        &inactive,
        false,
        true,
        false,
    );
}

test "joypad binding component exercises every constraint and physical wrap" {
    const action_transition = try joypad.Transition.apply(
        .{},
        .{ .set_pressed = joypad.Key.a.mask() },
    );
    const write_transition = try joypad.Transition.apply(
        action_transition.after,
        .{ .write_p1 = 0x10 },
    );
    const tick_transition = try joypad.Transition.apply(
        write_transition.after,
        .tick_mcycle,
    );
    const next_action_transition = try joypad.Transition.apply(
        tick_transition.after,
        .{ .set_pressed = joypad.Key.b.mask() },
    );
    const inactive = [_]QM31{QM31.zero()} ** binding.N_MAIN_COLUMNS;
    const action0 = row(action_transition, 0, false);
    const write0 = row(write_transition, 0, false);
    const tick0 = row(tick_transition, 0, false);
    const action1 = row(next_action_transition, 1, false);

    var inactive_clock = inactive;
    inactive_clock[binding.MCYCLE_OFFSET] = QM31.one();
    try expectConstraint(
        &inactive_clock,
        &inactive,
        false,
        true,
        0,
        0,
        1,
    );

    var non_binary_read = tick0;
    non_binary_read[binding.READ_ENABLED_OFFSET] =
        QM31.fromBase(M31.fromCanonical(2));
    try expectConstraint(
        &non_binary_read,
        &inactive,
        false,
        true,
        1,
        0,
        1,
    );

    var inactive_read = inactive;
    inactive_read[TICK_EVENT_OFFSET] = QM31.one();
    inactive_read[binding.READ_ENABLED_OFFSET] = QM31.one();
    try expectConstraint(
        &inactive_read,
        &inactive,
        false,
        true,
        2,
        0,
        1,
    );

    var action_read = action0;
    action_read[binding.READ_ENABLED_OFFSET] = QM31.one();
    try expectConstraint(
        &action_read,
        &tick0,
        false,
        false,
        3,
        0,
        1,
    );

    var late_tick = tick0;
    late_tick[binding.MCYCLE_OFFSET] = QM31.one();
    try expectConstraint(
        &action0,
        &late_tick,
        false,
        false,
        4,
        0,
        1,
    );
    try expectConstraint(
        &action0,
        &action0,
        false,
        false,
        5,
        0,
        1,
    );
    try expectConstraint(
        &write0,
        &action0,
        false,
        false,
        6,
        0,
        1,
    );
    try expectConstraint(
        &action1,
        &row(tick_transition, 1, false),
        true,
        false,
        7,
        0,
        2,
    );
    try expectConstraint(
        &action1,
        &inactive,
        false,
        false,
        8,
        0,
        1,
    );
    try expectConstraint(
        &tick0,
        &inactive,
        false,
        false,
        9,
        0,
        2,
    );

    const physical_last = row(tick_transition, 15, false);
    try expectRows(
        &physical_last,
        &tick0,
        false,
        true,
        0,
        16,
        true,
    );
    try expectRows(
        &physical_last,
        &tick0,
        false,
        false,
        0,
        16,
        false,
    );
}

test "joypad binding component point path binds offsets and next row" {
    const action_transition = try joypad.Transition.apply(
        .{},
        .{ .set_pressed = joypad.Key.a.mask() },
    );
    const tick_transition = try joypad.Transition.apply(
        action_transition.after,
        .tick_mcycle,
    );
    const action = row(action_transition, 7, false);
    const tick = row(tick_transition, 7, true);
    const component = subject.Component{
        .log_size = 4,
        .is_first_column = 2,
        .is_last_column = 4,
        .main_offset = 3,
        .initial_mcycle = 7,
        .final_mcycle = 8,
    };

    var preprocessed_storage =
        [_][1]QM31{.{QM31.zero()}} ** 5;
    preprocessed_storage[component.is_first_column][0] = QM31.one();
    var preprocessed: [preprocessed_storage.len][]QM31 = undefined;
    for (&preprocessed, &preprocessed_storage) |*column, *values|
        column.* = values;
    var main_storage =
        [_][2]QM31{.{ QM31.zero(), QM31.zero() }} **
        (3 + binding.N_MAIN_COLUMNS);
    for (
        main_storage[component.main_offset..][0..binding.N_MAIN_COLUMNS],
        action,
        tick,
    ) |*values, current, next| {
        values[0] = current;
        values[1] = next;
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

    main_storage[
        component.main_offset + binding.MCYCLE_OFFSET
    ][1] = QM31.fromBase(M31.fromCanonical(8));
    var mutated =
        core.air.accumulation.PointEvaluationAccumulator.init(QM31.one());
    try component.evaluateConstraintQuotientsAtPoint(
        point,
        &mask,
        &mutated,
        component.maxConstraintLogDegreeBound(),
    );
    try std.testing.expect(!mutated.finalize().isZero());

    var ignored =
        core.air.accumulation.PointEvaluationAccumulator.init(QM31.one());
    try std.testing.expectError(
        error.InvalidProofShape,
        component.evaluateConstraintQuotientsAtPoint(
            point,
            &mask,
            &ignored,
            component.log_size - 1,
        ),
    );
}

test "joypad binding component domain rejects clock and read mutations" {
    const log_size: u32 = 4;
    const evaluation_log_size: u32 = log_size + 1;
    const evaluation_size: usize = 1 << evaluation_log_size;
    const first_transition = try joypad.Transition.apply(
        .{},
        .{ .set_pressed = joypad.Key.a.mask() },
    );
    const second_transition = try joypad.Transition.apply(
        first_transition.after,
        .tick_mcycle,
    );
    const first_row = row(first_transition, 7, false);
    const second_row = row(second_transition, 7, true);
    const first_index: usize = 0;
    const second_index = core.utils.offsetBitReversedCircleDomainIndex(
        first_index,
        log_size,
        evaluation_log_size,
        1,
    );
    var last_index: ?usize = null;
    for (0..evaluation_size) |index| {
        if (core.utils.offsetBitReversedCircleDomainIndex(
            index,
            log_size,
            evaluation_log_size,
            1,
        ) == first_index) last_index = index;
    }

    var first_values = [_]M31{M31.zero()} ** evaluation_size;
    var last_values = [_]M31{M31.zero()} ** evaluation_size;
    first_values[first_index] = M31.one();
    last_values[last_index orelse return error.InvalidProofShape] = M31.one();
    var main_values =
        [_][evaluation_size]M31{
            [_]M31{M31.zero()} ** evaluation_size,
        } ** binding.N_MAIN_COLUMNS;
    for (&main_values, first_row, second_row) |
        *values,
        first_value,
        second_value,
    | {
        values[first_index] = first_value.toM31Array()[0];
        values[second_index] = second_value.toM31Array()[0];
    }
    var preprocessed = [_]prover_component.Poly{
        .{ .log_size = evaluation_log_size, .values = &first_values },
        .{ .log_size = evaluation_log_size, .values = &last_values },
    };
    var main: [binding.N_MAIN_COLUMNS]prover_component.Poly = undefined;
    for (&main, &main_values) |*polynomial, *values|
        polynomial.* = .{
            .log_size = evaluation_log_size,
            .values = values,
        };
    var trees = [_][]const prover_component.Poly{ &preprocessed, &main };
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
        .initial_mcycle = 7,
        .final_mcycle = 8,
    };
    const challenge = QM31.fromU32Unchecked(3, 5, 7, 11);
    try expectDomain(
        &component,
        &trace,
        challenge,
        evaluation_log_size,
        true,
    );

    main_values[binding.MCYCLE_OFFSET][second_index] =
        M31.fromCanonical(8);
    try expectDomain(
        &component,
        &trace,
        challenge,
        evaluation_log_size,
        false,
    );
    main_values[binding.MCYCLE_OFFSET][second_index] =
        M31.fromCanonical(7);
    main_values[binding.READ_ENABLED_OFFSET][first_index] = M31.one();
    try expectDomain(
        &component,
        &trace,
        challenge,
        evaluation_log_size,
        false,
    );
    main_values[binding.READ_ENABLED_OFFSET][first_index] = M31.zero();
    component.final_mcycle = 9;
    try expectDomain(
        &component,
        &trace,
        challenge,
        evaluation_log_size,
        false,
    );
}

fn row(
    transition: joypad.Transition,
    mcycle: u32,
    read_enabled: bool,
) [binding.N_MAIN_COLUMNS]QM31 {
    var result = [_]QM31{QM31.zero()} ** binding.N_MAIN_COLUMNS;
    const semantic = @import("joypad_component.zig").columns(
        joypad_air.ValidatedStep.init(transition) catch unreachable,
    );
    for (result[0..semantic.len], semantic) |*value, source|
        value.* = QM31.fromBase(source);
    result[binding.MCYCLE_OFFSET] =
        QM31.fromBase(M31.fromCanonical(mcycle));
    result[binding.READ_ENABLED_OFFSET] =
        if (read_enabled) QM31.one() else QM31.zero();
    return result;
}

fn expect(
    component: *const subject.Component,
    current: []const QM31,
    next: []const QM31,
    is_first: bool,
    is_last: bool,
    expected: bool,
) !void {
    const evaluation = try component.evaluateRow(
        current,
        next,
        if (is_first) QM31.one() else QM31.zero(),
        if (is_last) QM31.one() else QM31.zero(),
    );
    try std.testing.expectEqual(expected, evaluation.allZero());
}

fn expectRows(
    current: []const QM31,
    next: []const QM31,
    is_first: bool,
    is_last: bool,
    initial_mcycle: u32,
    final_mcycle: u32,
    expected: bool,
) !void {
    const evaluation = try subject.evaluateRows(
        QM31,
        current,
        next,
        if (is_first) QM31.one() else QM31.zero(),
        if (is_last) QM31.one() else QM31.zero(),
        initial_mcycle,
        final_mcycle,
    );
    try std.testing.expectEqual(expected, evaluation.allZero());
}

fn expectConstraint(
    current: []const QM31,
    next: []const QM31,
    is_first: bool,
    is_last: bool,
    constraint: usize,
    initial_mcycle: u32,
    final_mcycle: u32,
) !void {
    const evaluation = try subject.evaluateRows(
        QM31,
        current,
        next,
        if (is_first) QM31.one() else QM31.zero(),
        if (is_last) QM31.one() else QM31.zero(),
        initial_mcycle,
        final_mcycle,
    );
    try std.testing.expect(!evaluation.values[constraint].isZero());
}

fn expectDomain(
    component: *const subject.Component,
    trace: *const prover_component.Trace,
    challenge: QM31,
    evaluation_log_size: u32,
    expected: bool,
) !void {
    var accumulator =
        try prover_accumulation.DomainEvaluationAccumulator.init(
            std.testing.allocator,
            challenge,
            evaluation_log_size,
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
    pub fn add(a: Degree, b: Degree) Degree {
        return .{ .degree = @max(a.degree, b.degree) };
    }
    pub fn sub(a: Degree, b: Degree) Degree {
        return a.add(b);
    }
    pub fn mul(a: Degree, b: Degree) Degree {
        return .{ .degree = a.degree + b.degree };
    }
    pub fn isZero(_: Degree) bool {
        return false;
    }
};
