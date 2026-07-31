const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const prover_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const circle = core.circle;
const component = @import("joypad_component.zig");
const joypad_air = @import("joypad.zig");
const joypad = @import("../runner/joypad.zig");

const ACTION_OFFSET: usize = 27;
const BEFORE_PRESSED_OFFSET: usize = 11;

test "joypad component has exact cubic geometry and adapter shape" {
    try std.testing.expectEqual(@as(usize, 144), component.N_MAIN_COLUMNS);
    try std.testing.expectEqual(@as(usize, 410), component.N_CONSTRAINTS);

    const variables =
        [_]Degree{Degree.variable()} ** joypad_air.N_MAIN_COLUMNS;
    const initial = try stableState(2, 0);
    const evaluation = try component.evaluateRows(
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
    try std.testing.expectEqual(component.MAX_CONSTRAINT_DEGREE, maximum);

    const allocator = std.testing.allocator;
    const adapter = component.Component{
        .log_size = 4,
        .is_first_column = 2,
        .is_last_column = 4,
        .main_offset = 7,
        .initial = initial,
        .final = initial,
    };
    try std.testing.expectEqual(
        component.N_CONSTRAINTS,
        adapter.nConstraints(),
    );
    try std.testing.expectEqual(
        @as(u32, 5),
        adapter.maxConstraintLogDegreeBound(),
    );
    _ = adapter.asVerifierComponent();
    _ = adapter.asProverComponent();

    var bounds = try adapter.traceLogDegreeBounds(allocator);
    defer bounds.deinitDeep(allocator);
    try std.testing.expectEqual(@as(usize, 5), bounds.items[0].len);
    try std.testing.expectEqual(@as(usize, 151), bounds.items[1].len);

    var mask = try adapter.maskPoints(
        allocator,
        circle.SECURE_FIELD_CIRCLE_GEN,
        adapter.maxConstraintLogDegreeBound(),
    );
    defer mask.deinitDeep(allocator);
    try std.testing.expectEqual(@as(usize, 5), mask.items[0].len);
    try std.testing.expectEqual(@as(usize, 151), mask.items[1].len);
    for (mask.items[0]) |column|
        try std.testing.expectEqual(@as(usize, 1), column.len);
    for (mask.items[1]) |column|
        try std.testing.expectEqual(@as(usize, 2), column.len);
}

test "joypad component binds prefix chain endpoints and activity" {
    const first_transition = try joypad.Transition.apply(
        try stableState(2, 0),
        .{ .set_pressed = joypad.Key.right.mask() },
    );
    const second_transition = try joypad.Transition.apply(
        first_transition.after,
        .{ .write_p1 = 0x10 },
    );
    var first = lift(joypad_air.columns(
        try joypad_air.ValidatedStep.init(first_transition),
    ));
    var second = lift(joypad_air.columns(
        try joypad_air.ValidatedStep.init(second_transition),
    ));
    const inactive =
        [_]QM31{QM31.zero()} ** joypad_air.N_MAIN_COLUMNS;
    const honest = component.Component{
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

    first[ACTION_OFFSET] = QM31.one().sub(first[ACTION_OFFSET]);
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
    first[ACTION_OFFSET] = QM31.one().sub(first[ACTION_OFFSET]);

    second[BEFORE_PRESSED_OFFSET] =
        QM31.one().sub(second[BEFORE_PRESSED_OFFSET]);
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
    second[BEFORE_PRESSED_OFFSET] =
        QM31.one().sub(second[BEFORE_PRESSED_OFFSET]);

    for (0..24) |bit_index| {
        var forged = honest;
        forged.initial = mutateStateBit(forged.initial, bit_index);
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
        forged.final = mutateStateBit(forged.final, bit_index);
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
    const reentry = component.Component{
        .log_size = 4,
        .is_first_column = 0,
        .is_last_column = 1,
        .main_offset = 0,
        .initial = .{ .p1 = 0 },
        .final = .{ .p1 = 0 },
    };
    try expectRow(
        &reentry,
        &inactive,
        &second,
        false,
        true,
        false,
        false,
        false,
    );
    try expectRow(
        &honest,
        &inactive,
        &inactive,
        false,
        false,
        false,
        true,
        true,
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
}

test "joypad component domain rejects semantics endpoints activity and vacuity" {
    const allocator = std.testing.allocator;
    const log_size: u32 = 4;
    const evaluation_log_size: u32 = log_size + 1;
    const evaluation_size: usize = 1 << evaluation_log_size;
    const transition = try joypad.Transition.apply(
        try stableState(1, 0x20),
        .{ .set_pressed = 0x95 },
    );
    const witness = joypad_air.columns(
        try joypad_air.ValidatedStep.init(transition),
    );
    var proof_component = component.Component{
        .log_size = log_size,
        .is_first_column = 0,
        .is_last_column = 1,
        .main_offset = 0,
        .initial = transition.before,
        .final = transition.after,
    };

    var first_values = [_]M31{M31.one()} ** evaluation_size;
    var last_values = [_]M31{M31.one()} ** evaluation_size;
    var active_values = [_]M31{M31.one()} ** evaluation_size;
    var air_values: [joypad_air.N_MAIN_COLUMNS][evaluation_size]M31 = undefined;
    var air_polynomials: [joypad_air.N_MAIN_COLUMNS]prover_component.Poly = undefined;
    for (&air_values, &air_polynomials, witness) |
        *values,
        *polynomial,
        value,
    | {
        @memset(values, value);
        polynomial.* = .{
            .log_size = evaluation_log_size,
            .values = values,
        };
    }
    var preprocessed = [_]prover_component.Poly{
        .{ .log_size = evaluation_log_size, .values = &first_values },
        .{ .log_size = evaluation_log_size, .values = &last_values },
    };
    var main: [component.N_MAIN_COLUMNS]prover_component.Poly = undefined;
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
    const challenge = QM31.fromU32Unchecked(3, 5, 7, 11);

    try expectDomain(
        allocator,
        &proof_component,
        &trace,
        challenge,
        evaluation_log_size,
        true,
    );

    @memset(
        &air_values[ACTION_OFFSET],
        M31.one().sub(witness[ACTION_OFFSET]),
    );
    try expectDomain(
        allocator,
        &proof_component,
        &trace,
        challenge,
        evaluation_log_size,
        false,
    );
    @memset(&air_values[ACTION_OFFSET], witness[ACTION_OFFSET]);

    proof_component.initial =
        mutateStateBit(proof_component.initial, 10);
    try expectDomain(
        allocator,
        &proof_component,
        &trace,
        challenge,
        evaluation_log_size,
        false,
    );
    proof_component.initial = transition.before;
    proof_component.final = mutateStateBit(proof_component.final, 19);
    try expectDomain(
        allocator,
        &proof_component,
        &trace,
        challenge,
        evaluation_log_size,
        false,
    );
    proof_component.final = transition.after;

    @memset(&active_values, M31.zero());
    try expectDomain(
        allocator,
        &proof_component,
        &trace,
        challenge,
        evaluation_log_size,
        false,
    );

    @memset(&first_values, M31.zero());
    @memset(&last_values, M31.zero());
    for (&air_values) |*values| @memset(values, M31.zero());
    try expectDomain(
        allocator,
        &proof_component,
        &trace,
        challenge,
        evaluation_log_size,
        true,
    );
    @memset(&air_values[0], M31.one());
    try expectDomain(
        allocator,
        &proof_component,
        &trace,
        challenge,
        evaluation_log_size,
        false,
    );
}

test "joypad component domain enforces a two-row chain and no re-entry" {
    const allocator = std.testing.allocator;
    const log_size: u32 = 4;
    const evaluation_log_size: u32 = log_size + 1;
    const evaluation_size: usize = 1 << evaluation_log_size;
    const first_transition = try joypad.Transition.apply(
        try stableState(2, 0),
        .{ .set_pressed = joypad.Key.right.mask() },
    );
    const second_transition = try joypad.Transition.apply(
        first_transition.after,
        .{ .write_p1 = 0x10 },
    );
    const first_witness = joypad_air.columns(
        try joypad_air.ValidatedStep.init(first_transition),
    );
    const second_witness = joypad_air.columns(
        try joypad_air.ValidatedStep.init(second_transition),
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
        ) == first_index) {
            predecessor = row;
            break;
        }
    }
    const last_index = predecessor orelse return error.InvalidProofShape;

    var first_values = [_]M31{M31.zero()} ** evaluation_size;
    var last_values = [_]M31{M31.zero()} ** evaluation_size;
    var active_values = [_]M31{M31.zero()} ** evaluation_size;
    first_values[first_index] = M31.one();
    last_values[last_index] = M31.one();
    active_values[first_index] = M31.one();
    active_values[second_index] = M31.one();
    var air_values: [joypad_air.N_MAIN_COLUMNS][evaluation_size]M31 = undefined;
    var air_polynomials: [joypad_air.N_MAIN_COLUMNS]prover_component.Poly = undefined;
    for (&air_values, &air_polynomials, first_witness, second_witness) |
        *values,
        *polynomial,
        first_value,
        second_value,
    | {
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
    var main: [component.N_MAIN_COLUMNS]prover_component.Poly = undefined;
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
    var proof_component = component.Component{
        .log_size = log_size,
        .is_first_column = 0,
        .is_last_column = 1,
        .main_offset = 0,
        .initial = first_transition.before,
        .final = second_transition.after,
    };
    const challenge = QM31.fromU32Unchecked(13, 17, 19, 23);

    try expectDomain(
        allocator,
        &proof_component,
        &trace,
        challenge,
        evaluation_log_size,
        true,
    );

    const alternate = try joypad.Transition.apply(
        try stableState(0, 0xaa),
        .{ .set_pressed = 0x55 },
    );
    const alternate_witness = joypad_air.columns(
        try joypad_air.ValidatedStep.init(alternate),
    );
    for (&air_values, alternate_witness) |*values, value|
        values[second_index] = value;
    proof_component.final = alternate.after;
    try expectDomain(
        allocator,
        &proof_component,
        &trace,
        challenge,
        evaluation_log_size,
        false,
    );

    @memset(&first_values, M31.zero());
    @memset(&last_values, M31.zero());
    @memset(&active_values, M31.zero());
    active_values[second_index] = M31.one();
    for (&air_values, second_witness) |*values, value| {
        @memset(values, M31.zero());
        values[second_index] = value;
    }
    proof_component.final = second_transition.after;
    try expectDomain(
        allocator,
        &proof_component,
        &trace,
        challenge,
        evaluation_log_size,
        false,
    );
}

fn expectRow(
    proof_component: *const component.Component,
    current: []const QM31,
    next: []const QM31,
    current_active: bool,
    next_active: bool,
    is_first: bool,
    is_last: bool,
    expected: bool,
) !void {
    const evaluation = try proof_component.evaluateRow(
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
    proof_component: *const component.Component,
    trace: *const prover_component.Trace,
    challenge: QM31,
    evaluation_log_size: u32,
    expected: bool,
) !void {
    var accumulator = try prover_accumulation.DomainEvaluationAccumulator.init(
        allocator,
        challenge,
        evaluation_log_size,
        component.N_CONSTRAINTS,
    );
    defer accumulator.deinit();
    try proof_component.evaluateConstraintQuotientsOnDomain(
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

fn stableState(selection: u2, pressed: u8) !joypad.State {
    var state = joypad.State{};
    _ = state.setPressed(pressed);
    _ = state.writeP1(@as(u8, selection) << 4);
    _ = state.tickSameBoyCycles(48);
    try state.validate();
    return state;
}

fn mutateStateBit(state: joypad.State, bit_index: usize) joypad.State {
    var result = state;
    if (bit_index < 8)
        result.p1 ^= @as(u8, 1) << @intCast(bit_index)
    else if (bit_index < 16)
        result.pressed ^= @as(u8, 1) << @intCast(bit_index - 8)
    else if (bit_index < 18)
        result.pending_selection ^=
            @as(u2, 1) << @intCast(bit_index - 16)
    else
        result.switching_delay ^=
            @as(u8, 1) << @intCast(bit_index - 18);
    return result;
}

fn lift(
    values: [joypad_air.N_MAIN_COLUMNS]M31,
) [joypad_air.N_MAIN_COLUMNS]QM31 {
    var result: [joypad_air.N_MAIN_COLUMNS]QM31 = undefined;
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
