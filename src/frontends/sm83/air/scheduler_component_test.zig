//! Direct and prover-domain controls for the standalone scheduler component.

const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const prover_accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const runner = @import("../runner/mod.zig");
const machine = @import("../runner/machine.zig");
const scheduler = @import("scheduler.zig");
const subject = @import("scheduler_component.zig");

const EVENT_OFFSET: usize = 2;
const EFFECTIVE_IME_OFFSET: usize = 2 + 38;
const BEFORE_IME_OFFSET: usize = 2 + 39;
const BEFORE_HALT_BUG_OFFSET: usize = 2 + 42;

test "scheduler component has exact cubic geometry and adapter shape" {
    try std.testing.expectEqual(@as(usize, 54), subject.N_MAIN_COLUMNS);
    try std.testing.expectEqual(@as(usize, 167), subject.N_CONSTRAINTS);
    const variables =
        [_]Degree{Degree.variable()} ** subject.N_MAIN_COLUMNS;
    const boundary = subject.Boundary{
        .mcycle = 0,
        .ime = false,
        .ime_enable_pending = false,
        .halted = false,
        .halt_bug = false,
    };
    const evaluation = try subject.evaluateRows(
        Degree,
        &variables,
        &variables,
        Degree.variable(),
        Degree.variable(),
        boundary,
        boundary,
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
        .initial = boundary,
        .final = .{
            .mcycle = 1,
            .ime = false,
            .ime_enable_pending = false,
            .halted = false,
            .halt_bug = false,
        },
    };
    try std.testing.expectEqual(subject.N_CONSTRAINTS, component.nConstraints());
    try std.testing.expectEqual(@as(u32, 5), component.maxConstraintLogDegreeBound());
    _ = component.asVerifierComponent();
    _ = component.asProverComponent();
    var bounds = try component.traceLogDegreeBounds(std.testing.allocator);
    defer bounds.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 5), bounds.items[0].len);
    try std.testing.expectEqual(@as(usize, 61), bounds.items[1].len);
    var mask = try component.maskPoints(
        std.testing.allocator,
        core.circle.SECURE_FIELD_CIRCLE_GEN,
        component.maxConstraintLogDegreeBound(),
    );
    defer mask.deinitDeep(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 5), mask.items[0].len);
    try std.testing.expectEqual(@as(usize, 61), mask.items[1].len);
}

test "scheduler component binds prefix chain and every endpoint field" {
    const steps = try twoInstructionSteps();
    const first_source =
        try subject.columns(try scheduler.ValidatedStep.init(steps[0]), 0);
    const second_source =
        try subject.columns(try scheduler.ValidatedStep.init(steps[1]), 1);
    var first = lift(first_source);
    var second = lift(second_source);
    const inactive = [_]QM31{QM31.zero()} ** subject.N_MAIN_COLUMNS;
    const honest = subject.Component{
        .log_size = 4,
        .is_first_column = 0,
        .is_last_column = 1,
        .main_offset = 0,
        .initial = beforeBoundary(steps[0], 0),
        .final = afterBoundary(steps[1], 2),
    };
    try expectRow(&honest, &first, &second, true, false, true);
    try expectRow(&honest, &second, &inactive, false, false, true);
    try expectRow(&honest, &second, &first, false, true, true);

    first[EVENT_OFFSET] = QM31.zero();
    try expectRow(&honest, &first, &second, true, false, false);
    first[EVENT_OFFSET] = QM31.one();
    second[1] = QM31.fromBase(M31.fromCanonical(9));
    try expectRow(&honest, &first, &second, true, false, false);
    second[1] = QM31.one();
    second[EFFECTIVE_IME_OFFSET] = QM31.one();
    second[BEFORE_IME_OFFSET] = QM31.one();
    try expectRow(&honest, &first, &second, true, false, false);
    second[EFFECTIVE_IME_OFFSET] = QM31.zero();
    second[BEFORE_IME_OFFSET] = QM31.zero();

    for (0..5) |field| {
        var forged = honest;
        forged.initial = mutateBoundary(forged.initial, field);
        try expectRow(&forged, &first, &second, true, false, false);
        forged = honest;
        forged.final = mutateBoundary(forged.final, field);
        try expectRow(&forged, &second, &inactive, false, false, false);
    }

    try expectRow(&honest, &inactive, &inactive, true, false, false);
    try expectRow(&honest, &inactive, &second, false, false, false);
    var non_boolean = first;
    non_boolean[0] = QM31.fromBase(M31.fromCanonical(2));
    try expectRow(&honest, &non_boolean, &second, true, false, false);
    var inactive_clock = inactive;
    inactive_clock[1] = QM31.one();
    try expectRow(
        &honest,
        &inactive_clock,
        &inactive,
        false,
        true,
        false,
    );
}

test "scheduler component domain rejects semantics endpoints chain activity and vacuity" {
    const log_size: u32 = 4;
    const evaluation_log_size: u32 = log_size + 1;
    const evaluation_size: usize = 1 << evaluation_log_size;
    const steps = try twoInstructionSteps();
    const first_witness =
        try subject.columns(try scheduler.ValidatedStep.init(steps[0]), 0);
    const second_witness =
        try subject.columns(try scheduler.ValidatedStep.init(steps[1]), 1);
    const first_index: usize = 0;
    const second_index = core.utils.offsetBitReversedCircleDomainIndex(
        first_index,
        log_size,
        evaluation_log_size,
        1,
    );
    var last_index: ?usize = null;
    for (0..evaluation_size) |row| {
        if (core.utils.offsetBitReversedCircleDomainIndex(
            row,
            log_size,
            evaluation_log_size,
            1,
        ) == first_index) last_index = row;
    }

    var first_values = [_]M31{M31.zero()} ** evaluation_size;
    var last_values = [_]M31{M31.zero()} ** evaluation_size;
    first_values[first_index] = M31.one();
    last_values[last_index orelse return error.InvalidProofShape] = M31.one();
    var main_values =
        [_][evaluation_size]M31{
            [_]M31{M31.zero()} ** evaluation_size,
        } ** subject.N_MAIN_COLUMNS;
    for (&main_values, first_witness, second_witness) |
        *values,
        first_value,
        second_value,
    | {
        values[first_index] = first_value;
        values[second_index] = second_value;
    }
    var preprocessed = [_]prover_component.Poly{
        .{ .log_size = evaluation_log_size, .values = &first_values },
        .{ .log_size = evaluation_log_size, .values = &last_values },
    };
    var main: [subject.N_MAIN_COLUMNS]prover_component.Poly = undefined;
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
        .initial = beforeBoundary(steps[0], 0),
        .final = afterBoundary(steps[1], 2),
    };
    const challenge = QM31.fromU32Unchecked(3, 5, 7, 11);
    try expectDomain(&component, &trace, challenge, evaluation_log_size, true);

    main_values[EVENT_OFFSET][first_index] = M31.zero();
    try expectDomain(&component, &trace, challenge, evaluation_log_size, false);
    main_values[EVENT_OFFSET][first_index] = M31.one();
    main_values[1][second_index] = M31.fromCanonical(9);
    try expectDomain(&component, &trace, challenge, evaluation_log_size, false);
    main_values[1][second_index] = M31.one();

    component.initial.ime = true;
    try expectDomain(&component, &trace, challenge, evaluation_log_size, false);
    component.initial.ime = false;
    component.final.mcycle = 3;
    try expectDomain(&component, &trace, challenge, evaluation_log_size, false);
    component.final.mcycle = 2;

    main_values[0][first_index] = M31.zero();
    main_values[0][second_index] = M31.zero();
    try expectDomain(&component, &trace, challenge, evaluation_log_size, false);
    main_values[0][first_index] = M31.one();
    main_values[0][second_index] = M31.one();

    const third_index = core.utils.offsetBitReversedCircleDomainIndex(
        second_index,
        log_size,
        evaluation_log_size,
        1,
    );
    main_values[0][second_index] = M31.zero();
    main_values[0][third_index] = M31.one();
    for (2..subject.N_MAIN_COLUMNS) |column|
        main_values[column][third_index] = second_witness[column];
    try expectDomain(&component, &trace, challenge, evaluation_log_size, false);

    for (&main_values) |*values| @memset(values, M31.zero());
    try expectDomain(&component, &trace, challenge, evaluation_log_size, false);
}

test "scheduler component chains a canonical HALT bug transition" {
    const steps = try haltBugSteps();
    const first_source =
        try subject.columns(try scheduler.ValidatedStep.init(steps[0]), 0);
    const second_source =
        try subject.columns(try scheduler.ValidatedStep.init(steps[1]), 1);
    const first = lift(first_source);
    var second = lift(second_source);
    const component = subject.Component{
        .log_size = 4,
        .is_first_column = 0,
        .is_last_column = 1,
        .main_offset = 0,
        .initial = beforeBoundary(steps[0], 0),
        .final = afterBoundary(steps[1], 2),
    };
    try expectRow(&component, &first, &second, true, false, true);
    second[BEFORE_HALT_BUG_OFFSET] = QM31.zero();
    try expectRow(&component, &first, &second, true, false, false);
}

fn twoInstructionSteps() ![2]machine.StepResult {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.write(0, 0);
    memory.write(1, 0);
    var scheduler_machine = machine.Machine.init(&memory, .{});
    return .{ try scheduler_machine.step(), try scheduler_machine.step() };
}

fn haltBugSteps() ![2]machine.StepResult {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.write(0, 0x76);
    memory.write(1, 0);
    memory.write(0xffff, 1);
    memory.write(0xff0f, 1);
    var scheduler_machine = machine.Machine.init(&memory, .{});
    return .{
        try scheduler_machine.step(),
        try scheduler_machine.step(),
    };
}

fn beforeBoundary(
    result: machine.StepResult,
    mcycle: u32,
) subject.Boundary {
    return .{
        .mcycle = mcycle,
        .ime = result.before.cpu.ime,
        .ime_enable_pending = result.before.cpu.ime_enable_pending,
        .halted = result.before.cpu.halted,
        .halt_bug = result.before.halt_bug,
    };
}

fn afterBoundary(
    result: machine.StepResult,
    mcycle: u32,
) subject.Boundary {
    return .{
        .mcycle = mcycle,
        .ime = result.after.cpu.ime,
        .ime_enable_pending = result.after.cpu.ime_enable_pending,
        .halted = result.after.cpu.halted,
        .halt_bug = result.after.halt_bug,
    };
}

fn mutateBoundary(boundary: subject.Boundary, field: usize) subject.Boundary {
    var result = boundary;
    switch (field) {
        0 => result.mcycle += 1,
        1 => result.ime = !result.ime,
        2 => result.ime_enable_pending = !result.ime_enable_pending,
        3 => result.halted = !result.halted,
        4 => result.halt_bug = !result.halt_bug,
        else => unreachable,
    }
    return result;
}

fn lift(
    values: [subject.N_MAIN_COLUMNS]M31,
) [subject.N_MAIN_COLUMNS]QM31 {
    var result: [subject.N_MAIN_COLUMNS]QM31 = undefined;
    for (&result, values) |*destination, value|
        destination.* = QM31.fromBase(value);
    return result;
}

fn expectRow(
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
    try component.evaluateConstraintQuotientsOnDomain(trace, &accumulator);
    var result = try accumulator.finalize();
    defer result.deinit(std.testing.allocator);
    var zero = true;
    for (0..result.len()) |row| zero = zero and result.at(row).isZero();
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

    pub fn add(left: Degree, right: Degree) Degree {
        return .{ .degree = @max(left.degree, right.degree) };
    }

    pub fn sub(left: Degree, right: Degree) Degree {
        return add(left, right);
    }

    pub fn mul(left: Degree, right: Degree) Degree {
        return .{ .degree = left.degree + right.degree };
    }

    pub fn isZero(_: Degree) bool {
        return false;
    }
};
