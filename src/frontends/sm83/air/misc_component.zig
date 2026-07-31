//! Executable misc-opcode specialization of the shared family component.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const execution = @import("execution.zig");
const family_component = @import("family_component.zig");
const misc = @import("misc.zig");
const runner = @import("../runner/mod.zig");

pub const N_CONSTRAINTS: usize = misc.N_BOUND_CONSTRAINTS + 1;
pub const Component = family_component.Component(misc);

const test_component = Component{
    .log_size = 4,
    .is_active_main_column = execution.N_MAIN_COLUMNS,
    .execution_offset = 0,
    .main_offset = execution.N_MAIN_COLUMNS + 1,
};

fn stopStep() !runner.StepTrace {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.write(0xffff, 0x10);
    memory.write(0, 0xa5);
    var cpu = runner.Cpu{ .f = 0x80, .pc = 0xffff, .halted = true };
    return runner.step(&cpu, &memory);
}

test "misc component rejects flag halted and stopped mutations" {
    try std.testing.expectEqual(N_CONSTRAINTS, test_component.nConstraints());
    _ = test_component.asVerifierComponent();
    _ = test_component.asProverComponent();

    const step = try stopStep();
    var values: [misc.N_MAIN_COLUMNS]QM31 = undefined;
    for (
        &values,
        misc.columns(try misc.ValidatedStep.init(step)),
    ) |*value, source| value.* = QM31.fromBase(source);
    var machine_values: [execution.N_MAIN_COLUMNS]QM31 = undefined;
    for (&machine_values, execution.columns(step, 0)) |*value, source|
        value.* = QM31.fromBase(source);
    var machine = try execution.Row(QM31).fromColumns(&machine_values);
    try std.testing.expect(
        (try test_component.evaluateRow(&values, machine, QM31.one())).allZero(),
    );
    values[37] = QM31.zero();
    try std.testing.expect(
        !(try test_component.evaluateRow(&values, machine, QM31.one())).allZero(),
    );
    values[37] = QM31.one();
    machine.after.values[@intFromEnum(execution.StateIndex.halted)] =
        QM31.zero();
    try std.testing.expect(
        !(try test_component.evaluateRow(&values, machine, QM31.one())).allZero(),
    );
    machine = try execution.Row(QM31).fromColumns(&machine_values);
    machine.after.values[@intFromEnum(execution.StateIndex.stopped)] =
        QM31.zero();
    try std.testing.expect(
        !(try test_component.evaluateRow(&values, machine, QM31.one())).allZero(),
    );
}

test "misc component domain rejects a STOP second-fetch mutation" {
    const allocator = std.testing.allocator;
    const evaluation_log_size: u32 = 5;
    const evaluation_size: usize = 1 << evaluation_log_size;
    const step = try stopStep();
    const witness = misc.columns(try misc.ValidatedStep.init(step));
    const machine_witness = execution.columns(step, 0);

    var active_values = [_]M31{M31.one()} ** evaluation_size;
    var execution_values: [execution.N_MAIN_COLUMNS][evaluation_size]M31 =
        undefined;
    var execution_polynomials: [execution.N_MAIN_COLUMNS]prover_component.Poly =
        undefined;
    for (
        &execution_values,
        &execution_polynomials,
        machine_witness,
    ) |*values, *polynomial, value| {
        @memset(values, value);
        polynomial.* = .{ .log_size = evaluation_log_size, .values = values };
    }
    var main_values: [misc.N_MAIN_COLUMNS][evaluation_size]M31 = undefined;
    var main_polynomials: [misc.N_MAIN_COLUMNS]prover_component.Poly = undefined;
    for (&main_values, &main_polynomials, witness) |*values, *polynomial, value| {
        @memset(values, value);
        polynomial.* = .{ .log_size = evaluation_log_size, .values = values };
    }
    const active_polynomial = prover_component.Poly{
        .log_size = evaluation_log_size,
        .values = &active_values,
    };
    var preprocessed = [_]prover_component.Poly{};
    var combined: [execution.N_MAIN_COLUMNS + 1 + misc.N_MAIN_COLUMNS]prover_component.Poly =
        undefined;
    @memcpy(combined[0..execution.N_MAIN_COLUMNS], &execution_polynomials);
    combined[execution.N_MAIN_COLUMNS] = active_polynomial;
    @memcpy(combined[execution.N_MAIN_COLUMNS + 1 ..], &main_polynomials);
    var trees = [_][]const prover_component.Poly{ &preprocessed, &combined };
    const trace = prover_component.Trace{
        .polys = @import("stwo_core").pcs.TreeVec(
            []const prover_component.Poly,
        ).initOwned(&trees),
    };
    const challenge = QM31.fromU32Unchecked(3, 5, 7, 11);

    var honest = try accumulation.DomainEvaluationAccumulator.init(
        allocator,
        challenge,
        evaluation_log_size,
        N_CONSTRAINTS,
    );
    defer honest.deinit();
    try test_component.evaluateConstraintQuotientsOnDomain(&trace, &honest);
    var honest_result = try honest.finalize();
    defer honest_result.deinit(allocator);
    for (0..honest_result.len()) |row|
        try std.testing.expect(honest_result.at(row).isZero());

    const bus1_address =
        2 * execution.N_STATE_COLUMNS + execution.N_BUS_COLUMNS;
    @memset(&execution_values[bus1_address], M31.one());
    var mutated = try accumulation.DomainEvaluationAccumulator.init(
        allocator,
        challenge,
        evaluation_log_size,
        N_CONSTRAINTS,
    );
    defer mutated.deinit();
    try test_component.evaluateConstraintQuotientsOnDomain(&trace, &mutated);
    var mutated_result = try mutated.finalize();
    defer mutated_result.deinit(allocator);
    var saw_nonzero = false;
    for (0..mutated_result.len()) |row|
        saw_nonzero = saw_nonzero or !mutated_result.at(row).isZero();
    try std.testing.expect(saw_nonzero);
}
