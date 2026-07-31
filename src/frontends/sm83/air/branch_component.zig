//! Branch specialization of the shared execution-bound family component.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const accumulation = @import("stwo_prover_engine").air.accumulation;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const branch = @import("branch.zig");
const execution = @import("execution.zig");
const family_component = @import("family_component.zig");
const runner = @import("../runner/mod.zig");

pub const N_CONSTRAINTS: usize = branch.N_BOUND_CONSTRAINTS + 1;
pub const Component = family_component.Component(branch);

const test_component = Component{
    .log_size = 4,
    .is_active_main_column = execution.N_MAIN_COLUMNS,
    .execution_offset = 0,
    .main_offset = execution.N_MAIN_COLUMNS + 1,
};

fn callStep() !runner.StepTrace {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.write(0, 0xc4);
    memory.write(1, 0x34);
    memory.write(2, 0x12);
    var cpu = runner.Cpu{ .f = 0x70, .sp = 0 };
    return runner.step(&cpu, &memory);
}

test "branch component rejects CALL target and stack-bus mutations" {
    try std.testing.expectEqual(N_CONSTRAINTS, test_component.nConstraints());
    _ = test_component.asVerifierComponent();
    _ = test_component.asProverComponent();

    const step = try callStep();
    var values: [branch.N_MAIN_COLUMNS]QM31 = undefined;
    for (
        &values,
        branch.columns(try branch.ValidatedStep.init(step)),
    ) |*value, source| value.* = QM31.fromBase(source);
    var machine_values: [execution.N_MAIN_COLUMNS]QM31 = undefined;
    for (&machine_values, execution.columns(step, 0)) |*value, source|
        value.* = QM31.fromBase(source);
    var machine = try execution.Row(QM31).fromColumns(&machine_values);
    try std.testing.expect(
        (try test_component.evaluateRow(&values, machine, QM31.one())).allZero(),
    );
    values[45] = values[45].add(QM31.one());
    try std.testing.expect(
        !(try test_component.evaluateRow(&values, machine, QM31.one())).allZero(),
    );
    values[45] = values[45].sub(QM31.one());
    machine.bus[5].address = machine.bus[5].address.add(QM31.one());
    try std.testing.expect(
        !(try test_component.evaluateRow(&values, machine, QM31.one())).allZero(),
    );
}

test "branch component prover domain rejects a CALL stack-write mutation" {
    const allocator = std.testing.allocator;
    const evaluation_log_size: u32 = 5;
    const evaluation_size: usize = 1 << evaluation_log_size;
    const step = try callStep();
    const witness = branch.columns(try branch.ValidatedStep.init(step));
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
    var main_values: [branch.N_MAIN_COLUMNS][evaluation_size]M31 = undefined;
    var main_polynomials: [branch.N_MAIN_COLUMNS]prover_component.Poly =
        undefined;
    for (&main_values, &main_polynomials, witness) |*values, *polynomial, value| {
        @memset(values, value);
        polynomial.* = .{ .log_size = evaluation_log_size, .values = values };
    }
    const active_polynomial = prover_component.Poly{
        .log_size = evaluation_log_size,
        .values = &active_values,
    };
    var preprocessed = [_]prover_component.Poly{};
    var combined: [execution.N_MAIN_COLUMNS + 1 + branch.N_MAIN_COLUMNS]prover_component.Poly =
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

    const bus5_value =
        2 * execution.N_STATE_COLUMNS + 5 * execution.N_BUS_COLUMNS + 1;
    @memset(&execution_values[bus5_value], M31.fromCanonical(4));
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
